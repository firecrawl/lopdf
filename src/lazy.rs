//! Lazy object store: a loaded document holds the raw file bytes and
//! the xref map, and parses an object the first time something
//! dereferences it. Objects nothing dereferences are never parsed or
//! represented, so a document's memory cost follows what its consumer
//! touches, not what the file contains. The load-bearing invariant:
//! `cells` is structurally frozen after build (every xref id gets its
//! cell up front), so `&Object` references handed out of cells stay
//! valid for the document's life while `&self` resolution fills
//! other cells. Object-stream containers keep only a child-offset
//! index; the decompressed plaintext lives in a single most-recent-
//! container slot, and children parse ONE AT A TIME straight from
//! that plaintext — so touching an object costs its own parsed form
//! plus one transient container plaintext, never the parsed or textual
//! forms of giant unread siblings. A container whose plaintext would
//! be huge is never materialized: its children stream out of the
//! inflater through a fixed buffer.

use std::borrow::Cow;
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read};
use std::sync::Arc;

use flate2::read::ZlibDecoder;

use log::warn;

use crate::encryption::{self, EncryptionState};
use crate::load_options::FilterFunc;
use crate::parser::{self, ObjectResolver};
use crate::xref::{Xref, XrefEntry};
use crate::{Error, Object, ObjectId, Result, Stream};

/// Where an unresolved object's bytes live, straight from the xref.
#[derive(Debug, Clone, Copy)]
enum LazyEntry {
    Normal { offset: u32 },
    InStream { container: u32 },
}

/// A touched object-stream container's child index: (id, start, end)
/// byte ranges into the container's decompressed plaintext, where the
/// last child's end is None (it runs to the end of the plaintext), parsed
/// once from its header. The plaintext itself is NOT retained here —
/// see `plaintext_slot`.
#[derive(Debug, Clone)]
struct ObjStmIndex {
    children: Vec<(u32, usize, Option<usize>)>,
}

/// Containers whose children start past this many plaintext bytes are
/// never decompressed whole into the slot; real object streams are far
/// smaller, so only pathological ones (hundreds of MB of null arrays)
/// take the streaming path.
const STREAM_CONTAINERS_ABOVE: usize = 16 * 1024 * 1024;

/// Siblings up to this size are resolved during a streamed container's
/// pass, so one inflate serves every small object it holds instead of
/// one inflate per object; anything larger stays lazy.
const STREAM_SIBLINGS_UP_TO: usize = 64 * 1024;

/// Inflater output buffer for streamed containers.
const STREAM_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct LazyStore {
    /// The file's bytes, shared with the loader that produced them —
    /// wrapping the caller's vector costs nothing, where an owned
    /// copy doubled a large document's footprint for the store's
    /// whole life.
    buffer: Arc<Vec<u8>>,
    entries: HashMap<u32, LazyEntry>,
    /// One pre-built cell per xref id, holding the PARSED generation
    /// and the object. The generation the object header declares is
    /// authoritative for matching requests; the xref's generation
    /// column is only a locator, and real files disagree between the
    /// two.
    cells: HashMap<u32, OnceCell<(u16, Object)>>,
    /// Ids currently mid-resolve; re-entry means a reference cycle
    /// (e.g. a stream /Length chain reaching back into itself), which
    /// resolves as parse failure for the requested object, never a
    /// hang or unbounded recursion. Borrowed only in short scopes,
    /// never across a parse.
    resolving: RefCell<HashSet<u32>>,
    /// One pre-built cell per container id named by any Compressed
    /// xref entry; filled with the container's child index on the
    /// first child touch.
    containers: HashMap<u32, OnceCell<ObjStmIndex>>,
    /// The most recent container's decompressed plaintext. One slot:
    /// child access clusters by container, so a single slot keeps
    /// re-decompression rare while bounding plaintext residency to one
    /// container at a time. Borrowed only in short scopes.
    plaintext_slot: RefCell<Option<(u32, Vec<u8>)>>,
    filter: Option<FilterFunc>,
    /// Set for an encrypted document: every object parsed from its own
    /// xref offset is decrypted with its parsed id as it materializes;
    /// object-stream children are not, since their container was.
    decryption: Option<EncryptionState>,
}

impl Clone for LazyStore {
    fn clone(&self) -> Self {
        LazyStore {
            buffer: self.buffer.clone(),
            entries: self.entries.clone(),
            cells: self.cells.clone(),
            resolving: RefCell::new(HashSet::new()),
            containers: self.containers.clone(),
            plaintext_slot: RefCell::new(None),
            filter: self.filter,
            decryption: self.decryption.clone(),
        }
    }
}

impl LazyStore {
    pub(crate) fn build(buffer: Arc<Vec<u8>>, xref: &Xref, filter: Option<FilterFunc>) -> LazyStore {
        let mut entries = HashMap::new();
        for (&id, entry) in &xref.entries {
            match *entry {
                XrefEntry::Normal { offset, .. } => {
                    entries.insert(id, LazyEntry::Normal { offset });
                }
                XrefEntry::Compressed { container, .. } => {
                    entries.insert(id, LazyEntry::InStream { container });
                }
                _ => {}
            }
        }
        let cells = entries.keys().map(|&id| (id, OnceCell::new())).collect();
        let containers = entries
            .values()
            .filter_map(|entry| match entry {
                LazyEntry::InStream { container } => Some((*container, OnceCell::new())),
                LazyEntry::Normal { .. } => None,
            })
            .collect();
        LazyStore {
            buffer,
            entries,
            cells,
            resolving: RefCell::new(HashSet::new()),
            containers,
            plaintext_slot: RefCell::new(None),
            filter,
            decryption: None,
        }
    }

    /// The same store for an encrypted document, decrypting each object as
    /// it materializes (see `decryption`).
    pub(crate) fn decrypting(mut self, state: EncryptionState) -> LazyStore {
        self.decryption = Some(state);
        self
    }

    /// The parsed (generation, object) for an id, resolving on first
    /// touch. None = no xref entry, parse failure (already logged), a
    /// reference cycle, or a filter drop; every one of these reads as
    /// an absent object, never a propagated error, so one corrupt
    /// object costs itself and nothing else.
    pub(crate) fn resolve(&self, id: u32) -> Option<&(u16, Object)> {
        let cell = self.cells.get(&id)?;
        if let Some(hit) = cell.get() {
            return Some(hit);
        }
        let entry = *self.entries.get(&id)?;
        if !self.resolving.borrow_mut().insert(id) {
            warn!("reference cycle detected resolving object {id}");
            return None;
        }
        let outcome = self.parse_entry(id, entry);
        self.resolving.borrow_mut().remove(&id);
        match outcome {
            Ok(Some(parsed)) => {
                let _ = cell.set(parsed);
            }
            Ok(None) => {}
            Err(err) => warn!("object {id} failed to resolve: {err:?}"),
        }
        cell.get()
    }

    /// Like `resolve`, but an id not resolved yet is parsed into a value
    /// handed to the caller and not stored, so a single-pass walk over a
    /// large object graph keeps only what it currently holds; an id already
    /// resolved is borrowed. Absent in exactly the cases `resolve` is.
    pub(crate) fn resolve_transient(&self, id: u32) -> Option<Cow<'_, (u16, Object)>> {
        let cell = self.cells.get(&id)?;
        if let Some(hit) = cell.get() {
            return Some(Cow::Borrowed(hit));
        }
        let entry = *self.entries.get(&id)?;
        if !self.resolving.borrow_mut().insert(id) {
            warn!("reference cycle detected resolving object {id}");
            return None;
        }
        let outcome = self.parse_entry(id, entry);
        self.resolving.borrow_mut().remove(&id);
        match outcome {
            Ok(parsed) => parsed.map(Cow::Owned),
            Err(err) => {
                warn!("object {id} failed to resolve: {err:?}");
                None
            }
        }
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn entry_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.entries.keys().copied()
    }

    /// Move a resolved object out of its cell (for &mut access paths);
    /// the caller must also purge the entry so later reads cannot
    /// re-parse the file's version behind the materialized one.
    pub(crate) fn take(&mut self, id: u32) -> Option<(u16, Object)> {
        self.cells.get_mut(&id)?.take()
    }

    pub(crate) fn purge(&mut self, id: u32) {
        self.entries.remove(&id);
        self.cells.remove(&id);
    }

    /// Consume the store, yielding every resolved object (for
    /// materialize_all). Unresolved cells were already logged as
    /// skips during the resolve pass.
    pub(crate) fn into_resolved(self) -> impl Iterator<Item = (u32, u16, Object)> {
        self.cells
            .into_iter()
            .filter_map(|(id, cell)| cell.into_inner().map(|(generation, object)| (id, generation, object)))
    }

    /// Parses one xref entry into its (generation, object); Ok(None) when
    /// the load filter drops it.
    fn parse_entry(&self, id: u32, entry: LazyEntry) -> Result<Option<(u16, Object)>> {
        match entry {
            LazyEntry::Normal { offset } => {
                // An xref offset past the end of the file reads as an
                // absent object; handing it to the parser would panic
                // in the slice split instead.
                if offset as usize > self.buffer.len() {
                    return Err(Error::InvalidOffset(offset as usize));
                }
                let (parsed_id, mut object) =
                    parser::indirect_object(self.buffer.as_slice(), offset as usize, None, self, &mut HashSet::new())?;
                self.fix_zero_length_stream(&mut object);
                if let Some(state) = &self.decryption {
                    // A failure leaves the object as parsed, as the eager
                    // encrypted load did.
                    let _ = encryption::decrypt_object(state, parsed_id, &mut object);
                }
                if let Some(filter) = self.filter {
                    let Some((_, filtered)) = filter(parsed_id, &mut object) else {
                        return Ok(None);
                    };
                    object = filtered;
                }
                Ok(Some((parsed_id.1, object)))
            }
            LazyEntry::InStream { container } => {
                // The xref maps this id to this container (that is how
                // the entry was built), so stale copies of the id in
                // other containers (linearization sections) can never
                // serve it: the xref is the authority on membership.
                // Container unresolvable, its own index not carrying the
                // id the xref promised, or an unparsable child: absent,
                // never a panic.
                let Some(mut object) = self.with_child_bytes(container, id, parse_child) else {
                    return Err(Error::ObjectNotFound((id, 0)));
                };
                if let Some(filter) = self.filter {
                    let Some((_, filtered)) = filter((id, 0), &mut object) else {
                        return Ok(None);
                    };
                    object = filtered;
                }
                Ok(Some((0, object)))
            }
        }
    }

    /// Hands one child's plaintext bytes to `parse`, borrowed in place.
    /// The container decompresses into the single most-recent slot (and
    /// stays there for the next sibling) unless it is huge: then it is
    /// inflated in one streaming pass that keeps only this child's bytes
    /// and resolves every small sibling into its cell, so the giant
    /// children it holds are never materialized and the next small
    /// sibling needs no second pass. The child index is parsed once, from
    /// the plaintext header alone, and kept. None = the container failed
    /// to resolve, its index does not carry the id, or `parse` refused the
    /// bytes; children then read as absent, costing only themselves.
    /// `parse` must not resolve objects: it may run while the slot is
    /// borrowed.
    fn with_child_bytes<T>(&self, container: u32, id: u32, parse: impl FnOnce(&[u8]) -> Option<T>) -> Option<T> {
        let index_cell = self.containers.get(&container)?;
        {
            let slot = self.plaintext_slot.borrow();
            if let (Some((slot_id, plaintext)), Some(index)) = (slot.as_ref(), index_cell.get())
                && *slot_id == container
            {
                return slice_child(index, plaintext, id).and_then(parse);
            }
        }
        let (_, container_obj) = self.resolve(container)?;
        let stream = container_obj.as_stream().ok()?;
        let streamable = inflates_plainly(stream);
        if index_cell.get().is_none() {
            let first_offset: usize = stream
                .dict
                .get(b"First")
                .and_then(Object::as_i64)
                .ok()?
                .try_into()
                .ok()?;
            let header = streamable
                .then(|| inflate_ranges(&stream.content, &[(0, Some(first_offset))]))
                .flatten()
                .and_then(|(_, mut ranges)| ranges.pop());
            let index = match header {
                Some(header) => parse_objstm_index((header.len() == first_offset).then_some(&header[..]), first_offset),
                None => parse_objstm_index(full_plaintext(stream).get(..first_offset), first_offset),
            };
            let _ = index_cell.set(index);
        }
        let index = index_cell.get()?;
        let extent = index.children.iter().map(|&(_, start, _)| start).max().unwrap_or(0);
        if streamable && extent > STREAM_CONTAINERS_ABOVE {
            let &(_, start, end) = index.children.iter().find(|(child, ..)| *child == id)?;
            let siblings: Vec<(u32, usize, usize)> = index
                .children
                .iter()
                .filter_map(|&(child, start, end)| Some((child, start, end?)))
                .filter(|&(child, start, end)| {
                    child != id && end - start <= STREAM_SIBLINGS_UP_TO && self.is_unresolved_member(child, container)
                })
                .collect();
            let mut ranges = vec![(start, end)];
            ranges.extend(siblings.iter().map(|&(_, start, end)| (start, Some(end))));
            if let Some((plaintext_len, mut taken)) = inflate_ranges(&stream.content, &ranges) {
                for (&(child, ..), bytes) in siblings.iter().zip(taken.drain(1..)) {
                    let Some(mut object) = parse_child(&bytes) else {
                        continue;
                    };
                    if let Some(filter) = self.filter {
                        let Some((_, filtered)) = filter((child, 0), &mut object) else {
                            continue;
                        };
                        object = filtered;
                    }
                    if let Some(cell) = self.cells.get(&child) {
                        let _ = cell.set((0, object));
                    }
                }
                let wanted = taken.pop()?;
                return (plaintext_len >= start)
                    .then_some(wanted)
                    .and_then(|bytes| parse(&bytes));
            }
        }
        let plaintext = full_plaintext(stream);
        let parsed = slice_child(index, &plaintext, id).and_then(parse);
        *self.plaintext_slot.borrow_mut() = Some((container, plaintext));
        parsed
    }

    /// True when the xref places `id` in `container` (stale copies of an
    /// id in other containers never serve it) and nothing has resolved it
    /// yet.
    fn is_unresolved_member(&self, id: u32, container: u32) -> bool {
        matches!(self.entries.get(&id), Some(LazyEntry::InStream { container: owner }) if *owner == container)
            && self.cells.get(&id).is_some_and(|cell| cell.get().is_none())
    }

    /// A stream whose /Length was indirect parses with empty content
    /// and a recorded start position; its bytes are sliced from the
    /// buffer here, at resolve time. Failure leaves the empty-content
    /// stream in place: a broken length chain costs the stream its
    /// body, never the object or the document.
    fn fix_zero_length_stream(&self, object: &mut Object) {
        let Object::Stream(stream) = object else { return };
        if !stream.content.is_empty() {
            return;
        }
        let Some(start) = stream.start_position else { return };
        let length = match stream.dict.get(b"Length") {
            Ok(Object::Reference(len_id)) => match self.resolve(len_id.0) {
                Some((generation, object)) if *generation == len_id.1 => match object.as_i64() {
                    Ok(length) => length,
                    Err(_) => return,
                },
                _ => return,
            },
            Ok(direct) => match direct.as_i64() {
                Ok(length) => length,
                Err(_) => return,
            },
            Err(_) => return,
        };
        let Ok(length) = usize::try_from(length) else { return };
        let Some(end) = start.checked_add(length) else { return };
        if end > self.buffer.len() {
            return;
        }
        stream.set_content(self.buffer[start..end].to_vec());
    }
}

/// Parse an object stream's header index into (id, start, end) child
/// ranges; end = the next child's start (children are offset-ordered
/// per spec, but sorting defends against disordered emitters).
fn parse_objstm_index(index_block: Option<&[u8]>, first_offset: usize) -> ObjStmIndex {
    let Some(index_block) = index_block else {
        return ObjStmIndex { children: Vec::new() };
    };
    let Ok(index_text) = std::str::from_utf8(index_block) else {
        return ObjStmIndex { children: Vec::new() };
    };
    let numbers: Vec<Option<u32>> = index_text
        .split_whitespace()
        .map(|number| number.parse().ok())
        .collect();
    let pairs = numbers.len() / 2 * 2;
    let mut starts = Vec::with_capacity(pairs / 2);
    for chunk in numbers[..pairs].chunks(2) {
        let (Some(id), Some(offset)) = (chunk[0], chunk[1]) else {
            continue;
        };
        starts.push((id, first_offset + offset as usize));
    }
    let mut order: Vec<usize> = (0..starts.len()).collect();
    order.sort_unstable_by_key(|&i| starts[i].1);
    let mut children = vec![(0u32, 0usize, None); starts.len()];
    for (rank, &i) in order.iter().enumerate() {
        let (id, start) = starts[i];
        let end = order.get(rank + 1).map(|&next| starts[next].1.max(start));
        children[i] = (id, start, end);
    }
    ObjStmIndex { children }
}

fn slice_child<'a>(index: &ObjStmIndex, plaintext: &'a [u8], id: u32) -> Option<&'a [u8]> {
    let &(_, start, end) = index.children.iter().find(|(child, ..)| *child == id)?;
    let end = end.unwrap_or(plaintext.len().max(start));
    plaintext.get(start..end.min(plaintext.len()))
}

/// A container's whole plaintext, exactly as `Stream::decompress` leaves
/// the content: the decoded bytes, or the raw content when decoding fails.
fn full_plaintext(stream: &Stream) -> Vec<u8> {
    stream.decompressed_content().unwrap_or_else(|_| stream.content.clone())
}

/// True when the plaintext is a single zlib inflate of the content with
/// nothing applied after it, which is what `inflate_ranges` reproduces.
fn inflates_plainly(stream: &Stream) -> bool {
    let flate_only = stream
        .filters()
        .is_ok_and(|filters| filters.len() == 1 && filters[0] == b"FlateDecode");
    let predictor = stream
        .dict
        .get(b"DecodeParms")
        .and_then(Object::as_dict)
        .and_then(|params| params.get(b"Predictor"))
        .and_then(Object::as_i64)
        .unwrap_or(1);
    flate_only && !(10..=15).contains(&predictor)
}

/// One object-stream child parsed from its plaintext bytes.
fn parse_child(bytes: &[u8]) -> Option<Object> {
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace())?;
    parser::direct_object(&bytes[start..])
}

/// The plaintext bytes in each `start..end` range (end None = to the end of
/// the plaintext), from one inflate pass through a fixed buffer that never
/// materializes the rest; the pass stops once every range is complete.
/// Also returns how many plaintext bytes the pass saw, so a caller can tell
/// a range that starts past the end (absent, like an out-of-range slice of
/// the whole plaintext) from an empty one. None on any inflate error: the
/// whole-plaintext path keeps partial output and retries raw deflate there,
/// so the caller falls back to it rather than reproducing that here.
fn inflate_ranges(compressed: &[u8], ranges: &[(usize, Option<usize>)]) -> Option<(usize, Vec<Vec<u8>>)> {
    if compressed.is_empty() {
        return None;
    }
    let stop = ranges
        .iter()
        .try_fold(0usize, |stop, &(_, end)| end.map(|end| stop.max(end)));
    let mut decoder = ZlibDecoder::new(compressed);
    let mut chunk = vec![0u8; STREAM_CHUNK];
    let mut taken: Vec<Vec<u8>> = vec![Vec::new(); ranges.len()];
    let mut position = 0usize;
    while stop.is_none_or(|stop| position < stop) {
        let read = match decoder.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        let chunk_start = position;
        position += read;
        for (&(start, end), out) in ranges.iter().zip(taken.iter_mut()) {
            let from = start.max(chunk_start);
            let to = end.map_or(position, |end| end.min(position));
            if from < to {
                out.extend_from_slice(&chunk[from - chunk_start..to - chunk_start]);
            }
        }
    }
    Some((position, taken))
}

impl ObjectResolver for LazyStore {
    /// Parse-time /Length resolution routes back through the cells, so
    /// a length object resolved for one stream is cached for everyone.
    fn resolve_reference(&self, id: ObjectId, _already_seen: &mut HashSet<ObjectId>) -> Result<Object> {
        match self.resolve(id.0) {
            Some((generation, object)) if *generation == id.1 => Ok(object.clone()),
            _ => Err(Error::ObjectNotFound(id)),
        }
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use crate::xref::XrefType;

    /// A container chain that cycles (a child whose xref container is
    /// itself, or a longer loop) must resolve as absent through the
    /// shared resolving guard. The failure class killed: unbounded
    /// recursion when each container hop starts a fresh cycle check.
    #[test]
    fn container_membership_cycle_resolves_absent() {
        let mut xref = Xref::new(4, XrefType::CrossReferenceStream);
        xref.entries.insert(1, XrefEntry::Compressed { container: 2, index: 0 });
        xref.entries.insert(2, XrefEntry::Compressed { container: 3, index: 0 });
        xref.entries.insert(3, XrefEntry::Compressed { container: 2, index: 0 });
        let store = LazyStore::build(Arc::new(b"%PDF-1.4\n".to_vec()), &xref, None);
        assert!(store.resolve(1).is_none());
        // Repeated requests stay absent and terminate.
        assert!(store.resolve(1).is_none());
    }

    /// An xref offset pointing past the end of the file resolves as
    /// absent (the production shape: a truncated download whose xref
    /// survives names offsets beyond the bytes on hand); the sibling
    /// with an honest offset still resolves.
    #[test]
    fn out_of_range_offset_resolves_absent() {
        let mut xref = Xref::new(3, XrefType::CrossReferenceStream);
        xref.entries.insert(
            1,
            XrefEntry::Normal {
                offset: 26_690_392,
                generation: 0,
            },
        );
        xref.entries.insert(
            2,
            XrefEntry::Normal {
                offset: 9,
                generation: 0,
            },
        );
        let body = Arc::new(
            b"%PDF-1.4
2 0 obj
42
endobj
"
            .to_vec(),
        );
        let store = LazyStore::build(body, &xref, None);
        assert!(store.resolve(1).is_none());
        assert!(store.resolve(1).is_none());
        assert_eq!(store.resolve(2).and_then(|(_, o)| o.as_i64().ok()), Some(42));
    }

    /// A child the xref maps to a container whose plaintext does not
    /// carry it resolves as absent, repeatedly, with no panic — the
    /// cost of a lying xref is repeated work, never wrong output.
    #[test]
    fn lying_container_membership_resolves_absent() {
        let mut xref = Xref::new(3, XrefType::CrossReferenceStream);
        // Object 2 is a Normal entry that is NOT an ObjStm stream.
        let body = Arc::new(b"%PDF-1.4\n2 0 obj\n42\nendobj\n".to_vec());
        let offset = 9u32;
        xref.entries.insert(1, XrefEntry::Compressed { container: 2, index: 0 });
        xref.entries.insert(2, XrefEntry::Normal { offset, generation: 0 });
        let store = LazyStore::build(body, &xref, None);
        assert!(store.resolve(1).is_none());
        assert!(store.resolve(1).is_none());
        // The container itself still resolves as its own object.
        assert_eq!(store.resolve(2).and_then(|(_, o)| o.as_i64().ok()), Some(42));
    }
}
