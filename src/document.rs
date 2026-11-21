use super::encodings::Encoding;
use super::{Bookmark, Dictionary, Object, ObjectId};
use crate::encryption::crypt_filters::*;
use crate::encryption::{self, EncryptionState, PasswordAlgorithm};
use crate::xobject::PdfImage;
use crate::xref::{Xref, XrefType};
use crate::{Error, ObjectStream, Result, Stream};
use log::debug;
use std::borrow::Cow;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::str;
use std::sync::Arc;

/// A PDF document.
///
/// This can both be a combination of multiple incremental updates
/// or just one (the last) incremental update in a PDF file.
#[derive(Debug, Clone)]
pub struct Document {
    /// The version of the PDF specification to which the file conforms.
    pub version: String,

    /// The binary mark important for PDF A/2,3 tells various software tools to classify
    /// the file as containing 8-bit binary that should be preserved during processing
    pub binary_mark: Vec<u8>,

    /// The trailer gives the location of the cross-reference table and of certain special objects.
    pub trailer: Dictionary,

    /// The cross-reference table contains locations of the indirect objects.
    pub reference_table: Xref,

    /// The materialized objects: everything inserted by editing APIs
    /// plus every loaded object forced to `&mut` access. Loaded
    /// documents keep unread objects in `lazy` until first
    /// dereference; read through `get_object`, never this map, or
    /// unresolved objects are invisible.
    pub(crate) objects: BTreeMap<ObjectId, Object>,

    /// The lazy object store for documents loaded from bytes; `None`
    /// on created documents and after `materialize_all`.
    pub(crate) lazy: Option<crate::lazy::LazyStore>,

    /// Current maximum object id within the document.
    pub max_id: u32,

    /// Current maximum object id within Bookmarks.
    pub max_bookmark_id: u32,

    /// The bookmarks in the document. Render at the very end of document after renumbering objects.
    pub bookmarks: Vec<u32>,

    /// used to locate a stored Bookmark so children can be appended to it via its id. Otherwise we
    /// need to do recursive lookups and returns on the bookmarks internal layout Vec
    pub bookmark_table: HashMap<u32, Bookmark>,

    /// The byte the cross-reference table starts at.
    /// This value is only set during reading, but not when writing the file.
    /// It is used to support incremental updates in PDFs.
    /// Default value is `0`.
    pub xref_start: usize,

    /// The encryption state stores the parameters that were used to decrypt this document if the
    /// document has been decrypted.
    pub encryption_state: Option<EncryptionState>,
}

impl Document {
    /// Create new PDF document.
    pub fn new() -> Self {
        Self {
            version: "1.4".to_string(),
            binary_mark: vec![0xBB, 0xAD, 0xC0, 0xDE],
            trailer: Dictionary::new(),
            reference_table: Xref::new(0, XrefType::CrossReferenceStream),
            objects: BTreeMap::new(),
            lazy: None,
            max_id: 0,
            max_bookmark_id: 0,
            bookmarks: Vec::new(),
            bookmark_table: HashMap::new(),
            xref_start: 0,
            encryption_state: None,
        }
    }

    /// Create a new PDF document that is an incremental update to a previous document.
    pub fn new_from_prev(prev: &Document) -> Self {
        let mut new_trailer = prev.trailer.clone();
        new_trailer.set("Prev", Object::Integer(prev.xref_start as i64));
        Self {
            version: "1.4".to_string(),
            binary_mark: vec![0xBB, 0xAD, 0xC0, 0xDE],
            trailer: new_trailer,
            reference_table: Xref::new(0, prev.reference_table.cross_reference_type),
            objects: BTreeMap::new(),
            lazy: None,
            max_id: prev.max_id,
            max_bookmark_id: prev.max_bookmark_id,
            bookmarks: Vec::new(),
            bookmark_table: HashMap::new(),
            xref_start: 0,
            encryption_state: None,
        }
    }

    const DEREF_LIMIT: usize = 128;

    fn recursive_fix_pages(&mut self, bookmarks: &[u32], first: bool) -> ObjectId {
        if !bookmarks.is_empty() {
            for id in bookmarks {
                let (children, mut page) = match self.bookmark_table.get(id) {
                    Some(n) => (n.children.clone(), n.page),
                    None => return (0, 0),
                };

                if 0 == page.0 && !children.is_empty() {
                    let objectid = self.recursive_fix_pages(&children[..], false);

                    let bookmark = self.bookmark_table.get_mut(id).unwrap();
                    bookmark.page = objectid;
                    page = objectid;
                }

                if !first && 0 != page.0 {
                    return page;
                }

                if first && !children.is_empty() {
                    self.recursive_fix_pages(&children[..], first);
                }
            }
        }

        (0, 0)
    }

    /// Adjusts the Parents that have a ObjectId of (0,_) to that
    /// of their first child. will recurse through all entries
    /// till all parents of children are set. This should be
    /// ran before building the final bookmark objects but after
    /// renumbering of objects.
    pub fn adjust_zero_pages(&mut self) {
        self.recursive_fix_pages(&self.bookmarks.clone(), true);
    }

    /// Follow references if the supplied object is a reference.
    ///
    /// Returns a tuple of an optional object id and final object.
    /// The object id will be None if the object was not a
    /// reference. Otherwise, it will be the last object id in the
    /// reference chain.
    pub fn dereference<'a>(&'a self, mut object: &'a Object) -> Result<(Option<ObjectId>, &'a Object)> {
        let mut nb_deref = 0;
        let mut id = None;

        while let Ok(ref_id) = object.as_reference() {
            id = Some(ref_id);
            object = self.raw_get(ref_id)?;

            nb_deref += 1;
            if nb_deref > Self::DEREF_LIMIT {
                return Err(Error::ReferenceLimit);
            }
        }

        Ok((id, object))
    }

    /// One id lookup with no reference-following: materialized objects
    /// win (edits shadow file state), then the lazy store resolves on
    /// first touch. Every read goes through here.
    fn raw_get(&self, id: ObjectId) -> Result<&Object> {
        if let Some(object) = self.objects.get(&id) {
            return Ok(object);
        }
        if let Some(lazy) = &self.lazy {
            if let Some((generation, object)) = lazy.resolve(id.0) {
                if *generation == id.1 {
                    return Ok(object);
                }
            }
        }
        Err(Error::ObjectNotFound(id))
    }

    /// `raw_get` without storing a freshly parsed lazy object.
    fn raw_get_transient(&self, id: ObjectId) -> Result<Cow<'_, Object>> {
        if let Some(object) = self.objects.get(&id) {
            return Ok(Cow::Borrowed(object));
        }
        if let Some(lazy) = &self.lazy {
            match lazy.resolve_transient(id.0) {
                Some(Cow::Borrowed((generation, object))) if *generation == id.1 => return Ok(Cow::Borrowed(object)),
                Some(Cow::Owned((generation, object))) if generation == id.1 => return Ok(Cow::Owned(object)),
                _ => {}
            }
        }
        Err(Error::ObjectNotFound(id))
    }

    /// Force one object out of the lazy store into the materialized
    /// map (for `&mut` access). The lazy entry is purged so later
    /// reads cannot re-parse the file's version behind the
    /// materialized one.
    fn materialize(&mut self, id: ObjectId) -> Result<()> {
        if self.objects.contains_key(&id) {
            return Ok(());
        }
        let Some(lazy) = &self.lazy else {
            return Err(Error::ObjectNotFound(id));
        };
        if lazy.resolve(id.0).is_none() {
            return Err(Error::ObjectNotFound(id));
        }
        let lazy = self.lazy.as_mut().expect("lazy store checked above");
        let Some((generation, object)) = lazy.take(id.0) else {
            return Err(Error::ObjectNotFound(id));
        };
        if generation != id.1 {
            // Wrong generation requested: put the parsed object back.
            let stored = lazy.take(id.0);
            debug_assert!(stored.is_none());
            lazy.purge(id.0);
            self.objects.insert((id.0, generation), object);
            return Err(Error::ObjectNotFound(id));
        }
        lazy.purge(id.0);
        self.objects.insert((id.0, generation), object);
        Ok(())
    }

    /// Resolve and move EVERY remaining lazy object into the
    /// materialized map, dropping the lazy store. Whole-document
    /// operations (save, renumber, compression passes) call this
    /// first; per-entry parse failures are logged and skipped, so a
    /// document with corrupt orphan objects still saves.
    pub fn materialize_all(&mut self) {
        let Some(lazy) = &self.lazy else { return };
        for id in lazy.entry_ids().collect::<Vec<u32>>() {
            let _ = lazy.resolve(id);
        }
        let lazy = self.lazy.take().expect("lazy store checked above");
        for (id, generation, object) in lazy.into_resolved() {
            self.objects.entry((id, generation)).or_insert(object);
        }
    }

    /// Remove one id from BOTH stores; the id afterwards reads as
    /// absent (a lazy entry left behind would resurrect the deleted
    /// object from the file bytes on the next read).
    pub(crate) fn remove_object_everywhere(&mut self, id: ObjectId) -> Option<Object> {
        let removed = self.objects.remove(&id);
        if let Some(lazy) = self.lazy.as_mut() {
            lazy.purge(id.0);
        }
        removed
    }

    /// Objects reachable through reads: materialized plus unresolved
    /// lazy entries. An upper bound when an id is both edited and
    /// still carried by the lazy store; used for iteration budgets.
    pub fn object_count(&self) -> usize {
        self.objects.len() + self.lazy.as_ref().map_or(0, |lazy| lazy.entry_count())
    }

    /// The materialized objects only. Loaded-but-unread objects are
    /// NOT visible here; call `materialize_all` first for a
    /// whole-document view.
    pub fn iter_objects(&self) -> impl Iterator<Item = (&ObjectId, &Object)> {
        self.objects.iter()
    }

    /// Get object by object id, will iteratively dereference a referenced object.
    pub fn get_object(&self, id: ObjectId) -> Result<&Object> {
        let object = self.raw_get(id)?;
        self.dereference(object).map(|(_, object)| object)
    }

    /// Like `get_object`, but an object the lazy store has not resolved yet is
    /// parsed into a copy the document does not keep; materialized and already
    /// resolved objects are borrowed. For single-pass walks over large object
    /// graphs (a structure tree), whose visited objects would otherwise all
    /// stay resident for the document's life.
    pub fn get_object_transient(&self, id: ObjectId) -> Result<Cow<'_, Object>> {
        let mut object = self.raw_get_transient(id)?;
        let mut nb_deref = 0;
        while let Ok(ref_id) = object.as_reference() {
            object = self.raw_get_transient(ref_id)?;
            nb_deref += 1;
            if nb_deref > Self::DEREF_LIMIT {
                return Err(Error::ReferenceLimit);
            }
        }
        Ok(object)
    }

    /// Determines if an object exists in the current document (or incremental update.)
    /// with the given `ObjectId`.
    /// `true` if the object exists, `false` if it does not exist.
    pub fn has_object(&self, id: ObjectId) -> bool {
        self.raw_get(id).is_ok()
    }

    /// Get mutable reference to object by object ID, will iteratively dereference a referenced object.
    pub fn get_object_mut(&mut self, id: ObjectId) -> Result<&mut Object> {
        self.materialize(id)?;
        let object = self.objects.get(&id).ok_or(Error::ObjectNotFound(id))?;
        let (ref_id, _obj) = self.dereference(object)?;

        let target = ref_id.unwrap_or(id);
        self.materialize(target)?;
        Ok(self.objects.get_mut(&target).expect("materialized above"))
    }

    /// Get the object ID of the page that contains `id`.
    pub fn get_object_page(&self, id: ObjectId) -> Result<ObjectId> {
        for (_, object_id) in self.get_pages() {
            let page = self.get_object(object_id)?.as_dict()?;
            let annots = page.get(b"Annots")?.as_array()?;
            let mut objects_ids = annots.iter().map(Object::as_reference);

            let contains = objects_ids.any(|object_id| Some(id) == object_id.ok());
            if contains {
                return Ok(object_id);
            }
        }

        Err(Error::PageNumberNotFound(0))
    }

    /// Get dictionary object by id.
    pub fn get_dictionary(&self, id: ObjectId) -> Result<&Dictionary> {
        self.get_object(id).and_then(Object::as_dict)
    }

    /// Get a mutable dictionary object by id.
    pub fn get_dictionary_mut(&mut self, id: ObjectId) -> Result<&mut Dictionary> {
        self.get_object_mut(id).and_then(Object::as_dict_mut)
    }

    /// Get dictionary in dictionary by key.
    pub fn get_dict_in_dict<'a>(&'a self, node: &'a Dictionary, key: &[u8]) -> Result<&'a Dictionary> {
        match node.get(key)? {
            Object::Reference(object_id) => self.get_dictionary(*object_id),
            Object::Dictionary(dic) => Ok(dic),
            obj => Err(Error::ObjectType {
                expected: "Dictionary",
                found: obj.enum_variant(),
            }),
        }
    }

    /// Traverse objects from trailer recursively, return all referenced object IDs.
    pub fn traverse_objects<A: Fn(&mut Object)>(&mut self, action: A) -> Vec<ObjectId> {
        fn traverse_array<A: Fn(&mut Object)>(array: &mut [Object], action: &A, refs: &mut Vec<ObjectId>) {
            for item in array.iter_mut() {
                traverse_object(item, action, refs);
            }
        }
        fn traverse_dictionary<A: Fn(&mut Object)>(dict: &mut Dictionary, action: &A, refs: &mut Vec<ObjectId>) {
            for (_, v) in dict.iter_mut() {
                traverse_object(v, action, refs);
            }
        }
        fn traverse_object<A: Fn(&mut Object)>(object: &mut Object, action: &A, refs: &mut Vec<ObjectId>) {
            action(object);
            match object {
                Object::Array(array) => traverse_array(array, action, refs),
                Object::Dictionary(dict) => traverse_dictionary(dict, action, refs),
                Object::Stream(stream) => traverse_dictionary(&mut stream.dict, action, refs),
                Object::Reference(id) if !refs.contains(id) => {
                    refs.push(*id);
                }
                _ => {}
            }
        }
        self.materialize_all();
        let mut refs = vec![];
        traverse_dictionary(&mut self.trailer, &action, &mut refs);
        let mut index = 0;
        while index < refs.len() {
            if let Some(object) = self.objects.get_mut(&refs[index]) {
                traverse_object(object, &action, &mut refs);
            }
            index += 1;
        }
        refs
    }

    /// Return dictionary with encryption information
    pub fn get_encrypted(&self) -> Result<&Dictionary> {
        self.trailer
            .get(b"Encrypt")
            .and_then(Object::as_reference)
            .and_then(|id| self.get_dictionary(id))
    }

    /// Return true if PDF document is currently encrypted
    pub fn is_encrypted(&self) -> bool {
        self.get_encrypted().is_ok()
    }

    /// Return true if the document was originally encrypted when loaded
    pub fn was_encrypted(&self) -> bool {
        self.encryption_state.is_some()
    }

    /// Authenticate the provided owner password directly as bytes without sanitization
    pub fn authenticate_raw_owner_password<P>(&self, password: P) -> Result<()>
    where
        P: AsRef<[u8]>,
    {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        let password = password.as_ref();
        let algorithm = PasswordAlgorithm::try_from(self)?;
        algorithm.authenticate_owner_password(self, password)?;

        Ok(())
    }

    /// Authenticate the provided user password directly as bytes without sanitization
    pub fn authenticate_raw_user_password<P>(&self, password: P) -> Result<()>
    where
        P: AsRef<[u8]>,
    {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        let password = password.as_ref();
        let algorithm = PasswordAlgorithm::try_from(self)?;
        algorithm.authenticate_user_password(self, password)?;

        Ok(())
    }

    /// Authenticate the provided owner/user password as bytes without sanitization
    pub fn authenticate_raw_password<P>(&self, password: P) -> Result<()>
    where
        P: AsRef<[u8]>,
    {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        let password = password.as_ref();
        let algorithm = PasswordAlgorithm::try_from(self)?;
        algorithm
            .authenticate_owner_password(self, password)
            .or(algorithm.authenticate_user_password(self, password))?;

        Ok(())
    }

    /// Authenticate the provided owner password
    pub fn authenticate_owner_password(&self, password: &str) -> Result<()> {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        let algorithm = PasswordAlgorithm::try_from(self)?;
        let password = algorithm.sanitize_password(password)?;
        algorithm.authenticate_owner_password(self, &password)?;

        Ok(())
    }

    /// Authenticate the provided user password
    pub fn authenticate_user_password(&self, password: &str) -> Result<()> {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        let algorithm = PasswordAlgorithm::try_from(self)?;
        let password = algorithm.sanitize_password(password)?;
        algorithm.authenticate_user_password(self, &password)?;

        Ok(())
    }

    /// Authenticate the provided owner/user password
    pub fn authenticate_password(&self, password: &str) -> Result<()> {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        let algorithm = PasswordAlgorithm::try_from(self)?;
        let password = algorithm.sanitize_password(password)?;
        algorithm
            .authenticate_owner_password(self, &password)
            .or(algorithm.authenticate_user_password(self, &password))?;

        Ok(())
    }

    /// Returns a `BTreeMap` of the crypt filters available in the PDF document if any.
    pub fn get_crypt_filters(&self) -> BTreeMap<Vec<u8>, Arc<dyn CryptFilter>> {
        let mut crypt_filters = BTreeMap::new();

        if let Ok(filters) = self
            .get_encrypted()
            .and_then(|dict| dict.get(b"CF"))
            .and_then(|object| object.as_dict())
        {
            for (name, filter) in filters {
                let Ok(filter) = filter.as_dict() else {
                    continue;
                };

                if filter.get(b"Type").is_ok() && !filter.has_type(b"CryptFilter") {
                    continue;
                }

                // Get the Crypt Filter Method (CFM) used, if any, by the PDF reader to decrypt data.
                let cfm = filter.get(b"CFM").and_then(|object| object.as_name()).ok();

                let crypt_filter: Arc<dyn CryptFilter> = match cfm {
                    // The application shall ask the security handler for the file encryption key
                    // and shall implicitly decrypt data using the RC4 algorithm.
                    Some(b"V2") => Arc::new(Rc4CryptFilter),
                    // The application shall ask the security handler for the file encryption key
                    // and shall implicitly decrypt data using the AES-128 algorithm in Cipher
                    // Block Chaining (CBC) mode with a 16-byte block size and an initialization
                    // vector that shall be randomly generated and placed as the first 16 bytes in
                    // the stream or string. The key size (Length) shall be 128 bits.
                    Some(b"AESV2") => Arc::new(Aes128CryptFilter),
                    // The application shall ask the security handler for the file encryption key
                    // and shall implicitly decrypt data using the AES-256 algorithm in Cipher
                    // Block Chaining (CBC) with padding mode with a 16-byte block size and an
                    // initialization vector that is randomly generated and placed as the first 16
                    // bytes in the stream or string. The key size (Length) shall be 256 bits.
                    Some(b"AESV3") => Arc::new(Aes256CryptFilter),
                    // The application shall not decrypt data but shall direct the input stream to
                    // the security handler for decryption.
                    Some(b"Identity") | None => Arc::new(IdentityCryptFilter),
                    // Unknown crypt filter method.
                    _ => continue,
                };

                crypt_filters.insert(name.to_vec(), crypt_filter);
            }
        }

        crypt_filters
    }

    /// Replaces all encrypted Strings and Streams with their encrypted contents
    pub fn encrypt(&mut self, state: &EncryptionState) -> Result<()> {
        if self.is_encrypted() {
            return Err(Error::AlreadyEncrypted);
        }

        let encrypted = state.encode()?;

        self.materialize_all();
        for (&id, obj) in self.objects.iter_mut() {
            encryption::encrypt_object(state, id, obj)?;
        }

        let object_id = self.add_object(encrypted);
        self.trailer.set(b"Encrypt", Object::Reference(object_id));
        self.encryption_state = None;

        Ok(())
    }

    /// Replaces all encrypted Strings and Streams with their decrypted contents
    pub fn decrypt(&mut self, password: &str) -> Result<()> {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        let algorithm = PasswordAlgorithm::try_from(&*self)?;
        let password = algorithm.sanitize_password(password)?;
        self.decrypt_raw(&password)
    }

    /// Replaces all encrypted Strings and Streams with their decrypted contents with the password
    /// provided directly as bytes without sanitization
    pub fn decrypt_raw<P>(&mut self, password: P) -> Result<()>
    where
        P: AsRef<[u8]>,
    {
        if !self.is_encrypted() {
            return Err(Error::NotEncrypted);
        }

        self.authenticate_raw_password(&password)?;

        // Find the ID of the encryption dict; we'll want to skip it when decrypting
        let encryption_obj_id = self.trailer.get(b"Encrypt").and_then(Object::as_reference)?;

        let state = EncryptionState::decode(&*self, password)?;

        self.materialize_all();
        for (&id, obj) in self.objects.iter_mut() {
            // The encryption dictionary is not encrypted, leave it alone
            if id == encryption_obj_id {
                continue;
            }

            encryption::decrypt_object(&state, id, obj)?;
        }

        // Add the objects from the object streams now that they have been decrypted.
        let mut object_streams = vec![];

        for (_, object) in self.objects.iter_mut() {
            let Ok(ref mut stream) = object.as_stream_mut() else {
                continue;
            };

            if !stream.dict.has_type(b"ObjStm") {
                continue;
            }

            let Some(obj_stream) = ObjectStream::new(stream).ok() else {
                continue;
            };

            // TODO: Is insert and replace intended behavior?
            // See https://github.com/J-F-Liu/lopdf/issues/160 for more info
            object_streams.extend(obj_stream.objects);
        }

        // Only add entries, but never replace entries
        for (id, entry) in object_streams {
            self.objects.entry(id).or_insert(entry);
        }

        let object_id = self.trailer.remove(b"Encrypt").unwrap().as_reference()?;
        self.remove_object_everywhere(object_id);

        self.encryption_state = Some(state);

        Ok(())
    }

    /// Return the PDF document catalog, which is the root of the document's object graph.
    pub fn catalog(&self) -> Result<&Dictionary> {
        self.trailer
            .get(b"Root")
            .and_then(Object::as_reference)
            .and_then(|id| self.get_dictionary(id))
    }

    /// Return a mutable reference to the PDF document catalog, which is the root of the document's
    /// object graph.
    pub fn catalog_mut(&mut self) -> Result<&mut Dictionary> {
        self.trailer
            .get(b"Root")
            .and_then(Object::as_reference)
            .and_then(move |id| self.get_dictionary_mut(id))
    }

    /// Get page numbers and corresponding object ids.
    pub fn get_pages(&self) -> BTreeMap<u32, ObjectId> {
        self.page_iter().enumerate().map(|(i, p)| ((i + 1) as u32, p)).collect()
    }

    pub fn page_iter(&self) -> impl Iterator<Item = ObjectId> + '_ {
        PageTreeIter::new(self)
    }

    /// Get content stream object ids of a page.
    pub fn get_page_contents(&self, page_id: ObjectId) -> Vec<ObjectId> {
        let mut streams = vec![];
        if let Ok(page) = self.get_dictionary(page_id) {
            let mut nb_deref = 0;
            // Since we're looking for object IDs, we can't use get_deref
            // so manually walk any references in contents object
            if let Ok(mut contents) = page.get(b"Contents") {
                loop {
                    match contents {
                        Object::Reference(id) => match self.raw_get(*id).ok() {
                            None | Some(Object::Stream(_)) => {
                                streams.push(*id);
                            }
                            Some(o) => {
                                nb_deref += 1;
                                if nb_deref < Self::DEREF_LIMIT {
                                    contents = o;
                                    continue;
                                }
                            }
                        },
                        Object::Array(arr) => {
                            for content in arr {
                                if let Ok(id) = content.as_reference() {
                                    streams.push(id)
                                }
                            }
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
        streams
    }

    /// Add content to a page. All existing content will be unchanged.
    pub fn add_page_contents(&mut self, page_id: ObjectId, content: Vec<u8>) -> Result<()> {
        let page = self.get_dictionary(page_id)?;
        let mut current_content_list: Vec<Object> = match page.get(b"Contents") {
            Ok(Object::Reference(id)) => {
                vec![Object::Reference(*id)]
            }
            Ok(Object::Array(arr)) => arr.clone(),
            _ => vec![],
        };
        let content_object_id = self.add_object(Object::Stream(Stream::new(Dictionary::new(), content)));
        current_content_list.push(Object::Reference(content_object_id));

        let page_mut = self.get_object_mut(page_id).and_then(Object::as_dict_mut)?;
        page_mut.set("Contents", current_content_list);
        Ok(())
    }

    /// Get content of a page.
    pub fn get_page_content(&self, page_id: ObjectId) -> Result<Vec<u8>> {
        let mut content = Vec::new();
        let content_streams = self.get_page_contents(page_id);
        for object_id in content_streams {
            if let Ok(content_stream) = self.get_object(object_id).and_then(Object::as_stream) {
                match content_stream.decompressed_content_cow() {
                    // The first stream's decoded buffer becomes the result
                    // instead of being copied into an empty one.
                    Ok(data) if content.is_empty() => content = data.into_owned(),
                    Ok(data) => content.write_all(&data)?,
                    Err(_) => content.write_all(&content_stream.content)?,
                };
                content.push(b'\n');
            }
        }
        Ok(content)
    }

    /// Get resources used by a page.
    pub fn get_page_resources(&self, page_id: ObjectId) -> Result<(Option<&Dictionary>, Vec<ObjectId>)> {
        fn collect_resources(
            page_node: &Dictionary, resource_ids: &mut Vec<ObjectId>, doc: &Document,
            already_seen: &mut HashSet<ObjectId>,
        ) -> Result<()> {
            if let Ok(resource_id) = page_node.get(b"Resources").and_then(Object::as_reference) {
                resource_ids.push(resource_id);
            }
            if let Ok(parent_id) = page_node.get(b"Parent").and_then(Object::as_reference) {
                if already_seen.contains(&parent_id) {
                    return Err(Error::ReferenceCycle(parent_id));
                }
                already_seen.insert(parent_id);
                let parent_dict = doc.get_dictionary(parent_id)?;
                collect_resources(parent_dict, resource_ids, doc, already_seen)?;
            }
            Ok(())
        }

        let mut resource_dict = None;
        let mut resource_ids = Vec::new();
        if let Ok(page) = self.get_dictionary(page_id) {
            resource_dict = page.get(b"Resources").and_then(Object::as_dict).ok();
            collect_resources(page, &mut resource_ids, self, &mut HashSet::new())?;
        }
        Ok((resource_dict, resource_ids))
    }

    /// Get fonts used by a page.
    pub fn get_page_fonts(&self, page_id: ObjectId) -> Result<BTreeMap<Vec<u8>, &Dictionary>> {
        fn collect_fonts_from_resources<'a>(
            resources: &'a Dictionary, fonts: &mut BTreeMap<Vec<u8>, &'a Dictionary>, doc: &'a Document,
        ) {
            if let Ok(font) = resources.get(b"Font") {
                let font_dict = match font {
                    Object::Reference(id) => doc.get_object(*id).and_then(Object::as_dict).ok(),
                    Object::Dictionary(dict) => Some(dict),
                    _ => None,
                };
                if let Some(font_dict) = font_dict {
                    for (name, value) in font_dict.iter() {
                        let font = match value {
                            Object::Reference(id) => doc.get_dictionary(*id).ok(),
                            Object::Dictionary(dict) => Some(dict),
                            _ => None,
                        };
                        if !fonts.contains_key(name) {
                            font.map(|font| fonts.insert(name.clone(), font));
                        }
                    }
                }
            }
        }

        let mut fonts = BTreeMap::new();
        let (resource_dict, resource_ids) = self.get_page_resources(page_id)?;
        if let Some(resources) = resource_dict {
            collect_fonts_from_resources(resources, &mut fonts, self);
        }
        for resource_id in resource_ids {
            if let Ok(resources) = self.get_dictionary(resource_id) {
                collect_fonts_from_resources(resources, &mut fonts, self);
            }
        }
        Ok(fonts)
    }

    /// Get the PDF annotations of a page. The /Subtype of each annotation dictionary defines the
    /// annotation type (Text, Link, Highlight, Underline, Ink, Popup, Widget, etc.). The /Rect of
    /// an annotation dictionary defines its location on the page.
    pub fn get_page_annotations(&self, page_id: ObjectId) -> Result<Vec<&Dictionary>> {
        let mut annotations = vec![];
        if let Ok(page) = self.get_dictionary(page_id) {
            match page.get(b"Annots") {
                Ok(Object::Reference(id)) => self
                    .get_object(*id)
                    .and_then(Object::as_array)?
                    .iter()
                    .flat_map(Object::as_reference)
                    .flat_map(|id| self.get_dictionary(id))
                    .for_each(|a| annotations.push(a)),
                Ok(Object::Array(a)) => a
                    .iter()
                    .flat_map(Object::as_reference)
                    .flat_map(|id| self.get_dictionary(id))
                    .for_each(|a| annotations.push(a)),
                _ => {}
            }
        }
        Ok(annotations)
    }

    pub fn get_page_images(&'_ self, page_id: ObjectId) -> Result<Vec<PdfImage<'_>>> {
        let mut images = vec![];
        if let Ok(page) = self.get_dictionary(page_id) {
            let resources = self.get_dict_in_dict(page, b"Resources")?;
            let xobject = match self.get_dict_in_dict(resources, b"XObject") {
                Ok(xobject) => xobject,
                Err(err) => match err {
                    // XObject is optional, no images found
                    Error::DictKey(_) => return Ok(Vec::default()),
                    _ => Err(err)?,
                },
            };

            for (_, xvalue) in xobject.iter() {
                let id = xvalue.as_reference()?;
                let xvalue = self.get_object(id)?;
                let xvalue = xvalue.as_stream()?;
                let dict = &xvalue.dict;
                if dict.get(b"Subtype")?.as_name()? != b"Image" {
                    continue;
                }
                let width = dict.get(b"Width")?.as_i64()?;
                let height = dict.get(b"Height")?.as_i64()?;
                let color_space = match dict.get(b"ColorSpace") {
                    Ok(cs) => match cs {
                        Object::Array(array) => Some(String::from_utf8_lossy(array[0].as_name()?).to_string()),
                        Object::Name(name) => Some(String::from_utf8_lossy(name).to_string()),
                        _ => None,
                    },
                    Err(_) => None,
                };
                let bits_per_component = match dict.get(b"BitsPerComponent") {
                    Ok(bpc) => Some(bpc.as_i64()?),
                    Err(_) => None,
                };
                let mut filters = vec![];
                if let Ok(filter) = dict.get(b"Filter") {
                    match filter {
                        Object::Array(array) => {
                            for obj in array.iter() {
                                let name = obj.as_name()?;
                                filters.push(String::from_utf8_lossy(name).to_string());
                            }
                        }
                        Object::Name(name) => {
                            filters.push(String::from_utf8_lossy(name).to_string());
                        }
                        _ => {}
                    }
                };

                images.push(PdfImage {
                    id,
                    width,
                    height,
                    color_space,
                    bits_per_component,
                    filters: Some(filters),
                    content: &xvalue.content,
                    origin_dict: &xvalue.dict,
                });
            }
        }
        Ok(images)
    }

    pub fn decode_text(encoding: &Encoding, bytes: &[u8]) -> Result<String> {
        debug!("Decoding text with {encoding:#?}");
        encoding.bytes_to_string(bytes)
    }

    pub fn encode_text(encoding: &Encoding, text: &str) -> Vec<u8> {
        encoding.string_to_bytes(text)
    }
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

struct PageTreeIter<'a> {
    doc: &'a Document,
    stack: Vec<&'a [Object]>,
    kids: Option<&'a [Object]>,
    iter_limit: usize,
}

impl<'a> PageTreeIter<'a> {
    const PAGE_TREE_DEPTH_LIMIT: usize = 256;

    fn new(doc: &'a Document) -> Self {
        if let Ok(page_tree_id) = doc
            .catalog()
            .and_then(|cat| cat.get(b"Pages"))
            .and_then(Object::as_reference)
        {
            Self {
                doc,
                kids: Self::kids(doc, page_tree_id),
                stack: Vec::with_capacity(32),
                iter_limit: doc.object_count(),
            }
        } else {
            Self {
                doc,
                kids: None,
                stack: Vec::new(),
                iter_limit: doc.object_count(),
            }
        }
    }

    fn kids(doc: &Document, page_tree_id: ObjectId) -> Option<&[Object]> {
        doc.get_dictionary(page_tree_id)
            .and_then(|page_tree| page_tree.get_deref(b"Kids", doc))
            .and_then(Object::as_array)
            .map(|k| k.as_slice())
            .ok()
    }
}

impl Iterator for PageTreeIter<'_> {
    type Item = ObjectId;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            while let Some((kid, new_kids)) = self.kids.and_then(|k| k.split_first()) {
                if self.iter_limit == 0 {
                    return None;
                }
                self.iter_limit -= 1;

                self.kids = Some(new_kids);

                if let Ok(kid_id) = kid.as_reference() {
                    if let Ok(type_name) = self.doc.get_dictionary(kid_id).and_then(Dictionary::get_type) {
                        match type_name {
                            b"Page" => {
                                return Some(kid_id);
                            }
                            b"Pages" if self.stack.len() < Self::PAGE_TREE_DEPTH_LIMIT => {
                                let kids = self.kids.unwrap();
                                if !kids.is_empty() {
                                    self.stack.push(kids);
                                }
                                self.kids = Self::kids(self.doc, kid_id);
                            }
                            b"Pages" => {}
                            _ => {}
                        }
                    }
                }
            }

            // Current level exhausted, try to pop.
            if let kids @ Some(_) = self.stack.pop() {
                self.kids = kids;
            } else {
                return None;
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let kids = self.kids.unwrap_or(&[]);

        let nb_pages: usize = kids
            .iter()
            .chain(self.stack.iter().flat_map(|k| k.iter()))
            .map(|kid| {
                if let Ok(dict) = kid.as_reference().and_then(|id| self.doc.get_dictionary(id)) {
                    if let Ok(b"Pages") = dict.get_type() {
                        let count = dict.get_deref(b"Count", self.doc).and_then(Object::as_i64).unwrap_or(0);
                        // Don't let page count go backwards in case of an invalid document.
                        max(0, count) as usize
                    } else {
                        1
                    }
                } else {
                    1
                }
            })
            .sum();

        (nb_pages, Some(nb_pages))
    }
}

impl std::iter::FusedIterator for PageTreeIter<'_> {}
