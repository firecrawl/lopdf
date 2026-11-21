# lopdf 0.42.0, patched

Base: the published `lopdf 0.42.0` package (upstream commit
b68476c), with the package renamed to `lopdf-gov` so that it never
replaces `lopdf` for other crates in a dependency graph. The patched
`pdf-inspector-gov` branch of firecrawl/pdf-inspector depends on this
branch.

## What is patched

An additive streaming reader for content streams, a lazy object store
that replaces the eager whole-document load, and one backported
upstream fix.

### Lazy object loading (src/lazy.rs + document/reader/parser and the editing files)

`Document::load*` on an unencrypted file parses only the xref chain
and trailer. Each object materializes on first dereference through a
per-xref-entry cell store (`src/lazy.rs`). Objects that nothing
dereferences are never parsed, so a document's memory cost follows
what its consumer touches rather than what the file contains. This
matters most for large tagged PDFs, whose structure trees can dwarf
the page content. Mechanics:

- `Document.objects` is now `pub(crate)`. Reads go through
  `get_object`/`dereference` (materialized edits win over file
  state), `&mut` access materializes the object and purges its lazy
  entry, and removal APIs purge both stores so deleted objects cannot
  resurrect from the file bytes.
- Requests match the generation parsed from the object header, not
  the xref column, as the eager loader keyed its map.
- Object-stream children parse one at a time: a container's child
  index (byte ranges) is kept from its first touch, its decompressed
  plaintext lives in a single most-recent-container slot, and each
  requested child parses in place from that plaintext. Touching one
  object never materializes a large sibling. Stale linearization
  copies lose to the xref, as before.
- Whole-document operations (save, renumber, compress, decompress,
  encrypt/decrypt, traverse, prune) call `materialize_all()` first
  and behave exactly as the eager loader did.
- New public API: `materialize_all()`, `object_count()`,
  `iter_objects()` (materialized view). Removed public API: the
  `objects` field (use `set_object`/`get_object`/`iter_objects`).
- A shared mid-resolve guard turns reference cycles (including
  container-membership cycles, which previously recursed without
  bound) into absent-object results.
- Encrypted documents load lazily too: after authentication the store
  decrypts each object parsed from its own xref offset as it
  materializes, using its parsed id; object-stream children are not
  decrypted, since their container was. The encryption dictionary is
  removed from the document, as before. Without a usable password no
  store is attached.
- An object-stream container whose children start far into its
  plaintext is never decompressed whole: one streaming inflate pass
  copies out the requested child and resolves every small sibling into
  its cell, so very large children are never materialized and one pass
  serves all of the container's small objects. The child index is read
  from the plaintext header alone. Any inflate error falls back to
  whole-container decoding.
- New public API: `Document::get_object_transient` returns a `Cow`
  that borrows an already resolved object and otherwise parses a copy
  the document does not keep, for single-pass walks over large object
  graphs.
- `LoadOptions.filter` now runs at resolve time; objects never
  resolved are never filtered.

### Parsing and allocation

- `src/parser/mod.rs`: `operand` and `_direct_objects` dispatch on the
  first byte to the alternatives that can start with it, in their
  original order, instead of trying every alternative per token.
  Arrays and dictionaries parsed as objects are shrunk to fit
  (`Dictionary::shrink_to_fit`, crate-private).
- `src/object.rs`: `Stream::decompressed_content_cow` borrows the
  content when there is no `/Filter`; `decompressed_content` delegates
  to it.
- `src/document.rs`: `get_page_content` moves the first decoded buffer
  into its result instead of copying it.

### Streaming content reader

One additive API in two files. `Content::decode` and every other
existing item are untouched.

- `src/content.rs`: `ContentOperations`, a streaming reader over a
  content stream's operations. One reused operation buffer serves the
  whole stream, so operations with purely numeric operands iterate
  without allocating and no page materializes its operation vector.
  End-of-stream semantics mirror `Content::decode` exactly, including
  the discard of a partially parsed final operation. `poisoned()`
  reports the inputs for which whole-stream decoding returns an error
  (unrecoverable inline images, operand nesting beyond the supported
  depth); callers reproducing decode semantics must then discard every
  yielded operation. An equivalence test module compares the reader
  against `Content::decode` across the edge cases (comments, inline
  images and their recovery scan, nesting-depth failure, trailing
  garbage, operator at EOF, non-content whitespace).
- `src/parser/mod.rs`: `operator()` is split into a borrowed
  `operator_bytes` (the single home of the operator character class)
  plus a mapping wrapper; `operand`, `inline_image`, and
  `content_space` are exposed `pub(crate)` for the reader.

### Backport: 19-byte cross-reference entries

`src/parser/mod.rs`: `xref` accepts entries that end in a bare LF or
CR, one byte short of the 20 bytes ISO 32000-1 s7.5.4 requires, unless
`LoadOptions::strict` is set. The conforming two-byte terminators are
tried first, so a CR LF is never split. `xref_and_trailer` takes the
reader's `strict` flag, and `src/reader.rs` passes it. Without this,
such a file fails to load with "invalid file trailer". This is
upstream's change (J-F-Liu/lopdf#564), first released in lopdf 0.45.0.

## Packaging deltas

The manifest is the published (normalized) one, with the package
renamed to `lopdf-gov`, an empty `[workspace]` table so it always
builds standalone, and flate2's `zlib-rs` backend enabled.

## Upstreaming

Upstream is `github.com/J-F-Liu/lopdf`. The API is additive and
intended for an upstream PR; until then this branch carries it.
