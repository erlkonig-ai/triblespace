//! Lossless JSON importer that preserves structure and ordering.
//!
//! Every JSON value becomes a node tagged with a kind. Objects and arrays are
//! expressed via explicit entry entities that record field names or indices.
//! Entity ids are content-addressed so identical subtrees deduplicate across
//! imports.

use std::collections::HashSet;

use anybytes::{Bytes, View};
use winnow::stream::Stream;

use crate::blob::encodings::utf8string::UTF8String;
use crate::blob::Blob;
use crate::blob::IntoBlob;
use crate::blob::MemoryBlobStore;
use crate::id::{ExclusiveId, Id, RawId, ID_LEN};
use crate::inline::encodings::boolean::Boolean;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::{Blake3, Handle};
use crate::inline::encodings::iu256::U256BE;
use crate::inline::{Inline, RawInline};
use crate::macros::{entity, id_hex};
use crate::metadata;
use crate::repo::BlobStore;
use crate::trible::Fragment;
use crate::trible::TribleSet;
use triblespace_core_macros::attributes;

use crate::import::json::{
    parse_number_common, parse_string_common, parse_unicode_escape, EncodeError, JsonImportError,
};

type ParsedString = View<str>;

attributes! {
    /// Node kind tag (one of the `kind_*` constants).
    "D78B9D5A96029FDBBB327E377418AF51" unsafe as pub kind: GenId;
    /// String content stored as a UTF8String blob.
    "40BC51924FD5D2058A48D1FA6073F871" unsafe as pub string: Handle<UTF8String>;
    /// Raw decimal number string (preserves precision).
    "428E02672FFD0D010D95AE641ADE1730" unsafe as pub number_raw: Handle<UTF8String>;
    /// Boolean value.
    "6F43FC771207574BF4CC58D3080C313C" unsafe as pub boolean: Boolean;
    /// Parent entity of an object field entry.
    "97A4ACD83EC9EA29EE7E487BB058C437" unsafe as pub field_parent: GenId;
    /// Field name stored as a UTF8String blob.
    "2B9FCF2A60C9B05FADDA9F022762B822" unsafe as pub field_name: Handle<UTF8String>;
    /// Ordinal position of a field within its parent object.
    "38C7B1CDEA580DE70A520B2C8CBC4F14" unsafe as pub field_index: U256BE;
    /// Inline entity referenced by an object field entry.
    "6E6CA175F925B6AA0844D357B409F15A" unsafe as pub field_value: GenId;
    /// Parent entity of an array entry.
    "B49E6499D0A2CF5DD9A1E72D9D047747" unsafe as pub array_parent: GenId;
    /// Zero-based index of an array element.
    "D5DA41A093BD0DE490925126D1150B57" unsafe as pub array_index: U256BE;
    /// Inline entity referenced by an array entry.
    "33535F41827B476B1EC0CACECE9BEED0" unsafe as pub array_value: GenId;
}

/// JSON object node.
#[allow(non_upper_case_globals)]
pub const kind_object: Id = id_hex!("64D8981414502BF750387C617F1F9D09");
/// JSON array node.
#[allow(non_upper_case_globals)]
pub const kind_array: Id = id_hex!("5DC7096A184E658C8E16C54EB207C386");
/// JSON string node.
#[allow(non_upper_case_globals)]
pub const kind_string: Id = id_hex!("58A5EAC244801C5E26AD9178C784781A");
/// JSON number node.
#[allow(non_upper_case_globals)]
pub const kind_number: Id = id_hex!("711555ADF72B9499E6A7F68E0BD3B4B8");
/// JSON boolean node.
#[allow(non_upper_case_globals)]
pub const kind_bool: Id = id_hex!("7D3079C5E20658B6CA5F54771B5D0D30");
/// JSON null node.
#[allow(non_upper_case_globals)]
pub const kind_null: Id = id_hex!("FC1DCF98A3A8418D6090EBD367CFFD7A");
/// Object field entry.
#[allow(non_upper_case_globals)]
pub const kind_field: Id = id_hex!("890FC1F34B9FAD18F93E6EDF1B69A1A2");
/// Array entry.
#[allow(non_upper_case_globals)]
pub const kind_array_entry: Id = id_hex!("EB325EABEA8C35DE7E5D700A5EF9207B");

/// Returns a [`Fragment`] describing the lossless JSON tree schema —
/// all node kinds, attribute definitions, and value/blob encoding metadata.
pub fn build_json_tree_metadata() -> Fragment {
    // The macro-generated `describe()` for this module's attributes!{}
    // block emits each declared attribute's identity, schema spread,
    // and a usage entity rooted at
    // (metadata::attribute, metadata::source_module) with the rust
    // identifier as `metadata::name`. The `source_module` field
    // disambiguates "this is the JSON tree schema's usage of `kind`"
    // from any other crate's usage of the same attribute id, so we no
    // longer need a separate `json.kind` rename.
    let mut metadata = describe();

    metadata += describe_kind(kind_object, "json.kind.object", "JSON object node.");
    metadata += describe_kind(kind_array, "json.kind.array", "JSON array node.");
    metadata += describe_kind(kind_string, "json.kind.string", "JSON string node.");
    metadata += describe_kind(kind_number, "json.kind.number", "JSON number node.");
    metadata += describe_kind(kind_bool, "json.kind.bool", "JSON boolean node.");
    metadata += describe_kind(kind_null, "json.kind.null", "JSON null node.");
    metadata += describe_kind(kind_field, "json.kind.field", "JSON object field entry.");
    metadata += describe_kind(
        kind_array_entry,
        "json.kind.array_entry",
        "JSON array entry.",
    );

    metadata
}

fn describe_kind(kind_id: Id, name: &str, description: &str) -> Fragment {
    entity! { ExclusiveId::force_ref(&kind_id) @
        metadata::name:        name.to_owned(),
        metadata::description: description.to_owned(),
    }
}

#[derive(Clone)]
struct FieldEntry {
    name: View<str>,
    name_handle: Inline<Handle<UTF8String>>,
    index: u64,
    value: Id,
}

#[derive(Clone)]
struct ArrayEntry {
    index: u64,
    value: Id,
}

/// An array or object whose closing bracket has not been read yet.
enum Frame {
    Array(Vec<ArrayEntry>),
    /// `pending` is the name of the member whose value is being parsed.
    Object {
        fields: Vec<FieldEntry>,
        pending: (ParsedString, Inline<Handle<UTF8String>>),
    },
}

/// What one `import_blob` call accumulates.
struct ImportState {
    data: TribleSet,
    local_blobs: MemoryBlobStore,
    /// Handles already put during this import.
    stored: HashSet<RawInline>,
}

/// Lossless JSON importer that preserves ordering and encodes explicit entry nodes.
///
/// This importer encodes JSON values as an explicit node/entry graph (a JSON AST),
/// using content-addressed ids so identical subtrees deduplicate across imports.
///
/// Parsing is iterative, so deeply nested input cannot overflow the call
/// stack; nesting beyond [`with_max_depth`](Self::with_max_depth) (default
/// [`DEFAULT_MAX_DEPTH`]) is refused with [`JsonImportError::DepthExceeded`].
/// A `\uXXXX` surrogate that is not half of a pair is refused with
/// [`JsonImportError::LoneSurrogate`].
pub struct JsonTreeImporter<'a, Store>
where
    Store: BlobStore,
{
    store: &'a mut Store,
    id_salt: Option<[u8; 32]>,
    max_depth: usize,
}

/// Default nesting limit of [`JsonTreeImporter`]: a value may sit inside at
/// most this many arrays/objects.
pub const DEFAULT_MAX_DEPTH: usize = 128;

impl<'a, Store> JsonTreeImporter<'a, Store>
where
    Store: BlobStore,
{
    /// Creates a new lossless importer backed by `store`.
    ///
    /// `id_salt` namespaces the content-addressed entity ids: any `Some`
    /// salt gives every node and entry a different id than `None` does.
    /// Archive imports must pass `None`, so that the same document always
    /// lands on the same ids no matter who imports it; a salt is only for
    /// callers that deliberately want ids disjoint from everyone else's.
    pub fn new(store: &'a mut Store, id_salt: Option<[u8; 32]>) -> Self {
        Self {
            store,
            id_salt,
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    /// Sets how many arrays/objects a value may be nested inside (`0`
    /// admits only scalar documents). Deeper input is refused with
    /// [`JsonImportError::DepthExceeded`]; the limit bounds work per value,
    /// not stack use, which never grows with depth.
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Imports a JSON string. Convenience wrapper around [`import_blob`](Self::import_blob).
    pub fn import_str(&mut self, input: &str) -> Result<Fragment, JsonImportError> {
        self.import_blob(input.to_owned().to_blob())
    }

    /// Imports a JSON document from a [`UTF8String`] blob, returning a
    /// [`Fragment`] rooted at the document's top-level node.
    pub fn import_blob(&mut self, blob: Blob<UTF8String>) -> Result<Fragment, JsonImportError> {
        let mut state = ImportState {
            data: TribleSet::new(),
            local_blobs: MemoryBlobStore::new(),
            stored: HashSet::new(),
        };
        let mut bytes = blob.bytes.clone();
        self.skip_ws(&mut bytes);
        let root = self.parse_document(&mut bytes, &mut state)?;
        self.skip_ws(&mut bytes);
        if bytes.peek_token().is_some() {
            return Err(JsonImportError::Syntax("trailing tokens".into()));
        }
        let mut fragment = Fragment::rooted_with_blobs(root, state.data, state.local_blobs);
        // The node kinds are minted here rather than declared by an
        // `attributes!` block, so the importer has to attach their schema
        // itself. Keep it in the returned fragment's metafacts so committing
        // the import cannot silently lose the information needed to decode it.
        fragment.describe_with(build_json_tree_metadata());
        Ok(fragment)
    }

    /// Returns schema metadata for the lossless JSON tree format.
    /// Delegates to [`build_json_tree_metadata`].
    pub fn metadata(&self) -> Fragment {
        build_json_tree_metadata()
    }

    /// Parses one JSON value without recursion: open arrays/objects live on
    /// an explicit heap stack, so input depth costs heap, never call stack,
    /// and the depth limit is checked before a container is entered.
    fn parse_document(
        &mut self,
        bytes: &mut Bytes,
        state: &mut ImportState,
    ) -> Result<Id, JsonImportError> {
        let mut stack: Vec<Frame> = Vec::new();
        loop {
            // Parse the value at the cursor. A scalar or an empty container
            // completes at once; a non-empty container is pushed and its first
            // member's value is parsed on the next iteration.
            let mut value = match bytes.peek_token() {
                Some(open @ (b'[' | b'{')) => {
                    if stack.len() >= self.max_depth {
                        return Err(JsonImportError::DepthExceeded {
                            max_depth: self.max_depth,
                        });
                    }
                    bytes.pop_front();
                    self.skip_ws(bytes);
                    if open == b'[' {
                        if bytes.peek_token() == Some(b']') {
                            bytes.pop_front();
                            self.finish_array(&[], state)
                        } else {
                            stack.push(Frame::Array(Vec::new()));
                            continue;
                        }
                    } else if bytes.peek_token() == Some(b'}') {
                        bytes.pop_front();
                        self.finish_object(&[], state)
                    } else {
                        let pending = self.parse_member_name(bytes, state)?;
                        stack.push(Frame::Object {
                            fields: Vec::new(),
                            pending,
                        });
                        continue;
                    }
                }
                _ => self.parse_scalar(bytes, state)?,
            };

            // Hand the finished value to its parent, closing every container
            // that ends right after it.
            loop {
                let Some(frame) = stack.last_mut() else {
                    return Ok(value);
                };
                self.skip_ws(bytes);
                let closed = match frame {
                    Frame::Array(entries) => {
                        let index = entries.len() as u64;
                        entries.push(ArrayEntry { index, value });
                        match bytes.pop_front() {
                            Some(b',') => false,
                            Some(b']') => true,
                            _ => return Err(JsonImportError::Syntax("unexpected token".into())),
                        }
                    }
                    Frame::Object { fields, pending } => {
                        let index = fields.len() as u64;
                        let (name, name_handle) = pending.clone();
                        fields.push(FieldEntry {
                            name,
                            name_handle,
                            index,
                            value,
                        });
                        match bytes.pop_front() {
                            Some(b',') => {
                                self.skip_ws(bytes);
                                *pending = self.parse_member_name(bytes, state)?;
                                false
                            }
                            Some(b'}') => true,
                            _ => return Err(JsonImportError::Syntax("unexpected token".into())),
                        }
                    }
                };
                if !closed {
                    self.skip_ws(bytes);
                    break;
                }
                value = match stack.pop().expect("the frame just inspected") {
                    Frame::Array(entries) => self.finish_array(&entries, state),
                    Frame::Object { fields, .. } => self.finish_object(&fields, state),
                };
            }
        }
    }

    /// Parses `"name"`, the `:` and surrounding whitespace, storing the name.
    fn parse_member_name(
        &mut self,
        bytes: &mut Bytes,
        state: &mut ImportState,
    ) -> Result<(ParsedString, Inline<Handle<UTF8String>>), JsonImportError> {
        let name = self.parse_string(bytes)?;
        self.skip_ws(bytes);
        self.consume_byte(bytes, b':')?;
        self.skip_ws(bytes);
        let handle = self.store_text(name.clone().to_blob(), state, |source| {
            JsonImportError::EncodeString {
                field: "field".to_string(),
                source,
            }
        })?;
        Ok((name, handle))
    }

    fn parse_scalar(
        &mut self,
        bytes: &mut Bytes,
        state: &mut ImportState,
    ) -> Result<Id, JsonImportError> {
        match bytes.peek_token() {
            Some(b'n') => {
                self.consume_literal(bytes, b"null")?;
                let id = self.hash_tagged(b"null", &[]);
                state.data += entity! { ExclusiveId::force_ref(&id) @
                    kind: kind_null,
                };
                Ok(id)
            }
            Some(b't') => {
                self.consume_literal(bytes, b"true")?;
                let id = self.hash_tagged(b"bool", &[b"true"]);
                state.data += entity! { ExclusiveId::force_ref(&id) @
                    kind: kind_bool,
                    boolean: true,
                };
                Ok(id)
            }
            Some(b'f') => {
                self.consume_literal(bytes, b"false")?;
                let id = self.hash_tagged(b"bool", &[b"false"]);
                state.data += entity! { ExclusiveId::force_ref(&id) @
                    kind: kind_bool,
                    boolean: false,
                };
                Ok(id)
            }
            Some(b'"') => {
                let text = self.parse_string(bytes)?;
                let id = self.hash_tagged(b"string", &[text.as_ref().as_bytes()]);
                let handle = self.store_text(text.to_blob(), state, |source| {
                    JsonImportError::EncodeString {
                        field: "string".to_string(),
                        source,
                    }
                })?;
                state.data += entity! { ExclusiveId::force_ref(&id) @
                    kind: kind_string,
                    string: handle,
                };
                Ok(id)
            }
            _ => {
                let number = self.parse_number(bytes)?;
                let number_view = number
                    .view::<str>()
                    .map_err(|_| JsonImportError::Syntax("invalid number".into()))?;
                let id = self.hash_tagged(b"number", &[number_view.as_ref().as_bytes()]);
                let handle = self.store_text(number_view.to_blob(), state, |source| {
                    JsonImportError::EncodeNumber {
                        field: "number".to_string(),
                        source,
                    }
                })?;
                state.data += entity! { ExclusiveId::force_ref(&id) @
                    kind: kind_number,
                    number_raw: handle,
                };
                Ok(id)
            }
        }
    }

    /// Puts `blob` into the external store and the fragment's own store, once
    /// per distinct blob per import. Both stores hold the same refcounted
    /// bytes; nothing is copied.
    fn store_text(
        &mut self,
        blob: Blob<UTF8String>,
        state: &mut ImportState,
        on_error: impl FnOnce(EncodeError) -> JsonImportError,
    ) -> Result<Inline<Handle<UTF8String>>, JsonImportError> {
        let handle = blob.get_handle();
        if state.stored.insert(handle.raw) {
            self.store
                .put::<UTF8String, _>(blob.clone())
                .map_err(|err| on_error(EncodeError::from_error(err)))?;
            state.local_blobs.insert(blob);
        }
        Ok(handle)
    }

    fn finish_object(&self, fields: &[FieldEntry], state: &mut ImportState) -> Id {
        let object_id = self.hash_object(fields);
        state.data += entity! { ExclusiveId::force_ref(&object_id) @
            kind: kind_object,
        };

        for field in fields {
            let entry_id = self.hash_field_entry(&object_id, field);
            state.data += entity! { ExclusiveId::force_ref(&entry_id) @
                kind: kind_field,
                field_parent: object_id,
                field_name: field.name_handle,
                field_index: field.index,
                field_value: field.value,
            };
        }

        object_id
    }

    fn finish_array(&self, entries: &[ArrayEntry], state: &mut ImportState) -> Id {
        let array_id = self.hash_array(entries);
        state.data += entity! { ExclusiveId::force_ref(&array_id) @
            kind: kind_array,
        };

        for entry in entries {
            let entry_id = self.hash_array_entry(&array_id, entry);
            state.data += entity! { ExclusiveId::force_ref(&entry_id) @
                kind: kind_array_entry,
                array_parent: array_id,
                array_index: entry.index,
                array_value: entry.value,
            };
        }

        array_id
    }

    fn hash_object(&self, fields: &[FieldEntry]) -> Id {
        let mut hasher = self.seeded_hasher();
        hash_chunk(&mut hasher, b"object");
        for field in fields {
            let index_bytes = field.index.to_be_bytes();
            hash_chunk(&mut hasher, field.name.as_ref().as_bytes());
            hash_chunk(&mut hasher, &index_bytes);
            hash_chunk(&mut hasher, field.value.as_ref());
        }
        self.finish_hash(hasher)
    }

    fn hash_array(&self, entries: &[ArrayEntry]) -> Id {
        let mut hasher = self.seeded_hasher();
        hash_chunk(&mut hasher, b"array");
        for entry in entries {
            let index_bytes = entry.index.to_be_bytes();
            hash_chunk(&mut hasher, &index_bytes);
            hash_chunk(&mut hasher, entry.value.as_ref());
        }
        self.finish_hash(hasher)
    }

    fn hash_field_entry(&self, parent: &Id, entry: &FieldEntry) -> Id {
        let mut hasher = self.seeded_hasher();
        hash_chunk(&mut hasher, b"field");
        let index_bytes = entry.index.to_be_bytes();
        hash_chunk(&mut hasher, parent.as_ref());
        hash_chunk(&mut hasher, entry.name.as_ref().as_bytes());
        hash_chunk(&mut hasher, &index_bytes);
        hash_chunk(&mut hasher, entry.value.as_ref());
        self.finish_hash(hasher)
    }

    fn hash_array_entry(&self, parent: &Id, entry: &ArrayEntry) -> Id {
        let mut hasher = self.seeded_hasher();
        hash_chunk(&mut hasher, b"array_entry");
        let index_bytes = entry.index.to_be_bytes();
        hash_chunk(&mut hasher, parent.as_ref());
        hash_chunk(&mut hasher, &index_bytes);
        hash_chunk(&mut hasher, entry.value.as_ref());
        self.finish_hash(hasher)
    }

    fn hash_tagged(&self, tag: &[u8], parts: &[&[u8]]) -> Id {
        let mut hasher = self.seeded_hasher();
        hash_chunk(&mut hasher, tag);
        for part in parts {
            hash_chunk(&mut hasher, part);
        }
        self.finish_hash(hasher)
    }

    fn seeded_hasher(&self) -> Blake3 {
        let mut hasher = Blake3::new();
        if let Some(salt) = self.id_salt {
            hasher.update(salt.as_ref());
        }
        hasher
    }

    fn finish_hash(&self, hasher: Blake3) -> Id {
        let digest = hasher.finalize();
        id_from_digest(digest.as_ref())
    }

    /// RFC 8259 whitespace only: space, tab, newline, carriage return.
    fn skip_ws(&self, bytes: &mut Bytes) {
        super::scanner::skip_ws(bytes);
    }

    fn consume_byte(&self, bytes: &mut Bytes, expected: u8) -> Result<(), JsonImportError> {
        match bytes.pop_front() {
            Some(b) if b == expected => Ok(()),
            _ => Err(JsonImportError::Syntax("unexpected token".into())),
        }
    }

    fn consume_literal(&self, bytes: &mut Bytes, literal: &[u8]) -> Result<(), JsonImportError> {
        for expected in literal {
            self.consume_byte(bytes, *expected)?;
        }
        Ok(())
    }

    fn parse_string(&self, bytes: &mut Bytes) -> Result<ParsedString, JsonImportError> {
        let raw = parse_string_common(bytes, &mut parse_unicode_escape)?;
        raw.view::<str>()
            .map_err(|_| JsonImportError::Syntax("invalid utf-8".into()))
    }

    fn parse_number(&self, bytes: &mut Bytes) -> Result<Bytes, JsonImportError> {
        parse_number_common(bytes)
    }
}

fn hash_chunk(hasher: &mut Blake3, bytes: &[u8]) {
    let len = (bytes.len() as u64).to_be_bytes();
    hasher.update(&len);
    hasher.update(bytes);
}

fn id_from_digest(digest: &[u8]) -> Id {
    let mut raw: RawId = [0u8; ID_LEN];
    raw.copy_from_slice(&digest[digest.len() - ID_LEN..]);
    if raw == [0; ID_LEN] {
        raw[0] = 1;
    }
    Id::new(raw).unwrap_or_else(|| unsafe { Id::force(raw) })
}

#[cfg(test)]
mod tests {
    use anybytes::View;

    use super::{kind_array_entry, JsonTreeImporter};
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::blob::BlobEncoding;
    use crate::blob::IntoBlob;
    use crate::blob::MemoryBlobStore;
    use crate::blob::MemoryBlobStoreSnapshot;
    use crate::id::Id;
    use crate::import::json::JsonImportError;
    use crate::inline::encodings::hash::Handle;
    use crate::inline::{Inline, InlineEncoding, RawInline};
    use crate::macros::{find, pattern};
    use crate::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
    use crate::trible::Fragment;

    #[test]
    fn lossless_ids_are_content_based() {
        let input = r#"{ "a": [1, 2] }"#;
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonTreeImporter::<_>::new(&mut blobs, None);
        let root = importer
            .import_blob(input.to_blob())
            .unwrap()
            .root()
            .expect("import_blob returns a rooted fragment");
        drop(importer);
        let mut other = JsonTreeImporter::<_>::new(&mut blobs, None);
        let other_root = other
            .import_blob(input.to_blob())
            .unwrap()
            .root()
            .expect("import_blob returns a rooted fragment");
        assert_eq!(root, other_root);
    }

    #[test]
    fn lossless_preserves_array_order() {
        let input = r#"[1, 2]"#;
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonTreeImporter::<_>::new(&mut blobs, None);
        let fragment = importer.import_blob(input.to_blob()).unwrap();
        let root = fragment
            .root()
            .expect("import_blob returns a rooted fragment");
        assert!(
            !fragment.metafacts().is_empty(),
            "the imported tree carries its schema without a separate metadata call"
        );
        let catalog = fragment.facts();
        let mut entries = find!(
            (index: ethnum::U256, value: Id),
            pattern!(catalog, [{
                _?entry @
                super::kind: kind_array_entry,
                super::array_parent: root,
                super::array_index: ?index,
                super::array_value: ?value,
            }])
        )
        .collect::<Vec<_>>();
        entries.sort_by_key(|(index, _)| *index);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, ethnum::U256::new(0));
        assert_eq!(entries[1].0, ethnum::U256::new(1));
    }

    #[test]
    fn returned_fragment_carries_its_content_blobs() {
        let input = r#"{"field": "value"}"#;
        let mut external = MemoryBlobStore::new();
        let mut importer = JsonTreeImporter::<_>::new(&mut external, None);
        let fragment = importer.import_blob(input.to_blob()).unwrap();

        let string_handle = find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(fragment.facts(), [{ _?node @ super::string: ?handle }])
        )
        .map(|(handle,)| handle)
        .next()
        .expect("the string node has a content handle");

        let field_handle = find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(fragment.facts(), [{ _?entry @ super::field_name: ?handle }])
        )
        .map(|(handle,)| handle)
        .next()
        .expect("the field entry has a name handle");

        let mut local = fragment.blobs().clone();
        let reader = local.snapshot().expect("fragment blob-store snapshot");
        let value: View<str> = reader
            .get(string_handle)
            .expect("string bytes resolve from the returned fragment");
        let field: View<str> = reader
            .get(field_handle)
            .expect("field-name bytes resolve from the returned fragment");
        assert_eq!(&*value, "value");
        assert_eq!(&*field, "field");
    }
    fn import(doc: &str) -> Result<Fragment, JsonImportError> {
        let mut blobs = MemoryBlobStore::new();
        JsonTreeImporter::<_>::new(&mut blobs, None).import_str(doc)
    }

    fn read_blob(fragment: &Fragment, handle: Inline<Handle<UTF8String>>) -> String {
        let reader = fragment.blobs().clone().snapshot().unwrap();
        let text: View<str> = reader.get(handle).expect("blob resolves from fragment");
        text.as_ref().to_owned()
    }

    /// Decoded text of every string node in the fragment, sorted.
    fn string_values(fragment: &Fragment) -> Vec<String> {
        let mut out = find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(fragment.facts(), [{ _?node @
                super::kind: super::kind_string,
                super::string: ?handle,
            }])
        )
        .map(|(handle,)| read_blob(fragment, handle))
        .collect::<Vec<_>>();
        out.sort();
        out
    }

    /// Raw token of every number node in the fragment, sorted.
    fn number_tokens(fragment: &Fragment) -> Vec<String> {
        let mut out = find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(fragment.facts(), [{ _?node @
                super::kind: super::kind_number,
                super::number_raw: ?handle,
            }])
        )
        .map(|(handle,)| read_blob(fragment, handle))
        .collect::<Vec<_>>();
        out.sort();
        out
    }

    #[test]
    fn surrogate_pair_escape_decodes_to_one_scalar() {
        for (doc, expected) in [
            (r#""\ud83d\ude00""#, "\u{1F600}"),
            (r#""\uD83D\uDE00""#, "\u{1F600}"),
            (r#""a\ud83d\ude00b""#, "a\u{1F600}b"),
            (r#""\udbff\udfff""#, "\u{10FFFF}"),
        ] {
            let fragment = import(doc).unwrap_or_else(|e| panic!("{doc}: {e}"));
            assert_eq!(string_values(&fragment), vec![expected.to_owned()], "{doc}");
        }
        // Field names go through the same decoder.
        let fragment = import(r#"{"\ud83d\ude00": 1}"#).unwrap();
        let name = find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(fragment.facts(), [{ _?entry @ super::field_name: ?handle }])
        )
        .map(|(handle,)| read_blob(&fragment, handle))
        .next()
        .expect("field entry");
        assert_eq!(name, "\u{1F600}");
    }

    #[test]
    fn lone_surrogate_is_refused_with_its_code_unit() {
        for (doc, unit) in [
            (r#""\ud83d""#, 0xD83D),
            (r#""\ude00""#, 0xDE00),
            (r#""\ud83d x""#, 0xD83D),
            (r#""\ud83d\n""#, 0xD83D),
            (r#""\ud83d\u0041""#, 0xD83D),
            (r#""\ud83d\ud83d""#, 0xD83D),
            (r#""\ude00\ud83d""#, 0xDE00),
            (r#"{"\udfff": 1}"#, 0xDFFF),
            (r#"["ok", "\udbff"]"#, 0xDBFF),
        ] {
            match import(doc) {
                Err(JsonImportError::LoneSurrogate { code_unit }) => {
                    assert_eq!(code_unit, unit, "{doc}")
                }
                other => panic!("{doc}: expected LoneSurrogate, got {other:?}"),
            }
        }
    }

    /// A string that is not syntactically complete is a syntax error, even
    /// when it begins with a high surrogate; `LoneSurrogate` is only for a
    /// well-formed document whose escapes leave a surrogate unpaired.
    #[test]
    fn malformed_escape_after_high_surrogate_is_syntax() {
        for doc in [
            r#""\ud800\x""#,
            r#""\ud800\"#,
            r#""\ud800"#,
            r#""\ud800\u0041"#,
            r#""\ud800\u12""#,
            r#""\ud800\uzzzz""#,
            r#""\ude00\x""#,
            r#"["\ud800" 1]"#,
            r#"{"\ud800" 1}"#,
            r#""\ud800" x"#,
        ] {
            match import(doc) {
                Err(JsonImportError::Syntax(_)) => {}
                other => panic!("{doc}: expected a syntax error, got {other:?}"),
            }
        }
    }

    /// RFC 8259 whitespace is space, tab, newline and carriage return only:
    /// a form feed is refused wherever it appears, and so is an unescaped
    /// control character inside a string, while its escaped form decodes.
    #[test]
    fn only_json_whitespace_and_escaped_controls_are_accepted() {
        for bad in [
            "\x0c[]",
            "[\x0c1]",
            "[1\x0c]",
            "[\"a\"\x0c]",
            "{\x0c}",
            "[true\x0c]",
            "\"a\x01b\"",
            "\"a\tb\"",
            "\"a\x1fb\"",
            "{\"k\x00\": 1}",
        ] {
            assert!(
                matches!(import(bad), Err(JsonImportError::Syntax(_))),
                "{bad:?} must be refused"
            );
        }
        for good in ["[ 1 ]", "[\t1\n]", "\r\n[]", "\"a\\tb\"", "\"\\u0001\""] {
            assert!(import(good).is_ok(), "{good:?} must import");
        }
    }

    #[test]
    fn number_grammar_rejects_non_json_forms() {
        for bad in [
            "1-2", "01", "-01", "1.", ".5", "1e", "1E+", "+1", "-", "1e2e3", "1.2.3",
        ] {
            for doc in [
                bad.to_owned(),
                format!("[{bad}]"),
                format!("{{\"n\": {bad}}}"),
            ] {
                match import(&doc) {
                    Err(JsonImportError::Syntax(_)) => {}
                    other => panic!("{doc}: expected a syntax error, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn number_grammar_accepts_json_forms_with_exact_raw_tokens() {
        for good in [
            "0",
            "-0",
            "1.5e-3",
            "1E+2",
            "10",
            "-1",
            "0.25",
            "1e10",
            "123456789012345678901234567890",
        ] {
            for doc in [
                good.to_owned(),
                format!("[ {good} ]"),
                format!("{{\"n\":{good}}}"),
            ] {
                let fragment = import(&doc).unwrap_or_else(|e| panic!("{doc}: {e}"));
                assert_eq!(number_tokens(&fragment), vec![good.to_owned()], "{doc}");
            }
        }
    }

    /// Wraps a `MemoryBlobStore` and records every `put`.
    #[derive(Default)]
    struct CountingStore {
        inner: MemoryBlobStore,
        puts: Vec<RawInline>,
    }

    impl BlobStorePut for CountingStore {
        type PutError = std::convert::Infallible;

        fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
        where
            S: BlobEncoding + 'static,
            T: IntoBlob<S>,
            Handle<S>: InlineEncoding,
        {
            let blob = item.to_blob();
            let handle = blob.get_handle();
            self.puts.push(handle.raw);
            self.inner.insert(blob);
            Ok(handle)
        }
    }

    impl SnapshotSource for CountingStore {
        type Snapshot = MemoryBlobStoreSnapshot;
        type SnapshotError = std::convert::Infallible;

        fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
            self.inner.snapshot()
        }
    }

    #[test]
    fn each_distinct_blob_is_put_once_and_readable_from_both_sides() {
        // Distinct UTF-8 blobs: "k", "v", "1" (the number 1 and the string
        // "1" have the same bytes, hence the same blob).
        let doc = r#"[{"k":"v"},{"k":"v"},{"v":"k"}, 1, 1, "1", {"1": 1}]"#;
        let mut store = CountingStore::default();
        let fragment = JsonTreeImporter::<_>::new(&mut store, None)
            .import_str(doc)
            .unwrap();

        let mut distinct = store.puts.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 3, "three distinct blobs");
        assert_eq!(store.puts.len(), 3, "one put per distinct blob");

        let facts = fragment.facts();
        let mut handles = Vec::new();
        handles.extend(find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(facts, [{ _?n @ super::string: ?handle }])
        ));
        handles.extend(find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(facts, [{ _?n @ super::number_raw: ?handle }])
        ));
        handles.extend(find!(
            (handle: Inline<Handle<UTF8String>>),
            pattern!(facts, [{ _?n @ super::field_name: ?handle }])
        ));
        assert!(!handles.is_empty());
        let external = store.snapshot().unwrap();
        let local = fragment.blobs().clone().snapshot().unwrap();
        for (handle,) in handles {
            let a: View<str> = external.get(handle).expect("readable from the store");
            let b: View<str> = local.get(handle).expect("readable from the fragment");
            assert_eq!(a.as_ref(), b.as_ref());
        }
    }

    /// A refused document puts nothing into the caller's store, however
    /// much of it parsed before the refusal.
    #[test]
    fn refused_document_puts_nothing_into_the_store() {
        let mut store = CountingStore::default();
        let mut importer = JsonTreeImporter::<_>::new(&mut store, None);
        let bad = [
            r#"["kept", {"name": 1}, 01]"#.to_owned(),
            r#"["kept", {"name": "\ud800"}]"#.to_owned(),
            r#"["kept", 1e5, "x" "y"]"#.to_owned(),
            r#"["kept"] trailing"#.to_owned(),
            format!(r#"["kept", {}{}]"#, "[".repeat(200), "]".repeat(200)),
        ];
        for doc in &bad {
            assert!(importer.import_str(doc).is_err(), "{doc} must be refused");
        }
        importer.import_str(r#"["ok"]"#).unwrap();
        drop(importer);
        let ok: Inline<Handle<UTF8String>> = "ok".to_blob().get_handle();
        assert_eq!(
            store.puts,
            vec![ok.raw],
            "only the accepted document's blob"
        );
    }

    fn nested_arrays(depth: usize) -> String {
        format!("{}{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn nested_objects(depth: usize) -> String {
        format!("{}1{}", r#"{"a":"#.repeat(depth), "}".repeat(depth))
    }

    fn expect_depth_exceeded(result: Result<Fragment, JsonImportError>, max: usize) {
        match result {
            Err(JsonImportError::DepthExceeded { max_depth }) => assert_eq!(max_depth, max),
            other => panic!("expected DepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn default_depth_limit_is_128() {
        assert_eq!(super::DEFAULT_MAX_DEPTH, 128);
        import(&nested_arrays(128)).expect("depth 128 is accepted");
        import(&nested_objects(128)).expect("depth 128 is accepted");
        expect_depth_exceeded(import(&nested_arrays(129)), 128);
        expect_depth_exceeded(import(&nested_objects(129)), 128);
        // Mixed nesting counts both kinds of container.
        let mixed = format!("{}{}", r#"[{"a":"#.repeat(65), "}]".repeat(65));
        expect_depth_exceeded(import(&mixed), 128);
    }

    #[test]
    fn depth_limit_is_configurable() {
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonTreeImporter::<_>::new(&mut blobs, None).with_max_depth(2);
        importer.import_str("[[1]]").expect("depth 2 accepted");
        importer.import_str("1").expect("scalars have depth 0");
        expect_depth_exceeded(importer.import_str("[[[1]]]"), 2);
        expect_depth_exceeded(importer.import_str(r#"[{"a":[]}]"#), 2);

        let mut importer = JsonTreeImporter::<_>::new(&mut blobs, None).with_max_depth(0);
        importer
            .import_str("\"x\"")
            .expect("scalar root at depth 0");
        expect_depth_exceeded(importer.import_str("[]"), 0);
    }

    #[test]
    fn hundred_thousand_deep_array_does_not_overflow_the_stack() {
        let depth = 100_000;
        let doc = nested_arrays(depth);
        // Refused at the default limit ...
        expect_depth_exceeded(import(&doc), super::DEFAULT_MAX_DEPTH);
        // ... and imported without recursion when the limit allows it.
        let mut blobs = MemoryBlobStore::new();
        let fragment = JsonTreeImporter::<_>::new(&mut blobs, None)
            .with_max_depth(usize::MAX)
            .import_str(&doc)
            .expect("deep input imports");
        let arrays = find!(
            (node: Id),
            pattern!(fragment.facts(), [{ ?node @ super::kind: super::kind_array }])
        )
        .count();
        assert_eq!(arrays, depth);
    }

    /// Root id, BLAKE3 of the ordered facts, and fact count, recorded from
    /// the importer at triblespace e77f8e67 with `id_salt = None`. Archive
    /// identity depends on these never changing.
    const GOLDEN: &[(&str, &str, &str, usize)] = &[
        (
            "null",
            "2B4A4BD434B35C7CF395E7F13BEF4ED8",
            "dbfeb85f3f1bf4657c71688e12ebd876df5b20077fb6356595e67dd1d92e68de",
            1,
        ),
        (
            "true",
            "F6D597C71DC6B8E1A5EEFA183CBA0D78",
            "ec4d98d2a6567b61cf66a86e64d6451fb983ec36bc931b909413d542bdec174d",
            2,
        ),
        (
            "false",
            "16D8F8627E78352FC098A82D781500A1",
            "c9b4656a8cd9b0a559d9f9f8392a5110189b65149a4696fcc129bb1c224f80c4",
            2,
        ),
        (
            r#""""#,
            "B44093D9D4DFDB4A09206FED65D07C38",
            "bad450cfd69d604a33ad2db5ae44e9321a8b3edf2e7992f73ce577a864d6e6dd",
            2,
        ),
        (
            r#""plain""#,
            "03793CB3DEFC8BD11AD69124D2D9982F",
            "933ccc7d4f4fbf9116c4ea4be3a49cf27270a8c0d75536c763d0b2381fc35865",
            2,
        ),
        (
            r#""esc \"q\" \\ \/ \b\f\n\r\t \u00e9 \u263A""#,
            "F1472074009CE28D1DB1BF1AF20AE15D",
            "f8f7b0be7cac98c8fed5e2ddae77912641da950329640a5af6fcc98d85549f78",
            2,
        ),
        (
            "0",
            "2AD585590B310BEB5989EB32BF1A1874",
            "820997c35cb64b0b39707ac238ff703ac78f8dfbd2b5e53b7d5038dd4cc0376e",
            2,
        ),
        (
            "-0",
            "F4A45AFCF860A8E646726A81D5E4DB65",
            "d25b0abbde70602846258ee15b5dde3a553bb20e15a4f5a9d94ceb7e0fdb8748",
            2,
        ),
        (
            "1.5e-3",
            "F1FABE97CED50597F6001E8AA50EEB87",
            "30af8c8d55a5026f3e4b723fe311f01a6d8aa8811bf624dc5ed5e090015ae324",
            2,
        ),
        (
            "1E+2",
            "1F5FFBAE87BB32A7DD9F6B16A0C01395",
            "482980e494da52e21899e880b0b1d1aa47bdcfbc42deb9a5d590d2df1211f401",
            2,
        ),
        (
            "[]",
            "F3809F15292703583DA3CD42A3A316A2",
            "de1221098fe4b3fdc10cec1a94a069ae7243241915d4da9e922e897c9993a161",
            1,
        ),
        (
            "{}",
            "2F5563B933F5852111DDA9ADDFB38F8F",
            "678e8ac742b64e83bf1d80b0ec55318b8b4656ba634ebf2e4d4091fe1f026a0d",
            1,
        ),
        (
            r#"[1, 1, "1", [true, null]]"#,
            "7599CCC3AAE53A3AAAB72FC7221F0CEF",
            "d6787b18b7d0a16720151af5daa1e613cd9ce8da8535f910a9f43a3a88d1a8d6",
            33,
        ),
        (
            r#"{"a": [1, 2, {"b": null}], "c": "\u00e9", "": {}}"#,
            "0F9C4626E50FA6772864FF447B9E7655",
            "c9fd3d64e8a9a97278059226fef246df3b64ae946375cc0a39d1368a2c429de8",
            43,
        ),
        (
            r#"{"k": 1, "k": 2, "j": "k"}"#,
            "D4BA1587A68D409D378B9BD1D2748A18",
            "0db516a3bb746434833096d56c3fcb9c760e0a25a4027ebe9f2f6758c634e5e2",
            22,
        ),
    ];

    #[test]
    fn unsalted_ids_match_recorded_golden_values() {
        for &(doc, root_hex, facts_hex, facts_len) in GOLDEN {
            let fragment = import(doc).unwrap_or_else(|e| panic!("{doc}: {e}"));
            let root = fragment.root().expect("rooted");
            let mut hasher = blake3::Hasher::new();
            for trible in fragment.facts().iter_ordered() {
                hasher.update(&trible.data);
            }
            assert_eq!(format!("{root:X}"), root_hex, "root of {doc}");
            assert_eq!(
                hasher.finalize().to_hex().as_str(),
                facts_hex,
                "facts of {doc}"
            );
            assert_eq!(fragment.facts().len(), facts_len, "fact count of {doc}");
        }
    }

    #[test]
    fn a_salt_changes_ids() {
        let mut blobs = MemoryBlobStore::new();
        let salted = JsonTreeImporter::<_>::new(&mut blobs, Some([7u8; 32]))
            .import_str("[1]")
            .unwrap();
        let plain = import("[1]").unwrap();
        assert_ne!(salted.root(), plain.root());
    }
}
