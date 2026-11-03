//! Deterministic JSON *object* importer built on a winnow-based streaming parser.
//!
//! This importer uses the canonical `NIL || attribute || value` row protocol
//! shared with `entity!` to derive entity identifiers.
//! Identical JSON objects therefore converge to the same id, enabling structural
//! deduplication.
//!
//! Note: this importer only accepts a top-level JSON object, or a top-level JSON
//! array containing objects. Primitive roots are rejected.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

use anybytes::{Bytes, View};
use winnow::stream::Stream;

use crate::attribute::Attribute;
use crate::blob::encodings::utf8string::UTF8String;
use crate::blob::Blob;
use crate::blob::IntoBlob;
use crate::id::{ExclusiveId, Id};
use crate::import::scanner;
use crate::inline::encodings::boolean::Boolean;
use crate::inline::encodings::f64::F64;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding, IntoInline, RawInline};
use crate::macros::entity;
use crate::metadata;
use crate::metadata::{Describe, MetaDescribe};
use crate::repo::BlobStore;
use crate::trible::{
    build_intrinsic_entity, build_namespaced_intrinsic_entity, Fragment, IntrinsicEntityRow,
    TribleSet,
};

/// Error returned by [`JsonObjectImporter`] when importing a JSON document.
#[derive(Debug)]
pub enum JsonImportError {
    /// The document root is a primitive (string, number, bool, null) — only
    /// objects and arrays of objects are accepted.
    PrimitiveRoot,
    /// A string field could not be encoded into the target inline encoding.
    EncodeString {
        /// Name of the JSON field.
        field: String,
        /// Underlying encoding error.
        source: EncodeError,
    },
    /// A number field could not be encoded into the target inline encoding.
    EncodeNumber {
        /// Name of the JSON field.
        field: String,
        /// Underlying encoding error.
        source: EncodeError,
    },
    /// The JSON input is syntactically invalid.
    Syntax(String),
    /// A `\uXXXX` escape names a UTF-16 surrogate that is not half of a
    /// high/low pair. Such a string is valid JSON but has no UTF-8
    /// representation, so the importer refuses the document instead of
    /// substituting U+FFFD or inventing an encoding.
    LoneSurrogate {
        /// The unpaired UTF-16 code unit, `0xD800..=0xDFFF`.
        code_unit: u16,
    },
    /// Arrays and objects nest deeper than the importer's configured limit.
    DepthExceeded {
        /// The limit that was exceeded (the number of enclosing containers
        /// a value may have).
        max_depth: usize,
    },
}

impl fmt::Display for JsonImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimitiveRoot => write!(f, "cannot import JSON primitives as the document root"),
            Self::EncodeString { field, source } => {
                write!(f, "failed to encode string field {field:?}: {source}")
            }
            Self::EncodeNumber { field, source } => {
                write!(f, "failed to encode number field {field:?}: {source}")
            }
            Self::Syntax(msg) => write!(f, "failed to parse JSON: {msg}"),
            Self::LoneSurrogate { code_unit } => write!(
                f,
                "unpaired UTF-16 surrogate \\u{code_unit:04X} has no UTF-8 representation"
            ),
            Self::DepthExceeded { max_depth } => {
                write!(f, "JSON nests deeper than the limit of {max_depth}")
            }
        }
    }
}

impl std::error::Error for JsonImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrimitiveRoot
            | Self::Syntax(_)
            | Self::LoneSurrogate { .. }
            | Self::DepthExceeded { .. } => None,
            Self::EncodeString { source, .. } | Self::EncodeNumber { source, .. } => {
                Some(source.as_error())
            }
        }
    }
}

/// Opaque wrapper around a value-encoding error during JSON import.
#[derive(Debug)]
pub struct EncodeError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl EncodeError {
    /// Creates an encode error from a plain message string.
    pub fn message(message: impl Into<String>) -> Self {
        #[derive(Debug)]
        struct Message(String);

        impl fmt::Display for Message {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::error::Error for Message {}

        Self(Box::new(Message(message.into())))
    }

    fn as_error(&self) -> &(dyn std::error::Error + 'static) {
        self.0.as_ref()
    }

    /// Wraps an existing error as an encode error.
    pub fn from_error(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(err))
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

type ParsedString = View<str>;

/// Default nesting limit of [`JsonObjectImporter`] and
/// [`JsonTreeImporter`](crate::import::json_tree::JsonTreeImporter): a value
/// may sit inside at most this many arrays/objects.
pub const DEFAULT_MAX_DEPTH: usize = 128;

/// Deterministic JSON importer that derives entity ids from canonical fact rows.
///
/// This importer expects either:
/// - a top-level JSON object, or
/// - a top-level array of JSON objects.
///
/// Parsing is iterative, so deeply nested input cannot overflow the call
/// stack; nesting beyond [`with_max_depth`](Self::with_max_depth) (default
/// [`DEFAULT_MAX_DEPTH`]) is refused with [`JsonImportError::DepthExceeded`].
/// A refused document puts nothing into the store and leaves the attribute
/// cache as it was.
///
/// Use [`crate::import::json_tree::JsonTreeImporter`] when you need a lossless
/// representation of arbitrary JSON values (including primitive roots).
pub struct JsonObjectImporter<'a, Store>
where
    Store: BlobStore,
{
    store: &'a mut Store,
    bool_attrs: HashMap<View<str>, Attribute<Boolean>>,
    num_attrs: HashMap<View<str>, Attribute<F64>>,
    str_attrs: HashMap<View<str>, Attribute<Handle<UTF8String>>>,
    genid_attrs: HashMap<View<str>, Attribute<GenId>>,
    id_salt: Option<[u8; 32]>,
    array_fields: HashSet<View<str>>,
    max_depth: usize,
}

/// An attribute-cache insertion made while importing one document, undone
/// if the document is refused.
enum CacheEntry {
    Bool(ParsedString),
    Num(ParsedString),
    Str(ParsedString),
    GenId(ParsedString),
    ArrayField(ParsedString),
}

/// What one [`JsonObjectImporter::import_blob`] call accumulates before the
/// document is accepted.
#[derive(Default)]
struct ObjectImport {
    facts: TribleSet,
    /// Blobs to put once the document is accepted, each with the JSON field
    /// it belongs to (for the error if the put fails).
    blobs: Vec<(Blob<UTF8String>, ParsedString)>,
    staged: HashSet<RawInline>,
    undo: Vec<CacheEntry>,
    /// The first surrogate a complete string left unpaired.
    unpaired: Option<u16>,
}

impl ObjectImport {
    fn stage(
        &mut self,
        blob: Blob<UTF8String>,
        field: &ParsedString,
    ) -> Inline<Handle<UTF8String>> {
        let handle = blob.get_handle();
        if self.staged.insert(handle.raw) {
            self.blobs.push((blob, field.clone()));
        }
        handle
    }
}

/// An object whose closing brace has not been read yet. `field` names the
/// member whose value is being parsed; array elements belong to it too.
struct OpenObject {
    pairs: Vec<(Id, RawInline)>,
    field: ParsedString,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Container {
    Object,
    Array,
}

/// Looks `field` up in `cache`, deriving (and staging the name blob of) its
/// attribute on first use.
fn cached_attr<S: InlineEncoding + MetaDescribe>(
    cache: &mut HashMap<View<str>, Attribute<S>>,
    field: &ParsedString,
    import: &mut ObjectImport,
    entry: fn(ParsedString) -> CacheEntry,
) -> Attribute<S> {
    if let Some(attr) = cache.get(field) {
        return attr.clone();
    }
    let handle = import.stage(field.clone().to_blob(), field);
    let attr = Attribute::<S>::from_fragment_unchecked(entity! {
        metadata::name:         handle,
        metadata::value_encoding: <S as MetaDescribe>::id(),
    });
    cache.insert(field.clone(), attr.clone());
    import.undo.push(entry(field.clone()));
    attr
}

impl<'a, Store> JsonObjectImporter<'a, Store>
where
    Store: BlobStore,
{
    /// Creates a new importer backed by `store`. Pass an optional 32-byte
    /// salt to namespace the deterministic entity ids.
    pub fn new(store: &'a mut Store, id_salt: Option<[u8; 32]>) -> Self {
        Self {
            store,
            bool_attrs: HashMap::new(),
            num_attrs: HashMap::new(),
            str_attrs: HashMap::new(),
            genid_attrs: HashMap::new(),
            id_salt,
            array_fields: HashSet::new(),
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }

    /// Sets how many arrays/objects a value may be nested inside, counting
    /// the root object and a root array. Deeper input is refused with
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
    /// [`Fragment`] with the root entity ids as exports.
    ///
    /// The document's blobs are put into the store only after the whole
    /// document has been accepted, so a refused document leaves the store
    /// untouched. (A store that fails partway through those puts can still
    /// keep the blobs put before the failure; nothing references them.)
    pub fn import_blob(&mut self, blob: Blob<UTF8String>) -> Result<Fragment, JsonImportError> {
        let mut import = ObjectImport::default();
        let result = self
            .parse_document(&blob.bytes, &mut import)
            .and_then(|roots| self.commit(&mut import).map(|()| roots));
        match result {
            Ok(roots) => Ok(Fragment::new(roots, import.facts)),
            Err(err) => {
                self.rollback(import.undo);
                Err(err)
            }
        }
    }

    fn parse_document(
        &mut self,
        bytes: &Bytes,
        import: &mut ObjectImport,
    ) -> Result<Vec<Id>, JsonImportError> {
        let mut bytes = bytes.clone();
        self.skip_ws(&mut bytes);

        let mut roots = Vec::new();
        match bytes.peek_token() {
            Some(b'{') => roots.push(self.parse_object(&mut bytes, 0, import)?),
            Some(b'[') => {
                if self.max_depth == 0 {
                    return Err(JsonImportError::DepthExceeded { max_depth: 0 });
                }
                bytes.pop_front();
                self.skip_ws(&mut bytes);
                if bytes.peek_token() == Some(b']') {
                    bytes.pop_front();
                } else {
                    loop {
                        match bytes.peek_token() {
                            Some(b'{') => roots.push(self.parse_object(&mut bytes, 1, import)?),
                            Some(b']') | None => {
                                return Err(JsonImportError::Syntax("expected a value".into()))
                            }
                            Some(_) => return Err(JsonImportError::PrimitiveRoot),
                        }
                        self.skip_ws(&mut bytes);
                        match bytes.pop_front() {
                            Some(b',') => self.skip_ws(&mut bytes),
                            Some(b']') => break,
                            _ => {
                                return Err(JsonImportError::Syntax(
                                    "expected ',' or ']' in array".into(),
                                ))
                            }
                        }
                    }
                }
            }
            None => return Err(JsonImportError::Syntax("expected a value".into())),
            Some(first) => {
                // Name the primitive root only if it is one: anything else
                // is a syntax error.
                if first == b'"' {
                    // An unpaired surrogate does not make it any less primitive.
                    let _ = scanner::parse_string_checked(&mut bytes).map_err(from_scan)?;
                } else {
                    scanner::skip_value(&mut bytes).map_err(from_scan)?;
                }
                self.skip_ws(&mut bytes);
                if bytes.peek_token().is_some() {
                    return Err(JsonImportError::Syntax("trailing tokens".into()));
                }
                return Err(JsonImportError::PrimitiveRoot);
            }
        }

        self.skip_ws(&mut bytes);
        if bytes.peek_token().is_some() {
            return Err(JsonImportError::Syntax("trailing tokens".into()));
        }
        if let Some(code_unit) = import.unpaired {
            return Err(JsonImportError::LoneSurrogate { code_unit });
        }
        Ok(roots)
    }

    /// Puts the accepted document's blobs into the store.
    fn commit(&mut self, import: &mut ObjectImport) -> Result<(), JsonImportError> {
        for (blob, field) in import.blobs.drain(..) {
            self.store
                .put::<UTF8String, _>(blob)
                .map_err(|err| JsonImportError::EncodeString {
                    field: field.as_ref().to_owned(),
                    source: EncodeError::from_error(err),
                })?;
        }
        Ok(())
    }

    /// Forgets the attributes a refused document added to the cache.
    fn rollback(&mut self, undo: Vec<CacheEntry>) {
        for entry in undo {
            match entry {
                CacheEntry::Bool(field) => {
                    self.bool_attrs.remove(&field);
                }
                CacheEntry::Num(field) => {
                    self.num_attrs.remove(&field);
                }
                CacheEntry::Str(field) => {
                    self.str_attrs.remove(&field);
                }
                CacheEntry::GenId(field) => {
                    self.genid_attrs.remove(&field);
                }
                CacheEntry::ArrayField(field) => {
                    self.array_fields.remove(&field);
                }
            }
        }
    }

    /// Parses one object (the cursor at its `{`) without recursion: open
    /// objects and arrays live on heap stacks, so input depth costs heap,
    /// never call stack. `depth` counts the containers already open around
    /// it, and the limit is checked before each container is entered.
    fn parse_object(
        &mut self,
        bytes: &mut Bytes,
        depth: usize,
        import: &mut ObjectImport,
    ) -> Result<Id, JsonImportError> {
        let mut objects: Vec<OpenObject> = Vec::new();
        let mut open: Vec<Container> = Vec::new();
        loop {
            // Parse the value at the cursor. A scalar is added to the
            // innermost object at once; a non-empty container is pushed and
            // its first value is parsed on the next iteration.
            let mut finished = match bytes.peek_token() {
                Some(bracket @ (b'{' | b'[')) => {
                    if depth + open.len() >= self.max_depth {
                        return Err(JsonImportError::DepthExceeded {
                            max_depth: self.max_depth,
                        });
                    }
                    bytes.pop_front();
                    self.skip_ws(bytes);
                    if bracket == b'{' {
                        if bytes.peek_token() == Some(b'}') {
                            bytes.pop_front();
                            Some(self.finish_object(Vec::new(), import))
                        } else {
                            let field = self.parse_member_name(bytes, import)?;
                            objects.push(OpenObject {
                                pairs: Vec::new(),
                                field,
                            });
                            open.push(Container::Object);
                            continue;
                        }
                    } else {
                        let field = &objects.last().expect("arrays sit in objects").field;
                        if self.array_fields.insert(field.clone()) {
                            import.undo.push(CacheEntry::ArrayField(field.clone()));
                        }
                        if bytes.peek_token() == Some(b']') {
                            bytes.pop_front();
                            None
                        } else {
                            open.push(Container::Array);
                            continue;
                        }
                    }
                }
                _ => {
                    let object = objects.last_mut().expect("scalars sit in objects");
                    self.parse_scalar(bytes, object, import)?;
                    None
                }
            };

            // Hand a finished object to its parent and close every container
            // that ends right after the value.
            loop {
                if let Some(child) = finished.take() {
                    let Some(parent) = objects.last_mut() else {
                        return Ok(child);
                    };
                    let attr = cached_attr(
                        &mut self.genid_attrs,
                        &parent.field,
                        import,
                        CacheEntry::GenId,
                    );
                    parent
                        .pairs
                        .push((attr.id(), GenId::inline_from(&child).raw));
                }
                let container = *open.last().expect("the root object is still open");
                self.skip_ws(bytes);
                match (container, bytes.pop_front()) {
                    (Container::Array, Some(b',')) => {
                        self.skip_ws(bytes);
                        break;
                    }
                    (Container::Object, Some(b',')) => {
                        self.skip_ws(bytes);
                        let field = self.parse_member_name(bytes, import)?;
                        objects.last_mut().expect("open object").field = field;
                        break;
                    }
                    (Container::Array, Some(b']')) => {
                        open.pop();
                    }
                    (Container::Object, Some(b'}')) => {
                        open.pop();
                        let object = objects.pop().expect("open object");
                        finished = Some(self.finish_object(object.pairs, import));
                    }
                    _ => return Err(JsonImportError::Syntax("unexpected token".into())),
                }
            }
        }
    }

    /// Parses `"name"`, the `:` and surrounding whitespace.
    fn parse_member_name(
        &mut self,
        bytes: &mut Bytes,
        import: &mut ObjectImport,
    ) -> Result<ParsedString, JsonImportError> {
        let field = parse_json_string(bytes, &mut import.unpaired)?;
        self.skip_ws(bytes);
        self.consume_byte(bytes, b':')?;
        self.skip_ws(bytes);
        Ok(field)
    }

    fn finish_object(&self, pairs: Vec<(Id, RawInline)>, import: &mut ObjectImport) -> Id {
        let rows = pairs
            .into_iter()
            .map(|(attribute, value)| IntrinsicEntityRow::new(attribute, value))
            .collect();
        let (entity, entity_facts) = match self.id_salt.as_ref() {
            Some(namespace) => build_namespaced_intrinsic_entity(rows, namespace),
            None => build_intrinsic_entity(rows),
        };
        import.facts += entity_facts;
        entity
    }

    /// Parses one scalar value of `object`'s current field.
    fn parse_scalar(
        &mut self,
        bytes: &mut Bytes,
        object: &mut OpenObject,
        import: &mut ObjectImport,
    ) -> Result<(), JsonImportError> {
        let field = &object.field;
        match bytes.peek_token() {
            Some(b'n') => self.consume_literal(bytes, b"null"),
            Some(b't' | b'f') => {
                let value = bytes.peek_token() == Some(b't');
                self.consume_literal(bytes, if value { b"true" } else { b"false" })?;
                let attr = cached_attr(&mut self.bool_attrs, field, import, CacheEntry::Bool);
                object.pairs.push((attr.id(), attr.inline_from(value).raw));
                Ok(())
            }
            Some(b'"') => {
                let text = parse_json_string(bytes, &mut import.unpaired)?;
                let attr = cached_attr(&mut self.str_attrs, field, import, CacheEntry::Str);
                let handle = import.stage(text.to_blob(), field);
                object.pairs.push((attr.id(), handle.raw));
                Ok(())
            }
            _ => {
                let num = parse_number_common(bytes)?;
                let num_str = num
                    .view::<str>()
                    .map_err(|_| JsonImportError::Syntax("invalid number".into()))?;
                let number: f64 = f64::from_str(num_str.as_ref()).map_err(|err| {
                    JsonImportError::EncodeNumber {
                        field: field.as_ref().to_owned(),
                        source: EncodeError::from_error(err),
                    }
                })?;
                if !number.is_finite() {
                    return Err(JsonImportError::EncodeNumber {
                        field: field.as_ref().to_owned(),
                        source: EncodeError::message("non-finite number"),
                    });
                }
                let attr = cached_attr(&mut self.num_attrs, field, import, CacheEntry::Num);
                let encoded: Inline<F64> = number.to_inline();
                object.pairs.push((attr.id(), encoded.raw));
                Ok(())
            }
        }
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

    /// Returns a [`Fragment`] describing every attribute and schema
    /// encountered so far, suitable for committing alongside the data.
    pub fn metadata(&mut self) -> Fragment {
        let mut meta = Fragment::default();
        meta += <Boolean as MetaDescribe>::describe();
        meta += <F64 as MetaDescribe>::describe();
        meta += <GenId as MetaDescribe>::describe();
        meta += <Handle<UTF8String> as MetaDescribe>::describe();
        for (key, attr) in self.bool_attrs.iter() {
            meta += attr.describe();
            if self.array_fields.contains(key) {
                let attr_id = attr.id();
                let entity = ExclusiveId::force_ref(&attr_id);
                meta += entity! { &entity @ metadata::tag: metadata::KIND_MULTI };
            }
        }
        for (key, attr) in self.num_attrs.iter() {
            meta += attr.describe();
            if self.array_fields.contains(key) {
                let attr_id = attr.id();
                let entity = ExclusiveId::force_ref(&attr_id);
                meta += entity! { &entity @ metadata::tag: metadata::KIND_MULTI };
            }
        }
        for (key, attr) in self.str_attrs.iter() {
            meta += attr.describe();
            if self.array_fields.contains(key) {
                let attr_id = attr.id();
                let entity = ExclusiveId::force_ref(&attr_id);
                meta += entity! { &entity @ metadata::tag: metadata::KIND_MULTI };
            }
        }
        for (key, attr) in self.genid_attrs.iter() {
            meta += attr.describe();
            if self.array_fields.contains(key) {
                let attr_id = attr.id();
                let entity = ExclusiveId::force_ref(&attr_id);
                meta += entity! { &entity @ metadata::tag: metadata::KIND_MULTI };
            }
        }
        meta
    }

    /// Resets the cached attribute mappings. Call between unrelated import
    /// batches if you want field names to be re-derived.
    pub fn clear(&mut self) {
        self.bool_attrs.clear();
        self.num_attrs.clear();
        self.str_attrs.clear();
        self.genid_attrs.clear();
        self.array_fields.clear();
    }
}

fn from_scan(err: scanner::ScanError) -> JsonImportError {
    match err {
        scanner::ScanError::Syntax(msg) => JsonImportError::Syntax(msg),
    }
}

/// Parses one JSON string at the cursor.
///
/// A string that is syntactically complete but whose escapes leave a UTF-16
/// surrogate unpaired is not refused here: the first such code unit is
/// recorded in `unpaired`, an empty placeholder is returned, and the caller
/// keeps parsing, so that a syntax error anywhere in the document is still
/// reported as [`JsonImportError::Syntax`]. The caller refuses the document
/// with [`JsonImportError::LoneSurrogate`] once its syntax is complete.
pub(crate) fn parse_json_string(
    bytes: &mut Bytes,
    unpaired: &mut Option<u16>,
) -> Result<ParsedString, JsonImportError> {
    let raw = match scanner::parse_string_checked(bytes).map_err(from_scan)? {
        Ok(raw) => raw,
        Err(code_unit) => {
            unpaired.get_or_insert(code_unit);
            Bytes::empty()
        }
    };
    raw.view::<str>()
        .map_err(|_| JsonImportError::Syntax("invalid utf-8".into()))
}

/// Parses one RFC 8259 number and returns its raw token unchanged:
/// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`, followed by
/// whitespace, `,`, `]`, `}` or the end of input.
pub(crate) fn parse_number_common(bytes: &mut Bytes) -> Result<Bytes, JsonImportError> {
    scanner::parse_number(bytes).map_err(from_scan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::IntoBlob;
    use crate::blob::MemoryBlobStore;
    use crate::prelude::Attribute;
    use crate::repo::SnapshotSource;

    use anybytes::View;

    #[test]
    fn deterministic_imports_simple_object() {
        let input = r#"{ "title": "Dune", "pages": 412 }"#;
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        let fragment = importer.import_blob(input.to_blob()).unwrap();
        let roots = fragment.exports().collect::<Vec<_>>();
        assert_eq!(roots.len(), 1);
        assert_eq!(fragment.facts().len(), 2);
        assert!(!importer.metadata().facts().is_empty());
    }

    #[test]
    fn unsalted_json_root_matches_equivalent_entity_macro() {
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        let imported = importer
            .import_str(r#"{"title":"Dune","pages":412}"#)
            .unwrap();

        let title = importer
            .str_attrs
            .iter()
            .find(|(name, _)| name.as_ref() == "title")
            .map(|(_, attribute)| attribute.clone())
            .expect("title attribute was derived");
        let pages = importer
            .num_attrs
            .iter()
            .find(|(name, _)| name.as_ref() == "pages")
            .map(|(_, attribute)| attribute.clone())
            .expect("pages attribute was derived");
        let title_value: Inline<Handle<UTF8String>> = "Dune".to_blob().get_handle();
        let expected = entity! {
            title: title_value,
            pages: 412.0f64,
        };

        assert_eq!(imported.root(), expected.root());
        assert_eq!(imported.facts(), expected.facts());
    }

    #[test]
    fn duplicate_json_members_have_the_same_set_identity() {
        let mut single_blobs = MemoryBlobStore::new();
        let single = JsonObjectImporter::<_>::new(&mut single_blobs, None)
            .import_str(r#"{"tag":["x"]}"#)
            .unwrap();

        let mut duplicate_blobs = MemoryBlobStore::new();
        let duplicate = JsonObjectImporter::<_>::new(&mut duplicate_blobs, None)
            .import_str(r#"{"tag":["x","x"]}"#)
            .unwrap();

        assert_eq!(single.root(), duplicate.root());
        assert_eq!(single.facts(), duplicate.facts());
    }

    #[test]
    fn namespaced_json_identity_is_order_and_duplicate_invariant() {
        let namespace = [0x5au8; 32];
        let mut first_blobs = MemoryBlobStore::new();
        let first = JsonObjectImporter::<_>::new(&mut first_blobs, Some(namespace))
            .import_str(r#"{"tag":["x","x"],"active":true}"#)
            .unwrap();

        let mut second_blobs = MemoryBlobStore::new();
        let second = JsonObjectImporter::<_>::new(&mut second_blobs, Some(namespace))
            .import_str(r#"{"active":true,"tag":["x"]}"#)
            .unwrap();

        assert_eq!(first.root(), second.root());
        assert_eq!(first.facts(), second.facts());
    }

    fn extract_handle_raw(facts: &TribleSet, expected_attr: &str) -> RawInline {
        use crate::blob::IntoBlob;
        use crate::metadata::MetaDescribe;
        let h: Inline<Handle<UTF8String>> = String::from(expected_attr).to_blob().get_handle();
        let attr =
            Attribute::<Handle<UTF8String>>::from_fragment_unchecked(crate::macros::entity! {
                metadata::name:         h,
                metadata::value_encoding: <Handle<UTF8String> as MetaDescribe>::id(),
            })
            .id();
        let trible = facts
            .iter()
            .find(|t| *t.a() == attr)
            .expect("missing string trible");
        trible.v::<Handle<UTF8String>>().raw
    }

    fn read_text(blobs: &mut MemoryBlobStore, handle_raw: RawInline) -> String {
        let entries: Vec<_> = blobs.snapshot().unwrap().into_iter().collect();
        let (_, blob) = entries
            .iter()
            .find(|(h, _)| {
                let h: Inline<Handle<UTF8String>> = (*h).transmute();
                h.raw == handle_raw
            })
            .expect("handle not found in blob store");

        let text: View<str> = blob
            .clone()
            .transmute::<UTF8String>()
            .try_from_blob()
            .expect("blob should decode as string");
        text.as_ref().to_owned()
    }

    #[test]
    fn parses_escaped_string() {
        let input = r#"{ "text": "hello\nworld" }"#;
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        let fragment = importer.import_blob(input.to_blob()).unwrap();
        let handle = extract_handle_raw(fragment.facts(), "text");
        drop(importer);
        let text = read_text(&mut blobs, handle);
        assert_eq!(text, "hello\nworld");
    }

    #[test]
    fn parses_unicode_escape() {
        let input = r#"{ "text": "smile: \u263A" }"#;
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        let fragment = importer.import_blob(input.to_blob()).unwrap();
        let handle = extract_handle_raw(fragment.facts(), "text");
        drop(importer);
        let text = read_text(&mut blobs, handle);
        assert_eq!(text, "smile: \u{263A}");
    }

    #[test]
    fn object_importer_shares_the_strict_string_and_number_rules() {
        let input = r#"{ "text": "\ud83d\ude00" }"#;
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        let fragment = importer.import_blob(input.to_blob()).unwrap();
        let handle = extract_handle_raw(fragment.facts(), "text");
        drop(importer);
        assert_eq!(read_text(&mut blobs, handle), "\u{1F600}");

        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        assert!(matches!(
            importer.import_str(r#"{ "text": "\ude00" }"#),
            Err(JsonImportError::LoneSurrogate { code_unit: 0xDE00 })
        ));
        assert!(matches!(
            importer.import_str(r#"{ "n": 1-2 }"#),
            Err(JsonImportError::Syntax(_))
        ));
    }

    fn nested_objects(depth: usize) -> String {
        format!("{}1{}", r#"{"a":"#.repeat(depth), "}".repeat(depth))
    }

    /// `{"a": [[...1...]]}` with `depth` arrays inside the root object.
    fn arrays_in_object(depth: usize) -> String {
        format!(r#"{{"a":{}1{}}}"#, "[".repeat(depth), "]".repeat(depth))
    }

    /// Decoded text of every blob in the store, sorted.
    fn stored_texts(blobs: &mut MemoryBlobStore) -> Vec<String> {
        let mut out: Vec<String> = blobs
            .snapshot()
            .unwrap()
            .into_iter()
            .map(|(_, blob)| {
                let text: View<str> = blob
                    .clone()
                    .transmute::<UTF8String>()
                    .try_from_blob()
                    .expect("utf-8 blob");
                text.as_ref().to_owned()
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn object_importer_refuses_nesting_past_128() {
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        importer
            .import_str(&nested_objects(128))
            .expect("128 nested objects are accepted");
        // Arrays are containers too; the root object is the first one.
        importer
            .import_str(&arrays_in_object(127))
            .expect("an object holding 127 nested arrays is accepted");
        for doc in [
            nested_objects(129),
            arrays_in_object(128),
            // A root array counts as the first container.
            format!("[{}]", nested_objects(128)),
        ] {
            match importer.import_str(&doc) {
                Err(JsonImportError::DepthExceeded { max_depth: 128 }) => {}
                other => panic!("expected DepthExceeded, got {other:?}"),
            }
        }
    }

    #[test]
    fn object_importer_hundred_thousand_deep_does_not_overflow_the_stack() {
        let depth = 100_000;
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        for doc in [nested_objects(depth), arrays_in_object(depth)] {
            assert!(matches!(
                importer.import_str(&doc),
                Err(JsonImportError::DepthExceeded { max_depth: 128 })
            ));
        }
        // ... and imported without recursion when the limit allows it.
        let mut importer =
            JsonObjectImporter::<_>::new(&mut blobs, None).with_max_depth(usize::MAX);
        let objects = importer
            .import_str(&nested_objects(depth))
            .expect("deep objects import");
        assert_eq!(objects.facts().len(), depth, "one field per object");
        let arrays = importer
            .import_str(&arrays_in_object(depth))
            .expect("deep arrays import");
        assert_eq!(arrays.facts().len(), 1, "arrays flatten into one field");
    }

    #[test]
    fn object_importer_depth_limit_is_configurable() {
        assert_eq!(DEFAULT_MAX_DEPTH, 128);
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None).with_max_depth(2);
        importer
            .import_str(r#"{"a": {"b": 1}}"#)
            .expect("depth 2 accepted");
        importer
            .import_str(r#"[{"a": 1}]"#)
            .expect("a root array is one of the two containers");
        for doc in [r#"{"a": {"b": {}}}"#, r#"{"a": [[1]]}"#, r#"[{"a": {}}]"#] {
            match importer.import_str(doc) {
                Err(JsonImportError::DepthExceeded { max_depth: 2 }) => {}
                other => panic!("{doc}: expected DepthExceeded, got {other:?}"),
            }
        }
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None).with_max_depth(0);
        for doc in ["{}", "[]"] {
            match importer.import_str(doc) {
                Err(JsonImportError::DepthExceeded { max_depth: 0 }) => {}
                other => panic!("{doc}: expected DepthExceeded, got {other:?}"),
            }
        }
    }

    /// A refused document must leave the caller's store and the importer's
    /// attribute cache as they were: nothing of its parsed prefix survives.
    #[test]
    fn object_importer_refused_document_puts_and_caches_nothing() {
        let fresh = JsonObjectImporter::<_>::new(&mut MemoryBlobStore::new(), None).metadata();
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        let bad = [
            r#"{"f": "v", "n": 01}"#.to_owned(),
            r#"{"f": "v", "s": "\ud800"}"#.to_owned(),
            r#"{"f": "v", "g": {"h": [true, "w", 1e999]}}"#.to_owned(),
            r#"{"f": "v", "t": ["w"]"#.to_owned(),
            format!(r#"{{"f": "v", "d": {}}}"#, arrays_in_object(200)),
        ];
        for doc in &bad {
            assert!(importer.import_str(doc).is_err(), "{doc} must be refused");
            let meta = importer.metadata();
            assert_eq!(meta.facts(), fresh.facts(), "{doc} left attributes cached");
            assert_eq!(
                meta.metafacts(),
                fresh.metafacts(),
                "{doc} left attributes cached"
            );
        }
        // The field name refused above must still be stored when a later
        // document uses it.
        importer.import_str(r#"{"f": "w"}"#).unwrap();
        drop(importer);
        assert_eq!(stored_texts(&mut blobs), vec!["f", "w"]);
    }

    /// A string that is not syntactically complete is a syntax error, even
    /// when it begins with a high surrogate; `LoneSurrogate` is only for a
    /// well-formed document whose escapes leave a surrogate unpaired.
    #[test]
    fn object_importer_malformed_escape_after_high_surrogate_is_syntax() {
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        for doc in [
            r#"{"a": "\ud800\x"}"#,
            r#"{"a": "\ud800\"#,
            r#"{"a": "\ud800"#,
            r#"{"a": "\ud800\u0041"#,
            r#"{"a": "\ud800\u12"}"#,
            r#"{"\ud800": 1"#,
            r#"{"a": "\ud800" "b": 1}"#,
            r#"{"a": "\ud800"} x"#,
        ] {
            match importer.import_str(doc) {
                Err(JsonImportError::Syntax(_)) => {}
                other => panic!("{doc}: expected a syntax error, got {other:?}"),
            }
        }
        for (doc, unit) in [
            (r#"{"a": "\ud800\u0041"}"#, 0xD800),
            (r#"{"a": "\ud800\n"}"#, 0xD800),
            (r#"{"a": ["x", "\udc00"]}"#, 0xDC00),
        ] {
            match importer.import_str(doc) {
                Err(JsonImportError::LoneSurrogate { code_unit }) => assert_eq!(code_unit, unit),
                other => panic!("{doc}: expected LoneSurrogate, got {other:?}"),
            }
        }
    }

    /// Malformed input is a syntax error, not a primitive root.
    #[test]
    fn object_importer_names_syntax_errors_as_syntax() {
        let mut blobs = MemoryBlobStore::new();
        let mut importer = JsonObjectImporter::<_>::new(&mut blobs, None);
        for doc in [
            "",
            "x",
            "tru",
            r#"[{"a": 1} {"b": 2}]"#,
            r#"[{"a": 1},]"#,
            r#"[{"a": 1}"#,
            r#"{"a": 1} x"#,
            r#"{"a": 1}{"b": 2}"#,
            r#"[] []"#,
        ] {
            match importer.import_str(doc) {
                Err(JsonImportError::Syntax(_)) => {}
                other => panic!("{doc:?}: expected a syntax error, got {other:?}"),
            }
        }
        for doc in [
            "1",
            r#""s""#,
            "null",
            r#"[{"a": 1}, 2]"#,
            r#"[{"a": 1}, [{}]]"#,
        ] {
            match importer.import_str(doc) {
                Err(JsonImportError::PrimitiveRoot) => {}
                other => panic!("{doc:?}: expected PrimitiveRoot, got {other:?}"),
            }
        }
    }
}
