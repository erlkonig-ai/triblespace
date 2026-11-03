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

/// Deterministic JSON importer that derives entity ids from canonical fact rows.
///
/// This importer expects either:
/// - a top-level JSON object, or
/// - a top-level array of JSON objects.
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
}

impl<'a, Store> JsonObjectImporter<'a, Store>
where
    Store: BlobStore,
{
    fn attr_from_field<S: InlineEncoding + MetaDescribe>(
        &mut self,
        field: &ParsedString,
    ) -> Result<Attribute<S>, JsonImportError> {
        let handle =
            self.store
                .put(field.clone())
                .map_err(|err| JsonImportError::EncodeString {
                    field: field.as_ref().to_owned(),
                    source: EncodeError::from_error(err),
                })?;
        Ok(Attribute::<S>::from_fragment_unchecked(entity! {
            metadata::name:         handle,
            metadata::value_encoding: <S as MetaDescribe>::id(),
        }))
    }

    fn bool_attr(&mut self, field: &ParsedString) -> Result<Attribute<Boolean>, JsonImportError> {
        let key = field.clone();
        if let Some(attr) = self.bool_attrs.get(&key) {
            return Ok(attr.clone());
        }
        let attr = self.attr_from_field::<Boolean>(field)?;
        self.bool_attrs.insert(key, attr.clone());
        Ok(attr)
    }

    fn num_attr(&mut self, field: &ParsedString) -> Result<Attribute<F64>, JsonImportError> {
        let key = field.clone();
        if let Some(attr) = self.num_attrs.get(&key) {
            return Ok(attr.clone());
        }
        let attr = self.attr_from_field::<F64>(field)?;
        self.num_attrs.insert(key, attr.clone());
        Ok(attr)
    }

    fn str_attr(
        &mut self,
        field: &ParsedString,
    ) -> Result<Attribute<Handle<UTF8String>>, JsonImportError> {
        let key = field.clone();
        if let Some(attr) = self.str_attrs.get(&key) {
            return Ok(attr.clone());
        }
        let attr = self.attr_from_field::<Handle<UTF8String>>(field)?;
        self.str_attrs.insert(key, attr.clone());
        Ok(attr)
    }

    fn genid_attr(&mut self, field: &ParsedString) -> Result<Attribute<GenId>, JsonImportError> {
        let key = field.clone();
        if let Some(attr) = self.genid_attrs.get(&key) {
            return Ok(attr.clone());
        }
        let attr = self.attr_from_field::<GenId>(field)?;
        self.genid_attrs.insert(key, attr.clone());
        Ok(attr)
    }

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
        }
    }

    /// Imports a JSON string. Convenience wrapper around [`import_blob`](Self::import_blob).
    pub fn import_str(&mut self, input: &str) -> Result<Fragment, JsonImportError> {
        self.import_blob(input.to_owned().to_blob())
    }

    /// Imports a JSON document from a [`UTF8String`] blob, returning a
    /// [`Fragment`] with the root entity ids as exports.
    pub fn import_blob(&mut self, blob: Blob<UTF8String>) -> Result<Fragment, JsonImportError> {
        let mut bytes = blob.bytes.clone();
        self.skip_ws(&mut bytes);

        let mut roots = Vec::new();
        let mut staged = TribleSet::new();
        match bytes.peek_token() {
            Some(b'{') => {
                let (root, obj_staged) = self.parse_object(&mut bytes)?;
                staged += obj_staged;
                roots.push(root);
            }
            Some(b'[') => {
                self.consume_byte(&mut bytes, b'[')?;
                self.skip_ws(&mut bytes);
                if bytes.peek_token() == Some(b']') {
                    self.consume_byte(&mut bytes, b']')?;
                } else {
                    loop {
                        self.skip_ws(&mut bytes);
                        if bytes.peek_token() != Some(b'{') {
                            return Err(JsonImportError::PrimitiveRoot);
                        }
                        let (root, obj_staged) = self.parse_object(&mut bytes)?;
                        staged += obj_staged;
                        roots.push(root);
                        self.skip_ws(&mut bytes);
                        match bytes.peek_token() {
                            Some(b',') => {
                                self.consume_byte(&mut bytes, b',')?;
                                continue;
                            }
                            Some(b']') => {
                                self.consume_byte(&mut bytes, b']')?;
                                break;
                            }
                            _ => return Err(JsonImportError::PrimitiveRoot),
                        }
                    }
                }
            }
            _ => return Err(JsonImportError::PrimitiveRoot),
        }

        self.skip_ws(&mut bytes);
        Ok(Fragment::new(roots, staged))
    }

    fn parse_object(&mut self, bytes: &mut Bytes) -> Result<(Id, TribleSet), JsonImportError> {
        self.consume_byte(bytes, b'{')?;
        self.skip_ws(bytes);
        let mut pairs: Vec<(Id, RawInline)> = Vec::new();
        let mut staged = TribleSet::new();

        if bytes.peek_token() == Some(b'}') {
            self.consume_byte(bytes, b'}')?;
        } else {
            loop {
                let field = self.parse_string(bytes)?;
                self.skip_ws(bytes);
                self.consume_byte(bytes, b':')?;
                self.skip_ws(bytes);
                self.parse_value(bytes, &field, &mut pairs, &mut staged)?;
                self.skip_ws(bytes);
                match bytes.peek_token() {
                    Some(b',') => {
                        self.consume_byte(bytes, b',')?;
                        self.skip_ws(bytes);
                    }
                    Some(b'}') => {
                        self.consume_byte(bytes, b'}')?;
                        break;
                    }
                    _ => return Err(JsonImportError::Syntax("unexpected token".into())),
                }
            }
        }

        let rows = pairs
            .into_iter()
            .map(|(attribute, value)| IntrinsicEntityRow::new(attribute, value))
            .collect();
        let (entity, entity_facts) = match self.id_salt.as_ref() {
            Some(namespace) => build_namespaced_intrinsic_entity(rows, namespace),
            None => build_intrinsic_entity(rows),
        };
        staged += entity_facts;

        Ok((entity, staged))
    }

    fn parse_array(
        &mut self,
        bytes: &mut Bytes,
        field: &ParsedString,
        pairs: &mut Vec<(Id, RawInline)>,
        staged: &mut TribleSet,
    ) -> Result<(), JsonImportError> {
        self.consume_byte(bytes, b'[')?;
        self.array_fields.insert(field.clone());
        self.skip_ws(bytes);
        if bytes.peek_token() == Some(b']') {
            self.consume_byte(bytes, b']')?;
            return Ok(());
        }

        loop {
            self.parse_value(bytes, field, pairs, staged)?;
            self.skip_ws(bytes);
            match bytes.peek_token() {
                Some(b',') => {
                    self.consume_byte(bytes, b',')?;
                    self.skip_ws(bytes);
                }
                Some(b']') => {
                    self.consume_byte(bytes, b']')?;
                    break;
                }
                _ => return Err(JsonImportError::Syntax("unexpected token".into())),
            }
        }
        Ok(())
    }

    fn parse_value(
        &mut self,
        bytes: &mut Bytes,
        field: &ParsedString,
        pairs: &mut Vec<(Id, RawInline)>,
        staged: &mut TribleSet,
    ) -> Result<(), JsonImportError> {
        match bytes.peek_token() {
            Some(b'n') => {
                self.consume_literal(bytes, b"null")?;
                Ok(())
            }
            Some(b't') => {
                self.consume_literal(bytes, b"true")?;
                let attr = self.bool_attr(field)?;
                pairs.push((attr.id(), attr.inline_from(true).raw));
                Ok(())
            }
            Some(b'f') => {
                self.consume_literal(bytes, b"false")?;
                let attr = self.bool_attr(field)?;
                pairs.push((attr.id(), attr.inline_from(false).raw));
                Ok(())
            }
            Some(b'"') => {
                let text = self.parse_string(bytes)?;
                let field_name = field.as_ref().to_owned();
                let attr = self.str_attr(field)?;
                let handle: Inline<Handle<UTF8String>> =
                    self.store
                        .put(text)
                        .map_err(|err| JsonImportError::EncodeString {
                            field: field_name,
                            source: EncodeError::from_error(err),
                        })?;
                pairs.push((attr.id(), handle.raw));
                Ok(())
            }
            Some(b'{') => {
                let (child, child_staged) = self.parse_object(bytes)?;
                *staged += child_staged;
                let attr = self.genid_attr(field)?;
                let value = GenId::inline_from(&child);
                pairs.push((attr.id(), value.raw));
                Ok(())
            }
            Some(b'[') => self.parse_array(bytes, field, pairs, staged),
            _ => {
                let num = self.parse_number(bytes)?;
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
                let attr = self.num_attr(field)?;
                let encoded: Inline<F64> = number.to_inline();
                pairs.push((attr.id(), encoded.raw));
                Ok(())
            }
        }
    }

    fn skip_ws(&self, bytes: &mut Bytes) {
        while matches!(bytes.peek_token(), Some(b) if b.is_ascii_whitespace()) {
            bytes.pop_front();
        }
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

/// Decodes a JSON `\uXXXX` escape (cursor just after the `u`) into UTF-8.
///
/// A high surrogate consumes the `\uXXXX` low surrogate that must follow it,
/// and the pair decodes to one scalar value. A surrogate that is not half of
/// such a pair is valid JSON but has no UTF-8 form, so it is refused with
/// [`JsonImportError::LoneSurrogate`] rather than replaced.
pub(crate) fn parse_unicode_escape(bytes: &mut Bytes) -> Result<Vec<u8>, JsonImportError> {
    let first = scanner::parse_utf16_code_unit(bytes).map_err(from_scan)?;
    let scalar = match first {
        0xD800..=0xDBFF => {
            let mut ahead = bytes.clone();
            if ahead.pop_front() != Some(b'\\') || ahead.pop_front() != Some(b'u') {
                return Err(JsonImportError::LoneSurrogate { code_unit: first });
            }
            let low = scanner::parse_utf16_code_unit(&mut ahead).map_err(from_scan)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(JsonImportError::LoneSurrogate { code_unit: first });
            }
            *bytes = ahead;
            0x1_0000 + (((first as u32) - 0xD800) << 10) + ((low as u32) - 0xDC00)
        }
        0xDC00..=0xDFFF => return Err(JsonImportError::LoneSurrogate { code_unit: first }),
        unit => unit as u32,
    };
    let ch = char::from_u32(scalar).expect("a non-surrogate code point below 0x110000");
    let mut buf = [0u8; 4];
    Ok(ch.encode_utf8(&mut buf).as_bytes().to_vec())
}

pub(crate) fn parse_string_common(
    bytes: &mut Bytes,
    unicode_escape: &mut impl FnMut(&mut Bytes) -> Result<Vec<u8>, JsonImportError>,
) -> Result<Bytes, JsonImportError> {
    let consume_byte = |bytes: &mut Bytes, expected: u8| -> Result<(), JsonImportError> {
        match bytes.pop_front() {
            Some(b) if b == expected => Ok(()),
            _ => Err(JsonImportError::Syntax("unexpected token".into())),
        }
    };

    consume_byte(bytes, b'"')?;
    {
        use winnow::error::InputError;
        use winnow::token::take_while;
        use winnow::Parser;

        let mut tentative = bytes.clone();
        let mut segment = take_while::<_, _, InputError<Bytes>>(0.., |b: u8| {
            b != b'"' && b != b'\\' && b != b'\n' && b != b'\r'
        });

        if let Ok(prefix) = segment.parse_next(&mut tentative) {
            if tentative.peek_token() == Some(b'"') {
                tentative.pop_front();
                *bytes = tentative;
                return Ok(prefix);
            }
        }
    }

    let mut out = Vec::new();
    loop {
        use winnow::error::InputError;
        use winnow::token::take_while;
        use winnow::Parser;

        let mut segment = take_while::<_, _, InputError<Bytes>>(0.., |b: u8| {
            b != b'\\' && b != b'"' && b != b'\n' && b != b'\r'
        });
        let chunk = segment
            .parse_next(bytes)
            .map_err(|_| JsonImportError::Syntax("unterminated string".into()))?;
        out.extend_from_slice(chunk.as_ref());

        match bytes.peek_token() {
            Some(b'"') => {
                bytes.pop_front();
                return Ok(Bytes::from(out));
            }
            Some(b'\\') => {
                bytes.pop_front();
                let esc = bytes
                    .pop_front()
                    .ok_or_else(|| JsonImportError::Syntax("unterminated escape".into()))?;
                match esc {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => out.extend_from_slice(&unicode_escape(bytes)?),
                    _ => return Err(JsonImportError::Syntax("invalid escape sequence".into())),
                }
            }
            Some(b'\n') | Some(b'\r') | None => {
                return Err(JsonImportError::Syntax("unterminated string".into()))
            }
            _ => unreachable!("peek_token only yields bytes"),
        }
    }
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
}
