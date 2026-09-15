//! This is a collection of Rust types that can be (de)serialized as [crate::prelude::Blob]s.

/// Flat typed array blob encoding.
pub mod array;
/// Canonical grow-only sets of opaque entity IDs.
pub mod entity_id_set;
/// Opaque raw bytes blob encoding (positive choice, distinct from UnknownBlob).
pub mod rawbytes;
/// Canonical trible sequence blob encoding.
pub mod simplearchive;
/// Succinct (Ring-based) compressed trible archive blob encoding.
pub mod succinctarchive;
pub mod tensor;
/// Arbitrary-length UTF-8 text blob encoding.
pub mod utf8string;
/// WebAssembly bytecode blob encoding.
pub mod wasmcode;

use crate::inline::Encodes;
use anybytes::Bytes;

use crate::blob::BlobEncoding;
use crate::id_hex;
use crate::macros::entity;
use crate::metadata::{self, MetaDescribe};

use super::Blob;
use super::TryFromBlob;

/// A blob encoding for an unknown blob.
/// This blob encoding is used as a fallback when the blob encoding is not known.
/// It is not recommended to use this blob encoding in practice.
/// Instead, use a specific blob encoding.
///
/// Any bit pattern can be a valid blob of this schema.
pub struct UnknownBlob;
impl BlobEncoding for UnknownBlob {}

impl MetaDescribe for UnknownBlob {
    fn describe() -> crate::trible::Fragment {
        // Fixed-id fallback schema. Even though it's discouraged in
        // practice, the metadata should still self-describe so a
        // consumer encountering this id can recognise it.
        let id = id_hex!("EAB14005141181B0C10C4B5DD7985F8D");
        entity! { crate::id::ExclusiveId::force_ref(&id) @
            metadata::name:        "UnknownBlob",
            metadata::description: "Fallback blob encoding for byte payloads with no known type. Discouraged in practice — use a specific blob encoding (e.g. `UTF8String`, `Array<T>`, `SimpleArchive`) instead.",
            metadata::tag:         metadata::KIND_BLOB_ENCODING,
        }
    }
}

impl TryFromBlob<UnknownBlob> for Bytes {
    type Error = std::convert::Infallible;

    fn try_from_blob(blob: Blob<UnknownBlob>) -> Result<Self, Self::Error> {
        Ok(blob.bytes)
    }
}

impl Encodes<Bytes> for UnknownBlob
where
    crate::inline::encodings::hash::Handle<UnknownBlob>: crate::inline::InlineEncoding,
{
    type Output = Blob<UnknownBlob>;
    fn encode(source: Bytes) -> Blob<UnknownBlob> {
        Blob::new(source)
    }
}
