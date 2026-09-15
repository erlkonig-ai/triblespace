//! Inline and blob encodings minted for triblespace-search.
//!
//! - [`F32LE`] (inline encoding): packs an f32 into a 32-byte
//!   triblespace value, used by score-as-bound-variable
//!   constraints.
//! - [`Embedding`] (blob encoding): an arbitrary-length `[f32]`
//!   (little-endian) stored as a blob. HNSW indexes no longer
//!   inline vectors — they store `Handle<Embedding>` instead,
//!   so embeddings are content-addressed and dedupe across
//!   indexes.
//!
//! Other blob encodings (`SuccinctBM25Blob`, `SuccinctHNSWBlob`)
//! live next to their index types.
//!
//! The built-in tokenizers in [`crate::tokens`] return
//! `Inline<Handle<UTF8String>>` — the hash bytes are
//! valid UTF8String-blob handles by construction, so there's
//! no need for a bespoke "token hash" encoding.

use std::convert::Infallible;
use triblespace_core::inline::Encodes;

use anybytes::View;
use triblespace_core::blob::encodings::tensor::elements::F32;
use triblespace_core::blob::encodings::tensor::{tensor_blob, Tensor, TensorError, TensorView};
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::id::ExclusiveId;
use triblespace_core::id_hex;
use triblespace_core::inline::{Inline, InlineEncoding, IntoInline, TryFromInline};
use triblespace_core::macros::entity;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::trible::Fragment;

/// 32-bit IEEE-754 little-endian float packed into a 32-byte
/// triblespace `Inline`. Bytes `[0..4]` hold the raw f32 bytes;
/// bytes `[4..32]` are zero-padded.
///
/// Schema id was minted via `trible genid` and is fixed:
/// `816B4751EA8C12644CCB572F36188EBA`.
///
/// Every bit pattern decodes to some f32 (including NaN +
/// signed zero), so validation is infallible. Callers that want
/// stricter invariants (non-NaN, within a specific range)
/// should wrap `Inline<F32LE>` with their own newtype + checked
/// conversion.
pub enum F32LE {}

impl MetaDescribe for F32LE {
    fn describe() -> Fragment {
        let id = id_hex!("816B4751EA8C12644CCB572F36188EBA");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name:        "F32LE",
            metadata::description: "32-bit IEEE-754 float stored little-endian in the first 4 bytes of the 32-byte Inline, with the rest zero-padded.",
            metadata::tag:         metadata::KIND_INLINE_ENCODING,
        }
    }
}

impl InlineEncoding for F32LE {
    type ValidationError = Infallible;
    type Encoding = Self;
}

impl Encodes<f32> for F32LE {
    type Output = Inline<F32LE>;
    fn encode(source: f32) -> Inline<F32LE> {
        let mut raw = [0u8; 32];
        raw[0..4].copy_from_slice(&source.to_le_bytes());
        Inline::new(raw)
    }
}

impl Encodes<&f32> for F32LE {
    type Output = Inline<F32LE>;
    fn encode(source: &f32) -> Inline<F32LE> {
        (*source).to_inline()
    }
}

impl TryFromInline<'_, F32LE> for f32 {
    type Error = Infallible;

    fn try_from_inline(value: &Inline<F32LE>) -> Result<Self, Self::Error> {
        Ok(f32::from_le_bytes(value.raw[0..4].try_into().unwrap()))
    }
}

/// An L2-normalized f32 vector stored as a rank-1 tensor blob.
///
/// The bytes are exactly those of [`Tensor<F32, 1>`]: a 256-byte header
/// whose first eight bytes carry the dimension as a little-endian `u64`,
/// then the little-endian f32 payload, 256-byte aligned so the GPU path can
/// alias the mapped pages. So the dimension travels inside the blob and is
/// validated on read; an index that owns a handle no longer has to be the
/// only place that knows how long the vector is, and a vector of the wrong
/// length is refused by the encoding rather than discovered by a reader.
///
/// HNSW and flat indexes reference embeddings by [`Handle<Embedding>`][h], so
/// two indexes that embed the same entity share one on-disk blob, and a
/// vector stored as a plain rank-1 tensor is the same blob as well. What the
/// `Embedding` type adds to the tensor is the convention below.
///
/// ### Convention: L2-normalized
///
/// Embeddings in this crate's indexes are **L2-normalized by
/// the caller** at ingest time. Flat and HNSW retrieval use a single dot
/// product against each stored embedding, so bypassing normalization scales
/// ANN scores by vector magnitude. The exact `CosineAtLeast` predicate divides
/// by both norms and does not rely on this convention.
///
/// Use [`put_embedding`] to normalize + put in one step.
///
/// Schema id minted via `trible genid`:
/// `F5FC4D1C715921F68B392E4347464CCF`. The earlier id,
/// `EEC5DFDEA2FFCED70850DF83B03CB62B`, named headerless raw f32 bytes and is
/// retired without reuse.
///
/// [h]: triblespace_core::inline::encodings::hash::Handle
pub struct Embedding {}

impl BlobEncoding for Embedding {}

impl MetaDescribe for Embedding {
    fn describe() -> Fragment {
        let id = id_hex!("F5FC4D1C715921F68B392E4347464CCF");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name:        "Embedding",
            metadata::description: "An L2-normalized f32 vector stored as a rank-1 F32 tensor blob: a 256-byte header carrying the dimension as a little-endian u64, then the little-endian f32 payload, 256-byte aligned. The bytes are exactly those of Tensor<F32, 1>; the type adds the normalization convention.",
            metadata::tag:         metadata::KIND_BLOB_ENCODING,
            metadata::blob_encoding*: <Tensor<F32, 1> as MetaDescribe>::describe(),
        }
    }
}

/// Shorthand for the most common embedding-handle inline encoding:
/// `Handle<Embedding>`. Use in trible attributes, in
/// similarity constraint variables, wherever you'd otherwise
/// spell the full type.
///
/// ```
/// use triblespace_core::inline::Inline;
/// use triblespace_search::schemas::EmbHandle;
///
/// fn keep(_h: Inline<EmbHandle>) {}
/// # keep(Inline::new([0u8; 32]));
/// ```
pub type EmbHandle = triblespace_core::inline::encodings::hash::Handle<Embedding>;

/// Decode a blob back into a zero-copy `View<[f32]>`. Fails
/// iff the blob's byte length isn't a multiple of 4 (malformed)
/// or the backing buffer can't be aligned to `f32`.
/// Why an embedding blob could not be read: it is not a well-formed rank-1
/// F32 tensor, or its payload could not be viewed as `[f32]`.
#[derive(Debug)]
pub enum EmbeddingError {
    Tensor(TensorError),
    View(anybytes::view::ViewError),
}

impl core::fmt::Display for EmbeddingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tensor(error) => write!(f, "embedding is not a rank-1 F32 tensor: {error}"),
            Self::View(error) => write!(f, "embedding payload is not viewable as [f32]: {error:?}"),
        }
    }
}

impl std::error::Error for EmbeddingError {}

impl From<TensorError> for EmbeddingError {
    fn from(error: TensorError) -> Self {
        Self::Tensor(error)
    }
}

impl From<anybytes::view::ViewError> for EmbeddingError {
    fn from(error: anybytes::view::ViewError) -> Self {
        Self::View(error)
    }
}

/// The blob's own tensor view: its dimension and its payload bytes.
fn tensor_view(blob: Blob<Embedding>) -> Result<TensorView, EmbeddingError> {
    let tensor: Blob<Tensor<F32, 1>> = blob.transmute();
    Ok(TensorView::try_from_blob(tensor)?)
}

/// The dimension the blob declares in its header, validated against its
/// payload length.
pub fn dimension(blob: Blob<Embedding>) -> Result<usize, EmbeddingError> {
    Ok(tensor_view(blob)?.elems())
}

/// Decode a blob back into a zero-copy `View<[f32]>` of its payload.
/// Fails iff the header and payload disagree, or the payload cannot be
/// aligned to `f32` (it starts 256 bytes into the blob, so it can whenever the
/// blob itself is aligned).
impl TryFromBlob<Embedding> for View<[f32]> {
    type Error = EmbeddingError;
    fn try_from_blob(b: Blob<Embedding>) -> Result<Self, Self::Error> {
        let view = tensor_view(b)?;
        Ok(view.payload().clone().view()?)
    }
}

/// One rank-1 F32 tensor blob over `payload`, whose length is `dimension × 4`
/// by construction.
fn embedding_blob(dimension: usize, payload: Vec<u8>) -> Blob<Embedding> {
    let tensor = tensor_blob::<F32, 1>([dimension as u64], anybytes::Bytes::from_source(payload))
        .expect("a rank-1 f32 payload built from its own length always fits its header");
    tensor.transmute()
}

impl Encodes<View<[f32]>> for Embedding
where
    triblespace_core::inline::encodings::hash::Handle<Embedding>:
        triblespace_core::inline::InlineEncoding,
{
    type Output = Blob<Embedding>;
    fn encode(source: View<[f32]>) -> Blob<Embedding> {
        Self::encode(&source[..])
    }
}

impl Encodes<Vec<f32>> for Embedding
where
    triblespace_core::inline::encodings::hash::Handle<Embedding>:
        triblespace_core::inline::InlineEncoding,
{
    type Output = Blob<Embedding>;
    fn encode(source: Vec<f32>) -> Blob<Embedding> {
        Self::encode(&source[..])
    }
}

impl Encodes<&[f32]> for Embedding
where
    triblespace_core::inline::encodings::hash::Handle<Embedding>:
        triblespace_core::inline::InlineEncoding,
{
    type Output = Blob<Embedding>;
    fn encode(source: &[f32]) -> Blob<Embedding> {
        let mut bytes = Vec::with_capacity(source.len() * 4);
        for v in source {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        embedding_blob(source.len(), bytes)
    }
}

pub fn l2_normalize(vec: &mut [f32]) {
    let norm: f32 = vec.iter().map(|&x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        let inv = 1.0 / norm;
        for v in vec.iter_mut() {
            *v *= inv;
        }
    }
}

/// L2-normalize `vec` and `put` it into `store` as an
/// [`Embedding`] blob, returning the content-addressed handle.
///
/// Use this everywhere you ingest an embedding for a
/// cosine-similarity index — two callers with the same raw
/// input produce the same handle, so the pile's dedup layer
/// stores the blob once even across distinct indexes.
pub fn put_embedding<B>(
    store: &mut B,
    mut vec: Vec<f32>,
) -> Result<
    triblespace_core::inline::Inline<triblespace_core::inline::encodings::hash::Handle<Embedding>>,
    B::PutError,
>
where
    B: triblespace_core::repo::BlobStorePut,
    triblespace_core::inline::encodings::hash::Handle<Embedding>:
        triblespace_core::inline::InlineEncoding,
{
    l2_normalize(&mut vec);
    store.put::<Embedding, _>(vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace_core::blob::IntoBlob;

    #[test]
    fn round_trip_positive() {
        let original: f32 = 0.123;
        let v: Inline<F32LE> = original.to_inline();
        let back: f32 = f32::try_from_inline(&v).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn round_trip_negative() {
        let original: f32 = -42.75;
        let v: Inline<F32LE> = original.to_inline();
        let back: f32 = f32::try_from_inline(&v).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn round_trip_zero() {
        let original: f32 = 0.0;
        let v: Inline<F32LE> = original.to_inline();
        let back: f32 = f32::try_from_inline(&v).unwrap();
        assert_eq!(original.to_bits(), back.to_bits());
    }

    #[test]
    fn round_trip_nan() {
        let original: f32 = f32::NAN;
        let v: Inline<F32LE> = original.to_inline();
        let back: f32 = f32::try_from_inline(&v).unwrap();
        assert!(back.is_nan());
    }

    #[test]
    fn padding_is_zero() {
        // Arbitrary finite non-zero value; clippy flags 3.14 as
        // an approximation of `std::f32::consts::PI`.
        let v: Inline<F32LE> = 2.5f32.to_inline();
        assert_eq!(&v.raw[4..32], &[0u8; 28]);
    }

    #[test]
    fn deterministic_same_input_same_value() {
        let a: Inline<F32LE> = 1.5f32.to_inline();
        let b: Inline<F32LE> = 1.5f32.to_inline();
        assert_eq!(a.raw, b.raw);
    }

    #[test]
    fn embedding_blob_round_trip() {
        let original: Vec<f32> = vec![0.1, -0.5, 3.25, f32::consts::PI];
        let blob: Blob<Embedding> = original.clone().to_blob();
        let view: View<[f32]> = TryFromBlob::try_from_blob(blob).unwrap();
        assert_eq!(view.as_ref(), original.as_slice());
    }

    #[test]
    fn put_embedding_roundtrips_through_memory_store() {
        use triblespace_core::blob::MemoryBlobStore;
        use triblespace_core::repo::{BlobStoreGet, SnapshotSource};

        let mut store = MemoryBlobStore::new();
        let vec = vec![1.0_f32, 0.0, 0.0];
        let handle = put_embedding::<_>(&mut store, vec.clone()).unwrap();
        let snapshot = store.snapshot().unwrap();
        let view: View<[f32]> = snapshot.get::<View<[f32]>, Embedding>(handle).unwrap();
        // After normalize, [1,0,0] stays [1,0,0].
        assert_eq!(view.as_ref(), &[1.0_f32, 0.0, 0.0]);
    }

    #[test]
    fn embedding_handle_is_content_addressed() {
        use triblespace_core::inline::encodings::hash::Handle;

        let v1: Vec<f32> = vec![1.0, 2.0, 3.0];
        let v2: Vec<f32> = vec![1.0, 2.0, 3.0];
        let v3: Vec<f32> = vec![1.0, 2.0, 3.0, 4.0];

        let h1: Inline<Handle<Embedding>> = v1.to_blob().get_handle();
        let h2: Inline<Handle<Embedding>> = v2.to_blob().get_handle();
        let h3: Inline<Handle<Embedding>> = v3.to_blob().get_handle();

        assert_eq!(h1, h2, "identical vectors must dedup by handle");
        assert_ne!(h1, h3, "different vectors must have different handles");
    }

    use std::f32;
}

#[cfg(test)]
mod embedding_tensor_tests {
    use super::*;
    use triblespace_core::blob::encodings::tensor::TENSOR_HEADER_LEN;

    #[test]
    fn embedding_read_retains_the_original_tensor_payload() {
        let blob: Blob<Embedding> = Embedding::encode(vec![0.6_f32, 0.8, 0.0]);
        let payload = blob.bytes[TENSOR_HEADER_LEN..].as_ptr();
        let view = View::<[f32]>::try_from_blob(blob).unwrap();
        assert_eq!(view.as_ptr().cast::<u8>(), payload);
        assert_eq!(&view[..], &[0.6, 0.8, 0.0]);
    }

    #[test]
    fn an_embedding_is_a_rank_one_f32_tensor_with_its_dimension_in_the_header() {
        let blob: Blob<Embedding> = Embedding::encode(vec![0.6_f32, 0.8, 0.0]);
        assert_eq!(blob.bytes.len(), TENSOR_HEADER_LEN + 3 * 4);
        assert_eq!(&blob.bytes[..8], &3_u64.to_le_bytes());
        assert_eq!(dimension(blob.clone()).unwrap(), 3);
        let view: View<[f32]> = View::try_from_blob(blob.clone()).unwrap();
        assert_eq!(&view[..], &[0.6, 0.8, 0.0]);
        let tensor: TensorView =
            TensorView::try_from_blob(Blob::<Tensor<F32, 1>>::new(blob.bytes)).unwrap();
        assert_eq!(tensor.dims(), &[3]);
    }

    #[test]
    fn headerless_bytes_are_refused() {
        let raw: Blob<Embedding> = Blob::new(anybytes::Bytes::from_source(vec![0_u8; 12]));
        assert!(matches!(
            View::<[f32]>::try_from_blob(raw),
            Err(EmbeddingError::Tensor(_))
        ));
    }

    #[test]
    fn a_header_that_disagrees_with_its_payload_is_refused() {
        let mut bytes = vec![0_u8; TENSOR_HEADER_LEN + 8];
        bytes[..8].copy_from_slice(&3_u64.to_le_bytes());
        let blob: Blob<Embedding> = Blob::new(anybytes::Bytes::from_source(bytes));
        assert!(matches!(dimension(blob), Err(EmbeddingError::Tensor(_))));
    }

    #[test]
    fn the_same_vector_is_the_same_blob_as_a_plain_tensor() {
        let embedding: Blob<Embedding> = Embedding::encode(&[1.0_f32, 0.0][..]);
        let payload = [1.0_f32, 0.0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<u8>>();
        let tensor = tensor_blob::<F32, 1>([2], anybytes::Bytes::from_source(payload)).unwrap();
        assert_eq!(&embedding.bytes[..], &tensor.bytes[..]);
    }
}
