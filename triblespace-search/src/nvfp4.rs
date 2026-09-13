//! Canonical row-local NVFP4 cosine collection.
//!
//! The persisted value is a set of independently quantized embedding rows,
//! keyed and ordered by the exact embedding blob handle.  A row owns its FP32
//! global scale; adding another row can therefore never requantize an existing
//! one.  That independence is what makes sorted set union a canonical,
//! associative, commutative, and idempotent collection join.
//!
//! Each row stores a primary NVFP4 reconstruction and a second NVFP4
//! reconstruction of its residual. A member is a gapless structure-of-arrays:
//! `handles[N] | q0_globals[N] | q0_e4m3_scales[N][ceil256(D)/16] |
//! q0_e2m1_codes[N][ceil256(D)/2] | q1_globals[N] |
//! q1_e4m3_scales[N][ceil256(D)/16] | q1_e2m1_codes[N][ceil256(D)/2] |
//! norm_f32[N] | error_f32[N] | N_u64 | D_u64`.
//! Integers and floats are little-endian; handles are strictly ascending;
//! negative FP4 zero is rejected. `norm_f32` is an upward-rounded norm of the
//! summed canonical `f64` reconstruction. `error_f32` is one upward-rounded
//! row certificate which encloses both the transform-and-two-stage-
//! quantization L2 error and the discrepancy between the canonical `f64`
//! reconstruction and the encoding's prescribed explicit-`f32`
//! reconstruction. The latter lets a binary32 scanner remain exact without a
//! sidecar or another persisted plane.
//!
//! Approximation is confined to candidate discovery.  [`NvFp4CosineIndex`]
//! uses conservative error bounds and fetches original embedding blobs for
//! exact reranking, so [`NvFp4CosineIndex::top_k`] and
//! [`NvFp4CosineIndex::above`] retain exact cosine semantics.

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeSet, BinaryHeap};
use std::convert::Infallible;
use std::fmt;
use std::marker::PhantomData;
use std::num::NonZeroUsize;

use anybytes::{Bytes, View};
use mary::nn::nvfp4_cosine::{
    raw_dot_f64, CandidateCertificate, PreparedQuery, QuantizedRow, ScanSegment, ScanStage,
    UpperScanner, FLOAT_BYTES, QUANT_BLOCK, QUANT_STAGES, ROTATION_BLOCK,
};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::collection::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use triblespace_core::collection::{
    CollectionDerivation, CollectionEncoding, CollectionOperationError, Cover, TryFromCover,
    TryFromCoverError,
};
use triblespace_core::id::{id_hex, ExclusiveId, Id};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::encodings::iu256::U256BE;
use triblespace_core::inline::{Inline, IntoInline, TryFromInline};
use triblespace_core::macros::{attributes, entity};
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::query::Variable;
use triblespace_core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace_core::trible::{Fragment, TribleSet, TRIBLE_LEN};

pub(crate) const HANDLE_LEN: usize = 32;
const FLOAT_LEN: usize = FLOAT_BYTES;
const FOOTER_LEN: usize = 16;

// Stable marker for this exact byte and cosine recipe. Minted with
// `trible genid` on 2026-09-01 after strengthening `error_f32` to cover the
// prescribed explicit-f32 decode. It is embedded in the derived encoding's
// identity together with E, so a recipe or exact embedding encoding change
// necessarily produces another collection encoding.
pub const NVFP4_COSINE_SET: Id = id_hex!("9F1A2851ADCA92BAB92688441B262DEA");

// Stable identity for the SimpleArchive attribute-selection mapping. Minted
// with `trible genid` on 2026-09-01 for the strengthened row certificate. The
// selected attribute, exact blob encoding, and dimension remain concrete
// mapping-instance parameters.
pub const EMBEDDING_ATTRIBUTE_TO_NVFP4: Id = id_hex!("7B8668FD3857AD86B5AB24F5DD1BC1F9");

attributes! {
    /// Logical embedding dimension selected by one concrete NVFP4 mapping.
    ///
    /// Anchor minted with `trible genid` on 2026-09-01:
    /// `96ED6826E7FE88F1906D8C634A187C93`.
    /// Existing `metadata::attribute` and `metadata::blob_encoding` carry the
    /// other two parameters; this is the sole new mapping-field vocabulary.
    "96ED6826E7FE88F1906D8C634A187C93" as pub(crate) nvfp4_dimension: U256BE;
}

/// Failure to decode, construct, or query a canonical NVFP4 cosine set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NvFp4Error {
    message: String,
}

impl NvFp4Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for NvFp4Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NvFp4Error {}

impl From<mary::nn::nvfp4_cosine::Error> for NvFp4Error {
    fn from(source: mary::nn::nvfp4_cosine::Error) -> Self {
        Self::new(source.to_string())
    }
}

/// Canonical row-local NVFP4 carrier for exact embedding encoding `E`.
pub struct NvFp4CosineSet<E: BlobEncoding>(PhantomData<E>);

struct NvFp4CosineRecipe;

impl MetaDescribe for NvFp4CosineRecipe {
    fn describe() -> Fragment {
        let id = NVFP4_COSINE_SET;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "nvfp4-cosine-recipe",
            metadata::description: "Canonical row-local two-stage residual NVFP4 cosine carrier. Rows are ordered by exact embedding handle and independently normalized, deterministically rotated, block-scaled, quantized twice, and conservatively error-bounded for both canonical f64 and prescribed explicit-f32 reconstruction. Join is set union by handle; exact source embeddings remain lazy reranking dependencies.",
            metadata::tag: metadata::KIND_TAG,
        }
    }
}

impl<E> MetaDescribe for NvFp4CosineSet<E>
where
    E: BlobEncoding,
{
    fn describe() -> Fragment {
        let mut description = entity! {
            metadata::tag: metadata::KIND_BLOB_ENCODING,
            metadata::tag*: <NvFp4CosineRecipe as MetaDescribe>::describe(),
            metadata::blob_encoding*: E::describe(),
        };
        let id = description.root().expect("rooted NVFP4 encoding");
        description += entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "nvfp4-cosine-set",
            metadata::description: "Typed canonical set of independently two-stage residual-NVFP4-quantized embedding rows with one shared row certificate for canonical f64 and prescribed explicit-f32 reconstruction. The exact embedding blob encoding participates in this encoding's intrinsic identity.",
        };
        description
    }
}

impl<E> BlobEncoding for NvFp4CosineSet<E> where E: BlobEncoding {}

/// One exact similarity result.
#[derive(Debug)]
pub struct SimilarityHit<E: BlobEncoding> {
    /// Exact source embedding blob.
    pub embedding: Inline<Handle<E>>,
    /// Exact deterministic cosine score accumulated in `f64`.
    pub score: f64,
}

impl<E: BlobEncoding> Copy for SimilarityHit<E> {}

impl<E: BlobEncoding> Clone for SimilarityHit<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: BlobEncoding> PartialEq for SimilarityHit<E> {
    fn eq(&self, other: &Self) -> bool {
        self.embedding == other.embedding && self.score.to_bits() == other.score.to_bits()
    }
}

#[derive(Clone, Debug)]
struct StageLayout {
    globals: std::ops::Range<usize>,
    block_scales: std::ops::Range<usize>,
    codes: std::ops::Range<usize>,
}

#[derive(Clone, Debug)]
struct Layout {
    rows: usize,
    dimension: usize,
    blocks_per_row: usize,
    codes_per_row: usize,
    stages: [StageLayout; QUANT_STAGES],
    norms: std::ops::Range<usize>,
    errors: std::ops::Range<usize>,
}

impl Layout {
    fn parse(bytes: &[u8]) -> Result<Self, NvFp4Error> {
        if bytes.len() < FOOTER_LEN {
            return Err(NvFp4Error::new("NVFP4 member is shorter than its footer"));
        }
        let footer = bytes.len() - FOOTER_LEN;
        let rows = read_u64(&bytes[footer..footer + 8], "row count")?;
        let dimension = read_u64(&bytes[footer + 8..], "dimension")?;
        let rows =
            usize::try_from(rows).map_err(|_| NvFp4Error::new("NVFP4 row count exceeds usize"))?;
        let dimension = usize::try_from(dimension)
            .map_err(|_| NvFp4Error::new("NVFP4 dimension exceeds usize"))?;
        if dimension == 0 {
            return Err(NvFp4Error::new("NVFP4 dimension must be positive"));
        }
        let physical_dimension = dimension
            .checked_add(ROTATION_BLOCK - 1)
            .map(|value| value / ROTATION_BLOCK * ROTATION_BLOCK)
            .ok_or_else(|| NvFp4Error::new("NVFP4 padded dimension overflows usize"))?;
        let blocks_per_row = physical_dimension / QUANT_BLOCK;
        let codes_per_row = physical_dimension / 2;

        let handles_end = rows
            .checked_mul(HANDLE_LEN)
            .ok_or_else(|| NvFp4Error::new("NVFP4 handle plane overflows usize"))?;
        let global_len = rows
            .checked_mul(FLOAT_LEN)
            .ok_or_else(|| NvFp4Error::new("NVFP4 global-scale plane overflows usize"))?;
        let scales_len = rows
            .checked_mul(blocks_per_row)
            .ok_or_else(|| NvFp4Error::new("NVFP4 block-scale plane overflows usize"))?;
        let codes_len = rows
            .checked_mul(codes_per_row)
            .ok_or_else(|| NvFp4Error::new("NVFP4 code plane overflows usize"))?;
        let float_plane_len = rows
            .checked_mul(FLOAT_LEN)
            .ok_or_else(|| NvFp4Error::new("NVFP4 float plane overflows usize"))?;
        let mut cursor = handles_end;
        let mut next_stage = || -> Result<StageLayout, NvFp4Error> {
            let globals = take_plane(&mut cursor, global_len, "global-scale")?;
            let block_scales = take_plane(&mut cursor, scales_len, "block-scale")?;
            let codes = take_plane(&mut cursor, codes_len, "code")?;
            Ok(StageLayout {
                globals,
                block_scales,
                codes,
            })
        };
        let stages = [next_stage()?, next_stage()?];
        let norms = take_plane(&mut cursor, float_plane_len, "norm")?;
        let errors = take_plane(&mut cursor, float_plane_len, "error")?;
        if cursor != footer {
            return Err(NvFp4Error::new(format!(
                "NVFP4 member length {} does not match N={rows}, D={dimension}",
                bytes.len()
            )));
        }

        let layout = Self {
            rows,
            dimension,
            blocks_per_row,
            codes_per_row,
            stages,
            norms,
            errors,
        };
        layout.validate(bytes)?;
        Ok(layout)
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), NvFp4Error> {
        let mut previous: Option<&[u8]> = None;
        for row in 0..self.rows {
            let handle = self.handle(bytes, row);
            if previous.is_some_and(|old| old >= handle) {
                return Err(NvFp4Error::new(
                    "NVFP4 embedding handles must be strictly increasing",
                ));
            }
            previous = Some(handle);
            for stage in 0..QUANT_STAGES {
                validate_nonnegative_f32(self.global(bytes, row, stage), "global scale")?;
                if self
                    .block_scales(bytes, row, stage)
                    .iter()
                    .any(|&scale| scale > 0x7e)
                {
                    return Err(NvFp4Error::new(
                        "NVFP4 block scale is not a finite nonnegative E4M3 value",
                    ));
                }
                if self.codes(bytes, row, stage).iter().any(|&pair| {
                    let low = pair & 0x0f;
                    let high = pair >> 4;
                    low == 0x08 || high == 0x08
                }) {
                    return Err(NvFp4Error::new(
                        "NVFP4 code plane contains noncanonical negative zero",
                    ));
                }
            }
            validate_nonnegative_f32(self.norm(bytes, row), "reconstruction norm")?;
            validate_nonnegative_f32(self.error(bytes, row), "error bound")?;
        }
        Ok(())
    }

    fn handle<'a>(&self, bytes: &'a [u8], row: usize) -> &'a [u8] {
        &bytes[row * HANDLE_LEN..(row + 1) * HANDLE_LEN]
    }

    fn global(&self, bytes: &[u8], row: usize, stage: usize) -> f32 {
        let offset = self.stages[stage].globals.start + row * FLOAT_LEN;
        read_f32(&bytes[offset..offset + FLOAT_LEN])
    }

    fn block_scales<'a>(&self, bytes: &'a [u8], row: usize, stage: usize) -> &'a [u8] {
        let start = self.stages[stage].block_scales.start + row * self.blocks_per_row;
        &bytes[start..start + self.blocks_per_row]
    }

    fn codes<'a>(&self, bytes: &'a [u8], row: usize, stage: usize) -> &'a [u8] {
        let start = self.stages[stage].codes.start + row * self.codes_per_row;
        &bytes[start..start + self.codes_per_row]
    }

    fn norm(&self, bytes: &[u8], row: usize) -> f32 {
        read_f32(&bytes[self.norms.start + row * FLOAT_LEN..][..FLOAT_LEN])
    }

    fn error(&self, bytes: &[u8], row: usize) -> f32 {
        read_f32(&bytes[self.errors.start + row * FLOAT_LEN..][..FLOAT_LEN])
    }
}

fn take_plane(
    cursor: &mut usize,
    len: usize,
    field: &str,
) -> Result<std::ops::Range<usize>, NvFp4Error> {
    let start = *cursor;
    let end = start
        .checked_add(len)
        .ok_or_else(|| NvFp4Error::new(format!("NVFP4 {field} offset overflows usize")))?;
    *cursor = end;
    Ok(start..end)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredStage {
    global: [u8; FLOAT_LEN],
    block_scales: Vec<u8>,
    codes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredRow {
    handle: [u8; HANDLE_LEN],
    stages: [StoredStage; QUANT_STAGES],
    norm: [u8; FLOAT_LEN],
    error: [u8; FLOAT_LEN],
}

impl StoredRow {
    pub(crate) fn quantize(
        handle: [u8; HANDLE_LEN],
        embedding: &[f32],
        dimension: usize,
    ) -> Result<Self, NvFp4Error> {
        let quantized = QuantizedRow::quantize(embedding, dimension)?;
        Ok(Self {
            handle,
            stages: std::array::from_fn(|stage| {
                let stage = &quantized.stages()[stage];
                StoredStage {
                    global: *stage.global_scale_bytes(),
                    block_scales: stage.block_scales().to_vec(),
                    codes: stage.codes().to_vec(),
                }
            }),
            norm: *quantized.reconstruction_norm_bytes(),
            error: *quantized.error_bound_bytes(),
        })
    }
}

pub(crate) fn encode_rows<E: BlobEncoding>(
    dimension: usize,
    mut rows: Vec<StoredRow>,
) -> Result<Blob<NvFp4CosineSet<E>>, NvFp4Error> {
    if dimension == 0 {
        return Err(NvFp4Error::new("NVFP4 dimension must be positive"));
    }
    rows.sort_unstable_by_key(|row| row.handle);
    let physical_dimension = dimension
        .checked_add(ROTATION_BLOCK - 1)
        .map(|value| value / ROTATION_BLOCK * ROTATION_BLOCK)
        .ok_or_else(|| NvFp4Error::new("NVFP4 padded dimension overflows usize"))?;
    let blocks_per_row = physical_dimension / QUANT_BLOCK;
    let codes_per_row = physical_dimension / 2;
    let mut distinct: Vec<StoredRow> = Vec::with_capacity(rows.len());
    for row in rows {
        if row.stages.iter().any(|stage| {
            stage.block_scales.len() != blocks_per_row || stage.codes.len() != codes_per_row
        }) {
            return Err(NvFp4Error::new(
                "NVFP4 row payload does not match its dimension",
            ));
        }
        if let Some(previous) = distinct.last() {
            if previous.handle == row.handle {
                if previous != &row {
                    return Err(NvFp4Error::new(
                        "one embedding handle has two different NVFP4 rows",
                    ));
                }
                continue;
            }
        }
        distinct.push(row);
    }

    let stage_width = FLOAT_LEN
        .checked_add(blocks_per_row)
        .and_then(|value| value.checked_add(codes_per_row))
        .ok_or_else(|| NvFp4Error::new("NVFP4 stage width overflows usize"))?;
    let row_width = stage_width
        .checked_mul(QUANT_STAGES)
        .and_then(|value| value.checked_add(HANDLE_LEN))
        .and_then(|value| value.checked_add(FLOAT_LEN))
        .and_then(|value| value.checked_add(FLOAT_LEN))
        .ok_or_else(|| NvFp4Error::new("NVFP4 row width overflows usize"))?;
    let capacity = distinct
        .len()
        .checked_mul(row_width)
        .and_then(|value| value.checked_add(FOOTER_LEN))
        .ok_or_else(|| NvFp4Error::new("NVFP4 member length overflows usize"))?;
    let mut bytes = Vec::with_capacity(capacity);
    for row in &distinct {
        bytes.extend_from_slice(&row.handle);
    }
    for stage in 0..QUANT_STAGES {
        for row in &distinct {
            bytes.extend_from_slice(&row.stages[stage].global);
        }
        for row in &distinct {
            bytes.extend_from_slice(&row.stages[stage].block_scales);
        }
        for row in &distinct {
            bytes.extend_from_slice(&row.stages[stage].codes);
        }
    }
    for row in &distinct {
        bytes.extend_from_slice(&row.norm);
    }
    for row in &distinct {
        bytes.extend_from_slice(&row.error);
    }
    bytes.extend_from_slice(
        &u64::try_from(distinct.len())
            .map_err(|_| NvFp4Error::new("NVFP4 row count exceeds u64"))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u64::try_from(dimension)
            .map_err(|_| NvFp4Error::new("NVFP4 dimension exceeds u64"))?
            .to_le_bytes(),
    );
    debug_assert_eq!(bytes.len(), capacity);
    let blob = Blob::new(Bytes::from_source(bytes));
    Layout::parse(blob.bytes.as_ref())?;
    Ok(blob)
}

fn owned_row(bytes: &[u8], layout: &Layout, row: usize) -> StoredRow {
    StoredRow {
        handle: layout
            .handle(bytes, row)
            .try_into()
            .expect("32-byte handle"),
        stages: std::array::from_fn(|stage| StoredStage {
            global: bytes[layout.stages[stage].globals.start + row * FLOAT_LEN..][..FLOAT_LEN]
                .try_into()
                .expect("four-byte global scale"),
            block_scales: layout.block_scales(bytes, row, stage).to_vec(),
            codes: layout.codes(bytes, row, stage).to_vec(),
        }),
        norm: bytes[layout.norms.start + row * FLOAT_LEN..][..FLOAT_LEN]
            .try_into()
            .expect("four-byte reconstruction norm"),
        error: bytes[layout.errors.start + row * FLOAT_LEN..][..FLOAT_LEN]
            .try_into()
            .expect("four-byte error bound"),
    }
}

fn rows_equal(
    left_bytes: &[u8],
    left_layout: &Layout,
    left_row: usize,
    right_bytes: &[u8],
    right_layout: &Layout,
    right_row: usize,
) -> bool {
    let stages_equal = (0..QUANT_STAGES).all(|stage| {
        let left_global = left_layout.stages[stage].globals.start + left_row * FLOAT_LEN;
        let right_global = right_layout.stages[stage].globals.start + right_row * FLOAT_LEN;
        left_bytes[left_global..left_global + FLOAT_LEN]
            == right_bytes[right_global..right_global + FLOAT_LEN]
            && left_layout.block_scales(left_bytes, left_row, stage)
                == right_layout.block_scales(right_bytes, right_row, stage)
            && left_layout.codes(left_bytes, left_row, stage)
                == right_layout.codes(right_bytes, right_row, stage)
    });
    let left_norm = left_layout.norms.start + left_row * FLOAT_LEN;
    let right_norm = right_layout.norms.start + right_row * FLOAT_LEN;
    let left_error = left_layout.errors.start + left_row * FLOAT_LEN;
    let right_error = right_layout.errors.start + right_row * FLOAT_LEN;
    left_layout.handle(left_bytes, left_row) == right_layout.handle(right_bytes, right_row)
        && stages_equal
        && left_bytes[left_norm..left_norm + FLOAT_LEN]
            == right_bytes[right_norm..right_norm + FLOAT_LEN]
        && left_bytes[left_error..left_error + FLOAT_LEN]
            == right_bytes[right_error..right_error + FLOAT_LEN]
}

fn join_members<E: BlobEncoding>(
    low: &Blob<NvFp4CosineSet<E>>,
    high: &Blob<NvFp4CosineSet<E>>,
    dimension: usize,
) -> Result<Blob<NvFp4CosineSet<E>>, NvFp4Error> {
    let low_layout = Layout::parse(low.bytes.as_ref())?;
    let high_layout = Layout::parse(high.bytes.as_ref())?;
    if low_layout.dimension != dimension || high_layout.dimension != dimension {
        return Err(NvFp4Error::new(format!(
            "NVFP4 join member dimension does not match descriptor {dimension}"
        )));
    }
    let mut rows = Vec::with_capacity(low_layout.rows + high_layout.rows);
    let mut low_row = 0;
    let mut high_row = 0;
    while low_row < low_layout.rows && high_row < high_layout.rows {
        match low_layout
            .handle(low.bytes.as_ref(), low_row)
            .cmp(high_layout.handle(high.bytes.as_ref(), high_row))
        {
            Ordering::Less => {
                rows.push(owned_row(low.bytes.as_ref(), &low_layout, low_row));
                low_row += 1;
            }
            Ordering::Greater => {
                rows.push(owned_row(high.bytes.as_ref(), &high_layout, high_row));
                high_row += 1;
            }
            Ordering::Equal => {
                let left = owned_row(low.bytes.as_ref(), &low_layout, low_row);
                let right = owned_row(high.bytes.as_ref(), &high_layout, high_row);
                if left != right {
                    return Err(NvFp4Error::new(
                        "one embedding handle has two different NVFP4 rows",
                    ));
                }
                rows.push(left);
                low_row += 1;
                high_row += 1;
            }
        }
    }
    while low_row < low_layout.rows {
        rows.push(owned_row(low.bytes.as_ref(), &low_layout, low_row));
        low_row += 1;
    }
    while high_row < high_layout.rows {
        rows.push(owned_row(high.bytes.as_ref(), &high_layout, high_row));
        high_row += 1;
    }
    encode_rows(dimension, rows)
}

#[derive(Clone, Debug)]
struct Member {
    content_handle: [u8; HANDLE_LEN],
    bytes: Bytes,
    layout: Layout,
}

/// Lazy cover-aware query view over canonical NVFP4 members.
pub struct NvFp4CosineIndex<E: BlobEncoding> {
    members: Vec<Member>,
    dimension: usize,
    _encoding: PhantomData<E>,
}

/// The source attribute and logical dimension selected by an NVFP4 derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NvFp4EmbeddingAttribute {
    attribute: Id,
    dimension: NonZeroUsize,
}

impl NvFp4EmbeddingAttribute {
    /// Select one handle-valued attribute with exactly `dimension` components.
    ///
    /// The target [`NvFp4CosineSet<E>`] supplies the exact handle encoding.
    pub fn new(attribute: Id, dimension: usize) -> Result<Self, NvFp4Error> {
        let dimension = NonZeroUsize::new(dimension)
            .ok_or_else(|| NvFp4Error::new("embedding dimension must be positive"))?;
        u64::try_from(dimension.get())
            .map_err(|_| NvFp4Error::new("embedding dimension exceeds u64"))?;
        Ok(Self {
            attribute,
            dimension,
        })
    }

    /// Selected source attribute.
    pub fn attribute(&self) -> Id {
        self.attribute
    }

    /// Exact logical embedding dimension.
    pub fn dimension(&self) -> usize {
        self.dimension.get()
    }
}

struct EmbeddingAttributeToNvFp4Recipe;

impl MetaDescribe for EmbeddingAttributeToNvFp4Recipe {
    fn describe() -> Fragment {
        let id = EMBEDDING_ATTRIBUTE_TO_NVFP4;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "embedding-attribute-to-nvfp4",
            metadata::description: "Canonical join-preserving projection from one selected Handle<E>-valued SimpleArchive attribute to NvFp4CosineSet<E>. Each distinct exact handle contributes one independently normalized, fixed-sign block-Hadamard-rotated, two-stage residual-NVFP4 row with an upward-rounded reconstruction norm and one L2 certificate covering both exact-source reconstruction and prescribed explicit-f32 decode.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

fn mapping_fragment<E: BlobEncoding>(attribute: Id, dimension: usize) -> Fragment {
    let attribute: Inline<GenId> = attribute.to_inline();
    entity! { _ @
        metadata::tag: KIND_COLLECTION_MAPPING,
        mapping_algorithm*: <EmbeddingAttributeToNvFp4Recipe as MetaDescribe>::describe(),
        metadata::attribute: attribute,
        metadata::blob_encoding*: E::describe(),
        nvfp4_dimension: dimension as u64,
    }
}

fn mapping_attribute(descriptor: &Fragment) -> Result<Id, CollectionOperationError> {
    let raw = triblespace_core::collection::descriptor::mapping_argument(
        descriptor.facts(),
        metadata::attribute.id(),
    )
    .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
    .ok_or_else(|| {
        CollectionOperationError::Fatal("NVFP4 mapping is missing metadata::attribute".to_owned())
    })?;
    Inline::<GenId>::new(raw)
        .try_from_inline::<Id>()
        .map_err(|source| {
            CollectionOperationError::Fatal(format!(
                "NVFP4 mapping has an invalid metadata::attribute: {source:?}"
            ))
        })
}

fn mapping_embedding_encoding(descriptor: &Fragment) -> Result<Id, CollectionOperationError> {
    let raw = triblespace_core::collection::descriptor::mapping_argument(
        descriptor.facts(),
        metadata::blob_encoding.id(),
    )
    .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
    .ok_or_else(|| {
        CollectionOperationError::Fatal(
            "NVFP4 mapping is missing metadata::blob_encoding".to_owned(),
        )
    })?;
    Inline::<GenId>::new(raw)
        .try_from_inline::<Id>()
        .map_err(|source| {
            CollectionOperationError::Fatal(format!(
                "NVFP4 mapping has an invalid metadata::blob_encoding: {source:?}"
            ))
        })
}

pub(crate) fn mapping_dimension(descriptor: &Fragment) -> Result<usize, CollectionOperationError> {
    mapping_dimension_facts(descriptor.facts())
}

fn mapping_dimension_facts(facts: &TribleSet) -> Result<usize, CollectionOperationError> {
    let raw =
        triblespace_core::collection::descriptor::mapping_argument(facts, nvfp4_dimension.id())
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?
            .ok_or_else(|| {
                CollectionOperationError::Fatal(
                    "NVFP4 mapping is missing nvfp4_dimension".to_owned(),
                )
            })?;
    let dimension = u64::try_from_inline(&Inline::<U256BE>::new(raw)).map_err(|source| {
        CollectionOperationError::Fatal(format!(
            "NVFP4 mapping has an invalid dimension: {source:?}"
        ))
    })?;
    let dimension = usize::try_from(dimension).map_err(|_| {
        CollectionOperationError::Fatal("NVFP4 mapping dimension exceeds usize".to_owned())
    })?;
    if dimension == 0 {
        return Err(CollectionOperationError::Fatal(
            "NVFP4 mapping dimension must be positive".to_owned(),
        ));
    }
    Ok(dimension)
}

impl<E> CollectionDerivation for NvFp4CosineSet<E>
where
    E: BlobEncoding,
    View<[f32]>: TryFromBlob<E>,
    <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
{
    type Source = SimpleArchive;
    type Argument = NvFp4EmbeddingAttribute;

    fn fragment(argument: &Self::Argument) -> Fragment {
        mapping_fragment::<E>(argument.attribute, argument.dimension.get())
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        let actual = triblespace_core::collection::descriptor::mapping_algorithm(target.facts())
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        if actual != Some(EMBEDDING_ATTRIBUTE_TO_NVFP4) {
            return Err(CollectionOperationError::Fatal(format!(
                "NVFP4 mapping algorithm {:?} does not match {EMBEDDING_ATTRIBUTE_TO_NVFP4:X}",
                actual.map(|id| format!("{id:X}")),
            )));
        }
        let actual_encoding = mapping_embedding_encoding(target)?;
        if actual_encoding != E::id() {
            return Err(CollectionOperationError::Fatal(format!(
                "NVFP4 mapping names embedding encoding {actual_encoding:X}, expected {:X}",
                E::id(),
            )));
        }
        let attribute = mapping_attribute(target)?;
        let dimension = mapping_dimension(target)?;
        Ok(NvFp4EmbeddingAttribute {
            attribute,
            dimension: NonZeroUsize::new(dimension).expect("checked positive"),
        })
    }

    fn map<R>(
        argument: &Self::Argument,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        triblespace_core::collection::simplearchive_union::validate_element(source)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;

        let mut handles = BTreeSet::new();
        for raw in source.bytes.as_ref().chunks_exact(TRIBLE_LEN) {
            if raw[16..32] == argument.attribute[..] {
                handles.insert(raw[32..64].try_into().expect("32-byte trible value"));
            }
        }

        let mut rows = Vec::with_capacity(handles.len());
        for raw in handles {
            let handle = Inline::<Handle<E>>::new(raw);
            let resident = reader
                .metadata(handle)
                .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
            if resident.is_none() {
                return Err(CollectionOperationError::MissingDependency(
                    Handle::<E>::to_hash(handle),
                ));
            }
            let blob: Blob<E> = reader
                .get(handle)
                .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
            let embedding = View::<[f32]>::try_from_blob(blob).map_err(|source| {
                CollectionOperationError::Fatal(format!(
                    "embedding {} cannot be decoded: {source}",
                    uppercase_hex(&raw),
                ))
            })?;
            rows.push(
                StoredRow::quantize(raw, embedding.as_ref(), argument.dimension.get())
                    .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?,
            );
        }
        encode_rows::<E>(argument.dimension.get(), rows)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }
}

impl<E> CollectionEncoding for NvFp4CosineSet<E>
where
    E: BlobEncoding,
{
    fn validate_descriptor(descriptor: &Fragment) -> Result<(), CollectionOperationError> {
        mapping_dimension(descriptor).map(|_| ())
    }

    fn validate_member<R>(
        descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let expected = mapping_dimension(descriptor)?;
        let layout = Layout::parse(member.bytes.as_ref())
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))?;
        if layout.dimension != expected {
            return Err(CollectionOperationError::Fatal(format!(
                "NVFP4 member dimension {} does not match descriptor {expected}",
                layout.dimension,
            )));
        }
        // Member admission validates the self-contained byte grammar only.
        // Replaying the deterministic mapping here would fetch and requantize
        // every exact source embedding, defeating both lazy reranking and
        // persisted derivation work. Locally mapped members are canonical by
        // construction. The network currently does not reuse unsigned remote
        // DERIVE equations; introducing that would require an independent
        // trust or recomputation boundary rather than stronger byte parsing.
        Ok(())
    }

    fn join_members<R>(
        descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let expected = mapping_dimension(descriptor)?;
        join_members(low, high, expected)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }
}

impl<E: BlobEncoding> fmt::Debug for NvFp4CosineIndex<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NvFp4CosineIndex")
            .field("members", &self.members.len())
            .field("dimension", &self.dimension)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    handle: [u8; HANDLE_LEN],
    upper: f64,
}

impl<E: BlobEncoding> NvFp4CosineIndex<E> {
    /// Validated physical segments retained by this lazy cover view.
    ///
    /// Accelerators may copy these planes into a resident representation. The
    /// returned views expose each segment's content identity plus its persisted
    /// reconstruction-norm and error-certificate planes. Row handles and exact
    /// source dependencies remain private to this search view.
    pub fn scan_segments(&self) -> Vec<ScanSegment<'_>> {
        self.members
            .iter()
            .map(|member| {
                let bytes = member.bytes.as_ref();
                let stages = std::array::from_fn(|stage| {
                    let layout = &member.layout.stages[stage];
                    ScanStage::new(
                        &bytes[layout.globals.clone()],
                        &bytes[layout.block_scales.clone()],
                        &bytes[layout.codes.clone()],
                    )
                });
                ScanSegment::new(
                    member.content_handle,
                    member.layout.rows,
                    member.layout.dimension,
                    member.layout.blocks_per_row,
                    member.layout.codes_per_row,
                    stages,
                    &bytes[member.layout.norms.clone()],
                    &bytes[member.layout.errors.clone()],
                )
                .expect("validated canonical NVFP4 member has valid scan planes")
            })
            .collect()
    }

    /// Logical embedding dimension shared by every member in the cover.
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Number of physical cover segments retained by this lazy view.
    pub fn segment_count(&self) -> usize {
        self.members.len()
    }

    /// Whether the cover has no rows at all.
    pub fn is_empty(&self) -> bool {
        self.members.iter().all(|member| member.layout.rows == 0)
    }
}

impl<E> NvFp4CosineIndex<E>
where
    E: BlobEncoding,
    View<[f32]>: TryFromBlob<E>,
    <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
{
    /// Exact top `k` cosine neighbours, ranked by score then handle.
    ///
    /// Candidate discovery scans the compact rows once. Original embeddings
    /// are fetched in descending certified-upper-bound order until the stored
    /// envelopes prove that no unseen row can enter the exact result.
    pub fn top_k<R, S>(
        &self,
        snapshot: &R,
        query: &[f32],
        k: usize,
        scanner: &S,
    ) -> Result<Vec<SimilarityHit<E>>, NvFp4Error>
    where
        R: BlobStoreGet,
        S: UpperScanner,
    {
        if k == 0 || self.is_empty() {
            return Ok(Vec::new());
        }
        let prepared = PreparedQuery::new(query, self.dimension)?;
        let candidates = self.candidates(&prepared, scanner)?;
        self.top_k_candidates(snapshot, &prepared, k, candidates)
    }

    fn top_k_candidates<R>(
        &self,
        snapshot: &R,
        prepared: &PreparedQuery,
        k: usize,
        mut candidates: Vec<Candidate>,
    ) -> Result<Vec<SimilarityHit<E>>, NvFp4Error>
    where
        R: BlobStoreGet,
    {
        candidates.sort_unstable_by(|left, right| {
            right
                .upper
                .total_cmp(&left.upper)
                .then_with(|| left.handle.cmp(&right.handle))
        });
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let wanted = k.min(candidates.len());
        let mut ranked = Vec::with_capacity(wanted + 1);
        let mut checked = 0usize;
        let mut target = wanted;
        while checked < candidates.len() {
            let end = target.min(candidates.len());
            for candidate in &candidates[checked..end] {
                ranked.push(self.exact_hit(snapshot, prepared, candidate.handle)?);
            }
            sort_hits(&mut ranked);
            ranked.truncate(wanted);
            checked = end;

            let Some(unseen) = candidates.get(checked) else {
                break;
            };
            if ranked.len() == wanted && ranked[wanted - 1].score > unseen.upper {
                // Strict comparison preserves the secondary handle ordering
                // when an unseen exact score could tie the current boundary.
                break;
            }
            target = target.saturating_mul(2).max(checked.saturating_add(1));
        }
        Ok(ranked)
    }

    /// Every embedding whose exact cosine is at least `floor`.
    ///
    /// Only rows whose conservative upper bound can cross the threshold cause
    /// an exact blob fetch. Returned rows are ranked identically to `top_k`.
    pub fn above<R, S>(
        &self,
        snapshot: &R,
        query: &[f32],
        floor: f64,
        scanner: &S,
    ) -> Result<Vec<SimilarityHit<E>>, NvFp4Error>
    where
        R: BlobStoreGet,
        S: UpperScanner,
    {
        if floor.is_nan() {
            return Err(NvFp4Error::new("cosine floor must not be NaN"));
        }
        if floor > 1.0 || self.is_empty() {
            return Ok(Vec::new());
        }
        let prepared = PreparedQuery::new(query, self.dimension)?;
        let candidates = self.candidates(&prepared, scanner)?;
        self.above_candidates(snapshot, &prepared, floor, candidates)
    }

    /// Freeze the exact above-threshold support for one probe blob as a query
    /// constraint.
    ///
    /// The probe need not be a member of this index. Fetch and decoding errors
    /// remain visible to the caller; an unavailable probe is not an empty
    /// mathematical neighbourhood. Candidate discovery and exact membership
    /// are delegated to [`Self::above`], so the resulting constraint contains
    /// every and only indexed handle whose exact cosine clears `floor`.
    pub fn similar_to<R, S>(
        &self,
        snapshot: &R,
        probe: Inline<Handle<E>>,
        variable: Variable<Handle<E>>,
        floor: f64,
        scanner: &S,
    ) -> Result<crate::constraint::SimilarTo<E>, NvFp4Error>
    where
        R: BlobStoreGet,
        S: UpperScanner,
    {
        let blob: Blob<E> = snapshot.get(probe).map_err(|source| {
            NvFp4Error::new(format!(
                "cannot fetch probe embedding {}: {source}",
                uppercase_hex(&probe.raw),
            ))
        })?;
        let query = View::<[f32]>::try_from_blob(blob).map_err(|source| {
            NvFp4Error::new(format!(
                "cannot decode probe embedding {}: {source}",
                uppercase_hex(&probe.raw),
            ))
        })?;
        let candidates = self
            .above(snapshot, query.as_ref(), floor, scanner)?
            .into_iter()
            .map(|hit| hit.embedding.raw)
            .collect();
        Ok(crate::constraint::SimilarTo::from_candidates(
            variable, candidates,
        ))
    }

    /// The `k` best rows by the cosine between `query` and each row's own
    /// two-stage NVFP4 reconstruction, ranked by score then handle, without
    /// fetching any source embedding.
    ///
    /// The whole answer for an index whose rows are not blob handles (the
    /// semantic index keys rows by attribute and entity); an approximation
    /// for one whose rows are, since [`Self::top_k`] then reranks exactly.
    /// A two-stage row's reconstruction cosine sits within about 1e-4 of the
    /// exact cosine (measured 2026-09-11 on 17,744 of our own texts).
    pub fn reconstructed_top_k(
        &self,
        query: &[f32],
        k: usize,
    ) -> Result<Vec<([u8; HANDLE_LEN], f64)>, NvFp4Error> {
        if k == 0 || self.is_empty() {
            return Ok(Vec::new());
        }
        let prepared = PreparedQuery::new(query, self.dimension)?;
        let coordinates = prepared.scan_coordinates();
        let segments = self.scan_segments();
        let mut scored = Vec::new();
        self.for_each_unique_row(|handle, member_index, _member, row| {
            let segment = segments[member_index];
            let norm = segment.row_certificate(row)?.reconstruction_norm();
            let score = if norm == 0.0 {
                0.0
            } else {
                (raw_dot_f64(coordinates, segment, row) / norm).clamp(-1.0, 1.0)
            };
            scored.push((handle, score));
            Ok(())
        })?;
        scored.sort_unstable_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        scored.truncate(k);
        Ok(scored)
    }

    fn above_candidates<R>(
        &self,
        snapshot: &R,
        prepared: &PreparedQuery,
        floor: f64,
        candidates: Vec<Candidate>,
    ) -> Result<Vec<SimilarityHit<E>>, NvFp4Error>
    where
        R: BlobStoreGet,
    {
        let mut exact = Vec::new();
        for candidate in candidates {
            if candidate.upper < floor {
                continue;
            }
            let hit = self.exact_hit(snapshot, prepared, candidate.handle)?;
            if hit.score >= floor {
                exact.push(hit);
            }
        }
        sort_hits(&mut exact);
        Ok(exact)
    }

    fn candidates<S>(
        &self,
        query: &PreparedQuery,
        scanner: &S,
    ) -> Result<Vec<Candidate>, NvFp4Error>
    where
        S: UpperScanner,
    {
        let segments = self.scan_segments();
        let mut offsets = Vec::with_capacity(segments.len());
        let mut physical_rows = 0usize;
        for segment in &segments {
            offsets.push(physical_rows);
            physical_rows = physical_rows
                .checked_add(segment.rows())
                .ok_or_else(|| NvFp4Error::new("NVFP4 physical row count overflows usize"))?;
        }
        let mut upper_raw_dots = vec![0.0; physical_rows];
        scanner
            .scan_upper(query.scan_query(), &segments, &mut upper_raw_dots)
            .map_err(|source| NvFp4Error::new(format!("NVFP4 upper scan failed: {source}")))?;

        let certificate = CandidateCertificate::new(query);
        let mut candidates = Vec::new();
        self.for_each_unique_row(|handle, member_index, _member, row| {
            let dot_index = offsets[member_index]
                .checked_add(row)
                .expect("validated physical row offset");
            let upper = certificate.certify_upper(
                segments[member_index].row_certificate(row)?,
                upper_raw_dots[dot_index],
            )?;
            candidates.push(Candidate { handle, upper });
            Ok(())
        })?;
        Ok(candidates)
    }

    fn exact_hit<R>(
        &self,
        snapshot: &R,
        query: &PreparedQuery,
        raw: [u8; HANDLE_LEN],
    ) -> Result<SimilarityHit<E>, NvFp4Error>
    where
        R: BlobStoreGet,
    {
        let embedding = Inline::<Handle<E>>::new(raw);
        let blob: Blob<E> = snapshot.get(embedding).map_err(|source| {
            NvFp4Error::new(format!(
                "cannot fetch exact embedding {}: {source}",
                uppercase_hex(&raw),
            ))
        })?;
        let candidate = View::<[f32]>::try_from_blob(blob).map_err(|source| {
            NvFp4Error::new(format!(
                "cannot decode exact embedding {}: {source}",
                uppercase_hex(&raw),
            ))
        })?;
        if candidate.len() != self.dimension {
            return Err(NvFp4Error::new(format!(
                "exact embedding {} has dimension {}, expected {}",
                uppercase_hex(&raw),
                candidate.len(),
                self.dimension,
            )));
        }
        let score = query.exact_cosine(candidate.as_ref())?;
        Ok(SimilarityHit { embedding, score })
    }

    fn for_each_unique_row<F>(&self, mut visit: F) -> Result<(), NvFp4Error>
    where
        F: FnMut([u8; HANDLE_LEN], usize, &Member, usize) -> Result<(), NvFp4Error>,
    {
        let mut heap = BinaryHeap::new();
        for (member, segment) in self.members.iter().enumerate() {
            if segment.layout.rows > 0 {
                let handle = segment
                    .layout
                    .handle(segment.bytes.as_ref(), 0)
                    .try_into()
                    .expect("32-byte handle");
                heap.push(Reverse((handle, member, 0usize)));
            }
        }

        let mut occurrences = Vec::new();
        while let Some(Reverse((handle, member, row))) = heap.pop() {
            occurrences.clear();
            occurrences.push((member, row));
            while heap
                .peek()
                .is_some_and(|Reverse((next, _, _))| next == &handle)
            {
                let Reverse((_, member, row)) = heap.pop().expect("peeked row");
                occurrences.push((member, row));
            }
            for &(other_member, other_row) in &occurrences[1..] {
                if !rows_equal(
                    self.members[member].bytes.as_ref(),
                    &self.members[member].layout,
                    row,
                    self.members[other_member].bytes.as_ref(),
                    &self.members[other_member].layout,
                    other_row,
                ) {
                    return Err(NvFp4Error::new(
                        "one embedding handle has conflicting rows across cover members",
                    ));
                }
            }
            visit(handle, member, &self.members[member], row)?;

            for &(member, row) in &occurrences {
                let next = row + 1;
                if next < self.members[member].layout.rows {
                    let next_handle = self.members[member]
                        .layout
                        .handle(self.members[member].bytes.as_ref(), next)
                        .try_into()
                        .expect("32-byte handle");
                    heap.push(Reverse((next_handle, member, next)));
                }
            }
        }
        Ok(())
    }
}

fn sort_hits<E: BlobEncoding>(hits: &mut [SimilarityHit<E>]) {
    hits.sort_unstable_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.embedding.raw.cmp(&right.embedding.raw))
    });
}

fn uppercase_hex(raw: &[u8]) -> String {
    use std::fmt::Write;

    let mut rendered = String::with_capacity(raw.len() * 2);
    for byte in raw {
        write!(&mut rendered, "{byte:02X}").expect("write to String");
    }
    rendered
}

impl<E> TryFromCover<NvFp4CosineSet<E>> for NvFp4CosineIndex<E>
where
    E: BlobEncoding,
    View<[f32]>: TryFromBlob<E>,
    <View<[f32]> as TryFromBlob<E>>::Error: fmt::Display + Send + Sync + 'static,
{
    type Error = NvFp4Error;

    fn try_from_cover<R>(
        cover: &Cover<NvFp4CosineSet<E>>,
        descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let dimension = mapping_dimension_facts(descriptor.facts())
            .map_err(|source| TryFromCoverError::View(NvFp4Error::new(source.to_string())))?;

        let mut members = Vec::with_capacity(cover.len());
        for handle in cover.members() {
            let member = Handle::<NvFp4CosineSet<E>>::to_hash(handle);
            let blob: Blob<NvFp4CosineSet<E>> = snapshot
                .get(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            let layout = Layout::parse(blob.bytes.as_ref()).map_err(TryFromCoverError::View)?;
            if layout.dimension != dimension {
                return Err(TryFromCoverError::View(NvFp4Error::new(format!(
                    "NVFP4 member dimension {} does not match descriptor {dimension}",
                    layout.dimension,
                ))));
            }
            members.push(Member {
                content_handle: handle.raw,
                bytes: blob.bytes,
                layout,
            });
        }
        Ok(Self {
            members,
            dimension,
            _encoding: PhantomData,
        })
    }
}

fn read_u64(bytes: &[u8], field: &str) -> Result<u64, NvFp4Error> {
    let raw: [u8; 8] = bytes
        .try_into()
        .map_err(|_| NvFp4Error::new(format!("invalid NVFP4 {field}")))?;
    Ok(u64::from_le_bytes(raw))
}

fn read_f32(bytes: &[u8]) -> f32 {
    f32::from_le_bytes(bytes.try_into().expect("four-byte float field"))
}

fn validate_nonnegative_f32(value: f32, field: &str) -> Result<(), NvFp4Error> {
    if !value.is_finite() || value.is_sign_negative() {
        return Err(NvFp4Error::new(format!(
            "NVFP4 {field} must be finite and nonnegative"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::Embedding;
    use ed25519_dalek::SigningKey;
    use futures::executor::block_on;
    use mary::nn::nvfp4_cosine::{CpuF64UpperScanner, ScanQuery};
    use std::cell::Cell;
    use std::error::Error;
    use triblespace_core::attribute::Attribute;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionPolicy, CollectionSnapshotExt, CollectionStoreExt,
    };
    use triblespace_core::inline::InlineEncoding;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStorePut, SnapshotSource};
    use triblespace_core::trible::Trible;

    struct Counting<'a, R> {
        inner: &'a R,
        gets: Cell<usize>,
    }

    impl<'a, R> Counting<'a, R> {
        fn new(inner: &'a R) -> Self {
            Self {
                inner,
                gets: Cell::new(0),
            }
        }

        fn gets(&self) -> usize {
            self.gets.get()
        }
    }

    impl<R: BlobStoreGet> BlobStoreGet for Counting<'_, R> {
        type GetError<E: Error + Send + Sync + 'static> = R::GetError<E>;

        fn get<T, S>(
            &self,
            handle: Inline<Handle<S>>,
        ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
        where
            S: BlobEncoding + 'static,
            T: TryFromBlob<S>,
            Handle<S>: InlineEncoding,
        {
            self.gets.set(self.gets.get() + 1);
            self.inner.get(handle)
        }
    }

    fn row(handle: u8, values: &[f32]) -> StoredRow {
        StoredRow::quantize([handle; HANDLE_LEN], values, values.len()).unwrap()
    }

    fn member(
        rows: impl IntoIterator<Item = StoredRow>,
        dimension: usize,
    ) -> Blob<NvFp4CosineSet<Embedding>> {
        encode_rows(dimension, rows.into_iter().collect()).unwrap()
    }

    fn embedding_facts(
        attribute: Id,
        rows: impl IntoIterator<Item = (u8, Inline<Handle<Embedding>>)>,
    ) -> TribleSet {
        let mut facts = TribleSet::new();
        for (entity, embedding) in rows {
            let entity = Id::new([entity; 16]).unwrap();
            facts.insert(&Trible::force(&entity, &attribute, &embedding));
        }
        facts
    }

    #[test]
    fn canonical_rows_and_join_are_aci() {
        let a = row(1, &[1.0, 0.0, 0.0]);
        let b = row(2, &[0.0, 1.0, 0.0]);
        let c = row(3, &[0.0, 0.0, 1.0]);
        let ab = member([b.clone(), a.clone(), a.clone()], 3);
        let ba = member([a.clone(), b.clone()], 3);
        assert_eq!(ab.bytes.as_ref(), ba.bytes.as_ref());

        let bc = member([b, c.clone()], 3);
        let c = member([c], 3);
        let ab_bc = join_members(&ab, &bc, 3).unwrap();
        let bc_ab = join_members(&bc, &ab, 3).unwrap();
        assert_eq!(ab_bc.bytes.as_ref(), bc_ab.bytes.as_ref());

        let idempotent = join_members(&ab_bc, &ab_bc, 3).unwrap();
        assert_eq!(idempotent.bytes.as_ref(), ab_bc.bytes.as_ref());

        let left = join_members(&join_members(&ab, &bc, 3).unwrap(), &c, 3).unwrap();
        let right = join_members(&ab, &join_members(&bc, &c, 3).unwrap(), 3).unwrap();
        assert_eq!(left.bytes.as_ref(), right.bytes.as_ref());
    }

    #[test]
    fn mapping_is_a_join_homomorphism_with_overlap_and_empty() {
        const DIMENSION: usize = 3;
        let attribute = Attribute::<Handle<Embedding>>::named("nvfp4-homomorphism");
        let argument = NvFp4EmbeddingAttribute::new(attribute.id(), DIMENSION).unwrap();
        let mut store = MemoryRepo::default();
        let first = store.put::<Embedding, _>(vec![1.0f32, 0.0, 0.0]).unwrap();
        let shared = store.put::<Embedding, _>(vec![0.0f32, 1.0, 0.0]).unwrap();
        let last = store.put::<Embedding, _>(vec![0.0f32, 0.0, 1.0]).unwrap();
        let snapshot = store.snapshot().unwrap();

        let left = embedding_facts(attribute.id(), [(1, first), (2, shared), (3, first)]);
        let right = embedding_facts(attribute.id(), [(4, shared), (5, last)]);
        let mut union = left.clone();
        union += right.clone();

        let mapped_left =
            NvFp4CosineSet::<Embedding>::map(&argument, &left.to_blob(), &snapshot).unwrap();
        let mapped_right =
            NvFp4CosineSet::<Embedding>::map(&argument, &right.to_blob(), &snapshot).unwrap();
        let mapped_union =
            NvFp4CosineSet::<Embedding>::map(&argument, &union.to_blob(), &snapshot).unwrap();
        let joined = join_members(&mapped_left, &mapped_right, DIMENSION).unwrap();
        assert_eq!(mapped_union.bytes.as_ref(), joined.bytes.as_ref());

        let empty =
            NvFp4CosineSet::<Embedding>::map(&argument, &TribleSet::new().to_blob(), &snapshot)
                .unwrap();
        let with_empty = join_members(&mapped_left, &empty, DIMENSION).unwrap();
        assert_eq!(mapped_left.bytes.as_ref(), with_empty.bytes.as_ref());
    }

    struct UnexpectedScanner;

    impl UpperScanner for UnexpectedScanner {
        type Error = std::convert::Infallible;

        fn scan_upper(
            &self,
            _query: ScanQuery<'_>,
            _segments: &[ScanSegment<'_>],
            _upper_raw_dots: &mut [f64],
        ) -> Result<(), Self::Error> {
            panic!("logically empty covers must not invoke their scanner")
        }
    }

    #[test]
    fn logically_empty_covers_short_circuit_before_query_preparation() {
        const DIMENSION: usize = 3;
        let empty_member = member(Vec::new(), DIMENSION);
        let indices = [
            NvFp4CosineIndex {
                members: Vec::new(),
                dimension: DIMENSION,
                _encoding: PhantomData::<Embedding>,
            },
            NvFp4CosineIndex {
                members: vec![Member {
                    content_handle: empty_member.get_handle().raw,
                    layout: Layout::parse(empty_member.bytes.as_ref()).unwrap(),
                    bytes: empty_member.bytes.clone(),
                }],
                dimension: DIMENSION,
                _encoding: PhantomData::<Embedding>,
            },
        ];
        let mut store = MemoryRepo::default();
        let snapshot = store.snapshot().unwrap();

        for index in indices {
            assert!(index
                .top_k(&snapshot, &[f32::NAN], 1, &UnexpectedScanner)
                .unwrap()
                .is_empty());
            assert!(index
                .above(&snapshot, &[f32::NAN], 0.0, &UnexpectedScanner)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn lazy_view_and_candidate_scan_do_not_require_exact_sources() {
        const DIMENSION: usize = 3;
        let authority = SigningKey::from_bytes(&[73; 32]);
        let root = authority.verifying_key();
        let policy =
            CollectionPolicy::new(AdmissionPolicy::direct(root), AdmissionPolicy::direct(root));
        let attribute = Attribute::<Handle<Embedding>>::named("nvfp4-lazy-attachment");
        let mut source_store = MemoryRepo::default();
        let exact = source_store
            .put::<Embedding, _>(vec![1.0f32, 0.0, 0.0])
            .unwrap();
        let source = source_store
            .collection("nvfp4-lazy-source", policy.clone())
            .unwrap();
        let target = source_store
            .derive::<NvFp4CosineSet<Embedding>>(
                source,
                NvFp4EmbeddingAttribute::new(attribute.id(), DIMENSION).unwrap(),
                policy,
            )
            .unwrap();
        source_store
            .commit(
                source,
                &authority,
                Fragment::from(embedding_facts(attribute.id(), [(1, exact)])),
            )
            .unwrap();
        let source_snapshot = source_store.snapshot().unwrap();
        let support = source.admitted(&source_snapshot).unwrap();
        drop(source_snapshot);
        let source_snapshot =
            block_on(source_store.maintain_exact(target, &authority, &support)).unwrap();
        let collection = source_snapshot.collection_exact(target, &support).unwrap();
        let target_cover = collection.cover().clone();
        let source_snapshot = collection.snapshot();

        // Copy only the target descriptor and compact member into a fresh
        // store. The exact embedding blob is deliberately absent.
        let descriptor: Blob<SimpleArchive> = source_snapshot.get(target.handle()).unwrap();
        let descriptor_fragment =
            Fragment::from(TribleSet::try_from_blob(descriptor.clone()).unwrap());
        let member_handle = target_cover.members().next().unwrap();
        let compact: Blob<NvFp4CosineSet<Embedding>> = source_snapshot.get(member_handle).unwrap();
        let mut sparse = MemoryRepo::default();
        assert_eq!(
            sparse.put::<SimpleArchive, _>(descriptor).unwrap(),
            target.handle(),
        );
        assert_eq!(
            sparse.put::<NvFp4CosineSet<Embedding>, _>(compact).unwrap(),
            member_handle,
        );
        let sparse = sparse.snapshot().unwrap();
        assert!(sparse.metadata(exact).unwrap().is_none());

        let counted = Counting::new(&sparse);
        let index = NvFp4CosineIndex::<Embedding>::try_from_cover(
            &target_cover,
            &descriptor_fragment,
            &counted,
        )
        .unwrap();
        assert_eq!(counted.gets(), target_cover.len());
        let prepared = PreparedQuery::new(&[1.0, 0.0, 0.0], DIMENSION).unwrap();
        assert_eq!(
            index
                .candidates(&prepared, &CpuF64UpperScanner)
                .unwrap()
                .len(),
            1,
        );
        assert_eq!(counted.gets(), target_cover.len());
    }

    #[test]
    fn zero_row_has_stable_canonical_member_hash() {
        let blob = member([row(0x2a, &[0.0])], 1);
        assert_eq!(blob.bytes.len(), 352);
        assert_eq!(
            uppercase_hex(&blob.get_handle().raw),
            "305800D6C5020C39DBCC988FF4AC43B1D0302B5C4DCC5AAFEDF8D6611AFAEB1B",
        );
    }

    #[test]
    fn mary_scan_seam_preserves_segment_identity_and_cover_deduplication() {
        const DIMENSION: usize = 37;
        let rows = [
            row(
                1,
                &(0..DIMENSION).map(|index| index as f32).collect::<Vec<_>>(),
            ),
            row(
                2,
                &(0..DIMENSION)
                    .map(|index| (index as f32 - 11.0).sin())
                    .collect::<Vec<_>>(),
            ),
            row(
                3,
                &(0..DIMENSION)
                    .map(|index| (index as f32 + 3.0).cos())
                    .collect::<Vec<_>>(),
            ),
        ];
        let low = member(rows[..2].iter().cloned(), DIMENSION);
        let high = member(rows[1..].iter().cloned(), DIMENSION);
        let index = NvFp4CosineIndex {
            members: [&low, &high]
                .into_iter()
                .map(|blob| Member {
                    content_handle: blob.get_handle().raw,
                    layout: Layout::parse(blob.bytes.as_ref()).unwrap(),
                    bytes: blob.bytes.clone(),
                })
                .collect(),
            dimension: DIMENSION,
            _encoding: PhantomData::<Embedding>,
        };
        let segments = index.scan_segments();
        assert_eq!(segments[0].identity(), low.get_handle().raw);
        assert_eq!(segments[1].identity(), high.get_handle().raw);

        let query: Vec<_> = (0..DIMENSION)
            .map(|index| ((index * 17 + 5) as f32).sin())
            .collect();
        let prepared = PreparedQuery::new(&query, DIMENSION).unwrap();
        let candidates = index.candidates(&prepared, &CpuF64UpperScanner).unwrap();
        assert_eq!(candidates.len(), 3, "the overlapping row is deduplicated");
    }

    #[test]
    fn malformed_or_conflicting_members_are_rejected() {
        let one = row(1, &[1.0, 0.0]);
        let conflicting = row(1, &[0.0, 1.0]);
        assert!(encode_rows::<Embedding>(2, vec![one, conflicting]).is_err());

        let mut malformed = member([row(2, &[1.0, 1.0])], 2).bytes.as_ref().to_vec();
        malformed[0] = 3;
        assert!(Layout::parse(&malformed).is_ok());
        let last_code = Layout::parse(&malformed).unwrap().stages[0].codes.start;
        malformed[last_code] = 0x08;
        assert!(Layout::parse(&malformed).is_err());
    }
}
