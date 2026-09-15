mod succinctarchiveconstraint;
mod succinctarchiverangeconstraint;
mod unionarchive;
mod universe;

// Internal codec for the one public, architecture-independent raw layout. Its
// schema identity lives on `SuccinctArchiveBlob`; native runtime arenas and
// source-bound Rank9 accelerated roots never pass through this module.
mod portable;

use crate::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use crate::blob::Blob;
use crate::blob::BlobEncoding;
use crate::blob::TryFromBlob;
use crate::id::id_from_value;
use crate::id::id_into_value;
use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::encodings::UnknownInline;
use crate::inline::Encodes;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::RawInline;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
use crate::query::TriblePattern;
use crate::trible::Fragment;
use crate::trible::Trible;
use crate::trible::TribleSet;
use succinctarchiveconstraint::base_range;

/// Constraint implementation used by [`SuccinctArchive::pattern`].
pub use succinctarchiveconstraint::SuccinctArchiveConstraint;

/// Inclusive value-range constraint returned by [`SuccinctArchive::value_in_range`].
pub use succinctarchiverangeconstraint::SuccinctArchiveRangeConstraint;

/// Storage-neutral logical union over attached Succinct archive shards.
pub use unionarchive::{UnionArchive, UnionArchiveConstraint};

/// Re-export all universe types and traits.
pub use universe::*;

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::convert::TryInto;
use std::iter;
use std::sync::{Arc, OnceLock};

use itertools::Itertools;

use anybytes::area::{ByteArea, Section, SectionHandle, SectionWriter};
use anybytes::Bytes;
use jerky::bit_vector::rank9sel::Rank9SelIndex;
use jerky::bit_vector::Access;
use jerky::bit_vector::BitVector;
use jerky::bit_vector::BitVectorBuilder;
use jerky::bit_vector::BitVectorData;
use jerky::bit_vector::BitVectorDataMeta;
use jerky::bit_vector::NumBits;
use jerky::bit_vector::Rank;
use jerky::bit_vector::Select;
use jerky::bit_vector::{BitVectorIndex, NoIndex};
use jerky::char_sequences::wavelet_matrix::WaveletMatrixMeta;
use jerky::char_sequences::{WaveletMatrix, WaveletMatrixBuilder};
use jerky::serialization::{Metadata, Serializable};

/// Blob encoding for a succinct archive based on *The Ring* (Arroyuelo
/// et al., 2024) — a compact index that supports worst-case optimal
/// joins over triples in almost no extra space.
///
/// The Ring treats each triple (E, A, V) as a bidirectional cyclic
/// string of length 3. Two rings — forward (E→A→V) and reverse
/// (E→V→A) — cover all six attribute orderings using only two sorted
/// rotations each. The last column of each rotation is stored as a
/// wavelet matrix, enabling rank/select navigation between columns
/// without materialising six separate indexes.
///
/// Build from a [`TribleSet`] via [`IntoBlob`](crate::blob::IntoBlob), then query through
/// [`SuccinctArchive`] and its [`Constraint`](crate::query::Constraint)
/// implementation. Suitable for large, read-heavy, mostly-static
/// datasets where compact storage matters more than incremental updates.
pub struct SuccinctArchiveBlob;

impl BlobEncoding for SuccinctArchiveBlob {}

impl MetaDescribe for SuccinctArchiveBlob {
    fn describe() -> Fragment {
        // Minted with `trible genid` on 2026-08-08 for the incompatible
        // portable v2 format. Native v1 has no compatibility reader.
        let id: Id = id_hex!("D187C3155DD368B784E1F53DBE8C7513");
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "succinctarchive",
                metadata::description: "Portable canonical Ring archive for fast offline trible queries. The architecture-independent bytes contain the ordered raw domain and logical prefix, pair-change, and wavelet bit vectors. Query runtimes and source-bound Rank9 accelerated roots are reproducibly derived and excluded from its content identity.",
                metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Failure while deriving a canonical raw [`SuccinctArchiveBlob`] directly
/// from a [`SimpleArchive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccinctArchiveRawBuildError {
    /// The source bytes are not a canonical `SimpleArchive`.
    Source(UnarchiveError),
    /// The in-memory raw builder uses `u32` row offsets. Larger individual
    /// source blobs require the future external-memory construction path.
    TooManyRows(usize),
    /// The in-memory raw builder uses `u32` ordered-domain codes. Larger
    /// domains require the future external-memory construction path.
    DomainTooWide(usize),
    /// An internal checked layout or canonical-section invariant failed.
    Construction(String),
}

impl From<UnarchiveError> for SuccinctArchiveRawBuildError {
    fn from(error: UnarchiveError) -> Self {
        Self::Source(error)
    }
}

impl std::fmt::Display for SuccinctArchiveRawBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(error) => write!(formatter, "invalid SimpleArchive source: {error}"),
            Self::TooManyRows(rows) => write!(
                formatter,
                "SimpleArchive contains {rows} rows, exceeding the in-memory u32 raw-builder limit"
            ),
            Self::DomainTooWide(values) => write!(
                formatter,
                "succinct domain contains {values} values, exceeding the in-memory u32 raw-builder limit"
            ),
            Self::Construction(message) => {
                write!(
                    formatter,
                    "cannot construct portable succinct archive: {message}"
                )
            }
        }
    }
}

impl std::error::Error for SuccinctArchiveRawBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::TooManyRows(_) | Self::DomainTooWide(_) | Self::Construction(_) => None,
        }
    }
}

/// Failure while computing the canonical union of raw
/// [`SuccinctArchiveBlob`] artifacts.
///
/// Input validation is deliberately distinct from output geometry. A
/// capacity-looking failure while decoding one persisted input is still an
/// [`InvalidInput`](Self::InvalidInput); only growth of the decoded
/// union can produce [`DomainTooWide`](Self::DomainTooWide) or
/// [`TooManyRows`](Self::TooManyRows).
#[derive(Debug)]
pub enum SuccinctArchiveRawMergeError {
    /// One persisted input failed framing or source decoding.
    InvalidInput {
        /// Zero-based input position in the supplied segment slice.
        index: usize,
        /// Exact validation failure for that input.
        source: SuccinctArchiveError,
    },
    /// The decoded union needs more than the raw format's `u32` domain.
    DomainTooWide,
    /// The decoded union needs more than the raw format's `u32` row space.
    TooManyRows,
    /// Encoding the representable merged result violated an internal format
    /// invariant.
    Construction(SuccinctArchiveError),
}

impl std::fmt::Display for SuccinctArchiveRawMergeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput { index, source } => {
                write!(
                    formatter,
                    "raw merge input segment {index} is invalid: {source}"
                )
            }
            Self::DomainTooWide => formatter
                .write_str("merged succinct domain exceeds the raw format's u32 code space"),
            Self::TooManyRows => formatter
                .write_str("merged succinct archive exceeds the raw format's u32 row-offset space"),
            Self::Construction(source) => {
                write!(formatter, "cannot encode merged succinct archive: {source}")
            }
        }
    }
}

impl std::error::Error for SuccinctArchiveRawMergeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInput { source, .. } | Self::Construction(source) => Some(source),
            Self::DomainTooWide | Self::TooManyRows => None,
        }
    }
}

impl SuccinctArchiveBlob {
    /// Derives the canonical portable Ring artifact directly from one
    /// canonical `SimpleArchive` blob.
    ///
    /// The source is validated in its existing 64-byte EAV order, then mapped
    /// into one ordered raw-value domain. Five stable counting-sort passes
    /// derive the remaining Ring rotations while their prefixes, pair-change
    /// masks, and minimal-width wavelet planes are written directly into the
    /// final portable allocation. The method constructs neither a six-PATCH
    /// [`TribleSet`], a native [`SuccinctArchive`] query arena, nor a source-bound
    /// Rank9 accelerator. The returned [`Blob`] hashes the completed portable
    /// bytes exactly once and caches that handle.
    ///
    /// The in-memory implementation uses `u32` codes and offsets. A source
    /// with more than `u32::MAX` rows or domain values is rejected explicitly;
    /// such pathological single artifacts need an external-memory builder.
    pub fn build_from_simple_archive(
        source: &Blob<SimpleArchive>,
    ) -> Result<Blob<Self>, SuccinctArchiveRawBuildError> {
        Self::build_from_simple_archive_using(source, portable::encode_canonical_eav_u32)
    }

    /// Builds the same canonical raw artifact with accelerated wavelet packing.
    ///
    /// Domain construction, sorting and section layout remain on the CPU. The
    /// backend contract and validation are those of [`WaveletMatrixFreezeBackend`].
    /// A returned backend error is a construction failure; callers may retry the
    /// canonical CPU builder. Allocation failure, panic and OOM are not caught.
    pub fn build_from_simple_archive_with_backend<B>(
        source: &Blob<SimpleArchive>,
        backend: &B,
    ) -> Result<Blob<Self>, SuccinctArchiveRawBuildError>
    where
        B: WaveletMatrixFreezeBackend,
        B::Error: std::fmt::Display,
    {
        Self::build_from_simple_archive_using(source, |domain, rows| {
            portable::encode_canonical_eav_u32_with_backend(domain, rows, backend)
        })
    }

    fn build_from_simple_archive_using(
        source: &Blob<SimpleArchive>,
        encode: impl FnOnce(&[RawInline], Vec<[u32; 3]>) -> Result<Vec<u8>, portable::PortableError>,
    ) -> Result<Blob<Self>, SuccinctArchiveRawBuildError> {
        let bytes = source.bytes.as_ref();
        if bytes.len() % 64 != 0 {
            return Err(UnarchiveError::BadArchive.into());
        }
        let row_count = bytes.len() / 64;
        if row_count > u32::MAX as usize {
            return Err(SuccinctArchiveRawBuildError::TooManyRows(row_count));
        }

        let domain_capacity = row_count.checked_mul(3).ok_or_else(|| {
            SuccinctArchiveRawBuildError::Construction(
                "source-domain capacity overflows usize".to_owned(),
            )
        })?;
        let mut domain = Vec::with_capacity(domain_capacity);
        let mut previous: Option<&[u8]> = None;
        for chunk in bytes.chunks_exact(64) {
            let row: &[u8; 64] = chunk.try_into().expect("exact SimpleArchive row");
            if Trible::as_transmute_force_raw(row).is_none() {
                return Err(UnarchiveError::BadTrible.into());
            }
            if let Some(previous) = previous {
                if previous == chunk {
                    return Err(UnarchiveError::BadCanonicalizationRedundancy.into());
                }
                if previous > chunk {
                    return Err(UnarchiveError::BadCanonicalizationOrdering.into());
                }
            }
            previous = Some(chunk);

            let entity: &[u8; 16] = row[..16].try_into().expect("entity width");
            let attribute: &[u8; 16] = row[16..32].try_into().expect("attribute width");
            domain.push(id_into_value(entity));
            domain.push(id_into_value(attribute));
            domain.push(row[32..].try_into().expect("value width"));
        }
        domain.sort_unstable();
        domain.dedup();
        domain.shrink_to_fit();
        if domain.len() > u32::MAX as usize {
            return Err(SuccinctArchiveRawBuildError::DomainTooWide(domain.len()));
        }

        let mut eav_rows = Vec::with_capacity(row_count);
        for chunk in bytes.chunks_exact(64) {
            let row: &[u8; 64] = chunk.try_into().expect("exact SimpleArchive row");
            let entity: &[u8; 16] = row[..16].try_into().expect("entity width");
            let attribute: &[u8; 16] = row[16..32].try_into().expect("attribute width");
            let entity = id_into_value(entity);
            let attribute = id_into_value(attribute);
            let value: RawInline = row[32..].try_into().expect("value width");
            eav_rows.push([
                u32::try_from(
                    domain
                        .binary_search(&entity)
                        .expect("source entity was inserted into the domain"),
                )
                .expect("domain width checked above"),
                u32::try_from(
                    domain
                        .binary_search(&attribute)
                        .expect("source attribute was inserted into the domain"),
                )
                .expect("domain width checked above"),
                u32::try_from(
                    domain
                        .binary_search(&value)
                        .expect("source value was inserted into the domain"),
                )
                .expect("domain width checked above"),
            ]);
        }

        let portable = encode(&domain, eav_rows)
            .map_err(|error| SuccinctArchiveRawBuildError::Construction(error.to_string()))?;
        Ok(Blob::new(Bytes::from(portable)))
    }

    /// Computes the canonical set union of portable succinct archive blobs.
    ///
    /// Every input receives checked framing and its EAV source is decoded,
    /// without rederiving its other rotations or pair-change masks. Their
    /// ordered domains are merged once, archive-local EAV codes are remapped,
    /// and the sorted runs are k-way merged with duplicate rows removed. The
    /// shared raw writer emits the final portable bytes directly; no input or
    /// output query runtime, Rank9 accelerator, or intermediate finished blob
    /// is constructed. [`Blob::new`] hashes the result exactly once.
    ///
    /// Input order and duplicate segments do not affect the result. An empty
    /// slice produces the canonical empty archive. The in-memory path uses
    /// `u32` codes and row offsets; an external-memory spool remains necessary
    /// for a single merged artifact exceeding those limits.
    pub fn merge(segments: &[Blob<Self>]) -> Result<Blob<Self>, SuccinctArchiveRawMergeError> {
        Self::merge_using(segments, portable::encode_canonical_eav_u32)
    }

    /// Computes the canonical raw union with accelerated wavelet packing.
    ///
    /// Inputs receive exactly the same framing and source decoding as
    /// [`Self::merge`]. Only the final wavelet packing uses the supplied backend;
    /// no native query arena or Rank9 accelerator is constructed.
    pub fn merge_with_backend<B>(
        segments: &[Blob<Self>],
        backend: &B,
    ) -> Result<Blob<Self>, SuccinctArchiveRawMergeError>
    where
        B: WaveletMatrixFreezeBackend,
        B::Error: std::fmt::Display,
    {
        Self::merge_using(segments, |domain, rows| {
            portable::encode_canonical_eav_u32_with_backend(domain, rows, backend)
        })
    }

    fn merge_using(
        segments: &[Blob<Self>],
        encode: impl FnOnce(&[RawInline], Vec<[u32; 3]>) -> Result<Vec<u8>, portable::PortableError>,
    ) -> Result<Blob<Self>, SuccinctArchiveRawMergeError> {
        let mut decoded = Vec::with_capacity(segments.len());
        for (index, segment) in segments.iter().enumerate() {
            decoded.push(
                portable::decode_eav(segment.bytes.as_ref()).map_err(|error| {
                    SuccinctArchiveRawMergeError::InvalidInput {
                        index,
                        source: raw_merge_error(format!("source decoding failed: {error}")),
                    }
                })?,
            );
        }

        let (domain, rows) = merge_raw_eav_parts(decoded)?;
        let bytes = encode(&domain, rows).map_err(|error| {
            SuccinctArchiveRawMergeError::Construction(raw_merge_error(error.to_string()))
        })?;
        Ok(Blob::new(Bytes::from(bytes)))
    }

    /// Explicitly audits all semantic/canonical invariants of a raw archive.
    /// Ordinary attachment and raw MERGE do not perform this rederivation.
    pub fn validate(raw: &Blob<Self>) -> Result<(), SuccinctArchiveError> {
        portable::parse(raw.bytes.as_ref())
            .and_then(|view| view.prove_canonical())
            .map_err(|error| SuccinctArchiveError(portable_codec_error(error)))
    }
}

/// Complete Rank9-accelerated Merkle encoding of one [`SuccinctArchiveBlob`].
///
/// The first 32 bytes are the source archive's content handle. Keeping that
/// dependency at aligned offset zero makes ordinary blob reachability follow
/// the accelerator to its raw archive without format-specific traversal code.
/// The remaining bytes are native-ABI Rank9 payloads and their relative
/// section table. The root's identity covers both parts through the child
/// handle; a different ABI may reproducibly derive its own complete root for
/// the same logical set.
pub struct Rank9AcceleratedSuccinctArchiveBlob;

impl BlobEncoding for Rank9AcceleratedSuccinctArchiveBlob {}

/// Rank9-accelerated SuccinctArchive encoding for 32-bit little-endian targets.
///
/// Minted with `trible genid` on 2026-08-29. Encoding identity is
/// ABI-qualified because the canonical root bytes contain native Rank9 words.
pub const RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_32_LE: Id =
    id_hex!("1597B627B9F5257C3BA2593E9AD21D5D");

/// Rank9-accelerated SuccinctArchive encoding for 32-bit big-endian targets.
pub const RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_32_BE: Id =
    id_hex!("2B8E6864C14EBCCA42D864CCE9B3CA8D");

/// Rank9-accelerated SuccinctArchive encoding for 64-bit little-endian targets.
pub const RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_64_LE: Id =
    id_hex!("5D034B396CCD0E39CADDAD7FDFEC45FC");

/// Rank9-accelerated SuccinctArchive encoding for 64-bit big-endian targets.
pub const RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_64_BE: Id =
    id_hex!("0E0CC312AA0157D3377100D4010BEEAB");

#[cfg(all(target_pointer_width = "32", target_endian = "little"))]
const CURRENT_RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB: Id =
    RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_32_LE;
#[cfg(all(target_pointer_width = "32", target_endian = "big"))]
const CURRENT_RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB: Id =
    RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_32_BE;
#[cfg(all(target_pointer_width = "64", target_endian = "little"))]
const CURRENT_RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB: Id =
    RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_64_LE;
#[cfg(all(target_pointer_width = "64", target_endian = "big"))]
const CURRENT_RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB: Id =
    RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB_V1_64_BE;

/// Encoding id for the exact native ABI supported by this build.
pub const fn current_rank9_accelerated_succinctarchive_blob() -> Id {
    CURRENT_RANK9_ACCELERATED_SUCCINCTARCHIVE_BLOB
}

impl MetaDescribe for Rank9AcceleratedSuccinctArchiveBlob {
    fn describe() -> Fragment {
        let id = current_rank9_accelerated_succinctarchive_blob();
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "rank9-accelerated-succinctarchive",
                metadata::description: "ABI-qualified accelerated SuccinctArchive encoding. Its first 32 bytes name one exact portable SuccinctArchiveBlob and the remaining bytes carry that source's canonical native Rank9/select payload. A reader resolves the named raw blob to construct the query runtime.",
                metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

impl Rank9AcceleratedSuccinctArchiveBlob {
    /// Read the canonical raw-archive handle embedded at offset zero.
    ///
    /// This deliberately performs only the small, format-level header check
    /// needed to pair unordered manifest handles. Full native-ABI and Rank9
    /// validation remains the responsibility of
    /// [`SuccinctArchive::from_accelerated_parts`].
    pub fn source_handle(
        blob: &Blob<Self>,
    ) -> Result<Inline<Handle<SuccinctArchiveBlob>>, SuccinctArchiveError> {
        if blob.bytes.len() < std::mem::size_of::<Rank9IndexHeader>() {
            return Err(SuccinctArchiveError(invalid_rank9_metadata(
                "Rank9 index blob is truncated before its source header",
            )));
        }
        let header = *blob
            .bytes
            .clone()
            .slice(0..std::mem::size_of::<Rank9IndexHeader>())
            .view::<Rank9IndexHeader>()
            .map_err(|error| {
                SuccinctArchiveError(invalid_rank9_metadata(format!(
                    "cannot read Rank9 source header: {error}"
                )))
            })?;
        if header.marker != RANK9_INDEX_MARKER
            || header.version != RANK9_INDEX_VERSION
            || header.flags != RANK9_INDEX_FLAGS
            || header.word_bytes != std::mem::size_of::<usize>() as u8
            || header.endian != RANK9_INDEX_ENDIAN
            || header.reserved != [0; 6]
        {
            return Err(SuccinctArchiveError(invalid_rank9_metadata(
                "unsupported Rank9 index header or native ABI",
            )));
        }
        Ok(Inline::new(header.source))
    }
}

#[derive(Debug, Clone, Copy, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
#[repr(C)]
/// Process-local handles into the rebuilt query arena.
///
/// This native metadata is never serialized in [`SuccinctArchiveBlob`] and is
/// not a compatibility format. The portable blob identity contains only the
/// ordered raw domain and logical bit-vector words.
struct SuccinctArchiveMeta<D: Metadata> {
    /// Domain (universe) metadata — maps integer codes to raw values.
    pub domain: D,
    /// Entity-axis prefix bit vector metadata.
    pub e_a: BitVectorDataMeta,
    /// Attribute-axis prefix bit vector metadata.
    pub a_a: BitVectorDataMeta,
    /// Inline-axis prefix bit vector metadata.
    pub v_a: BitVectorDataMeta,
    /// First-occurrence markers for (entity, attribute) pairs.
    pub changed_e_a: BitVectorDataMeta,
    /// First-occurrence markers for (entity, value) pairs.
    pub changed_e_v: BitVectorDataMeta,
    /// First-occurrence markers for (attribute, entity) pairs.
    pub changed_a_e: BitVectorDataMeta,
    /// First-occurrence markers for (attribute, value) pairs.
    pub changed_a_v: BitVectorDataMeta,
    /// First-occurrence markers for (value, entity) pairs.
    pub changed_v_e: BitVectorDataMeta,
    /// First-occurrence markers for (value, attribute) pairs.
    pub changed_v_a: BitVectorDataMeta,
    /// Forward ring: EAV last-column wavelet matrix metadata.
    pub eav_c: WaveletMatrixMeta,
    /// Forward ring: VEA last-column wavelet matrix metadata.
    pub vea_c: WaveletMatrixMeta,
    /// Forward ring: AVE last-column wavelet matrix metadata.
    pub ave_c: WaveletMatrixMeta,
    /// Reverse ring: VAE last-column wavelet matrix metadata.
    pub vae_c: WaveletMatrixMeta,
    /// Reverse ring: EVA last-column wavelet matrix metadata.
    pub eva_c: WaveletMatrixMeta,
    /// Reverse ring: AEV last-column wavelet matrix metadata.
    pub aev_c: WaveletMatrixMeta,
}

/// Stable marker for the source-bound Rank9 accelerated-root format, minted with
/// `trible genid` on 2026-07-13.
const RANK9_INDEX_MARKER: [u8; 16] = [
    0xFE, 0xFF, 0x44, 0xEF, 0x2D, 0x61, 0xBD, 0x45, 0x0F, 0xE2, 0x54, 0xA0, 0xAA, 0xE8, 0xB4, 0xA5,
];
const RANK9_INDEX_VERSION: u32 = 1;
const RANK9_INDEX_FLAGS: u32 = 0;
#[cfg(target_endian = "little")]
const RANK9_INDEX_ENDIAN: u8 = 1;
#[cfg(target_endian = "big")]
const RANK9_INDEX_ENDIAN: u8 = 2;
const TOP_LEVEL_RANK9_INDEX_COUNT: usize = 9;

#[derive(Debug, Clone, Copy, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
#[repr(C)]
struct Rank9IndexHeader {
    source: [u8; 32],
    marker: [u8; 16],
    version: u32,
    flags: u32,
    word_bytes: u8,
    endian: u8,
    reserved: [u8; 6],
}

#[derive(Debug, Clone, Copy, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
#[repr(C)]
struct Rank9IndexFooter {
    marker: [u8; 16],
    version: u32,
    flags: u32,
    word_bytes: u8,
    endian: u8,
    reserved: [u8; 6],
    indexes: SectionHandle<SectionHandle<usize>>,
}

fn invalid_rank9_metadata(message: impl Into<String>) -> jerky::error::Error {
    jerky::error::Error::invalid_metadata(message.into())
}

fn checked_align_up(value: usize, align: usize) -> Result<usize, jerky::error::Error> {
    debug_assert!(align.is_power_of_two());
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or_else(|| invalid_rank9_metadata("succinct archive alignment overflow"))
}

fn checked_section_range<T>(
    handle: SectionHandle<T>,
    limit: usize,
    description: &str,
) -> Result<std::ops::Range<usize>, jerky::error::Error> {
    let element_size = std::mem::size_of::<T>();
    let alignment = std::mem::align_of::<T>();
    if handle.offset % alignment != 0 {
        return Err(invalid_rank9_metadata(format!(
            "{description} offset {} is not aligned to {alignment}",
            handle.offset
        )));
    }
    if element_size != 0 && handle.len % element_size != 0 {
        return Err(invalid_rank9_metadata(format!(
            "{description} length {} is not a multiple of {element_size}",
            handle.len
        )));
    }
    let end = handle
        .offset
        .checked_add(handle.len)
        .ok_or_else(|| invalid_rank9_metadata(format!("{description} range overflow")))?;
    if end > limit {
        return Err(invalid_rank9_metadata(format!(
            "{description} range {}..{end} exceeds limit {limit}",
            handle.offset
        )));
    }
    Ok(handle.offset..end)
}

fn ensure_zero_bytes(
    bytes: &Bytes,
    range: std::ops::Range<usize>,
    description: &str,
) -> Result<(), jerky::error::Error> {
    if bytes.as_ref()[range.clone()].iter().any(|byte| *byte != 0) {
        return Err(invalid_rank9_metadata(format!(
            "{description} contains non-zero padding in {}..{}",
            range.start, range.end
        )));
    }
    Ok(())
}

fn persist_top_level_rank9_indexes(
    writer: &mut SectionWriter<'_>,
    vectors: [&BitVector<Rank9SelIndex>; TOP_LEVEL_RANK9_INDEX_COUNT],
) -> Vec<SectionHandle<usize>> {
    vectors
        .into_iter()
        .map(|vector| vector.index.persist(writer).unwrap())
        .collect()
}

fn reserve_rank9_index_header<'area>(
    writer: &mut SectionWriter<'area>,
) -> Section<'area, Rank9IndexHeader> {
    let mut header = writer
        .reserve::<Rank9IndexHeader>(1)
        .expect("temporary Rank9 arena must remain writable");
    assert_eq!(header.handle().offset, 0, "source handle must be first");
    header[0] = Rank9IndexHeader {
        source: [0; 32],
        marker: RANK9_INDEX_MARKER,
        version: RANK9_INDEX_VERSION,
        flags: RANK9_INDEX_FLAGS,
        word_bytes: std::mem::size_of::<usize>() as u8,
        endian: RANK9_INDEX_ENDIAN,
        reserved: [0; 6],
    };
    header
}

/// Appends the relative index table and exact native-ABI footer to a source-bound
/// Rank9 blob. Its fixed header must already occupy offset zero.
fn try_finalize_rank9_index(
    writer: &mut SectionWriter<'_>,
    index_handles: &[SectionHandle<usize>],
) -> Result<(), jerky::error::Error> {
    let mut table = writer
        .reserve::<SectionHandle<usize>>(index_handles.len())
        .map_err(jerky::error::Error::from)?;
    table.as_mut_slice().copy_from_slice(index_handles);
    let table_handle = table.handle();
    let table_end = table_handle
        .offset
        .checked_add(table_handle.len)
        .ok_or_else(|| invalid_rank9_metadata("Rank9 index table position overflow"))?;
    table.freeze().map_err(jerky::error::Error::from)?;

    let mut footer = writer
        .reserve::<Rank9IndexFooter>(1)
        .map_err(jerky::error::Error::from)?;
    if footer.handle().offset != table_end {
        return Err(invalid_rank9_metadata(
            "Rank9 footer has an unexpected alignment gap",
        ));
    }
    footer.as_mut_slice()[0] = Rank9IndexFooter {
        marker: RANK9_INDEX_MARKER,
        version: RANK9_INDEX_VERSION,
        flags: RANK9_INDEX_FLAGS,
        word_bytes: std::mem::size_of::<usize>() as u8,
        endian: RANK9_INDEX_ENDIAN,
        reserved: [0; 6],
        indexes: table_handle,
    };
    footer.freeze().map_err(jerky::error::Error::from)?;
    Ok(())
}

fn build_prefix_bv<I>(
    domain_len: usize,
    triple_count: usize,
    iter: I,
    writer: &mut SectionWriter,
) -> BitVector<Rank9SelIndex>
where
    I: IntoIterator<Item = (usize, usize)>,
{
    let mut builder =
        BitVectorBuilder::from_bit(false, triple_count + domain_len + 1, writer).unwrap();

    let mut seen = 0usize;
    let mut last = 0usize;
    for (val, count) in iter {
        for c in last..=val {
            builder.set_bit(seen + c, true).unwrap();
        }
        seen += count;
        last = val + 1;
    }
    for c in last..=domain_len {
        builder.set_bit(seen + c, true).unwrap();
    }
    builder.freeze::<Rank9SelIndex>()
}

/// Query-time rank/select strategy. Raw archives scan their stored words;
/// accelerated archives borrow the explicitly supplied Rank9 index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccinctIndex {
    /// No auxiliary index is constructed, including on first query.
    Raw,
    /// Existing source-bound Rank9/select bytes.
    Rank9(Rank9SelIndex),
}

impl BitVectorIndex for SuccinctIndex {
    fn build(_: &BitVectorData) -> Self {
        Self::Raw
    }
    fn num_ones(&self, data: &BitVectorData) -> usize {
        match self {
            Self::Raw => NoIndex.rank1(data, data.len()).unwrap_or(0),
            Self::Rank9(index) => index.num_ones(),
        }
    }
    fn rank1(&self, data: &BitVectorData, pos: usize) -> Option<usize> {
        match self {
            Self::Raw => NoIndex.rank1(data, pos),
            Self::Rank9(index) => index.rank1(data, pos),
        }
    }
    fn select1(&self, data: &BitVectorData, k: usize) -> Option<usize> {
        match self {
            Self::Raw => NoIndex.select1(data, k).filter(|pos| *pos < data.len()),
            Self::Rank9(index) => index.select1(data, k),
        }
    }
    fn select0(&self, data: &BitVectorData, k: usize) -> Option<usize> {
        match self {
            Self::Raw => NoIndex.select0(data, k),
            Self::Rank9(index) => index.select0(data, k),
        }
    }
}

/// Deserialized Ring index — two rings of wavelet matrices with prefix
/// bit vectors and pair-change markers, backed by a shared `Bytes`
/// buffer.
///
/// The forward ring (E→A→V) stores three sorted rotations whose last
/// columns are `eav_c`, `vea_c`, and `ave_c`. The reverse ring
/// (E→V→A) stores `eva_c`, `aev_c`, and `vae_c`. Together they cover
/// all six attribute orderings needed for WCO joins without
/// materialising six separate indexes.
///
/// Implements [`Constraint`](crate::query::Constraint) via
/// `TriblePattern::pattern`, so it can be used directly in `find!` and
/// `pattern!` queries alongside regular [`TribleSet`]s.
#[derive(Debug, Clone)]
pub struct SuccinctArchive<U> {
    /// The canonical, architecture-independent raw archive blob bytes.
    pub bytes: Bytes,
    /// Cached identity of the canonical raw archive bytes.
    raw_handle: Inline<Handle<SuccinctArchiveBlob>>,
    /// Detached persisted Rank9/select accelerator bytes.
    rank9_index_bytes: Option<Bytes>,
    /// Cached identity of the source-bound Rank9/select accelerator bytes.
    rank9_handle: Option<Inline<Handle<Rank9AcceleratedSuccinctArchiveBlob>>>,
    /// Scalar query statistics, populated independently on first request and
    /// shared by clones. Attachment does not inspect the unary prefixes.
    distinct_counts: Arc<[OnceLock<usize>; 3]>,
    /// The universe — maps integer codes to raw 32-byte values (the
    /// domain of all distinct values appearing in E, A, or V positions).
    pub domain: U,

    /// Entity-axis prefix bit vector: unary encoding of group sizes for
    /// the entity column, enabling rank/select navigation.
    pub e_a: BitVector<SuccinctIndex>,
    /// Attribute-axis prefix bit vector.
    pub a_a: BitVector<SuccinctIndex>,
    /// Inline-axis prefix bit vector.
    pub v_a: BitVector<SuccinctIndex>,

    /// Bit vector marking the first occurrence of each `(entity, attribute)` pair
    /// in `eav_c`.
    pub changed_e_a: BitVector<SuccinctIndex>,
    /// Bit vector marking the first occurrence of each `(entity, value)` pair in
    /// `eva_c`.
    pub changed_e_v: BitVector<SuccinctIndex>,
    /// Bit vector marking the first occurrence of each `(attribute, entity)` pair
    /// in `aev_c`.
    pub changed_a_e: BitVector<SuccinctIndex>,
    /// Bit vector marking the first occurrence of each `(attribute, value)` pair
    /// in `ave_c`.
    pub changed_a_v: BitVector<SuccinctIndex>,
    /// Bit vector marking the first occurrence of each `(value, entity)` pair in
    /// `vea_c`.
    pub changed_v_e: BitVector<SuccinctIndex>,
    /// Bit vector marking the first occurrence of each `(value, attribute)` pair
    /// in `vae_c`.
    pub changed_v_a: BitVector<SuccinctIndex>,

    /// Forward ring: last column of EAV-sorted rotation (values).
    pub eav_c: WaveletMatrix<SuccinctIndex>,
    /// Forward ring: last column of VEA-sorted rotation (attributes).
    pub vea_c: WaveletMatrix<SuccinctIndex>,
    /// Forward ring: last column of AVE-sorted rotation (entities).
    pub ave_c: WaveletMatrix<SuccinctIndex>,
    /// Reverse ring: last column of VAE-sorted rotation (entities).
    pub vae_c: WaveletMatrix<SuccinctIndex>,
    /// Reverse ring: last column of EVA-sorted rotation (attributes).
    pub eva_c: WaveletMatrix<SuccinctIndex>,
    /// Reverse ring: last column of AEV-sorted rotation (values).
    pub aev_c: WaveletMatrix<SuccinctIndex>,
}

fn top_level_bitvector_meta<D: Metadata>(
    meta: &SuccinctArchiveMeta<D>,
) -> [BitVectorDataMeta; TOP_LEVEL_RANK9_INDEX_COUNT] {
    [
        meta.e_a,
        meta.a_a,
        meta.v_a,
        meta.changed_e_a,
        meta.changed_e_v,
        meta.changed_a_e,
        meta.changed_a_v,
        meta.changed_v_e,
        meta.changed_v_a,
    ]
}

fn wavelet_meta<D: Metadata>(meta: &SuccinctArchiveMeta<D>) -> [WaveletMatrixMeta; 6] {
    [
        meta.eav_c, meta.vea_c, meta.ave_c, meta.vae_c, meta.eva_c, meta.aev_c,
    ]
}

fn portable_codec_error(error: impl std::fmt::Display) -> jerky::error::Error {
    invalid_rank9_metadata(error.to_string())
}

fn copy_raw_words(
    handle: SectionHandle<u64>,
    runtime_bytes: &Bytes,
) -> Result<Vec<u64>, jerky::error::Error> {
    Ok(handle.view(runtime_bytes)?.iter().copied().collect())
}

/// Canonicalizes an internal query arena into the portable raw representation.
/// Universe compression and native section offsets deliberately disappear at
/// this boundary: only the ordered raw domain and logical bit-vector words
/// participate in the public blob identity.
fn encode_portable_runtime<U>(
    meta: &SuccinctArchiveMeta<U::Meta>,
    domain: &U,
    runtime_bytes: &Bytes,
) -> Result<Bytes, jerky::error::Error>
where
    U: Universe,
{
    let domain_values: Vec<_> = (0..domain.len()).map(|code| domain.access(code)).collect();
    let top_level = top_level_bitvector_meta(meta)
        .into_iter()
        .map(|vector| copy_raw_words(vector.handle, runtime_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let [
        e_a,
        a_a,
        v_a,
        changed_e_a,
        changed_e_v,
        changed_a_e,
        changed_a_v,
        changed_v_e,
        changed_v_a,
    ]: [Vec<u64>; TOP_LEVEL_RANK9_INDEX_COUNT] =
        top_level.try_into().expect("nine top-level raw vectors");

    let mut wavelets = Vec::with_capacity(SuccinctRotation::ALL.len());
    for (position, matrix) in wavelet_meta(meta).into_iter().enumerate() {
        if matrix.alph_size != domain.len() {
            return Err(invalid_rank9_metadata(format!(
                "wavelet matrix {position} alphabet size {} does not match domain cardinality {}",
                matrix.alph_size,
                domain.len()
            )));
        }
        if matrix.len != meta.eav_c.len {
            return Err(invalid_rank9_metadata(format!(
                "wavelet matrix {position} contains {} rows, expected {}",
                matrix.len, meta.eav_c.len
            )));
        }
        let handles = matrix.layers.view(runtime_bytes)?;
        if handles.len() != matrix.alph_width {
            return Err(invalid_rank9_metadata(format!(
                "wavelet matrix {position} has {} raw planes, expected {}",
                handles.len(),
                matrix.alph_width
            )));
        }
        let mut words = Vec::new();
        for handle in handles.iter().copied() {
            words.extend(copy_raw_words(handle, runtime_bytes)?);
        }
        wavelets.push(words);
    }
    let [eav_c, vea_c, ave_c, vae_c, eva_c, aev_c]: [Vec<u64>; 6] =
        wavelets.try_into().expect("six Ring wavelet matrices");

    portable::encode(portable::PortableParts {
        triple_count: meta.eav_c.len,
        domain: &domain_values,
        prefixes: [&e_a, &a_a, &v_a],
        changes: [
            &changed_e_a,
            &changed_e_v,
            &changed_a_e,
            &changed_a_v,
            &changed_v_e,
            &changed_v_a,
        ],
        wavelets: [&eav_c, &vea_c, &ave_c, &vae_c, &eva_c, &aev_c],
    })
    .map(Bytes::from)
    .map_err(portable_codec_error)
}

/// Borrowed query sections. This holds only typed byte views and small layer
/// descriptors; no raw-domain/plane copy or canonical reconstruction occurs.
struct QueryParts<U> {
    domain: U,
    top_level: Vec<BitVectorData>,
    matrices: Vec<Vec<BitVectorData>>,
}

impl<U: Universe + Serializable<Error = jerky::error::Error>> QueryParts<U> {
    fn from_portable(bytes: &Bytes) -> Result<Self, jerky::error::Error> {
        let layout = portable::parse_layout(bytes.as_ref()).map_err(portable_codec_error)?;
        let values = bytes.slice(layout.domain.clone()).view::<[RawInline]>()?;
        let domain = U::from_ordered_values(values);
        let vector = |range: std::ops::Range<usize>, len| -> Result<_, jerky::error::Error> {
            let section = bytes.slice(range);
            // Portable words are little-endian. Native LE readers retain the
            // exact original owner; a BE interpretation must convert words.
            #[cfg(target_endian = "little")]
            let words = section.view::<[u64]>()?;
            #[cfg(target_endian = "big")]
            let words = Bytes::from_source(
                section
                    .chunks_exact(8)
                    .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
                    .collect::<Vec<_>>(),
            )
            .view::<[u64]>()?;
            Ok(BitVectorData {
                words,
                len,
                handle: None,
            })
        };
        let mut top_level = Vec::with_capacity(TOP_LEVEL_RANK9_INDEX_COUNT);
        for range in layout.prefixes {
            top_level.push(vector(range, layout.prefix_bits)?);
        }
        for range in layout.changes {
            top_level.push(vector(range, layout.triple_count)?);
        }
        let mut matrices = Vec::with_capacity(6);
        for range in layout.wavelets {
            let mut layers = Vec::with_capacity(layout.alphabet_width);
            let plane_bytes = layout.row_words * std::mem::size_of::<u64>();
            for depth in 0..layout.alphabet_width {
                let start = range.start + depth * plane_bytes;
                layers.push(vector(start..start + plane_bytes, layout.triple_count)?);
            }
            matrices.push(layers);
        }
        Ok(Self {
            domain,
            top_level,
            matrices,
        })
    }

    fn from_runtime(
        meta: SuccinctArchiveMeta<U::Meta>,
        bytes: &Bytes,
    ) -> Result<Self, jerky::error::Error> {
        validate_raw_rank9_sources(&meta, bytes, bytes.len())?;
        let top_level = top_level_bitvector_meta(&meta)
            .into_iter()
            .map(|meta| BitVectorData::from_bytes(meta, bytes.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let matrices = wavelet_meta(&meta)
            .into_iter()
            .map(|matrix| {
                matrix
                    .layers
                    .view(bytes)?
                    .iter()
                    .copied()
                    .map(|handle| {
                        BitVectorData::from_bytes(
                            BitVectorDataMeta {
                                handle,
                                len: matrix.len,
                            },
                            bytes.clone(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, jerky::error::Error>>()?;
        let domain = U::from_bytes(meta.domain, bytes.clone())?;
        Ok(Self {
            domain,
            top_level,
            matrices,
        })
    }

    fn data(&self) -> impl Iterator<Item = &BitVectorData> {
        self.top_level.iter().chain(self.matrices.iter().flatten())
    }
}

fn build_rank9_index<U>(
    parts: &QueryParts<U>,
    source: Inline<Handle<SuccinctArchiveBlob>>,
) -> Result<Bytes, jerky::error::Error>
where
    U: Universe + Serializable<Error = jerky::error::Error>,
{
    let mut area = ByteArea::new()?;
    let mut sections = area.sections();
    let mut header = reserve_rank9_index_header(&mut sections);
    header[0].source = source.raw;
    let indexes = parts
        .data()
        .map(|data| Rank9SelIndex::<true, true>::new(data).persist(&mut sections))
        .collect::<Result<Vec<_>, _>>()?;
    try_finalize_rank9_index(&mut sections, &indexes)?;
    header.freeze()?;
    area.freeze().map_err(Into::into)
}

fn bitvector_word_bytes(len: usize) -> Result<usize, jerky::error::Error> {
    len.checked_add(63)
        .map(|bits| bits / 64)
        .and_then(|words| words.checked_mul(std::mem::size_of::<u64>()))
        .ok_or_else(|| invalid_rank9_metadata("bit-vector raw section length overflow"))
}

/// Preflights every runtime-arena handle before any AnyBytes/Jerky view
/// constructor can slice with it. `changed_v_a` is the final internal raw
/// section; public portable bytes have their own gapless layout validator.
fn validate_raw_rank9_sources<D: Metadata>(
    meta: &SuccinctArchiveMeta<D>,
    bytes: &Bytes,
    raw_limit: usize,
) -> Result<usize, jerky::error::Error> {
    if raw_limit > bytes.len() {
        return Err(invalid_rank9_metadata(format!(
            "raw Rank9 source limit {raw_limit} exceeds {} bytes",
            bytes.len()
        )));
    }
    let changed_v_a_range = checked_section_range(
        meta.changed_v_a.handle,
        raw_limit,
        "changed_v_a raw bit vector",
    )?;
    if meta.changed_v_a.handle.len != bitvector_word_bytes(meta.changed_v_a.len)? {
        return Err(invalid_rank9_metadata(
            "changed_v_a raw bit-vector length is not canonical",
        ));
    }
    let raw_end = changed_v_a_range.end;

    for (position, vector) in top_level_bitvector_meta(meta).into_iter().enumerate() {
        let range = checked_section_range(
            vector.handle,
            raw_end,
            &format!("top-level raw bit vector {position}"),
        )?;
        let expected = bitvector_word_bytes(vector.len)?;
        if range.len() != expected {
            return Err(invalid_rank9_metadata(format!(
                "top-level raw bit vector {position} has {} bytes, expected {expected}",
                range.len()
            )));
        }
    }

    for (matrix_index, matrix) in wavelet_meta(meta).into_iter().enumerate() {
        if matrix.alph_width != jerky::utils::alphabet_width(matrix.alph_size) {
            return Err(invalid_rank9_metadata(format!(
                "wavelet matrix {matrix_index} has a non-canonical alphabet width"
            )));
        }
        let table_range = checked_section_range(
            matrix.layers,
            raw_end,
            &format!("wavelet matrix {matrix_index} raw layer table"),
        )?;
        let expected_table_len = matrix
            .alph_width
            .checked_mul(std::mem::size_of::<SectionHandle<u64>>())
            .ok_or_else(|| invalid_rank9_metadata("wavelet layer table length overflow"))?;
        if table_range.len() != expected_table_len {
            return Err(invalid_rank9_metadata(format!(
                "wavelet matrix {matrix_index} raw layer table has {} bytes, expected {expected_table_len}",
                table_range.len()
            )));
        }
        let layers = matrix.layers.view(bytes)?;
        let expected_layer_len = bitvector_word_bytes(matrix.len)?;
        for (depth, layer) in layers.iter().copied().enumerate() {
            let range = checked_section_range(
                layer,
                raw_end,
                &format!("wavelet matrix {matrix_index} raw layer {depth}"),
            )?;
            if range.len() != expected_layer_len {
                return Err(invalid_rank9_metadata(format!(
                    "wavelet matrix {matrix_index} raw layer {depth} has {} bytes, expected {expected_layer_len}",
                    range.len()
                )));
            }
        }
    }

    Ok(raw_end)
}

fn validate_rank9_index_handles(
    expected_count: usize,
    index_bytes: &Bytes,
    handles: &[SectionHandle<usize>],
    index_limit: usize,
) -> Result<usize, jerky::error::Error> {
    if handles.len() != expected_count {
        return Err(invalid_rank9_metadata(format!(
            "Rank9 index table has {} handles, expected {expected_count}",
            handles.len()
        )));
    }

    let first = handles
        .first()
        .ok_or_else(|| invalid_rank9_metadata("Rank9 index table is empty"))?;
    checked_section_range(*first, index_limit, "first Rank9 index")?;
    let expected_start = checked_align_up(
        std::mem::size_of::<Rank9IndexHeader>(),
        std::mem::align_of::<usize>(),
    )?;
    if first.offset != expected_start {
        return Err(invalid_rank9_metadata(format!(
            "first Rank9 index starts at {}, expected {expected_start}",
            first.offset
        )));
    }
    ensure_zero_bytes(
        index_bytes,
        std::mem::size_of::<Rank9IndexHeader>()..expected_start,
        "Rank9 header-to-index gap",
    )?;

    let mut cursor = expected_start;
    for (position, handle) in handles.iter().copied().enumerate() {
        if handle.offset != cursor {
            return Err(invalid_rank9_metadata(format!(
                "Rank9 index {position} starts at {}, expected {cursor}",
                handle.offset
            )));
        }
        if handle.len == 0 {
            return Err(invalid_rank9_metadata(format!(
                "Rank9 index {position} is empty"
            )));
        }
        cursor =
            checked_section_range(handle, index_limit, &format!("Rank9 index {position}"))?.end;
    }

    Ok(cursor)
}

fn parse_rank9_index(
    expected_count: usize,
    source: Inline<Handle<SuccinctArchiveBlob>>,
    index_bytes: &Bytes,
) -> Result<Vec<SectionHandle<usize>>, jerky::error::Error> {
    let header_size = std::mem::size_of::<Rank9IndexHeader>();
    let footer_size = std::mem::size_of::<Rank9IndexFooter>();
    if index_bytes.len() < header_size + footer_size {
        return Err(invalid_rank9_metadata("Rank9 index blob is truncated"));
    }
    let header = *index_bytes
        .clone()
        .slice(0..header_size)
        .view::<Rank9IndexHeader>()?;
    if header.source != source.raw {
        return Err(invalid_rank9_metadata(
            "Rank9 index source handle does not match the raw archive",
        ));
    }
    if header.marker != RANK9_INDEX_MARKER
        || header.version != RANK9_INDEX_VERSION
        || header.flags != RANK9_INDEX_FLAGS
        || header.word_bytes != std::mem::size_of::<usize>() as u8
        || header.endian != RANK9_INDEX_ENDIAN
        || header.reserved != [0; 6]
    {
        return Err(invalid_rank9_metadata(
            "unsupported Rank9 index format or native ABI",
        ));
    }

    let footer_start = index_bytes.len() - footer_size;
    let footer = *index_bytes
        .clone()
        .slice(footer_start..)
        .view::<Rank9IndexFooter>()?;
    if footer.marker != RANK9_INDEX_MARKER || footer.version != RANK9_INDEX_VERSION {
        return Err(invalid_rank9_metadata("unsupported Rank9 index footer"));
    }
    if footer.flags != RANK9_INDEX_FLAGS
        || footer.word_bytes != std::mem::size_of::<usize>() as u8
        || footer.endian != RANK9_INDEX_ENDIAN
        || footer.reserved != [0; 6]
    {
        return Err(invalid_rank9_metadata(format!(
            "unsupported Rank9 index flags or native ABI ({:#x})",
            footer.flags
        )));
    }

    let expected_table_len = expected_count
        .checked_mul(std::mem::size_of::<SectionHandle<usize>>())
        .ok_or_else(|| invalid_rank9_metadata("Rank9 index table length overflow"))?;
    let table_range =
        checked_section_range(footer.indexes, footer_start, "Rank9 index handle table")?;
    if table_range.len() != expected_table_len {
        return Err(invalid_rank9_metadata(format!(
            "Rank9 index handle table has {} bytes, expected {expected_table_len}",
            table_range.len()
        )));
    }
    if table_range.end != footer_start {
        return Err(invalid_rank9_metadata(
            "Rank9 index footer is not immediately after its handle table",
        ));
    }
    let handles_view = footer.indexes.view(index_bytes)?;
    let handles: Vec<_> = handles_view.iter().copied().collect();
    let index_end =
        validate_rank9_index_handles(expected_count, index_bytes, &handles, footer.indexes.offset)?;
    if index_end != footer.indexes.offset {
        return Err(invalid_rank9_metadata(format!(
            "Rank9 indexes end at {index_end}, table starts at {}",
            footer.indexes.offset
        )));
    }
    Ok(handles)
}

impl<U> SuccinctArchive<U>
where
    U: Universe,
{
    /// Counts distinct entities on first request; clones reuse the scalar.
    pub fn entity_count(&self) -> usize {
        *self.distinct_counts[0].get_or_init(|| prefix_distinct_count(&self.e_a.data))
    }

    /// Counts distinct attributes on first request; clones reuse the scalar.
    pub fn attribute_count(&self) -> usize {
        *self.distinct_counts[1].get_or_init(|| prefix_distinct_count(&self.a_a.data))
    }

    /// Counts distinct values on first request; clones reuse the scalar.
    pub fn value_count(&self) -> usize {
        *self.distinct_counts[2].get_or_init(|| prefix_distinct_count(&self.v_a.data))
    }

    /// Returns the last-column wavelet matrix of `rotation`.
    pub fn ring_col(&self, rotation: SuccinctRotation) -> &WaveletMatrix<SuccinctIndex> {
        match rotation {
            SuccinctRotation::Eav => &self.eav_c,
            SuccinctRotation::Vea => &self.vea_c,
            SuccinctRotation::Ave => &self.ave_c,
            SuccinctRotation::Vae => &self.vae_c,
            SuccinctRotation::Eva => &self.eva_c,
            SuccinctRotation::Aev => &self.aev_c,
        }
    }

    /// Returns the first-occurrence markers for `(first, middle)` pairs in
    /// `rotation`.
    ///
    /// The returned vector has one bit per Ring row. A set bit starts a new
    /// pair in the sorted order named by `rotation`; its rank is therefore the
    /// compact pair code used by one-peer resident navigation.
    pub fn pair_changes(&self, rotation: SuccinctRotation) -> &BitVector<SuccinctIndex> {
        self.rotation_view(rotation).changed_pair
    }

    /// A constraint over the intersection of the archive's V-axis domain and
    /// the inclusive byte-lexicographic range `[min, max]`.
    ///
    /// Mirrors [`TribleSet::value_in_range`](crate::trible::TribleSet::value_in_range).
    /// The cost is O(log n + k) for an [`OrderedUniverse`] (n = universe
    /// size, k = matching values that appear in V position) — closes
    /// the date-window query collapse documented in the SPB case study's
    /// storage-axis appendix.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// find!(ts: Inline<NsTAIInterval>,
    ///     and!(
    ///         pattern!(&archive, [{ ?id @ attr: ?ts }]),
    ///         archive.value_in_range(ts, min_ts, max_ts),
    ///     )
    /// )
    /// ```
    pub fn value_in_range<V: InlineEncoding>(
        &self,
        variable: crate::query::Variable<V>,
        min: Inline<V>,
        max: Inline<V>,
    ) -> SuccinctArchiveRangeConstraint<'_, U> {
        SuccinctArchiveRangeConstraint::new(variable, min, max, self)
    }

    /// Iterates over all tribles by walking the EAV wavelet matrix and
    /// resolving each triple through the domain mapping.
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = Trible> + 'a {
        (0..self.eav_c.len()).map(move |position| self.decode_eav_trible(position))
    }

    /// Decode one position in canonical EAV order.
    ///
    /// Kept as a direct positional operation so sibling logical-cover views
    /// can merge several physical archives without exposing archive-local
    /// universe codes.
    fn decode_eav_trible(&self, position: usize) -> Trible {
        let v = self.eav_c.access(position).unwrap();
        let a_i = self.v_a.select1(v).unwrap() - v + self.eav_c.rank(position, v).unwrap();
        let a = self.vea_c.access(a_i).unwrap();
        let e_i = self.a_a.select1(a).unwrap() - a + self.vea_c.rank(a_i, a).unwrap();
        let e = self.ave_c.access(e_i).unwrap();

        let e = self.domain.access(e);
        let a = self.domain.access(a);
        let v = self.domain.access(v);

        let e: Id = Id::new(id_from_value(&e).unwrap()).unwrap();
        let a: Id = Id::new(id_from_value(&a).unwrap()).unwrap();
        let v: Inline<UnknownInline> = Inline::new(v);

        Trible::force(&e, &a, &v)
    }

    /// Iterates over the facts for one fixed attribute in ascending AVE order.
    ///
    /// Each item is the decoded `(value, entity)` pair for one fact. Ordering is
    /// byte-lexicographic by raw value, then by entity ID. The returned iterator
    /// is double-ended, so `.rev()` walks the same attribute in descending
    /// `(value, entity)` order.
    ///
    /// Archive-local universe codes never leave this iterator. Consequently,
    /// iterators from independent archive segments can be merged by their
    /// decoded tuples even when the same value has a different code in each
    /// segment. Deduplication and any joins needed to interpret the facts remain
    /// the caller's responsibility.
    pub fn iter_attribute_value_entities<'a>(
        &'a self,
        attribute: &Id,
    ) -> impl DoubleEndedIterator<Item = (RawInline, Id)> + ExactSizeIterator + 'a {
        let range = base_range(&self.domain, &self.a_a, &id_into_value(attribute));
        range.map(move |position| self.decode_ave_value_entity(position))
    }

    fn decode_ave_value_entity(&self, position: usize) -> (RawInline, Id) {
        let entity_code = self.ave_c.access(position).unwrap();
        let eav_position = self.e_a.select1(entity_code).unwrap() - entity_code
            + self.ave_c.rank(position, entity_code).unwrap();
        let value_code = self.eav_c.access(eav_position).unwrap();

        let value = self.domain.access(value_code);
        let entity = self.domain.access(entity_code);
        let entity = Id::new(id_from_value(&entity).unwrap()).unwrap();
        (value, entity)
    }

    /// Count the number of set bits in `bv` within `range`.
    ///
    /// The bit vectors in this archive encode the first occurrence of each
    /// component pair.  By counting the set bits between two offsets we can
    /// quickly determine how many distinct pairs appear in that slice of the
    /// index.
    pub fn distinct_in(
        &self,
        bv: &BitVector<SuccinctIndex>,
        range: &std::ops::Range<usize>,
    ) -> usize {
        bv.rank1(range.end).unwrap() - bv.rank1(range.start).unwrap()
    }

    /// Enumerate the rotated offsets of set bits in `bv` within `range`.
    ///
    /// `bv` marks the first occurrence of component pairs in the ordering that
    /// produced `col`.  For each selected bit this function reads the component
    /// value from `col` and uses `prefix` to translate the index to the adjacent
    /// orientation.  The iterator therefore yields indices positioned to access
    /// the middle component of each pair.
    pub fn enumerate_in<'a>(
        &'a self,
        bv: &'a BitVector<SuccinctIndex>,
        range: &std::ops::Range<usize>,
        col: &'a WaveletMatrix<SuccinctIndex>,
        prefix: &'a BitVector<SuccinctIndex>,
    ) -> impl Iterator<Item = usize> + 'a {
        let start = bv.rank1(range.start).unwrap();
        let end = bv.rank1(range.end).unwrap();
        (start..end).map(move |r| {
            let idx = bv.select1(r).unwrap();
            let val = col.access(idx).unwrap();
            prefix.select1(val).unwrap() - val + col.rank(idx, val).unwrap()
        })
    }

    /// Enumerate the identifiers present in `prefix` using `rank`/`select` to
    /// jump directly to the next distinct prefix sum.
    pub fn enumerate_domain<'a>(
        &'a self,
        prefix: &'a BitVector<SuccinctIndex>,
    ) -> impl Iterator<Item = RawInline> + 'a {
        let zero_count = prefix.num_bits() - (self.domain.len() + 1);
        let mut z = 0usize;
        std::iter::from_fn(move || {
            if z >= zero_count {
                return None;
            }
            let pos = prefix.select0(z).unwrap();
            let id = prefix.rank1(pos).unwrap() - 1;
            z = prefix.rank0(prefix.select1(id + 1).unwrap()).unwrap();
            Some(self.domain.access(id))
        })
    }

    /// Like [`Self::enumerate_domain`], but bounded to the half-open code range
    /// `[code_range.start, code_range.end)`. Output-sensitive: iterates
    /// only over codes that actually appear in `prefix` *and* fall within
    /// the range. Empty groups are skipped via the `select1`-based stride.
    ///
    /// Combined with [`Universe::search_range`], this gives O(K) range
    /// proposals where K = distinct codes-in-range that have at least one
    /// occurrence on the indexed axis.
    pub fn enumerate_domain_in_range<'a>(
        &'a self,
        prefix: &'a BitVector<SuccinctIndex>,
        code_range: std::ops::Range<usize>,
    ) -> impl Iterator<Item = RawInline> + 'a {
        let zero_count_total = prefix.num_bits() - (self.domain.len() + 1);
        let end_code = code_range.end;
        // Seek to the first 0-bit (first trible) at or after `code_range.start`'s
        // group boundary. select1(start) is the position of the start-code's
        // group's leading 1-bit; rank0 of that position is the trible-index of
        // the first trible whose code >= start.
        let mut z = if code_range.start >= self.domain.len() + 1 {
            zero_count_total
        } else {
            let start_pos = prefix.select1(code_range.start).unwrap();
            prefix.rank0(start_pos).unwrap()
        };
        std::iter::from_fn(move || {
            if z >= zero_count_total {
                return None;
            }
            let pos = prefix.select0(z).unwrap();
            let id = prefix.rank1(pos).unwrap() - 1;
            if id >= end_code {
                return None;
            }
            z = prefix.rank0(prefix.select1(id + 1).unwrap()).unwrap();
            Some(self.domain.access(id))
        })
    }
}

#[cfg(test)]
thread_local! {
    static PREFIX_DISTINCT_COUNT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn prefix_distinct_count(data: &BitVectorData) -> usize {
    #[cfg(test)]
    PREFIX_DISTINCT_COUNT_CALLS.with(|calls| calls.set(calls.get() + 1));
    // Each nonempty unary group has exactly one 1→0 transition. No rank
    // directory or domain-sized array is required.
    let mut count = 0;
    for (position, &word) in data.words().iter().enumerate() {
        let start = position * 64;
        let remaining = data.len().saturating_sub(start).saturating_sub(1);
        let mask = if remaining >= 64 {
            u64::MAX
        } else {
            (1u64 << remaining) - 1
        };
        let next = (word >> 1) | (data.words().get(position + 1).copied().unwrap_or(0) << 63);
        count += (word & !next & mask).count_ones() as usize;
    }
    count
}

/// One of the six sorted Ring rotations stored by a [`SuccinctArchive`].
///
/// The order is also the canonical wavelet-matrix serialization order used by
/// [`merge_ordered_archives_with_backend`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuccinctRotation {
    /// Entity → attribute → value.
    Eav,
    /// Value → entity → attribute.
    Vea,
    /// Attribute → value → entity.
    Ave,
    /// Value → attribute → entity.
    Vae,
    /// Entity → value → attribute.
    Eva,
    /// Attribute → entity → value.
    Aev,
}

impl SuccinctRotation {
    /// All rotations in their canonical serialization and accelerator-array
    /// order.
    pub const ALL: [Self; 6] = [
        Self::Eav,
        Self::Vea,
        Self::Ave,
        Self::Vae,
        Self::Eva,
        Self::Aev,
    ];

    /// Returns this rotation's position in [`Self::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Self::Eav => 0,
            Self::Vea => 1,
            Self::Ave => 2,
            Self::Vae => 3,
            Self::Eva => 4,
            Self::Aev => 5,
        }
    }
}

#[derive(Clone, Copy)]
struct RotationView<'a> {
    first_prefix: &'a BitVector<SuccinctIndex>,
    changed_pair: &'a BitVector<SuccinctIndex>,
    last_column: &'a WaveletMatrix<SuccinctIndex>,
    last_prefix: &'a BitVector<SuccinctIndex>,
    middle_column: &'a WaveletMatrix<SuccinctIndex>,
}

impl<U> SuccinctArchive<U>
where
    U: Universe,
{
    fn rotation_view(&self, rotation: SuccinctRotation) -> RotationView<'_> {
        match rotation {
            SuccinctRotation::Eav => RotationView {
                first_prefix: &self.e_a,
                changed_pair: &self.changed_e_a,
                last_column: &self.eav_c,
                last_prefix: &self.v_a,
                middle_column: &self.vea_c,
            },
            SuccinctRotation::Vea => RotationView {
                first_prefix: &self.v_a,
                changed_pair: &self.changed_v_e,
                last_column: &self.vea_c,
                last_prefix: &self.a_a,
                middle_column: &self.ave_c,
            },
            SuccinctRotation::Ave => RotationView {
                first_prefix: &self.a_a,
                changed_pair: &self.changed_a_v,
                last_column: &self.ave_c,
                last_prefix: &self.e_a,
                middle_column: &self.eav_c,
            },
            SuccinctRotation::Vae => RotationView {
                first_prefix: &self.v_a,
                changed_pair: &self.changed_v_a,
                last_column: &self.vae_c,
                last_prefix: &self.e_a,
                middle_column: &self.eva_c,
            },
            SuccinctRotation::Eva => RotationView {
                first_prefix: &self.e_a,
                changed_pair: &self.changed_e_v,
                last_column: &self.eva_c,
                last_prefix: &self.a_a,
                middle_column: &self.aev_c,
            },
            SuccinctRotation::Aev => RotationView {
                first_prefix: &self.a_a,
                changed_pair: &self.changed_a_e,
                last_column: &self.aev_c,
                last_prefix: &self.v_a,
                middle_column: &self.vae_c,
            },
        }
    }
}

/// Sequentially decodes one of the six sorted Ring rotations as archive-local
/// integer codes. The pair-change marker lets the cursor pay the Ring hop for
/// the middle component only once per distinct `(first, middle)` pair.
struct RotationCursor<'a> {
    view: RotationView<'a>,
    pos: usize,
    first: usize,
    middle: usize,
    have_pair: bool,
}

impl<'a> RotationCursor<'a> {
    fn new<U>(archive: &'a SuccinctArchive<U>, rotation: SuccinctRotation) -> Self
    where
        U: Universe,
    {
        Self {
            view: archive.rotation_view(rotation),
            pos: 0,
            first: 0,
            middle: 0,
            have_pair: false,
        }
    }
}

impl Iterator for RotationCursor<'_> {
    type Item = [usize; 3];

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.view.last_column.len() {
            return None;
        }

        let pos = self.pos;
        let last = self.view.last_column.access(pos).unwrap();
        if self.view.changed_pair.access(pos).unwrap() {
            let first_pos = self.view.first_prefix.select0(pos).unwrap();
            self.first = self.view.first_prefix.rank1(first_pos).unwrap() - 1;

            let rotated = self.view.last_prefix.select1(last).unwrap() - last
                + self.view.last_column.rank(pos, last).unwrap();
            self.middle = self.view.middle_column.access(rotated).unwrap();
            self.have_pair = true;
        }
        debug_assert!(self.have_pair, "first row must start a component pair");

        self.pos += 1;
        Some([self.first, self.middle, last])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.view.last_column.len() - self.pos;
        (remaining, Some(remaining))
    }
}

/// All domain entries from all segments in raw-value order. Equal raw values
/// remain adjacent and retain their source/code coordinates.
struct DomainEntries<'a, U> {
    segments: &'a [SuccinctArchive<U>],
    heap: BinaryHeap<Reverse<(RawInline, usize, usize)>>,
}

impl<'a, U> DomainEntries<'a, U>
where
    U: Universe,
{
    fn new(segments: &'a [SuccinctArchive<U>]) -> Self {
        let heap = segments
            .iter()
            .enumerate()
            .filter(|(_, segment)| !segment.domain.is_empty())
            .map(|(source, segment)| Reverse((segment.domain.access(0), source, 0)))
            .collect();
        Self { segments, heap }
    }
}

impl<U> Iterator for DomainEntries<'_, U>
where
    U: Universe,
{
    type Item = (RawInline, usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let Reverse((value, source, old_code)) = self.heap.pop()?;
        let next_code = old_code + 1;
        if next_code < self.segments[source].domain.len() {
            self.heap.push(Reverse((
                self.segments[source].domain.access(next_code),
                source,
                next_code,
            )));
        }
        Some((value, source, old_code))
    }
}

fn raw_merge_error(message: impl Into<String>) -> SuccinctArchiveError {
    SuccinctArchiveError(invalid_rank9_metadata(message.into()))
}

/// Merge exact-decoded raw inputs without constructing a query runtime.
fn merge_raw_eav_parts(
    parts: Vec<portable::CanonicalEavU32>,
) -> Result<(Vec<RawInline>, Vec<[u32; 3]>), SuccinctArchiveRawMergeError> {
    let mut remaps: Vec<Vec<u32>> = parts
        .iter()
        .map(|part| vec![0; part.domain.len()])
        .collect();
    let mut domain_heap = BinaryHeap::with_capacity(parts.len());
    for (source, part) in parts.iter().enumerate() {
        if let Some(&value) = part.domain.first() {
            domain_heap.push(Reverse((value, source, 0usize)));
        }
    }

    // The largest input domain is a lower bound on the union. Starting there
    // avoids retaining a sum-sized allocation when the inputs overlap heavily.
    let domain_capacity = parts
        .iter()
        .map(|part| part.domain.len())
        .max()
        .unwrap_or(0);
    let mut domain = Vec::with_capacity(domain_capacity);
    while let Some(Reverse((value, source, old_code))) = domain_heap.pop() {
        let new_code = if domain.last() == Some(&value) {
            domain.len() - 1
        } else {
            if domain.len() == u32::MAX as usize {
                return Err(SuccinctArchiveRawMergeError::DomainTooWide);
            }
            domain.push(value);
            domain.len() - 1
        };
        remaps[source][old_code] =
            u32::try_from(new_code).expect("merged domain length was checked before insertion");

        let next_code = old_code + 1;
        if let Some(&next) = parts[source].domain.get(next_code) {
            domain_heap.push(Reverse((next, source, next_code)));
        }
    }
    drop(domain_heap);

    let runs = parts
        .into_iter()
        .zip(remaps)
        .map(|(part, remap)| {
            let mut rows = part.rows;
            for row in &mut rows {
                row[0] = remap[row[0] as usize];
                row[1] = remap[row[1] as usize];
                row[2] = remap[row[2] as usize];
            }
            debug_assert!(rows.windows(2).all(|pair| pair[0] < pair[1]));
            rows
        })
        .collect::<Vec<_>>();
    // Input domains and remap tables are gone before the output writer's
    // equally-sized rotation scratch appears.
    domain.shrink_to_fit();

    let row_capacity = runs.iter().map(Vec::len).max().unwrap_or(0);
    let mut rows = Vec::with_capacity(row_capacity);
    let mut row_heap = BinaryHeap::with_capacity(runs.len());
    for (source, run) in runs.iter().enumerate() {
        if let Some(&row) = run.first() {
            row_heap.push(Reverse((row, source, 0usize)));
        }
    }

    while let Some(Reverse((row, source, position))) = row_heap.pop() {
        if rows.last() != Some(&row) {
            if rows.len() == u32::MAX as usize {
                return Err(SuccinctArchiveRawMergeError::TooManyRows);
            }
            rows.push(row);
        }
        let next_position = position + 1;
        if let Some(&next) = runs[source].get(next_position) {
            row_heap.push(Reverse((next, source, next_position)));
        }
    }
    drop(row_heap);
    drop(runs);
    rows.shrink_to_fit();
    Ok((domain, rows))
}

struct MergedRows<'a> {
    cursors: Vec<(RotationCursor<'a>, &'a [usize])>,
    heap: BinaryHeap<Reverse<([usize; 3], usize)>>,
    last_emitted: Option<[usize; 3]>,
}

#[cfg(feature = "parallel")]
const PARALLEL_EAV_DECODE_THRESHOLD: usize = 4 * 1024;

/// Merge already-remapped, individually sorted EAV runs into their canonical
/// set union. Decoding can fill the runs concurrently, while this deliberately
/// small heap remains serial and deterministic.
#[cfg(feature = "parallel")]
fn merge_sorted_row_runs(row_runs: Vec<Vec<[usize; 3]>>) -> Vec<[usize; 3]> {
    let input_rows = row_runs.iter().map(Vec::len).sum();
    let mut rows = Vec::with_capacity(input_rows);
    let mut heap = BinaryHeap::with_capacity(row_runs.len());

    for (source, run) in row_runs.iter().enumerate() {
        if let Some(&row) = run.first() {
            heap.push(Reverse((row, source, 0usize)));
        }
    }

    while let Some(Reverse((row, source, position))) = heap.pop() {
        if rows.last() != Some(&row) {
            rows.push(row);
        }
        let next_position = position + 1;
        if let Some(&next) = row_runs[source].get(next_position) {
            heap.push(Reverse((next, source, next_position)));
        }
    }
    rows
}

fn materialize_merged_eav(
    segments: &[SuccinctArchive<OrderedUniverse>],
    remaps: &[Vec<usize>],
) -> Vec<[usize; 3]> {
    debug_assert_eq!(segments.len(), remaps.len());

    #[cfg(feature = "parallel")]
    {
        let nonempty_segments = segments
            .iter()
            .filter(|segment| !segment.eav_c.is_empty())
            .count();
        let input_rows: usize = segments.iter().map(|segment| segment.eav_c.len()).sum();
        if nonempty_segments > 1 && input_rows >= PARALLEL_EAV_DECODE_THRESHOLD {
            use rayon::prelude::*;

            let row_runs = segments
                .par_iter()
                .zip(remaps.par_iter())
                .map(|(segment, remap)| {
                    RotationCursor::new(segment, SuccinctRotation::Eav)
                        .map(|row| remap_row(row, remap))
                        .collect()
                })
                .collect();
            let mut rows = merge_sorted_row_runs(row_runs);
            // Heavy overlap can make the input-sized output allocation much
            // larger than the union. The decode runs have been dropped here,
            // so compact before the equally-sized rotation scratch is made.
            rows.shrink_to_fit();
            return rows;
        }
    }

    MergedRows::new(segments, remaps, SuccinctRotation::Eav).collect()
}

impl<'a> MergedRows<'a> {
    fn new(
        segments: &'a [SuccinctArchive<OrderedUniverse>],
        remaps: &'a [Vec<usize>],
        rotation: SuccinctRotation,
    ) -> Self {
        debug_assert_eq!(segments.len(), remaps.len());
        let mut cursors = Vec::with_capacity(segments.len());
        let mut heap = BinaryHeap::new();
        for (source, (segment, remap)) in segments.iter().zip(remaps).enumerate() {
            let mut cursor = RotationCursor::new(segment, rotation);
            if let Some(row) = cursor.next() {
                heap.push(Reverse((remap_row(row, remap), source)));
            }
            cursors.push((cursor, remap.as_slice()));
        }
        Self {
            cursors,
            heap,
            last_emitted: None,
        }
    }
}

impl Iterator for MergedRows<'_> {
    type Item = [usize; 3];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Reverse((row, source)) = self.heap.pop()?;
            let (cursor, remap) = &mut self.cursors[source];
            if let Some(next) = cursor.next() {
                self.heap.push(Reverse((remap_row(next, remap), source)));
            }
            if self.last_emitted == Some(row) {
                continue;
            }
            self.last_emitted = Some(row);
            return Some(row);
        }
    }
}

fn remap_row(row: [usize; 3], remap: &[usize]) -> [usize; 3] {
    [remap[row[0]], remap[row[1]], remap[row[2]]]
}

/// Device-agnostic seam for accelerating the expensive wavelet-freeze phase
/// of raw [`SuccinctArchiveBlob`] construction or structural runtime merges.
///
/// Core performs the domain remap and sorted k-way merge of EAV once, derives
/// the other Ring rotations by stable counting sort, and passes each resulting
/// last-column code sequence to this backend together with preallocated
/// canonical output bit planes. A backend may use a GPU, SIMD, or another
/// accelerator; no such dependency is imposed on `triblespace-core` itself.
///
/// `planes[0]` is the most-significant wavelet level. Bit `position` is stored
/// in `planes[level][position / 64]` at `position % 64` (least-significant-bit
/// first). Each deeper plane must be in the order produced by stable
/// zero/one-partitioning the preceding level. Every word must be written and
/// unused high bits in the final word must remain zero. Meeting this contract
/// makes the resulting archive byte-identical to the canonical CPU builder.
///
/// Core validates the output shape (by allocating the planes itself), every
/// all-zero plane before the sequence's highest set bit, that first informative
/// plane pointwise, and zero padding in every final word. If every code is zero,
/// it validates that every plane is zero. It deliberately does not rebuild the
/// deeper stable partitions on the CPU, because doing so would duplicate the
/// work this seam exists to accelerate. A backend returning `Ok(())` is
/// therefore trusted for the ordering of interior bits after the first
/// informative plane and must synchronize and surface device-side validation
/// errors before it returns.
pub trait WaveletMatrixFreezeBackend {
    /// Backend-specific failure.
    type Error;

    /// Freeze one remapped Ring rotation into its packed wavelet bit planes.
    fn freeze_rotation(
        &self,
        rotation: SuccinctRotation,
        alphabet_size: usize,
        sequence: &[u32],
        planes: &mut [&mut [u64]],
    ) -> Result<(), Self::Error>;
}

/// Failure from [`merge_ordered_archives_with_backend`].
#[derive(Debug)]
pub enum SuccinctArchiveMergeError<E> {
    /// The accelerator rejected or failed a freeze operation.
    Backend(E),
    /// A remapped domain code does not fit the backend contract's `u32` lane.
    DomainTooWide(usize),
    /// A remapped code unexpectedly lies outside the merged domain.
    CodeOutsideDomain {
        /// The invalid remapped code.
        code: usize,
        /// Number of values in the merged domain.
        domain_size: usize,
    },
    /// An all-zero prefix plane or the first informative plane is invalid.
    PlanePrefixMismatch {
        /// Rotation whose output failed validation.
        rotation: SuccinctRotation,
        /// Zero-based wavelet depth that differs from the input sequence.
        depth: usize,
    },
    /// The backend wrote non-canonical padding bits.
    NonZeroTail(SuccinctRotation),
}

impl<E: std::fmt::Display> std::fmt::Display for SuccinctArchiveMergeError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(error) => write!(f, "wavelet-freeze backend failed: {error}"),
            Self::DomainTooWide(size) => {
                write!(
                    f,
                    "succinct domain of {size} values exceeds u32 backend codes"
                )
            }
            Self::CodeOutsideDomain { code, domain_size } => {
                write!(
                    f,
                    "remapped code {code} lies outside domain of size {domain_size}"
                )
            }
            Self::PlanePrefixMismatch { rotation, depth } => {
                write!(
                    f,
                    "wavelet-freeze backend wrote an invalid prefix plane {depth} for {rotation:?}"
                )
            }
            Self::NonZeroTail(rotation) => {
                write!(
                    f,
                    "wavelet-freeze backend wrote padding bits for {rotation:?}"
                )
            }
        }
    }
}

impl<E> std::error::Error for SuccinctArchiveMergeError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(error) => Some(error),
            Self::DomainTooWide(_)
            | Self::CodeOutsideDomain { .. }
            | Self::PlanePrefixMismatch { .. }
            | Self::NonZeroTail(_) => None,
        }
    }
}

trait MergedWaveletOutputs {
    type Error;

    fn set_int(
        &mut self,
        rotation: SuccinctRotation,
        position: usize,
        value: usize,
    ) -> Result<(), Self::Error>;

    fn finish_rotation(&mut self, rotation: SuccinctRotation) -> Result<(), Self::Error>;

    fn freeze_with_rank9_indexes(
        self,
        writer: &mut SectionWriter<'_>,
    ) -> Result<([WaveletMatrixMeta; 6], Vec<SectionHandle<usize>>), Self::Error>;
}

trait MergedWaveletFactory {
    type Error;
    type Outputs<'area>: MergedWaveletOutputs<Error = Self::Error>
    where
        Self: 'area;

    fn create<'area>(
        &self,
        alphabet_size: usize,
        len: usize,
        writer: &mut SectionWriter<'area>,
    ) -> Result<Self::Outputs<'area>, Self::Error>
    where
        Self: 'area;
}

struct JerkyWaveletFactory;

struct JerkyWaveletOutputs<'area> {
    builders: Vec<WaveletMatrixBuilder<'area>>,
}

impl MergedWaveletFactory for JerkyWaveletFactory {
    type Error = jerky::error::Error;
    type Outputs<'area> = JerkyWaveletOutputs<'area>;

    fn create<'area>(
        &self,
        alphabet_size: usize,
        len: usize,
        writer: &mut SectionWriter<'area>,
    ) -> Result<Self::Outputs<'area>, Self::Error>
    where
        Self: 'area,
    {
        let mut builders = Vec::with_capacity(SuccinctRotation::ALL.len());
        for _ in SuccinctRotation::ALL {
            builders.push(WaveletMatrixBuilder::with_capacity(
                alphabet_size,
                len,
                writer,
            )?);
        }
        Ok(JerkyWaveletOutputs { builders })
    }
}

impl MergedWaveletOutputs for JerkyWaveletOutputs<'_> {
    type Error = jerky::error::Error;

    fn set_int(
        &mut self,
        rotation: SuccinctRotation,
        position: usize,
        value: usize,
    ) -> Result<(), Self::Error> {
        self.builders[rotation.index()].set_int(position, value)
    }

    fn finish_rotation(&mut self, _rotation: SuccinctRotation) -> Result<(), Self::Error> {
        Ok(())
    }

    fn freeze_with_rank9_indexes(
        self,
        writer: &mut SectionWriter<'_>,
    ) -> Result<([WaveletMatrixMeta; 6], Vec<SectionHandle<usize>>), Self::Error> {
        let builders = self.builders.into_iter();
        let mut metadata = Vec::with_capacity(SuccinctRotation::ALL.len());
        let mut handles = Vec::new();
        for builder in builders {
            let matrix = builder.freeze::<Rank9SelIndex>()?;
            metadata.push(matrix.metadata());
            handles.extend(matrix.persist_layer_indexes(writer)?);
        }
        Ok((
            metadata.try_into().expect("six Ring wavelet matrices"),
            handles,
        ))
    }
}

fn wavelet_tail_is_zero<'a>(len: usize, mut planes: impl Iterator<Item = &'a [u64]>) -> bool {
    let tail = len % 64;
    if tail == 0 {
        return true;
    }
    let mask = !((1u64 << tail) - 1);
    planes.all(|plane| plane.last().is_none_or(|word| word & mask == 0))
}

fn validate_wavelet_plane_prefix(sequence: &[u32], planes: &[&[u64]]) -> Result<(), usize> {
    let code_or = sequence.iter().copied().fold(0, |bits, code| bits | code);
    if code_or == 0 {
        return planes
            .iter()
            .position(|plane| plane.iter().any(|word| *word != 0))
            .map_or(Ok(()), Err);
    }
    let highest_bit = (u32::BITS - 1 - code_or.leading_zeros()) as usize;
    let informative_depth = planes.len() - 1 - highest_bit;
    if let Some(depth) = planes[..informative_depth]
        .iter()
        .position(|plane| plane.iter().any(|word| *word != 0))
    {
        return Err(depth);
    }
    let plane = planes[informative_depth];
    if sequence.iter().enumerate().all(|(position, code)| {
        let expected = (code >> highest_bit) & 1;
        let actual = (plane[position / 64] >> (position % 64)) & 1;
        actual == u64::from(expected)
    }) {
        Ok(())
    } else {
        Err(informative_depth)
    }
}

/// Preallocated packed wavelet output with the same section order as Jerky's
/// `WaveletMatrixBuilder`, but without constructing a temporary CPU index.
struct PackedWaveletBuilder<'area> {
    alphabet_size: usize,
    len: usize,
    handles: Section<'area, SectionHandle<u64>>,
    planes: Vec<Section<'area, u64>>,
}

impl<'area> PackedWaveletBuilder<'area> {
    fn new(alphabet_size: usize, len: usize, writer: &mut SectionWriter<'area>) -> Self {
        let width = jerky::utils::alphabet_width(alphabet_size);
        let mut handles = writer.reserve::<SectionHandle<u64>>(width).unwrap();
        let mut planes = Vec::with_capacity(width);
        for depth in 0..width {
            let mut plane = writer.reserve::<u64>(len.div_ceil(64)).unwrap();
            plane.as_mut_slice().fill(0);
            handles[depth] = plane.handle();
            planes.push(plane);
        }
        Self {
            alphabet_size,
            len,
            handles,
            planes,
        }
    }

    fn plane_slices(&mut self) -> Vec<&mut [u64]> {
        self.planes.iter_mut().map(Section::as_mut_slice).collect()
    }

    fn tail_is_zero(&self) -> bool {
        wavelet_tail_is_zero(self.len, self.planes.iter().map(|plane| &**plane))
    }

    fn validate_plane_prefix(&self, sequence: &[u32]) -> Result<(), usize> {
        let planes: Vec<&[u64]> = self.planes.iter().map(|plane| &**plane).collect();
        validate_wavelet_plane_prefix(sequence, &planes)
    }

    fn freeze_with_rank9_indexes(
        self,
        writer: &mut SectionWriter<'_>,
    ) -> (WaveletMatrixMeta, Vec<SectionHandle<usize>>) {
        let layers = self.handles.handle();
        let alph_width = self.planes.len();
        self.handles.freeze().unwrap();
        let mut index_handles = Vec::with_capacity(alph_width);
        for plane in self.planes {
            let handle = plane.handle();
            let words = plane.freeze().unwrap().view::<[u64]>().unwrap();
            let data = BitVectorData {
                words,
                len: self.len,
                handle: Some(handle),
            };
            let (_, index_handle) =
                Rank9SelIndex::<true, true>::build_and_persist(&data, writer).unwrap();
            index_handles.push(index_handle);
        }
        (
            WaveletMatrixMeta {
                alph_size: self.alphabet_size,
                alph_width,
                len: self.len,
                layers,
            },
            index_handles,
        )
    }
}

struct PackedCpuWaveletFactory;

struct PackedCpuWaveletOutputs<'area> {
    alphabet_size: usize,
    builders: Vec<PackedWaveletBuilder<'area>>,
    sequence: Vec<u32>,
    scratch: Vec<u32>,
}

#[cfg(feature = "parallel")]
const PACKED_FREEZE_MIN_CHUNK_ROWS: usize = 64 * 1024;

/// Choose at most two chunks per worker while keeping every nominal chunk
/// large enough to amortise the two Rayon barriers at each wavelet level.
/// Small inputs therefore densify to fewer tasks instead of crossing a single
/// machine-specific row cutoff.
#[cfg(feature = "parallel")]
fn packed_freeze_chunk_rows(len: usize) -> Option<usize> {
    let workers = rayon::current_num_threads();
    if workers <= 1 {
        return None;
    }
    let max_tasks = workers.saturating_mul(2);
    let tasks = (len / PACKED_FREEZE_MIN_CHUNK_ROWS).min(max_tasks);
    if tasks < 2 {
        return None;
    }
    let chunk_words = len.div_ceil(64).div_ceil(tasks).max(1);
    Some(chunk_words * 64)
}

/// Scatter one source range into its stable zero/one partition. Each recursive
/// branch owns disjoint slices of both destinations, so Rayon can parallelise
/// the scatter without raw pointers or another full-sized staging buffer.
#[cfg(feature = "parallel")]
fn scatter_packed_partition(
    current: &[u32],
    zero_counts: &[usize],
    zero_output: &mut [u32],
    one_output: &mut [u32],
    shift: usize,
    chunk_rows: usize,
) {
    debug_assert!(!zero_counts.is_empty());
    debug_assert_eq!(zero_output.len() + one_output.len(), current.len());

    if zero_counts.len() == 1 {
        let mut zero = 0usize;
        let mut one = 0usize;
        for &code in current {
            if (code >> shift) & 1 == 0 {
                zero_output[zero] = code;
                zero += 1;
            } else {
                one_output[one] = code;
                one += 1;
            }
        }
        debug_assert_eq!(zero, zero_output.len());
        debug_assert_eq!(one, one_output.len());
        return;
    }

    let middle_chunk = zero_counts.len() / 2;
    let middle_row = (middle_chunk * chunk_rows).min(current.len());
    let left_zeros = zero_counts[..middle_chunk].iter().sum();
    let left_ones = middle_row - left_zeros;
    let (left_current, right_current) = current.split_at(middle_row);
    let (left_zero_output, right_zero_output) = zero_output.split_at_mut(left_zeros);
    let (left_one_output, right_one_output) = one_output.split_at_mut(left_ones);
    let (left_counts, right_counts) = zero_counts.split_at(middle_chunk);

    rayon::join(
        || {
            scatter_packed_partition(
                left_current,
                left_counts,
                left_zero_output,
                left_one_output,
                shift,
                chunk_rows,
            )
        },
        || {
            scatter_packed_partition(
                right_current,
                right_counts,
                right_zero_output,
                right_one_output,
                shift,
                chunk_rows,
            )
        },
    );
}

/// Pack one wavelet plane and, unless it is the final plane, produce the next
/// stable partition. Source chunks align to output words and are sized from
/// the active Rayon topology rather than a fixed machine width.
#[cfg(feature = "parallel")]
fn freeze_packed_plane_parallel(
    current: &[u32],
    next: Option<&mut [u32]>,
    plane: &mut [u64],
    shift: usize,
    chunk_rows: usize,
) {
    use rayon::prelude::*;

    debug_assert_eq!(plane.len(), current.len().div_ceil(64));
    debug_assert_eq!(chunk_rows % 64, 0);
    let chunk_words = chunk_rows / 64;
    let zero_counts: Vec<usize> = plane
        .par_chunks_mut(chunk_words)
        .zip(current.par_chunks(chunk_rows))
        .map(|(plane_chunk, current_chunk)| {
            debug_assert_eq!(plane_chunk.len(), current_chunk.len().div_ceil(64));
            let mut ones = 0usize;
            for (word, codes) in plane_chunk.iter_mut().zip(current_chunk.chunks(64)) {
                let mut packed = 0u64;
                for (position, &code) in codes.iter().enumerate() {
                    packed |= u64::from((code >> shift) & 1) << position;
                }
                *word = packed;
                ones += packed.count_ones() as usize;
            }
            current_chunk.len() - ones
        })
        .collect();

    if let Some(next) = next {
        let zeros = zero_counts.iter().sum();
        let (zero_output, one_output) = next.split_at_mut(zeros);
        scatter_packed_partition(
            current,
            &zero_counts,
            zero_output,
            one_output,
            shift,
            chunk_rows,
        );
    }
}

impl MergedWaveletFactory for PackedCpuWaveletFactory {
    type Error = SuccinctArchiveMergeError<std::convert::Infallible>;
    type Outputs<'area> = PackedCpuWaveletOutputs<'area>;

    fn create<'area>(
        &self,
        alphabet_size: usize,
        len: usize,
        writer: &mut SectionWriter<'area>,
    ) -> Result<Self::Outputs<'area>, Self::Error>
    where
        Self: 'area,
    {
        if alphabet_size > u32::MAX as usize {
            return Err(SuccinctArchiveMergeError::DomainTooWide(alphabet_size));
        }
        let builders = SuccinctRotation::ALL
            .into_iter()
            .map(|_| PackedWaveletBuilder::new(alphabet_size, len, writer))
            .collect();
        Ok(PackedCpuWaveletOutputs {
            alphabet_size,
            builders,
            sequence: Vec::with_capacity(len),
            scratch: Vec::with_capacity(len),
        })
    }
}

impl MergedWaveletOutputs for PackedCpuWaveletOutputs<'_> {
    type Error = SuccinctArchiveMergeError<std::convert::Infallible>;

    fn set_int(
        &mut self,
        _rotation: SuccinctRotation,
        position: usize,
        value: usize,
    ) -> Result<(), Self::Error> {
        debug_assert_eq!(position, self.sequence.len());
        if value >= self.alphabet_size {
            return Err(SuccinctArchiveMergeError::CodeOutsideDomain {
                code: value,
                domain_size: self.alphabet_size,
            });
        }
        self.sequence.push(
            u32::try_from(value)
                .map_err(|_| SuccinctArchiveMergeError::DomainTooWide(self.alphabet_size))?,
        );
        Ok(())
    }

    fn finish_rotation(&mut self, rotation: SuccinctRotation) -> Result<(), Self::Error> {
        let builder = &mut self.builders[rotation.index()];
        let mut planes = builder.plane_slices();
        self.scratch.resize(self.sequence.len(), 0);
        let mut sequence_is_current = true;
        let width = planes.len();

        #[cfg(feature = "parallel")]
        if let Some(chunk_rows) = packed_freeze_chunk_rows(self.sequence.len()) {
            for (depth, plane) in planes.iter_mut().enumerate() {
                let shift = width - 1 - depth;
                let has_next = depth + 1 < width;
                let (current, next) = if sequence_is_current {
                    (self.sequence.as_slice(), self.scratch.as_mut_slice())
                } else {
                    (self.scratch.as_slice(), self.sequence.as_mut_slice())
                };
                freeze_packed_plane_parallel(
                    current,
                    has_next.then_some(next),
                    plane,
                    shift,
                    chunk_rows,
                );
                if has_next {
                    sequence_is_current = !sequence_is_current;
                }
            }
            self.sequence.clear();
            return Ok(());
        }

        for (depth, plane) in planes.iter_mut().enumerate() {
            plane.fill(0);
            let shift = width - 1 - depth;
            let current = if sequence_is_current {
                self.sequence.as_slice()
            } else {
                self.scratch.as_slice()
            };
            let mut zeros = 0usize;
            for (position, &code) in current.iter().enumerate() {
                let bit = (code >> shift) & 1;
                if bit == 0 {
                    zeros += 1;
                } else {
                    plane[position / 64] |= 1u64 << (position % 64);
                }
            }

            if depth + 1 < width {
                let (current, next) = if sequence_is_current {
                    (self.sequence.as_slice(), self.scratch.as_mut_slice())
                } else {
                    (self.scratch.as_slice(), self.sequence.as_mut_slice())
                };
                let (mut zero, mut one) = (0usize, zeros);
                for &code in current {
                    if (code >> shift) & 1 == 0 {
                        next[zero] = code;
                        zero += 1;
                    } else {
                        next[one] = code;
                        one += 1;
                    }
                }
                sequence_is_current = !sequence_is_current;
            }
        }
        self.sequence.clear();
        Ok(())
    }

    fn freeze_with_rank9_indexes(
        self,
        writer: &mut SectionWriter<'_>,
    ) -> Result<([WaveletMatrixMeta; 6], Vec<SectionHandle<usize>>), Self::Error> {
        let mut metadata = Vec::with_capacity(SuccinctRotation::ALL.len());
        let mut handles = Vec::new();
        for builder in self.builders {
            let (meta, layer_handles) = builder.freeze_with_rank9_indexes(writer);
            metadata.push(meta);
            handles.extend(layer_handles);
        }
        Ok((
            metadata.try_into().expect("six Ring wavelet matrices"),
            handles,
        ))
    }
}

struct BackendWaveletFactory<'backend, B> {
    backend: &'backend B,
}

struct BackendWaveletOutputs<'area, 'backend, B> {
    backend: &'backend B,
    alphabet_size: usize,
    builders: Vec<PackedWaveletBuilder<'area>>,
    sequence: Vec<u32>,
}

impl<'backend, B> MergedWaveletFactory for BackendWaveletFactory<'backend, B>
where
    B: WaveletMatrixFreezeBackend,
{
    type Error = SuccinctArchiveMergeError<B::Error>;
    type Outputs<'area>
        = BackendWaveletOutputs<'area, 'backend, B>
    where
        Self: 'area;

    fn create<'area>(
        &self,
        alphabet_size: usize,
        len: usize,
        writer: &mut SectionWriter<'area>,
    ) -> Result<Self::Outputs<'area>, Self::Error>
    where
        Self: 'area,
    {
        if alphabet_size > u32::MAX as usize {
            return Err(SuccinctArchiveMergeError::DomainTooWide(alphabet_size));
        }
        let builders = SuccinctRotation::ALL
            .into_iter()
            .map(|_| PackedWaveletBuilder::new(alphabet_size, len, writer))
            .collect();
        Ok(BackendWaveletOutputs {
            backend: self.backend,
            alphabet_size,
            builders,
            sequence: Vec::with_capacity(len),
        })
    }
}

impl<B> MergedWaveletOutputs for BackendWaveletOutputs<'_, '_, B>
where
    B: WaveletMatrixFreezeBackend,
{
    type Error = SuccinctArchiveMergeError<B::Error>;

    fn set_int(
        &mut self,
        _rotation: SuccinctRotation,
        position: usize,
        value: usize,
    ) -> Result<(), Self::Error> {
        debug_assert_eq!(position, self.sequence.len());
        if value >= self.alphabet_size {
            return Err(SuccinctArchiveMergeError::CodeOutsideDomain {
                code: value,
                domain_size: self.alphabet_size,
            });
        }
        let value = u32::try_from(value)
            .map_err(|_| SuccinctArchiveMergeError::DomainTooWide(self.alphabet_size))?;
        self.sequence.push(value);
        Ok(())
    }

    fn finish_rotation(&mut self, rotation: SuccinctRotation) -> Result<(), Self::Error> {
        let builder = &mut self.builders[rotation.index()];
        let mut planes = builder.plane_slices();
        self.backend
            .freeze_rotation(rotation, self.alphabet_size, &self.sequence, &mut planes)
            .map_err(SuccinctArchiveMergeError::Backend)?;
        if let Err(depth) = builder.validate_plane_prefix(&self.sequence) {
            return Err(SuccinctArchiveMergeError::PlanePrefixMismatch { rotation, depth });
        }
        if !builder.tail_is_zero() {
            return Err(SuccinctArchiveMergeError::NonZeroTail(rotation));
        }
        self.sequence.clear();
        Ok(())
    }

    fn freeze_with_rank9_indexes(
        self,
        writer: &mut SectionWriter<'_>,
    ) -> Result<([WaveletMatrixMeta; 6], Vec<SectionHandle<usize>>), Self::Error> {
        let mut metadata = Vec::with_capacity(SuccinctRotation::ALL.len());
        let mut handles = Vec::new();
        for builder in self.builders {
            let (meta, layer_handles) = builder.freeze_with_rank9_indexes(writer);
            metadata.push(meta);
            handles.extend(layer_handles);
        }
        Ok((
            metadata.try_into().expect("six Ring wavelet matrices"),
            handles,
        ))
    }
}

#[derive(Default)]
struct PrefixAccumulator {
    last: Option<usize>,
    distinct: usize,
}

impl PrefixAccumulator {
    fn record(&mut self, builder: &mut BitVectorBuilder<'_>, position: usize, code: usize) {
        if self.last == Some(code) {
            return;
        }
        if let Some(last) = self.last {
            assert!(last < code, "merged rotation must be sorted");
        }
        let start = self.last.map_or(0, |last| last + 1);
        for empty_or_current in start..=code {
            builder.set_bit(position + empty_or_current, true).unwrap();
        }
        self.last = Some(code);
        self.distinct += 1;
    }

    fn finish(
        self,
        builder: &mut BitVectorBuilder<'_>,
        triple_count: usize,
        domain_len: usize,
    ) -> usize {
        let start = self.last.map_or(0, |last| last + 1);
        for trailing in start..=domain_len {
            builder.set_bit(triple_count + trailing, true).unwrap();
        }
        self.distinct
    }
}

fn fill_materialized_rotation<O>(
    rows: &[[usize; 3]],
    rotation: SuccinctRotation,
    wavelets: &mut O,
    changed_pair: &mut BitVectorBuilder<'_>,
    mut prefix: Option<&mut BitVectorBuilder<'_>>,
    triple_count: usize,
    domain_len: usize,
) -> Result<usize, O::Error>
where
    O: MergedWaveletOutputs,
{
    let [first_component, middle_component, last_component] = match rotation {
        SuccinctRotation::Eav => [0, 1, 2],
        SuccinctRotation::Vea => [2, 0, 1],
        SuccinctRotation::Ave => [1, 2, 0],
        SuccinctRotation::Vae => [2, 1, 0],
        SuccinctRotation::Eva => [0, 2, 1],
        SuccinctRotation::Aev => [1, 0, 2],
    };
    let mut last_pair = None;
    let mut prefix_accumulator = PrefixAccumulator::default();

    for (position, row) in rows.iter().enumerate() {
        let first = row[first_component];
        let pair = [first, row[middle_component]];
        wavelets.set_int(rotation, position, row[last_component])?;
        let changed = last_pair != Some(pair);
        changed_pair.set_bit(position, changed).unwrap();
        last_pair = Some(pair);
        if let Some(builder) = prefix.as_deref_mut() {
            prefix_accumulator.record(builder, position, first);
        }
    }
    assert_eq!(rows.len(), triple_count, "all rotations have equal length");
    wavelets.finish_rotation(rotation)?;

    Ok(match prefix {
        Some(builder) => prefix_accumulator.finish(builder, triple_count, domain_len),
        None => 0,
    })
}

/// Stably makes `component` the primary key while retaining the relative order
/// of the other two components. Ring rotations differ by exactly that move, so
/// five linear counting-sort passes walk the canonical serialization order:
/// EAV -> VEA -> AVE -> VAE -> EVA -> AEV.
fn stable_sort_materialized_rows(
    rows: &mut Vec<[usize; 3]>,
    scratch: &mut Vec<[usize; 3]>,
    counts: &mut [usize],
    component: usize,
) {
    counts.fill(0);
    for row in rows.iter() {
        counts[row[component]] += 1;
    }

    let mut offset = 0usize;
    for count in counts.iter_mut() {
        let len = *count;
        *count = offset;
        offset += len;
    }
    debug_assert_eq!(offset, rows.len());

    scratch.resize(rows.len(), [0; 3]);
    for row in rows.iter().copied() {
        let destination = &mut counts[row[component]];
        scratch[*destination] = row;
        *destination += 1;
    }
    std::mem::swap(rows, scratch);
}

/// Structurally merges sorted succinct-archive segments without reconstructing
/// their six-PATCH [`TribleSet`] representation. Segment-local value domains
/// are merged first. EAV is decoded, remapped, merged, and deduplicated once;
/// the other five rotations are derived by stable linear counting sorts. The
/// result is then emitted through the same portable canonical codec as a full
/// rebuild.
fn merge_ordered_archives_with_factory<F>(
    segments: &[SuccinctArchive<OrderedUniverse>],
    factory: &F,
    source_union: Option<&Blob<SuccinctArchiveBlob>>,
) -> Result<SuccinctArchive<OrderedUniverse>, F::Error>
where
    F: MergedWaveletFactory,
{
    let mut area = ByteArea::new().unwrap();
    let mut sections = area.sections();
    let mut rank9_area = ByteArea::new().unwrap();
    let mut rank9_sections = rank9_area.sections();
    let mut rank9_header = reserve_rank9_index_header(&mut rank9_sections);

    let domain_values = DomainEntries::new(segments)
        .map(|(value, _, _)| value)
        .dedup();
    let domain = OrderedUniverse::with_sorted_dedup(domain_values, &mut sections);
    let domain_len = domain.len();

    let mut remaps: Vec<Vec<usize>> = segments
        .iter()
        .map(|segment| vec![0; segment.domain.len()])
        .collect();
    let mut current_value = None;
    let mut current_code = 0usize;
    let mut next_code = 0usize;
    for (value, source, old_code) in DomainEntries::new(segments) {
        if current_value != Some(value) {
            current_value = Some(value);
            current_code = next_code;
            next_code += 1;
        }
        remaps[source][old_code] = current_code;
    }
    assert_eq!(next_code, domain_len, "domain merge and remap agree");

    // Decoding a Ring row performs wavelet rank/select navigation. Materialise
    // the canonical EAV union once rather than paying that cost for a count and
    // again for every rotation. Once remapped, the source archives and remap
    // tables are no longer touched by the rotation builder.
    let mut rows = materialize_merged_eav(segments, &remaps);
    let triple_count = rows.len();
    drop(remaps);
    let mut row_scratch = Vec::with_capacity(triple_count);
    let mut radix_counts = vec![0usize; domain_len];

    // Reserve one compact process-local arena for the runtime. Public raw bytes
    // are supplied by a witnessed source union or encoded independently below.
    let mut e_a_builder =
        BitVectorBuilder::from_bit(false, triple_count + domain_len + 1, &mut sections).unwrap();
    let mut a_a_builder =
        BitVectorBuilder::from_bit(false, triple_count + domain_len + 1, &mut sections).unwrap();
    let mut v_a_builder =
        BitVectorBuilder::from_bit(false, triple_count + domain_len + 1, &mut sections).unwrap();

    let mut wavelets = factory.create(domain_len, triple_count, &mut sections)?;

    let mut changed_e_a_builder =
        BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
    let mut changed_e_v_builder =
        BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
    let mut changed_a_e_builder =
        BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
    let mut changed_a_v_builder =
        BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
    let mut changed_v_e_builder =
        BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
    let mut changed_v_a_builder =
        BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();

    fill_materialized_rotation(
        &rows,
        SuccinctRotation::Eav,
        &mut wavelets,
        &mut changed_e_a_builder,
        Some(&mut e_a_builder),
        triple_count,
        domain_len,
    )?;
    stable_sort_materialized_rows(&mut rows, &mut row_scratch, &mut radix_counts, 2);
    fill_materialized_rotation(
        &rows,
        SuccinctRotation::Vea,
        &mut wavelets,
        &mut changed_v_e_builder,
        Some(&mut v_a_builder),
        triple_count,
        domain_len,
    )?;
    stable_sort_materialized_rows(&mut rows, &mut row_scratch, &mut radix_counts, 1);
    fill_materialized_rotation(
        &rows,
        SuccinctRotation::Ave,
        &mut wavelets,
        &mut changed_a_v_builder,
        Some(&mut a_a_builder),
        triple_count,
        domain_len,
    )?;
    stable_sort_materialized_rows(&mut rows, &mut row_scratch, &mut radix_counts, 2);
    fill_materialized_rotation(
        &rows,
        SuccinctRotation::Vae,
        &mut wavelets,
        &mut changed_v_a_builder,
        None,
        triple_count,
        domain_len,
    )?;
    stable_sort_materialized_rows(&mut rows, &mut row_scratch, &mut radix_counts, 0);
    fill_materialized_rotation(
        &rows,
        SuccinctRotation::Eva,
        &mut wavelets,
        &mut changed_e_v_builder,
        None,
        triple_count,
        domain_len,
    )?;
    stable_sort_materialized_rows(&mut rows, &mut row_scratch, &mut radix_counts, 1);
    fill_materialized_rotation(
        &rows,
        SuccinctRotation::Aev,
        &mut wavelets,
        &mut changed_a_e_builder,
        None,
        triple_count,
        domain_len,
    )?;
    drop((rows, row_scratch, radix_counts));

    let e_a = e_a_builder.freeze::<Rank9SelIndex>();
    let a_a = a_a_builder.freeze::<Rank9SelIndex>();
    let v_a = v_a_builder.freeze::<Rank9SelIndex>();
    let changed_e_a = changed_e_a_builder.freeze::<Rank9SelIndex>();
    let changed_e_v = changed_e_v_builder.freeze::<Rank9SelIndex>();
    let changed_a_e = changed_a_e_builder.freeze::<Rank9SelIndex>();
    let changed_a_v = changed_a_v_builder.freeze::<Rank9SelIndex>();
    let changed_v_e = changed_v_e_builder.freeze::<Rank9SelIndex>();
    let changed_v_a = changed_v_a_builder.freeze::<Rank9SelIndex>();

    let mut index_handles = persist_top_level_rank9_indexes(
        &mut rank9_sections,
        [
            &e_a,
            &a_a,
            &v_a,
            &changed_e_a,
            &changed_e_v,
            &changed_a_e,
            &changed_a_v,
            &changed_v_e,
            &changed_v_a,
        ],
    );
    let ([eav_c, vea_c, ave_c, vae_c, eva_c, aev_c], wavelet_index_handles) =
        wavelets.freeze_with_rank9_indexes(&mut rank9_sections)?;
    index_handles.extend(wavelet_index_handles);

    let meta = SuccinctArchiveMeta {
        domain: domain.metadata(),
        e_a: e_a.metadata(),
        a_a: a_a.metadata(),
        v_a: v_a.metadata(),
        changed_e_a: changed_e_a.metadata(),
        changed_e_v: changed_e_v.metadata(),
        changed_a_e: changed_a_e.metadata(),
        changed_a_v: changed_a_v.metadata(),
        changed_v_e: changed_v_e.metadata(),
        changed_v_a: changed_v_a.metadata(),
        eav_c,
        vea_c,
        ave_c,
        vae_c,
        eva_c,
        aev_c,
    };

    try_finalize_rank9_index(&mut rank9_sections, &index_handles)
        .expect("temporary Rank9 arena must remain writable");
    drop((
        e_a,
        a_a,
        v_a,
        changed_e_a,
        changed_e_v,
        changed_a_e,
        changed_a_v,
        changed_v_e,
        changed_v_a,
    ));
    let runtime_bytes = area.freeze().unwrap();
    let raw_blob = match source_union {
        Some(raw) => raw.clone(),
        None => Blob::<SuccinctArchiveBlob>::new(
            encode_portable_runtime(&meta, &domain, &runtime_bytes).unwrap(),
        ),
    };
    rank9_header[0].source = raw_blob.get_handle().raw;
    rank9_header.freeze().unwrap();
    let rank9_bytes = rank9_area.freeze().unwrap();
    Ok(SuccinctArchive::from_runtime_bytes_with_rank9_indexes(
        meta,
        runtime_bytes,
        raw_blob,
        Blob::new(rank9_bytes),
    )
    .unwrap())
}

/// Structurally merge sorted succinct-archive segments on the default CPU
/// backend, preserving the canonical SuccinctArchive byte representation.
pub fn merge_ordered_archives(
    segments: &[SuccinctArchive<OrderedUniverse>],
) -> SuccinctArchive<OrderedUniverse> {
    merge_ordered_archives_with_source_union(segments, None)
}

fn merge_ordered_archives_with_source_union(
    segments: &[SuccinctArchive<OrderedUniverse>],
    source_union: Option<&Blob<SuccinctArchiveBlob>>,
) -> SuccinctArchive<OrderedUniverse> {
    match merge_ordered_archives_with_factory(segments, &PackedCpuWaveletFactory, source_union) {
        Ok(archive) => archive,
        Err(SuccinctArchiveMergeError::DomainTooWide(_)) => {
            merge_ordered_archives_with_factory(segments, &JerkyWaveletFactory, source_union)
                .unwrap()
        }
        Err(SuccinctArchiveMergeError::Backend(never)) => match never {},
        Err(error) => panic!("internal packed wavelet freeze violated its contract: {error}"),
    }
}

/// Reuse a witnessed, resident raw union while merging its accelerated children.
///
/// The collection mapping caller has accepted the equations identifying
/// `source_union` as the canonical raw union of these exact segments. This
/// internal path trusts that witness: it neither replays the equation nor
/// serializes or hashes raw union bytes. Only the accelerated root is produced.
pub(crate) fn merge_accelerated_archives_with_source_union(
    segments: &[SuccinctArchive<OrderedUniverse>],
    source_union: &Blob<SuccinctArchiveBlob>,
) -> Blob<Rank9AcceleratedSuccinctArchiveBlob> {
    merge_ordered_archives_with_source_union(segments, Some(source_union)).accelerated_root()
}

/// Structurally merge sorted succinct-archive segments while delegating only
/// the six wavelet-freeze passes to `backend`.
///
/// Domain remapping, the EAV k-way row merge, stable rotation sorts,
/// prefix/change vectors, canonical section order, and final blob attachment
/// remain in `triblespace-core`; consequently an accelerator implementation can
/// live in an optional companion crate and does not add GPU dependencies to the
/// default core build.
///
/// The returned error covers backend-reported failures and the inexpensive
/// output checks described by [`WaveletMatrixFreezeBackend`]. Allocation
/// failure, a backend panic, or process abort are not caught here.
pub fn merge_ordered_archives_with_backend<B>(
    segments: &[SuccinctArchive<OrderedUniverse>],
    backend: &B,
) -> Result<SuccinctArchive<OrderedUniverse>, SuccinctArchiveMergeError<B::Error>>
where
    B: WaveletMatrixFreezeBackend,
{
    merge_ordered_archives_with_factory(segments, &BackendWaveletFactory { backend }, None)
}

fn fill_tribleset_wavelet<O, I>(
    wavelets: &mut O,
    rotation: SuccinctRotation,
    values: I,
) -> Result<(), O::Error>
where
    O: MergedWaveletOutputs,
    I: IntoIterator<Item = usize>,
{
    for (position, value) in values.into_iter().enumerate() {
        wavelets.set_int(rotation, position, value)?;
    }
    wavelets.finish_rotation(rotation)
}

fn build_archive_from_tribleset_with_factory<U, F>(
    set: &TribleSet,
    factory: &F,
) -> Result<SuccinctArchive<U>, F::Error>
where
    U: Universe + Serializable<Error = jerky::error::Error>,
    <U as Serializable>::Meta: Clone,
    F: MergedWaveletFactory,
{
    let triple_count = set.eav.len() as usize;

    let e_iter = set
        .eav
        .iter_prefix_count::<16>()
        .map(|(e, _)| id_into_value(&e));
    let a_iter = set
        .ave
        .iter_prefix_count::<16>()
        .map(|(a, _)| id_into_value(&a));
    let v_iter = set.vea.iter_prefix_count::<32>().map(|(v, _)| v);

    let mut area = ByteArea::new().unwrap();
    let mut sections = area.sections();
    let mut rank9_area = ByteArea::new().unwrap();
    let mut rank9_sections = rank9_area.sections();
    let mut rank9_header = reserve_rank9_index_header(&mut rank9_sections);

    let domain_iter = e_iter.merge(a_iter).merge(v_iter).dedup();
    let domain = U::with_sorted_dedup(domain_iter, &mut sections);

    let e_a = build_prefix_bv(
        domain.len(),
        triple_count,
        set.eav.iter_prefix_count::<16>().map(|(e, c)| {
            (
                domain.search(&id_into_value(&e)).expect("e in domain"),
                c as usize,
            )
        }),
        &mut sections,
    );

    let a_a = build_prefix_bv(
        domain.len(),
        triple_count,
        set.ave.iter_prefix_count::<16>().map(|(a, c)| {
            (
                domain.search(&id_into_value(&a)).expect("a in domain"),
                c as usize,
            )
        }),
        &mut sections,
    );

    let v_a = build_prefix_bv(
        domain.len(),
        triple_count,
        set.vea
            .iter_prefix_count::<32>()
            .map(|(v, c)| (domain.search(&v).expect("v in domain"), c as usize)),
        &mut sections,
    );

    let mut wavelets = factory.create(domain.len(), triple_count, &mut sections)?;
    fill_tribleset_wavelet(
        &mut wavelets,
        SuccinctRotation::Eav,
        set.eav
            .iter_prefix_count::<64>()
            .map(|(t, _)| t[32..64].try_into().unwrap())
            .map(|v| domain.search(&v).expect("v in domain")),
    )?;
    fill_tribleset_wavelet(
        &mut wavelets,
        SuccinctRotation::Vea,
        set.vea
            .iter_prefix_count::<64>()
            .map(|(t, _)| id_into_value(t[48..64].try_into().unwrap()))
            .map(|a| domain.search(&a).expect("a in domain")),
    )?;
    fill_tribleset_wavelet(
        &mut wavelets,
        SuccinctRotation::Ave,
        set.ave
            .iter_prefix_count::<64>()
            .map(|(t, _)| id_into_value(t[48..64].try_into().unwrap()))
            .map(|e| domain.search(&e).expect("e in domain")),
    )?;
    fill_tribleset_wavelet(
        &mut wavelets,
        SuccinctRotation::Vae,
        set.vae
            .iter_prefix_count::<64>()
            .map(|(t, _)| id_into_value(t[48..64].try_into().unwrap()))
            .map(|e| domain.search(&e).expect("e in domain")),
    )?;
    fill_tribleset_wavelet(
        &mut wavelets,
        SuccinctRotation::Eva,
        set.eva
            .iter_prefix_count::<64>()
            .map(|(t, _)| id_into_value(t[48..64].try_into().unwrap()))
            .map(|a| domain.search(&a).expect("a in domain")),
    )?;
    fill_tribleset_wavelet(
        &mut wavelets,
        SuccinctRotation::Aev,
        set.aev
            .iter_prefix_count::<64>()
            .map(|(t, _)| t[32..64].try_into().unwrap())
            .map(|v| domain.search(&v).expect("v in domain")),
    )?;
    let changed_e_a = {
        let mut b = BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
        let mut bits = set
            .eav
            .iter_prefix_count::<32>()
            .flat_map(|(_, c)| iter::once(true).chain(std::iter::repeat_n(false, c as usize - 1)));
        b.set_bits_from_iter(0, &mut bits).unwrap();
        b.freeze::<Rank9SelIndex>()
    };

    let changed_e_v = {
        let mut b = BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
        let mut bits = set
            .eva
            .iter_prefix_count::<48>()
            .flat_map(|(_, c)| iter::once(true).chain(std::iter::repeat_n(false, c as usize - 1)));
        b.set_bits_from_iter(0, &mut bits).unwrap();
        b.freeze::<Rank9SelIndex>()
    };

    let changed_a_e = {
        let mut b = BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
        let mut bits = set
            .aev
            .iter_prefix_count::<32>()
            .flat_map(|(_, c)| iter::once(true).chain(std::iter::repeat_n(false, c as usize - 1)));
        b.set_bits_from_iter(0, &mut bits).unwrap();
        b.freeze::<Rank9SelIndex>()
    };

    let changed_a_v = {
        let mut b = BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
        let mut bits = set
            .ave
            .iter_prefix_count::<48>()
            .flat_map(|(_, c)| iter::once(true).chain(std::iter::repeat_n(false, c as usize - 1)));
        b.set_bits_from_iter(0, &mut bits).unwrap();
        b.freeze::<Rank9SelIndex>()
    };

    let changed_v_e = {
        let mut b = BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
        let mut bits = set
            .vea
            .iter_prefix_count::<48>()
            .flat_map(|(_, c)| iter::once(true).chain(std::iter::repeat_n(false, c as usize - 1)));
        b.set_bits_from_iter(0, &mut bits).unwrap();
        b.freeze::<Rank9SelIndex>()
    };

    let changed_v_a = {
        let mut b = BitVectorBuilder::with_capacity(triple_count, &mut sections).unwrap();
        let mut bits = set
            .vae
            .iter_prefix_count::<48>()
            .flat_map(|(_, c)| iter::once(true).chain(std::iter::repeat_n(false, c as usize - 1)));
        b.set_bits_from_iter(0, &mut bits).unwrap();
        b.freeze::<Rank9SelIndex>()
    };

    let mut index_handles = persist_top_level_rank9_indexes(
        &mut rank9_sections,
        [
            &e_a,
            &a_a,
            &v_a,
            &changed_e_a,
            &changed_e_v,
            &changed_a_e,
            &changed_a_v,
            &changed_v_e,
            &changed_v_a,
        ],
    );
    let ([eav_c, vea_c, ave_c, vae_c, eva_c, aev_c], wavelet_index_handles) =
        wavelets.freeze_with_rank9_indexes(&mut rank9_sections)?;
    index_handles.extend(wavelet_index_handles);

    let meta = SuccinctArchiveMeta {
        domain: domain.metadata(),
        e_a: e_a.metadata(),
        a_a: a_a.metadata(),
        v_a: v_a.metadata(),
        changed_e_a: changed_e_a.metadata(),
        changed_e_v: changed_e_v.metadata(),
        changed_a_e: changed_a_e.metadata(),
        changed_a_v: changed_a_v.metadata(),
        changed_v_e: changed_v_e.metadata(),
        changed_v_a: changed_v_a.metadata(),
        eav_c,
        vea_c,
        ave_c,
        vae_c,
        eva_c,
        aev_c,
    };

    try_finalize_rank9_index(&mut rank9_sections, &index_handles)
        .expect("temporary Rank9 arena must remain writable");
    drop((
        e_a,
        a_a,
        v_a,
        changed_e_a,
        changed_e_v,
        changed_a_e,
        changed_a_v,
        changed_v_e,
        changed_v_a,
    ));

    let runtime_bytes = area.freeze().unwrap();
    let bytes = encode_portable_runtime(&meta, &domain, &runtime_bytes).unwrap();
    let raw_blob = Blob::<SuccinctArchiveBlob>::new(bytes.clone());
    rank9_header[0].source = raw_blob.get_handle().raw;
    rank9_header.freeze().unwrap();
    let rank9_bytes = rank9_area.freeze().unwrap();

    Ok(SuccinctArchive::from_runtime_bytes_with_rank9_indexes(
        meta,
        runtime_bytes,
        raw_blob,
        Blob::new(rank9_bytes),
    )
    .unwrap())
}

impl<U> From<&TribleSet> for SuccinctArchive<U>
where
    U: Universe + Serializable<Error = jerky::error::Error>,
    <U as Serializable>::Meta: Clone,
{
    fn from(set: &TribleSet) -> Self {
        match build_archive_from_tribleset_with_factory(set, &PackedCpuWaveletFactory) {
            Ok(archive) => archive,
            Err(SuccinctArchiveMergeError::DomainTooWide(_)) => {
                build_archive_from_tribleset_with_factory(set, &JerkyWaveletFactory).unwrap()
            }
            Err(SuccinctArchiveMergeError::Backend(never)) => match never {},
            Err(error) => panic!("internal packed wavelet freeze violated its contract: {error}"),
        }
    }
}

/// Builds a queryable succinct index directly from a canonical
/// [`SimpleArchive`] blob.
///
/// The source decoder keeps the archive's 64-byte records behind PATCH
/// LocalLeaves while the six succinct rotations are built, so callers do not
/// need to materialize a second owned copy of every trible first.
impl<U> TryFromBlob<SimpleArchive> for SuccinctArchive<U>
where
    U: Universe + Serializable<Error = jerky::error::Error>,
    <U as Serializable>::Meta: Clone,
{
    type Error = UnarchiveError;

    fn try_from_blob(blob: Blob<SimpleArchive>) -> Result<Self, Self::Error> {
        // SimpleArchive's decoder keeps canonical trible bytes archive-backed
        // through PATCH LocalLeaves, avoiding a second 64-byte trible copy while
        // the succinct builders consume the six sorted rotations.
        let source = TribleSet::try_from_blob(blob)?;
        Ok((&source).into())
    }
}

impl<U> From<&SuccinctArchive<U>> for TribleSet
where
    U: Universe,
{
    fn from(archive: &SuccinctArchive<U>) -> Self {
        archive.iter().collect()
    }
}

impl<U> TriblePattern for SuccinctArchive<U>
where
    U: Universe + Send + Sync,
{
    type PatternConstraint<'a>
        = SuccinctArchiveConstraint<'a, U>
    where
        U: 'a;

    fn pattern<'a, V: InlineEncoding>(
        &'a self,
        e: impl Into<crate::query::Term<GenId>>,
        a: impl Into<crate::query::Term<GenId>>,
        v: impl Into<crate::query::Term<V>>,
    ) -> Self::PatternConstraint<'a> {
        SuccinctArchiveConstraint::new(e, a, v, self)
    }
}

impl<U> SuccinctArchive<U>
where
    U: Universe + Serializable<Error = jerky::error::Error>,
{
    /// Attaches producer-built native sections without auditing their contents.
    fn from_runtime_bytes_with_rank9_indexes(
        meta: SuccinctArchiveMeta<U::Meta>,
        runtime_bytes: Bytes,
        raw: Blob<SuccinctArchiveBlob>,
        rank9: Blob<Rank9AcceleratedSuccinctArchiveBlob>,
    ) -> Result<Self, jerky::error::Error> {
        Self::from_query_parts(
            QueryParts::from_runtime(meta, &runtime_bytes)?,
            raw,
            Some(rank9),
        )
    }

    fn from_query_parts(
        parts: QueryParts<U>,
        raw: Blob<SuccinctArchiveBlob>,
        rank9: Option<Blob<Rank9AcceleratedSuccinctArchiveBlob>>,
    ) -> Result<Self, jerky::error::Error> {
        let source = raw.get_handle();
        let rank9_handle = rank9.as_ref().map(Blob::get_handle);
        let rank9_index_bytes = rank9.map(|blob| blob.bytes);
        let mut indexes = match &rank9_index_bytes {
            Some(bytes) => parse_rank9_index(parts.data().count(), source, bytes)?,
            None => Vec::new(),
        }
        .into_iter();
        let mut vector = |data: BitVectorData| -> Result<_, jerky::error::Error> {
            let index = match &rank9_index_bytes {
                Some(bytes) => {
                    let handle = indexes
                        .next()
                        .ok_or_else(|| invalid_rank9_metadata("missing Rank9 index"))?;
                    SuccinctIndex::Rank9(Rank9SelIndex::from_bytes_with_len(
                        data.len(),
                        handle.bytes(bytes),
                    )?)
                }
                None => SuccinctIndex::Raw,
            };
            Ok(BitVector::new(data, index))
        };
        let top_level = parts
            .top_level
            .into_iter()
            .map(&mut vector)
            .collect::<Result<Vec<_>, _>>()?;
        let [e_a, a_a, v_a, changed_e_a, changed_e_v, changed_a_e, changed_a_v, changed_v_e, changed_v_a]:
            [BitVector<SuccinctIndex>; TOP_LEVEL_RANK9_INDEX_COUNT] =
            top_level.try_into().expect("nine top-level vectors");
        let mut matrices = Vec::with_capacity(6);
        for layers in parts.matrices {
            let layers = layers
                .into_iter()
                .map(&mut vector)
                .collect::<Result<Vec<_>, _>>()?;
            matrices.push(WaveletMatrix::from_layers(parts.domain.len(), layers)?);
        }
        let [eav_c, vea_c, ave_c, vae_c, eva_c, aev_c]: [WaveletMatrix<SuccinctIndex>; 6] =
            matrices.try_into().expect("six Ring matrices");
        Ok(Self {
            bytes: raw.bytes,
            raw_handle: source,
            rank9_index_bytes,
            rank9_handle,
            distinct_counts: Arc::default(),
            domain: parts.domain,
            e_a,
            a_a,
            v_a,
            changed_e_a,
            changed_e_v,
            changed_a_e,
            changed_a_v,
            changed_v_e,
            changed_v_a,
            eav_c,
            vea_c,
            ave_c,
            vae_c,
            eva_c,
            aev_c,
        })
    }
}

impl<U> Encodes<&SuccinctArchive<U>> for SuccinctArchiveBlob
where
    U: Universe + Serializable,
    crate::inline::encodings::hash::Handle<SuccinctArchiveBlob>: crate::inline::InlineEncoding,
{
    type Output = Blob<SuccinctArchiveBlob>;
    fn encode(source: &SuccinctArchive<U>) -> Blob<SuccinctArchiveBlob> {
        Blob::with_handle(source.bytes.clone(), source.raw_handle)
    }
}

impl<U> Encodes<SuccinctArchive<U>> for SuccinctArchiveBlob
where
    U: Universe + Serializable,
    crate::inline::encodings::hash::Handle<SuccinctArchiveBlob>: crate::inline::InlineEncoding,
{
    type Output = Blob<SuccinctArchiveBlob>;
    fn encode(source: SuccinctArchive<U>) -> Blob<SuccinctArchiveBlob> {
        Blob::with_handle(source.bytes, source.raw_handle)
    }
}

/// Error returned when validating, merging, or attaching a raw succinct archive.
pub struct SuccinctArchiveError(jerky::error::Error);

impl From<jerky::error::Error> for SuccinctArchiveError {
    fn from(error: jerky::error::Error) -> Self {
        Self(error)
    }
}

impl std::error::Error for SuccinctArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

impl std::fmt::Display for SuccinctArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid succinct archive: {}", self.0)
    }
}

impl std::fmt::Debug for SuccinctArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SuccinctArchiveError")
            .field(&self.0)
            .finish()
    }
}

impl<U> SuccinctArchive<U>
where
    U: Universe + Serializable<Error = jerky::error::Error>,
{
    /// Borrows the portable sections. Rank/select queries scan their source
    /// words until the caller explicitly supplies or builds a Rank9 root.
    fn from_portable_blob(raw: Blob<SuccinctArchiveBlob>) -> Result<Self, SuccinctArchiveError> {
        let parts = QueryParts::from_portable(&raw.bytes)?;
        Self::from_query_parts(parts, raw, None).map_err(SuccinctArchiveError)
    }

    /// Builds a queryable archive and returns its raw and Rank9 artifacts.
    pub fn build_accelerated_parts(
        source: &TribleSet,
    ) -> (
        Blob<SuccinctArchiveBlob>,
        Blob<Rank9AcceleratedSuccinctArchiveBlob>,
    )
    where
        U::Meta: Clone,
    {
        let archive: Self = source.into();
        archive.to_accelerated_parts()
    }

    /// Returns the canonical raw archive and its source-bound Rank9
    /// accelerator as two independently content-addressed blobs.
    pub fn to_accelerated_parts(
        &self,
    ) -> (
        Blob<SuccinctArchiveBlob>,
        Blob<Rank9AcceleratedSuccinctArchiveBlob>,
    ) {
        (
            Blob::with_handle(self.bytes.clone(), self.raw_handle),
            self.accelerated_root(),
        )
    }

    /// Explicitly obtains this archive's source-bound Rank9 accelerated root.
    ///
    /// This is useful when the caller already owns the canonical raw blob and
    /// must persist the accelerator without hashing the raw bytes again.
    /// If this is an unaccelerated raw view, this method constructs a new
    /// accelerator; ordinary query methods never do so.
    pub fn accelerated_root(&self) -> Blob<Rank9AcceleratedSuccinctArchiveBlob> {
        match (&self.rank9_index_bytes, self.rank9_handle) {
            (Some(bytes), Some(handle)) => Blob::with_handle(bytes.clone(), handle),
            _ => {
                Self::build_accelerated_root(Blob::with_handle(self.bytes.clone(), self.raw_handle))
                    .expect("explicit Rank9 construction failed")
            }
        }
    }

    /// Explicitly constructs only the Rank9 accelerator from stored raw words.
    /// The raw sections are structurally attached, not canonically rederived.
    pub fn build_accelerated_root(
        raw: Blob<SuccinctArchiveBlob>,
    ) -> Result<Blob<Rank9AcceleratedSuccinctArchiveBlob>, SuccinctArchiveError> {
        let source = raw.get_handle();
        let parts = QueryParts::<U>::from_portable(&raw.bytes)?;
        let index = build_rank9_index(&parts, source).map_err(SuccinctArchiveError)?;
        Ok(Blob::new(index))
    }

    /// Attaches a source-bound raw/index pair using only typed framing and
    /// section geometry. Producer-endorsed rank/select contents are not reproved.
    pub fn from_accelerated_parts(
        raw: Blob<SuccinctArchiveBlob>,
        rank9: Blob<Rank9AcceleratedSuccinctArchiveBlob>,
    ) -> Result<Self, SuccinctArchiveError> {
        let parts = QueryParts::from_portable(&raw.bytes)?;
        Self::from_query_parts(parts, raw, Some(rank9)).map_err(SuccinctArchiveError)
    }

    /// Explicitly audits raw canonical bytes and every Rank9 directory/hint
    /// against its corresponding raw words. Ordinary readers never call this.
    pub fn validate_accelerated_parts(
        raw: &Blob<SuccinctArchiveBlob>,
        rank9: &Blob<Rank9AcceleratedSuccinctArchiveBlob>,
    ) -> Result<(), SuccinctArchiveError> {
        SuccinctArchiveBlob::validate(raw)?;
        let parts = QueryParts::<U>::from_portable(&raw.bytes)?;
        let handles = parse_rank9_index(parts.data().count(), raw.get_handle(), &rank9.bytes)?;
        for (data, handle) in parts.data().zip(handles) {
            Rank9SelIndex::<true, true>::from_bytes_for_data(data, handle.bytes(&rank9.bytes))?;
        }
        Ok(())
    }
}

impl<U> TryFromBlob<SuccinctArchiveBlob> for SuccinctArchive<U>
where
    U: Universe + Serializable<Error = jerky::error::Error>,
{
    type Error = SuccinctArchiveError;

    fn try_from_blob(blob: Blob<SuccinctArchiveBlob>) -> Result<Self, Self::Error> {
        Self::from_portable_blob(blob)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::blob::IntoBlob;
    use crate::id::fucid;
    use crate::inline::IntoInline;
    use crate::inline::TryToInline;
    use crate::prelude::*;
    use crate::query::find;
    use crate::trible::Trible;

    use super::*;
    use anybytes::area::ByteArea;
    use itertools::Itertools;
    use proptest::prelude::*;

    struct ReferencePackedFreeze;

    impl WaveletMatrixFreezeBackend for ReferencePackedFreeze {
        type Error = std::convert::Infallible;

        fn freeze_rotation(
            &self,
            _rotation: SuccinctRotation,
            _alphabet_size: usize,
            sequence: &[u32],
            planes: &mut [&mut [u64]],
        ) -> Result<(), Self::Error> {
            let mut current = sequence.to_vec();
            let mut next = vec![0u32; sequence.len()];
            let width = planes.len();
            for (depth, plane) in planes.iter_mut().enumerate() {
                plane.fill(0);
                let shift = width - 1 - depth;
                let mut zeros = 0usize;
                for (position, &code) in current.iter().enumerate() {
                    let bit = (code >> shift) & 1;
                    if bit == 0 {
                        zeros += 1;
                    } else {
                        plane[position / 64] |= 1u64 << (position % 64);
                    }
                }
                let (mut zero, mut one) = (0usize, zeros);
                for &code in &current {
                    if (code >> shift) & 1 == 0 {
                        next[zero] = code;
                        zero += 1;
                    } else {
                        next[one] = code;
                        one += 1;
                    }
                }
                std::mem::swap(&mut current, &mut next);
            }
            Ok(())
        }
    }

    pub mod knights {
        use crate::prelude::*;

        attributes! {
            "328edd7583de04e2bedd6bd4fd50e651" as loves: inlineencodings::GenId;
            "328147856cc1984f0806dbb824d2b4cb" as name: inlineencodings::ShortString;
            "328f2c33d2fdd675e733388770b2d6c4" as title: inlineencodings::ShortString;
        }
    }

    proptest! {
        #[test]
        fn create(entries in prop::collection::vec(prop::collection::vec(0u8..255, 64), 1..128)) {
            let mut set = TribleSet::new();
            for entry in entries {
                let mut key = [0; 64];
                key.iter_mut().set_from(entry.iter().cloned());
                set.insert(&Trible{ data: key});
            }

            let _archive: SuccinctArchive<CompressedUniverse> = (&set).into();
        }

        #[test]
        fn roundtrip(entries in prop::collection::vec(prop::collection::vec(0u8..255, 64), 1..128)) {
            let mut set = TribleSet::new();
            for entry in entries {
                let mut key = [0; 64];
                key.iter_mut().set_from(entry.iter().cloned());
                set.insert(&Trible{ data: key});
            }

            let archive: SuccinctArchive<CompressedUniverse> = (&set).into();
            let set_: TribleSet = (&archive).into();
            let blob: Blob<SuccinctArchiveBlob> = (&archive).to_blob();
            let restored: SuccinctArchive<CompressedUniverse> =
                blob.try_from_blob().unwrap();
            let restored_set: TribleSet = (&restored).into();

            assert_eq!(set, set_);
            assert_eq!(set, restored_set);
        }

        #[test]
        fn packed_leaf_build_matches_jerky_bytes(
            entries in prop::collection::vec(any::<[u8; 64]>(), 0..256)
        ) {
            let set: TribleSet = entries
                .into_iter()
                .map(|data| Trible { data })
                .collect();
            let packed: SuccinctArchive<OrderedUniverse> =
                build_archive_from_tribleset_with_factory(&set, &PackedCpuWaveletFactory)
                    .unwrap();
            let jerky: SuccinctArchive<OrderedUniverse> =
                build_archive_from_tribleset_with_factory(&set, &JerkyWaveletFactory).unwrap();

            prop_assert_eq!(packed.bytes.as_ref(), jerky.bytes.as_ref());
            prop_assert_eq!(
                packed.rank9_index_bytes.as_ref(),
                jerky.rank9_index_bytes.as_ref()
            );
            prop_assert_eq!(TribleSet::from(&packed), set);
        }

        #[test]
        fn raw_simplearchive_builder_matches_both_runtime_universes(
            entries in prop::collection::vec(any::<[u8; 64]>(), 0..256)
        ) {
            let set: TribleSet = entries
                .into_iter()
                .map(|mut data| {
                    data[0] |= 1;
                    data[16] |= 1;
                    Trible { data }
                })
                .collect();
            let source: Blob<SimpleArchive> = (&set).to_blob();
            let raw = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
            let backend_raw = SuccinctArchiveBlob::build_from_simple_archive_with_backend(
                &source, &ReferencePackedFreeze,
            ).unwrap();
            let ordered: SuccinctArchive<OrderedUniverse> = (&set).into();
            let compressed: SuccinctArchive<CompressedUniverse> = (&set).into();

            prop_assert_eq!(raw.bytes.as_ref(), ordered.bytes.as_ref());
            prop_assert_eq!(raw.bytes.as_ref(), compressed.bytes.as_ref());
            prop_assert_eq!(backend_raw.bytes.as_ref(), raw.bytes.as_ref());
            prop_assert_eq!(backend_raw.get_handle(), raw.get_handle());
            let attached: SuccinctArchive<OrderedUniverse> = raw.try_from_blob().unwrap();
            prop_assert_eq!(TribleSet::from(&attached), set);
        }

        #[test]
        fn raw_merge_matches_canonical_set_union_independent_of_input_order(
            entries in prop::collection::vec(
                (
                    any::<[u8; 16]>(),
                    any::<[u8; 16]>(),
                    any::<[u8; 32]>(),
                    1u8..16,
                ),
                0..64,
            )
        ) {
            let mut sets: [TribleSet; 4] = std::array::from_fn(|_| TribleSet::new());
            for (mut entity, mut attribute, value, membership) in entries {
                entity[0] |= 1;
                attribute[0] |= 1;
                let trible = Trible::force(
                    &Id::new(entity).unwrap(),
                    &Id::new(attribute).unwrap(),
                    &Inline::<UnknownInline>::new(value),
                );
                for (index, set) in sets.iter_mut().enumerate() {
                    if membership & (1 << index) != 0 {
                        set.insert(&trible);
                    }
                }
            }

            let mut segments = sets
                .iter()
                .map(|set| {
                    let source: Blob<SimpleArchive> = set.to_blob();
                    SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap()
                })
                .collect::<Vec<_>>();
            let forward = SuccinctArchiveBlob::merge(&segments).unwrap();
            let backend_forward = SuccinctArchiveBlob::merge_with_backend(&segments, &ReferencePackedFreeze).unwrap();
            segments.reverse();
            let reverse = SuccinctArchiveBlob::merge(&segments).unwrap();
            let backend_reverse = SuccinctArchiveBlob::merge_with_backend(&segments, &ReferencePackedFreeze).unwrap();
            let union = sets.into_iter().fold(TribleSet::new(), |left, right| left + right);
            let union_source: Blob<SimpleArchive> = (&union).to_blob();
            let expected = SuccinctArchiveBlob::build_from_simple_archive(&union_source).unwrap();

            prop_assert_eq!(forward.bytes.as_ref(), expected.bytes.as_ref());
            prop_assert_eq!(reverse.bytes.as_ref(), expected.bytes.as_ref());
            prop_assert_eq!(forward.get_handle(), expected.get_handle());
            prop_assert_eq!(backend_forward.bytes.as_ref(), expected.bytes.as_ref());
            prop_assert_eq!(backend_reverse.bytes.as_ref(), expected.bytes.as_ref());
            prop_assert_eq!(backend_forward.get_handle(), expected.get_handle());
            let attached: SuccinctArchive<OrderedUniverse> = forward.try_from_blob().unwrap();
            prop_assert_eq!(TribleSet::from(&attached), union);
        }

        #[test]
        fn structural_merge_matches_rebuild_for_overlapping_segments(
            entries in prop::collection::vec(
                (
                    any::<[u8; 16]>(),
                    any::<[u8; 16]>(),
                    any::<[u8; 32]>(),
                    1u8..16,
                ),
                0..96,
            )
        ) {
            let mut sets: [TribleSet; 4] = std::array::from_fn(|_| TribleSet::new());
            for (mut entity, mut attribute, value, membership) in entries {
                entity[0] |= 1;
                attribute[0] |= 1;
                let entity = Id::new(entity).unwrap();
                let attribute = Id::new(attribute).unwrap();
                let value = Inline::<UnknownInline>::new(value);
                let trible = Trible::force(&entity, &attribute, &value);
                for (index, set) in sets.iter_mut().enumerate() {
                    if membership & (1 << index) != 0 {
                        set.insert(&trible);
                    }
                }
            }

            let archives: Vec<SuccinctArchive<OrderedUniverse>> =
                sets.iter().map(Into::into).collect();
            let merged = merge_ordered_archives(&archives);
            let backend_merged =
                merge_ordered_archives_with_backend(&archives, &ReferencePackedFreeze).unwrap();
            let union = sets.into_iter().fold(TribleSet::new(), |left, right| left + right);
            let rebuilt: SuccinctArchive<OrderedUniverse> = (&union).into();

            prop_assert_eq!(merged.bytes.as_ref(), rebuilt.bytes.as_ref());
            prop_assert_eq!(backend_merged.bytes.as_ref(), rebuilt.bytes.as_ref());
            prop_assert_eq!(&TribleSet::from(&merged), &union);
            prop_assert_eq!(&TribleSet::from(&backend_merged), &union);
        }

        #[test]
        fn ordered_universe(values in prop::collection::vec(prop::collection::vec(0u8..255, 32), 1..128)) {
            let mut values: Vec<RawInline> = values.into_iter().map(|v| v.try_into().unwrap()).collect();
            values.sort();
            let mut area = ByteArea::new().unwrap();
            let mut sections = area.sections();
            let u = OrderedUniverse::with(values.iter().copied(), &mut sections);
            drop(sections);
            let _bytes = area.freeze().unwrap();
            for i in 0..u.len() {
                let original = values[i];
                let reconstructed = u.access(i);
                assert_eq!(original, reconstructed);
            }
            for i in 0..u.len() {
                let original = Some(i);
                let found = u.search(&values[i]);
                assert_eq!(original, found);
            }
        }

        #[test]
        fn compressed_universe(values in prop::collection::vec(prop::collection::vec(0u8..255, 32), 1..128)) {
            let mut values: Vec<RawInline> = values.into_iter().map(|v| v.try_into().unwrap()).collect();
            values.sort();
            let mut area = ByteArea::new().unwrap();
            let mut sections = area.sections();
            let u = CompressedUniverse::with(values.iter().copied(), &mut sections);
            drop(sections);
            let _bytes = area.freeze().unwrap();
            for i in 0..u.len() {
                let original = values[i];
                let reconstructed = u.access(i);
                assert_eq!(original, reconstructed);
            }
            for i in 0..u.len() {
                let original = Some(i);
                let found = u.search(&values[i]);
                assert_eq!(original, found);
            }
        }
    }

    fn ordered_id(last: u8) -> Id {
        let mut raw = [0; 16];
        raw[15] = last;
        Id::new(raw).unwrap()
    }

    fn ordered_value(first: u8) -> Inline<UnknownInline> {
        Inline::new([first; 32])
    }

    #[test]
    fn fixed_attribute_ave_iteration_is_decoded_and_double_ended() {
        let attribute = ordered_id(10);
        let other_attribute = ordered_id(11);
        let low = ordered_value(0x20);
        let high = ordered_value(0x40);
        let e1 = ordered_id(1);
        let e2 = ordered_id(2);
        let e3 = ordered_id(3);
        let e4 = ordered_id(4);

        let mut set = TribleSet::new();
        set.insert(&Trible::force(&e3, &attribute, &high));
        set.insert(&Trible::force(&e2, &attribute, &low));
        set.insert(&Trible::force(&e1, &attribute, &low));
        set.insert(&Trible::force(&e4, &other_attribute, &ordered_value(0x10)));
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let expected = vec![(low.raw, e1), (low.raw, e2), (high.raw, e3)];

        assert_eq!(
            archive
                .iter_attribute_value_entities(&attribute)
                .collect_vec(),
            expected
        );
        assert_eq!(
            archive
                .iter_attribute_value_entities(&attribute)
                .rev()
                .collect_vec(),
            expected.iter().copied().rev().collect_vec()
        );

        let mut from_both_ends = archive.iter_attribute_value_entities(&attribute);
        assert_eq!(from_both_ends.len(), 3);
        assert_eq!(from_both_ends.next(), Some(expected[0]));
        assert_eq!(from_both_ends.next_back(), Some(expected[2]));
        assert_eq!(from_both_ends.next(), Some(expected[1]));
        assert_eq!(from_both_ends.next_back(), None);

        assert_eq!(
            archive.iter_attribute_value_entities(&ordered_id(99)).len(),
            0
        );
    }

    #[test]
    fn decoded_attribute_ave_iterators_kmerge_across_local_domains() {
        let attribute = ordered_id(10);
        let e1 = ordered_id(1);
        let e2 = ordered_id(2);
        let e3 = ordered_id(3);
        let e4 = ordered_id(4);
        let v1 = ordered_value(0x10);
        let v2 = ordered_value(0x20);
        let v3 = ordered_value(0x30);
        let v4 = ordered_value(0x40);

        let mut left = TribleSet::new();
        left.insert(&Trible::force(&e1, &attribute, &v1));
        left.insert(&Trible::force(&e3, &attribute, &v3));

        let mut right = TribleSet::new();
        right.insert(&Trible::force(&e2, &attribute, &v2));
        right.insert(&Trible::force(&e3, &attribute, &v3));
        right.insert(&Trible::force(&e4, &attribute, &v4));

        let left: SuccinctArchive<OrderedUniverse> = (&left).into();
        let right: SuccinctArchive<OrderedUniverse> = (&right).into();

        // The shared `(v3, e3)` fact has different archive-local codes because
        // the two segment domains contain different preceding entities/values.
        let merged = [
            left.iter_attribute_value_entities(&attribute),
            right.iter_attribute_value_entities(&attribute),
        ]
        .into_iter()
        .kmerge()
        .dedup()
        .collect_vec();

        assert_eq!(
            merged,
            vec![(v1.raw, e1), (v2.raw, e2), (v3.raw, e3), (v4.raw, e4)]
        );
    }

    #[test]
    fn archive_pattern() {
        let juliet = fucid();
        let romeo = fucid();

        let mut kb = TribleSet::new();

        kb += entity! { &juliet @
           knights::name: "Juliet",
           knights::loves: &romeo,
           knights::title: "Maiden"
        };
        kb += entity! { &romeo @
           knights::name: "Romeo",
           knights::loves: &juliet,
           knights::title: "Prince"
        };
        kb += entity! {
           knights::name: "Angelica",
           knights::title: "Nurse"
        };

        let archive: SuccinctArchive<OrderedUniverse> = (&kb).into();

        let r: Vec<_> = find!(
            (juliet, name),
            pattern!(&archive, [
            {knights::name: "Romeo",
             knights::loves: ?juliet},
            {?juliet @
                knights::name: ?name
            }])
        )
        .collect();
        assert_eq!(
            vec![((&juliet).to_inline(), "Juliet".try_to_inline().unwrap(),)],
            r
        );
    }

    #[test]
    fn blob_roundtrip() {
        let juliet = fucid();
        let romeo = fucid();

        let mut kb = TribleSet::new();

        kb += entity! {&juliet @
            knights::name: "Juliet",
            knights::loves: &romeo,
            knights::title: "Maiden"
        };
        kb += entity! {&romeo @
            knights::name: "Romeo",
            knights::loves: &juliet,
            knights::title: "Prince"
        };

        let archive: SuccinctArchive<OrderedUniverse> = (&kb).into();
        let blob: Blob<SuccinctArchiveBlob> = (&archive).to_blob();
        let rebuilt: SuccinctArchive<OrderedUniverse> = blob.try_from_blob().unwrap();
        let kb2: TribleSet = (&rebuilt).into();
        assert_eq!(kb, kb2);
    }

    #[test]
    fn public_builder_matches_the_portable_singleton_golden() {
        let entity = ordered_id(1);
        let attribute = ordered_id(2);
        let mut raw_value = [0u8; 32];
        raw_value[0] = 1;
        let value = Inline::<UnknownInline>::new(raw_value);
        let set: TribleSet = [Trible::force(&entity, &attribute, &value)]
            .into_iter()
            .collect();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

        assert_eq!(
            blake3::hash(archive.bytes.as_ref()).to_hex().as_str(),
            "c55fa61e822974f3cb0e5b2d156dbf35b0e5bbb7599595209e6672ec91d8b8c1"
        );
        let decoded: SuccinctArchive<OrderedUniverse> =
            Blob::<SuccinctArchiveBlob>::new(archive.bytes.clone())
                .try_from_blob()
                .unwrap();
        assert_eq!(TribleSet::from(&decoded), set);
    }

    #[test]
    fn empty_portable_archive_and_source_bound_rank9_roundtrip() {
        let set = TribleSet::new();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let (raw, rank9) = archive.to_accelerated_parts();
        let raw_only: SuccinctArchive<OrderedUniverse> = raw.clone().try_from_blob().unwrap();
        let paired =
            SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw, rank9).unwrap();
        assert_eq!(TribleSet::from(&raw_only), set);
        assert_eq!(TribleSet::from(&paired), set);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn raw_attachment_borrows_sections_and_never_builds_a_rank9_index() {
        let set = varied_knights();
        let source: Blob<SimpleArchive> = (&set).to_blob();
        let raw = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
        let start = raw.bytes.as_ptr() as usize;
        let end = start + raw.bytes.len();
        let parts = QueryParts::<OrderedUniverse>::from_portable(&raw.bytes).unwrap();
        for data in parts.data() {
            let pointer = data.words().as_ptr() as usize;
            assert!((start..end).contains(&pointer));
            assert!(pointer + std::mem::size_of_val(data.words()) <= end);
        }
        let archive: SuccinctArchive<OrderedUniverse> = raw.clone().try_from_blob().unwrap();
        assert_eq!(archive.bytes.as_ptr(), raw.bytes.as_ptr());
        assert_eq!(archive.domain.values().as_ptr() as usize, start);
        for vector in [
            &archive.e_a,
            &archive.a_a,
            &archive.v_a,
            &archive.changed_e_a,
            &archive.changed_e_v,
            &archive.changed_a_e,
            &archive.changed_a_v,
            &archive.changed_v_e,
            &archive.changed_v_a,
        ] {
            assert!(matches!(vector.index, SuccinctIndex::Raw));
            let pointer = vector.data.words().as_ptr() as usize;
            assert!((start..end).contains(&pointer));
            assert!(pointer + std::mem::size_of_val(vector.data.words()) <= end);
        }
        assert!(archive.rank9_index_bytes.is_none());
        assert!(archive.rank9_handle.is_none());
        assert_eq!(TribleSet::from(&archive), set);
        assert_eq!(
            archive.entity_count(),
            set.eav.segmented_len(&[0; 0]) as usize
        );
        assert_eq!(
            archive.attribute_count(),
            set.ave.segmented_len(&[0; 0]) as usize
        );
        assert_eq!(
            archive.value_count(),
            set.vea.segmented_len(&[0; 0]) as usize
        );
        // Querying did not defer a hidden whole-index construction.
        assert!(archive.rank9_index_bytes.is_none());
        assert!(matches!(archive.e_a.index, SuccinctIndex::Raw));

        // Asking for the accelerator is an explicit construction operation.
        let rank9 = archive.accelerated_root();
        assert!(archive.rank9_index_bytes.is_none());
        let rank_pointer = rank9.bytes.as_ptr();
        let paired =
            SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw, rank9).unwrap();
        assert_eq!(paired.bytes.as_ptr() as usize, start);
        assert_eq!(paired.domain.values().as_ptr() as usize, start);
        assert_eq!(
            paired.rank9_index_bytes.as_ref().unwrap().as_ptr(),
            rank_pointer
        );
        assert_eq!(
            paired.e_a.data.words().as_ptr(),
            archive.e_a.data.words().as_ptr()
        );
        assert!(matches!(paired.e_a.index, SuccinctIndex::Rank9(_)));
        assert_eq!(TribleSet::from(&paired), set);
    }

    #[test]
    fn distinct_counts_are_lazy_and_shared_across_clones() {
        let set = varied_knights();
        let source: Blob<SimpleArchive> = (&set).to_blob();
        let raw = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
        let before = PREFIX_DISTINCT_COUNT_CALLS.with(std::cell::Cell::get);
        let archive: SuccinctArchive<OrderedUniverse> = raw.try_from_blob().unwrap();
        let clone = archive.clone();
        assert_eq!(
            PREFIX_DISTINCT_COUNT_CALLS.with(std::cell::Cell::get),
            before
        );
        assert!(archive
            .distinct_counts
            .iter()
            .all(|count| count.get().is_none()));
        assert!(Arc::ptr_eq(
            &archive.distinct_counts,
            &clone.distinct_counts
        ));

        let entities = set.eav.segmented_len(&[0; 0]) as usize;
        assert_eq!(archive.entity_count(), entities);
        assert_eq!(
            PREFIX_DISTINCT_COUNT_CALLS.with(std::cell::Cell::get),
            before + 1
        );
        assert_eq!(clone.distinct_counts[0].get(), Some(&entities));
        assert!(clone.distinct_counts[1].get().is_none());
        assert!(clone.distinct_counts[2].get().is_none());
        for _ in 0..4 {
            assert_eq!(clone.entity_count(), entities);
            assert_eq!(archive.entity_count(), entities);
        }
        assert_eq!(
            PREFIX_DISTINCT_COUNT_CALLS.with(std::cell::Cell::get),
            before + 1
        );

        let attributes = set.ave.segmented_len(&[0; 0]) as usize;
        let values = set.vea.segmented_len(&[0; 0]) as usize;
        for _ in 0..4 {
            assert_eq!(clone.attribute_count(), attributes);
            assert_eq!(archive.attribute_count(), attributes);
            assert_eq!(archive.value_count(), values);
            assert_eq!(clone.value_count(), values);
        }
        assert_eq!(
            PREFIX_DISTINCT_COUNT_CALLS.with(std::cell::Cell::get),
            before + 3
        );
        assert!(archive.rank9_index_bytes.is_none());
        assert!(matches!(archive.e_a.index, SuccinctIndex::Raw));
        assert!(matches!(archive.a_a.index, SuccinctIndex::Raw));
        assert!(matches!(archive.v_a.index, SuccinctIndex::Raw));
    }

    #[test]
    fn typed_attachment_rejects_truncated_overflowing_and_misaligned_sections() {
        let archive: SuccinctArchive<OrderedUniverse> = (&varied_knights()).into();
        let (raw, rank9) = archive.to_accelerated_parts();
        for length in 0..raw.bytes.len() {
            let candidate = Blob::<SuccinctArchiveBlob>::new(raw.bytes.slice(..length));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                SuccinctArchive::<OrderedUniverse>::try_from_blob(candidate)
            }));
            assert!(result.is_ok(), "truncated raw framing panicked at {length}");
        }
        let mut overflowing = raw.bytes.as_ref().to_vec();
        let footer = overflowing.len() - 16;
        overflowing[footer..footer + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        let result: Result<SuccinctArchive<OrderedUniverse>, _> =
            Blob::<SuccinctArchiveBlob>::new(Bytes::from(overflowing)).try_from_blob();
        assert!(result.is_err());

        let mut offset = vec![0u8];
        offset.extend_from_slice(raw.bytes.as_ref());
        let candidate = Blob::<SuccinctArchiveBlob>::new(Bytes::from(offset).slice(1..));
        #[cfg(target_endian = "little")]
        assert!(SuccinctArchive::<OrderedUniverse>::try_from_blob(candidate).is_err());
        #[cfg(target_endian = "big")]
        drop(candidate); // BE words require an explicit byte-order conversion.

        for length in 0..rank9.bytes.len() {
            let candidate =
                Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(rank9.bytes.slice(..length));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw.clone(), candidate)
            }));
            assert!(
                matches!(result, Ok(Err(_))),
                "truncated Rank9 accepted or panicked at {length}"
            );
        }
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn mmap_backing_survives_raw_and_accelerated_attachment() {
        let set = varied_knights();
        let (raw, rank9) = SuccinctArchive::<OrderedUniverse>::build_accelerated_parts(&set);
        let map = |bytes: &Bytes| {
            let mut area = memmap2::MmapMut::map_anon(bytes.len()).unwrap();
            area.copy_from_slice(bytes.as_ref());
            Bytes::from_source(area.make_read_only().unwrap())
        };
        let raw = Blob::<SuccinctArchiveBlob>::new(map(&raw.bytes));
        let rank9 = Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(map(&rank9.bytes));
        let raw_pointer = raw.bytes.as_ptr();
        let rank9_pointer = rank9.bytes.as_ptr();
        let raw_view: SuccinctArchive<OrderedUniverse> = raw.clone().try_from_blob().unwrap();
        let paired =
            SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw, rank9).unwrap();
        assert_eq!(raw_view.bytes.as_ptr(), raw_pointer);
        assert_eq!(paired.bytes.as_ptr(), raw_pointer);
        assert_eq!(
            paired.rank9_index_bytes.as_ref().unwrap().as_ptr(),
            rank9_pointer
        );
        assert_eq!(
            raw_view.domain.values().as_ptr() as usize,
            raw_pointer as usize
        );
        assert_eq!(
            paired.e_a.data.words().as_ptr(),
            raw_view.e_a.data.words().as_ptr()
        );
        // The Blob owners above were consumed; the typed query views own
        // their mappings and remain usable independently.
        assert_eq!(TribleSet::from(&raw_view), set);
        assert_eq!(TribleSet::from(&paired), set);
    }

    #[test]
    fn rank9_attachment_does_not_reprove_semantic_directory_contents() {
        let archive: SuccinctArchive<OrderedUniverse> = (&varied_knights()).into();
        let (raw, rank9) = archive.to_accelerated_parts();
        let mut bytes = rank9.bytes.as_ref().to_vec();
        let first_payload = std::mem::size_of::<Rank9IndexHeader>();
        bytes[first_payload + 2 * std::mem::size_of::<usize>()] ^= 1;
        let changed = Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(Bytes::from(bytes));
        assert!(SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(
            raw.clone(),
            changed.clone()
        )
        .is_ok());
        assert!(
            SuccinctArchive::<OrderedUniverse>::validate_accelerated_parts(&raw, &changed).is_err()
        );
    }

    fn two_by_two_permutation(swapped: bool) -> TribleSet {
        let e1 = ordered_id(1);
        let e2 = ordered_id(2);
        let a1 = ordered_id(3);
        let a2 = ordered_id(4);
        let v1 = ordered_value(0x10);
        let v2 = ordered_value(0x20);
        let pairs = if swapped {
            [(e1, a1, v2), (e2, a2, v1)]
        } else {
            [(e1, a1, v1), (e2, a2, v2)]
        };
        pairs
            .into_iter()
            .map(|(entity, attribute, value)| Trible::force(&entity, &attribute, &value))
            .collect()
    }

    #[test]
    fn explicit_audit_rejects_changed_mask_drift_without_reproving_on_read_or_merge() {
        let archive: SuccinctArchive<OrderedUniverse> = (&two_by_two_permutation(false)).into();
        let mut bytes = archive.bytes.as_ref().to_vec();
        let n = 2usize;
        let d = 6usize;
        let prefix_words = (n + d + 1).div_ceil(64);
        let changed_start = d * 32 + 3 * prefix_words * 8;
        bytes[changed_start] ^= 1 << 1;

        let malformed = Blob::<SuccinctArchiveBlob>::new(Bytes::from(bytes));
        assert!(SuccinctArchiveBlob::validate(&malformed).is_err());
        assert_eq!(
            SuccinctArchiveBlob::merge(&[malformed.clone()])
                .unwrap()
                .bytes,
            archive.bytes
        );
        let result: Result<SuccinctArchive<OrderedUniverse>, _> = malformed.try_from_blob();
        assert!(result.is_ok());
    }

    #[test]
    fn explicit_audit_rejects_foreign_secondary_rotation_without_reproving_on_read_or_merge() {
        let left: SuccinctArchive<OrderedUniverse> = (&two_by_two_permutation(false)).into();
        let right: SuccinctArchive<OrderedUniverse> = (&two_by_two_permutation(true)).into();
        let mut bytes = left.bytes.as_ref().to_vec();

        let n = 2usize;
        let d = 6usize;
        let prefix_words = (n + d + 1).div_ceil(64);
        let row_words = n.div_ceil(64);
        let width = portable::alphabet_width(d);
        let wavelets_start = d * 32 + 3 * prefix_words * 8 + 6 * row_words * 8;
        let wavelet_len = width * row_words * 8;
        let vae = wavelets_start + SuccinctRotation::Vae.index() * wavelet_len;
        bytes[vae..vae + wavelet_len]
            .copy_from_slice(&right.bytes.as_ref()[vae..vae + wavelet_len]);

        // Each source archive is canonical and both have identical domain and
        // per-axis histograms, so the splice passes raw structural validation.
        portable::parse(&bytes).unwrap();
        let malformed = Blob::<SuccinctArchiveBlob>::new(Bytes::from(bytes));
        assert!(SuccinctArchiveBlob::validate(&malformed).is_err());
        assert_eq!(
            SuccinctArchiveBlob::merge(&[malformed.clone()])
                .unwrap()
                .bytes,
            left.bytes
        );
        let result: Result<SuccinctArchive<OrderedUniverse>, _> = malformed.try_from_blob();
        assert!(result.is_ok());
    }

    #[test]
    fn explicit_canonical_audits_agree_for_all_single_bit_mutations() {
        let archive: SuccinctArchive<OrderedUniverse> = (&two_by_two_permutation(false)).into();
        let canonical = archive.bytes.as_ref();

        for byte in 0..canonical.len() {
            for shift in 0..u8::BITS {
                let mut mutated = canonical.to_vec();
                mutated[byte] ^= 1u8 << shift;
                let candidate = Blob::<SuccinctArchiveBlob>::new(Bytes::from(mutated));
                let raw = portable::parse(candidate.bytes.as_ref())
                    .and_then(|view| view.prove_canonical_eav_u32());
                let runtime = SuccinctArchiveBlob::validate(&candidate);

                assert_eq!(
                    raw.is_ok(),
                    runtime.is_ok(),
                    "validation disagreement at byte {byte}, bit {shift}"
                );
                if raw.is_ok() {
                    let merged = SuccinctArchiveBlob::merge(&[candidate.clone()]).unwrap();
                    assert_eq!(
                        merged.bytes, candidate.bytes,
                        "canonical singleton changed at byte {byte}, bit {shift}"
                    );
                }
            }
        }
    }

    #[test]
    fn portable_identity_is_independent_of_runtime_universe_encoding() {
        let set = varied_knights();
        let ordered: SuccinctArchive<OrderedUniverse> = (&set).into();
        let compressed: SuccinctArchive<CompressedUniverse> = (&set).into();
        assert_eq!(ordered.bytes, compressed.bytes);
        assert_eq!(TribleSet::from(&ordered), set);
        assert_eq!(TribleSet::from(&compressed), set);
    }

    fn assert_source_bound_rank9_corruption_rejected(mutate: impl FnOnce(&mut Vec<u8>)) {
        let archive: SuccinctArchive<OrderedUniverse> = (&varied_knights()).into();
        let (raw, rank9) = archive.to_accelerated_parts();
        let mut bytes = rank9.bytes.as_ref().to_vec();
        mutate(&mut bytes);
        let corrupted = Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(Bytes::from_source(bytes));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SuccinctArchive::<OrderedUniverse>::validate_accelerated_parts(&raw, &corrupted)
        }));
        assert!(matches!(result, Ok(Err(_))));
    }

    #[test]
    fn source_bound_rank9_rejects_header_table_and_payload_corruption_without_panicking() {
        assert_source_bound_rank9_corruption_rejected(|bytes| {
            bytes[std::mem::offset_of!(Rank9IndexHeader, marker)] ^= 1;
        });

        assert_source_bound_rank9_corruption_rejected(|bytes| {
            let footer_start = bytes.len() - std::mem::size_of::<Rank9IndexFooter>();
            let table_offset = footer_start + std::mem::offset_of!(Rank9IndexFooter, indexes);
            bytes[table_offset..table_offset + std::mem::size_of::<usize>()]
                .copy_from_slice(&usize::MAX.to_ne_bytes());
        });

        assert_source_bound_rank9_corruption_rejected(|bytes| {
            let first_payload = std::mem::size_of::<Rank9IndexHeader>();
            bytes[first_payload + 2 * std::mem::size_of::<usize>()] ^= 1;
        });
    }

    fn rotation_codes(
        archive: &SuccinctArchive<OrderedUniverse>,
        set: &TribleSet,
        rotation: SuccinctRotation,
    ) -> Vec<[usize; 3]> {
        let mut rows: Vec<_> = set
            .iter()
            .map(|trible| {
                let e = archive.domain.search(&id_into_value(trible.e())).unwrap();
                let a = archive.domain.search(&id_into_value(trible.a())).unwrap();
                let v = archive
                    .domain
                    .search(&trible.v::<UnknownInline>().raw)
                    .unwrap();
                match rotation {
                    SuccinctRotation::Eav => [e, a, v],
                    SuccinctRotation::Vea => [v, e, a],
                    SuccinctRotation::Ave => [a, v, e],
                    SuccinctRotation::Vae => [v, a, e],
                    SuccinctRotation::Eva => [e, v, a],
                    SuccinctRotation::Aev => [a, e, v],
                }
            })
            .collect();
        rows.sort_unstable();
        rows.dedup();
        rows
    }

    fn varied_knights() -> TribleSet {
        let juliet = fucid();
        let romeo = fucid();
        let nurse = fucid();
        let mut set = TribleSet::new();
        set += entity! { &juliet @
            knights::name: "Juliet",
            knights::loves: &romeo,
            knights::title: "Maiden"
        };
        set += entity! { &romeo @
            knights::name: "Romeo",
            knights::loves: &juliet,
            knights::title: "Prince"
        };
        set += entity! { &nurse @
            knights::name: "Angelica",
            knights::loves: &juliet,
            knights::title: "Nurse"
        };
        set
    }

    #[test]
    fn all_rotation_cursors_match_sorted_tribles() {
        let set = varied_knights();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

        for rotation in SuccinctRotation::ALL {
            let actual: Vec<_> = RotationCursor::new(&archive, rotation).collect();
            assert_eq!(
                actual,
                rotation_codes(&archive, &set, rotation),
                "{rotation:?}"
            );
        }
    }

    #[test]
    fn pair_changes_follow_each_rotation_sorted_pair_runs() {
        let set = varied_knights();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();

        for rotation in SuccinctRotation::ALL {
            let rows = rotation_codes(&archive, &set, rotation);
            let expected: Vec<_> = rows
                .iter()
                .enumerate()
                .map(|(index, row)| index == 0 || row[..2] != rows[index - 1][..2])
                .collect();
            let actual: Vec<_> = (0..rows.len())
                .map(|position| archive.pair_changes(rotation).access(position).unwrap())
                .collect();
            assert_eq!(actual, expected, "{rotation:?}");
        }
    }

    #[test]
    fn structural_merge_matches_canonical_rebuild_bytes() {
        let ada = fucid();
        let grace = fucid();
        let alan = fucid();

        let mut left = TribleSet::new();
        left += entity! { &ada @
            knights::name: "Ada",
            knights::title: "Countess",
            knights::loves: &grace
        };
        left += entity! { &grace @ knights::name: "Grace" };

        let mut middle = TribleSet::new();
        // Exact overlap exercises set-union deduplication during compaction.
        middle += entity! { &grace @ knights::name: "Grace" };
        middle += entity! { &grace @
            knights::title: "Rear Admiral",
            knights::loves: &ada
        };

        let mut right = TribleSet::new();
        right += entity! { &alan @
            knights::name: "Alan",
            knights::title: "Mathematician",
            knights::loves: &ada
        };

        let archives: Vec<SuccinctArchive<OrderedUniverse>> = [&left, &middle, &right]
            .into_iter()
            .map(Into::into)
            .collect();
        let merged = merge_ordered_archives(&archives);
        let backend_merged =
            merge_ordered_archives_with_backend(&archives, &ReferencePackedFreeze).unwrap();

        let mut union = left;
        union += middle;
        union += right;
        let rebuilt: SuccinctArchive<OrderedUniverse> = (&union).into();
        let merged_set: TribleSet = (&merged).into();

        assert_eq!(merged_set, union);
        assert_eq!(merged.bytes.as_ref(), rebuilt.bytes.as_ref());
        assert_eq!(backend_merged.bytes.as_ref(), rebuilt.bytes.as_ref());
        assert_eq!(merged.entity_count(), rebuilt.entity_count());
        assert_eq!(merged.attribute_count(), rebuilt.attribute_count());
        assert_eq!(merged.value_count(), rebuilt.value_count());
    }

    #[test]
    fn raw_backend_handles_word_block_and_alphabet_boundaries() {
        struct Counted(std::cell::Cell<usize>);
        impl WaveletMatrixFreezeBackend for Counted {
            type Error = std::convert::Infallible;
            fn freeze_rotation(
                &self,
                rotation: SuccinctRotation,
                alphabet: usize,
                sequence: &[u32],
                planes: &mut [&mut [u64]],
            ) -> Result<(), Self::Error> {
                self.0.set(self.0.get() + 1);
                ReferencePackedFreeze.freeze_rotation(rotation, alphabet, sequence, planes)
            }
        }
        for rows in [
            0u32, 1, 2, 5, 6, 7, 14, 15, 16, 30, 31, 32, 33, 62, 63, 64, 65, 126, 127, 128, 129,
            254, 255, 256, 257,
        ] {
            let mut set = TribleSet::new();
            for row in 0..rows {
                let mut data = [0u8; 64];
                data[0] = 1;
                data[16] = 2;
                data[32] = 3;
                data[60..].copy_from_slice(&row.to_be_bytes());
                set.insert(&Trible { data });
            }
            // One entity, one attribute, N distinct values: D = N + 2.
            let source: Blob<SimpleArchive> = (&set).to_blob();
            let cpu = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
            let backend = Counted(std::cell::Cell::new(0));
            let raw =
                SuccinctArchiveBlob::build_from_simple_archive_with_backend(&source, &backend)
                    .unwrap();
            assert_eq!(raw.bytes.as_ref(), cpu.bytes.as_ref(), "rows={rows}");
            assert_eq!(raw.get_handle(), cpu.get_handle());
            assert_eq!(backend.0.get(), if rows == 0 { 0 } else { 6 });
            let joined =
                SuccinctArchiveBlob::merge_with_backend(&[raw.clone(), raw.clone()], &backend)
                    .unwrap();
            assert_eq!(joined.get_handle(), cpu.get_handle());
            assert_eq!(backend.0.get(), if rows == 0 { 0 } else { 12 });
            let accelerated =
                SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw.clone()).unwrap();
            let attached =
                SuccinctArchive::<OrderedUniverse>::from_accelerated_parts(raw, accelerated)
                    .unwrap();
            assert_eq!(TribleSet::from(&attached), set);
        }
    }

    #[test]
    fn raw_backend_failure_and_noncanonical_planes_are_rejected() {
        struct Broken(u8);
        impl WaveletMatrixFreezeBackend for Broken {
            type Error = &'static str;
            fn freeze_rotation(
                &self,
                rotation: SuccinctRotation,
                alphabet: usize,
                sequence: &[u32],
                planes: &mut [&mut [u64]],
            ) -> Result<(), Self::Error> {
                ReferencePackedFreeze
                    .freeze_rotation(rotation, alphabet, sequence, planes)
                    .unwrap();
                match self.0 {
                    0 => return Err("device failure after writing planes"),
                    1 => planes[0][0] ^= 1,
                    _ => *planes[0].last_mut().unwrap() |= 1u64 << 63,
                }
                Ok(())
            }
        }
        let set = entity! { knights::name: "A" }.into_facts();
        let source: Blob<SimpleArchive> = (&set).to_blob();
        let cpu = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
        for broken in [Broken(0), Broken(1), Broken(2)] {
            assert!(
                SuccinctArchiveBlob::build_from_simple_archive_with_backend(&source, &broken)
                    .is_err()
            );
            assert!(
                SuccinctArchiveBlob::merge_with_backend(std::slice::from_ref(&cpu), &broken)
                    .is_err()
            );
        }
        let malformed = Blob::<SimpleArchive>::new(Bytes::from(vec![0; 1]));
        assert!(SuccinctArchiveBlob::build_from_simple_archive_with_backend(
            &malformed,
            &ReferencePackedFreeze
        )
        .is_err());
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LaterFailure;

    struct FailOnRotation(SuccinctRotation);

    impl WaveletMatrixFreezeBackend for FailOnRotation {
        type Error = LaterFailure;

        fn freeze_rotation(
            &self,
            rotation: SuccinctRotation,
            alphabet_size: usize,
            sequence: &[u32],
            planes: &mut [&mut [u64]],
        ) -> Result<(), Self::Error> {
            if rotation == self.0 {
                return Err(LaterFailure);
            }
            ReferencePackedFreeze
                .freeze_rotation(rotation, alphabet_size, sequence, planes)
                .unwrap();
            Ok(())
        }
    }

    enum Corruption {
        FirstPlane,
        Tail,
    }

    struct CorruptOnRotation {
        rotation: SuccinctRotation,
        corruption: Corruption,
    }

    impl WaveletMatrixFreezeBackend for CorruptOnRotation {
        type Error = std::convert::Infallible;

        fn freeze_rotation(
            &self,
            rotation: SuccinctRotation,
            alphabet_size: usize,
            sequence: &[u32],
            planes: &mut [&mut [u64]],
        ) -> Result<(), Self::Error> {
            ReferencePackedFreeze.freeze_rotation(rotation, alphabet_size, sequence, planes)?;
            if rotation == self.rotation {
                match self.corruption {
                    Corruption::FirstPlane => planes[0][0] ^= 1,
                    Corruption::Tail => {
                        let tail = sequence.len() % 64;
                        assert_ne!(tail, 0);
                        *planes.last_mut().unwrap().last_mut().unwrap() |= 1u64 << tail;
                    }
                }
            }
            Ok(())
        }
    }

    #[test]
    fn backend_errors_keep_the_later_rotation() {
        let set = varied_knights();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let result =
            merge_ordered_archives_with_backend(&[archive], &FailOnRotation(SuccinctRotation::Eva));
        assert!(matches!(
            result,
            Err(SuccinctArchiveMergeError::Backend(LaterFailure))
        ));
    }

    #[test]
    fn backend_first_plane_corruption_is_rejected() {
        let set = varied_knights();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let result = merge_ordered_archives_with_backend(
            &[archive],
            &CorruptOnRotation {
                rotation: SuccinctRotation::Ave,
                corruption: Corruption::FirstPlane,
            },
        );
        assert!(matches!(
            result,
            Err(SuccinctArchiveMergeError::PlanePrefixMismatch {
                rotation: SuccinctRotation::Ave,
                depth: 0,
            })
        ));
    }

    #[test]
    fn backend_nonzero_tail_on_later_rotation_is_rejected() {
        let set = varied_knights();
        let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
        let result = merge_ordered_archives_with_backend(
            &[archive],
            &CorruptOnRotation {
                rotation: SuccinctRotation::Vae,
                corruption: Corruption::Tail,
            },
        );
        assert!(matches!(
            result,
            Err(SuccinctArchiveMergeError::NonZeroTail(
                SuccinctRotation::Vae
            ))
        ));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn backend_factory_rejects_alphabet_beyond_u32() {
        let backend = ReferencePackedFreeze;
        let factory = BackendWaveletFactory { backend: &backend };
        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let result = factory.create(u32::MAX as usize + 1, 0, &mut sections);
        assert!(matches!(
            result,
            Err(SuccinctArchiveMergeError::DomainTooWide(size))
                if size == u32::MAX as usize + 1
        ));
    }

    #[test]
    fn backend_output_rejects_code_outside_domain() {
        let backend = ReferencePackedFreeze;
        let factory = BackendWaveletFactory { backend: &backend };
        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let mut outputs = factory.create(2, 1, &mut sections).unwrap();
        let result = outputs.set_int(SuccinctRotation::Eav, 0, 2);
        assert!(matches!(
            result,
            Err(SuccinctArchiveMergeError::CodeOutsideDomain {
                code: 2,
                domain_size: 2
            })
        ));
    }

    struct ZeroFreeze;

    impl WaveletMatrixFreezeBackend for ZeroFreeze {
        type Error = std::convert::Infallible;

        fn freeze_rotation(
            &self,
            _rotation: SuccinctRotation,
            _alphabet_size: usize,
            _sequence: &[u32],
            planes: &mut [&mut [u64]],
        ) -> Result<(), Self::Error> {
            for plane in planes {
                plane.fill(0);
            }
            Ok(())
        }
    }

    #[test]
    fn zero_backend_is_rejected_after_a_leading_zero_plane() {
        let backend = ZeroFreeze;
        let factory = BackendWaveletFactory { backend: &backend };
        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let mut outputs = factory.create(256, 3, &mut sections).unwrap();
        for (position, code) in [1usize, 2, 127].into_iter().enumerate() {
            outputs
                .set_int(SuccinctRotation::Eav, position, code)
                .unwrap();
        }
        let result = outputs.finish_rotation(SuccinctRotation::Eav);
        assert!(matches!(
            result,
            Err(SuccinctArchiveMergeError::PlanePrefixMismatch {
                rotation: SuccinctRotation::Eav,
                depth: 1,
            })
        ));
    }

    struct OneBitFreeze {
        depth: usize,
    }

    impl WaveletMatrixFreezeBackend for OneBitFreeze {
        type Error = std::convert::Infallible;

        fn freeze_rotation(
            &self,
            _rotation: SuccinctRotation,
            _alphabet_size: usize,
            _sequence: &[u32],
            planes: &mut [&mut [u64]],
        ) -> Result<(), Self::Error> {
            for plane in planes.iter_mut() {
                plane.fill(0);
            }
            planes[self.depth][0] = 1;
            Ok(())
        }
    }

    #[test]
    fn all_zero_sequence_requires_every_plane_to_be_zero() {
        let backend = OneBitFreeze { depth: 7 };
        let factory = BackendWaveletFactory { backend: &backend };
        let mut area = ByteArea::new().unwrap();
        let mut sections = area.sections();
        let mut outputs = factory.create(256, 3, &mut sections).unwrap();
        for position in 0..3 {
            outputs.set_int(SuccinctRotation::Eav, position, 0).unwrap();
        }
        let result = outputs.finish_rotation(SuccinctRotation::Eav);
        assert!(matches!(
            result,
            Err(SuccinctArchiveMergeError::PlanePrefixMismatch {
                rotation: SuccinctRotation::Eav,
                depth: 7,
            })
        ));
    }

    fn synthetic_trible(ordinal: usize) -> Trible {
        let mut state = (ordinal as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut data = [0u8; 64];
        for chunk in data.chunks_exact_mut(8) {
            state ^= state >> 30;
            state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            state ^= state >> 27;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        data[0] |= 0x80;
        data[16] |= 0x80;
        Trible { data }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_packed_freeze_matches_serial_section_bytes() {
        let len = 4 * PACKED_FREEZE_MIN_CHUNK_ROWS + 37;
        let alphabet_size = 1usize << 17;
        let sequence: Vec<u32> = (0..len)
            .map(|position| {
                let mixed = (position as u64)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left(17);
                (mixed % alphabet_size as u64) as u32
            })
            .collect();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let parallel_bytes = pool.install(|| {
            let mut parallel_area = ByteArea::new().unwrap();
            let mut parallel_sections = parallel_area.sections();
            let mut parallel = PackedCpuWaveletFactory
                .create(alphabet_size, len, &mut parallel_sections)
                .unwrap();
            for rotation in SuccinctRotation::ALL {
                for (position, &code) in sequence.iter().enumerate() {
                    parallel.set_int(rotation, position, code as usize).unwrap();
                }
                parallel.finish_rotation(rotation).unwrap();
            }
            parallel
                .freeze_with_rank9_indexes(&mut parallel_sections)
                .unwrap();
            drop(parallel_sections);
            parallel_area.freeze().unwrap().as_ref().to_vec()
        });

        let reference_backend = ReferencePackedFreeze;
        let reference_factory = BackendWaveletFactory {
            backend: &reference_backend,
        };
        let mut reference_area = ByteArea::new().unwrap();
        let mut reference_sections = reference_area.sections();
        let mut reference = reference_factory
            .create(alphabet_size, len, &mut reference_sections)
            .unwrap();
        for rotation in SuccinctRotation::ALL {
            for (position, &code) in sequence.iter().enumerate() {
                reference
                    .set_int(rotation, position, code as usize)
                    .unwrap();
            }
            reference.finish_rotation(rotation).unwrap();
        }
        reference
            .freeze_with_rank9_indexes(&mut reference_sections)
            .unwrap();
        drop(reference_sections);
        let reference_bytes = reference_area.freeze().unwrap();

        assert_eq!(parallel_bytes.as_slice(), reference_bytes.as_ref());
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn sorted_row_runs_merge_interleaved_overlap_and_empty_inputs() {
        let runs = vec![
            vec![[0, 1, 2], [2, 3, 4], [6, 7, 8]],
            Vec::new(),
            vec![[1, 2, 3], [2, 3, 4], [5, 6, 7]],
            vec![[0, 1, 2], [3, 4, 5], [9, 10, 11]],
        ];

        assert_eq!(
            merge_sorted_row_runs(runs),
            vec![
                [0, 1, 2],
                [1, 2, 3],
                [2, 3, 4],
                [3, 4, 5],
                [5, 6, 7],
                [6, 7, 8],
                [9, 10, 11],
            ]
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_eav_decode_preserves_canonical_bytes_with_overlap() {
        let unique_rows = PARALLEL_EAV_DECODE_THRESHOLD + 1;
        let mut sets: [TribleSet; 4] = std::array::from_fn(|_| TribleSet::new());
        for ordinal in 0..unique_rows {
            let segment = ordinal % 3;
            let trible = synthetic_trible(ordinal);
            sets[segment].insert(&trible);
            if ordinal % 17 == 0 {
                sets[(segment + 1) % 3].insert(&trible);
            }
        }

        let archives: Vec<SuccinctArchive<OrderedUniverse>> = sets.iter().map(Into::into).collect();
        assert!(
            archives
                .iter()
                .map(|archive| archive.eav_c.len())
                .sum::<usize>()
                >= PARALLEL_EAV_DECODE_THRESHOLD
        );
        let merged = merge_ordered_archives(&archives);
        let union = sets
            .into_iter()
            .fold(TribleSet::new(), |union, set| union + set);
        let rebuilt: SuccinctArchive<OrderedUniverse> = (&union).into();

        assert_eq!(TribleSet::from(&merged), union);
        assert_eq!(merged.bytes.as_ref(), rebuilt.bytes.as_ref());
        assert_eq!(
            merged.rank9_index_bytes.as_ref(),
            rebuilt.rank9_index_bytes.as_ref()
        );
    }

    #[test]
    fn packed_cpu_merge_is_canonical_across_word_and_block_boundaries() {
        for rows in [31usize, 32, 33, 63, 64, 65, 255, 256, 257] {
            let mut sets: [TribleSet; 3] = std::array::from_fn(|_| TribleSet::new());
            for ordinal in 0..rows {
                sets[ordinal % sets.len()].insert(&synthetic_trible(ordinal));
            }
            let archives: Vec<SuccinctArchive<OrderedUniverse>> =
                sets.iter().map(Into::into).collect();
            let merged = merge_ordered_archives(&archives);
            let union = sets
                .into_iter()
                .fold(TribleSet::new(), |union, set| union + set);
            let rebuilt: SuccinctArchive<OrderedUniverse> = (&union).into();
            assert_eq!(merged.bytes.as_ref(), rebuilt.bytes.as_ref(), "{rows} rows");
        }
    }

    #[test]
    fn witnessed_source_merge_reuses_raw_bytes_and_preserves_canonical_rank9() {
        for rows in [0usize, 1, 31, 32, 33, 63, 64, 65, 255, 256, 257] {
            let mut sets: [TribleSet; 2] = std::array::from_fn(|_| TribleSet::new());
            for ordinal in 0..rows {
                let trible = synthetic_trible(ordinal);
                sets[ordinal % 2].insert(&trible);
                if ordinal % 3 == 0 {
                    sets[(ordinal + 1) % 2].insert(&trible);
                }
            }
            let mut archives: Vec<SuccinctArchive<OrderedUniverse>> =
                sets.iter().map(Into::into).collect();
            let union = sets
                .into_iter()
                .fold(TribleSet::new(), |union, set| union + set);
            let simple: Blob<SimpleArchive> = union.clone().to_blob();
            let raw = SuccinctArchiveBlob::build_from_simple_archive(&simple).unwrap();
            let expected =
                SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw.clone()).unwrap();

            for _ in 0..2 {
                let merged = merge_ordered_archives_with_source_union(&archives, Some(&raw));
                assert_eq!(merged.bytes.as_ref().as_ptr(), raw.bytes.as_ref().as_ptr());
                assert_eq!(merged.raw_handle, raw.get_handle());
                let root = merged.accelerated_root();
                assert_eq!(root.bytes, expected.bytes, "{rows} rows");
                assert_eq!(root.get_handle(), expected.get_handle(), "{rows} rows");
                assert_eq!(TribleSet::from(&merged), union);
                archives.reverse();
            }
        }
    }

    #[test]
    fn packed_leaf_build_is_canonical_across_word_and_block_boundaries() {
        for rows in [0usize, 1, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1024] {
            let set: TribleSet = (0..rows).map(synthetic_trible).collect();

            let packed: SuccinctArchive<OrderedUniverse> =
                build_archive_from_tribleset_with_factory(&set, &PackedCpuWaveletFactory).unwrap();
            let jerky: SuccinctArchive<OrderedUniverse> =
                build_archive_from_tribleset_with_factory(&set, &JerkyWaveletFactory).unwrap();
            assert_eq!(packed.bytes.as_ref(), jerky.bytes.as_ref(), "{rows} rows");
            assert_eq!(
                packed.rank9_index_bytes.as_ref(),
                jerky.rank9_index_bytes.as_ref(),
                "{rows} Rank9 bytes"
            );

            let packed_compressed: SuccinctArchive<CompressedUniverse> =
                build_archive_from_tribleset_with_factory(&set, &PackedCpuWaveletFactory).unwrap();
            let jerky_compressed: SuccinctArchive<CompressedUniverse> =
                build_archive_from_tribleset_with_factory(&set, &JerkyWaveletFactory).unwrap();
            assert_eq!(
                packed_compressed.bytes.as_ref(),
                jerky_compressed.bytes.as_ref(),
                "{rows} compressed rows"
            );
            assert_eq!(
                packed_compressed.rank9_index_bytes.as_ref(),
                jerky_compressed.rank9_index_bytes.as_ref(),
                "{rows} compressed Rank9 bytes"
            );
        }
    }

    #[test]
    fn structural_merge_recodes_interleaved_domains() {
        fn ordered_id(last: u8) -> Id {
            let mut raw = [0; 16];
            raw[15] = last;
            Id::new(raw).unwrap()
        }

        let lower = ordered_id(1);
        let higher = ordered_id(2);
        let attribute = ordered_id(4);
        let value = Inline::<UnknownInline>::new([0x80; 32]);

        let mut left = TribleSet::new();
        let left_fact = Trible::force(&higher, &attribute, &value);
        left.insert(&left_fact);
        let mut right = TribleSet::new();
        let right_fact = Trible::force(&lower, &attribute, &value);
        right.insert(&right_fact);

        let left_archive: SuccinctArchive<OrderedUniverse> = (&left).into();
        let right_archive: SuccinctArchive<OrderedUniverse> = (&right).into();
        let old_code = left_archive.domain.search(&id_into_value(&higher)).unwrap();
        let merged = merge_ordered_archives(&[left_archive, right_archive]);
        let new_code = merged.domain.search(&id_into_value(&higher)).unwrap();
        assert_ne!(old_code, new_code, "the left domain must be recoded");

        let mut expected = left;
        expected += right;
        let actual: TribleSet = (&merged).into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn structural_merge_handles_empty_inputs() {
        let merged = merge_ordered_archives(&[]);
        let empty = TribleSet::new();
        let rebuilt: SuccinctArchive<OrderedUniverse> = (&empty).into();
        assert_eq!(merged.bytes.as_ref(), rebuilt.bytes.as_ref());
    }

    #[test]
    fn raw_merge_identifies_the_invalid_persisted_input() {
        let empty = TribleSet::new();
        let source: Blob<SimpleArchive> = (&empty).to_blob();
        let valid = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
        let malformed = Blob::<SuccinctArchiveBlob>::new(Bytes::from(vec![0u8; 1]));

        assert!(matches!(
            SuccinctArchiveBlob::merge(&[valid, malformed]),
            Err(SuccinctArchiveRawMergeError::InvalidInput { index: 1, .. })
        ));
    }

    #[test]
    fn raw_merge_handles_empty_overlap_and_interleaved_domain_remapping() {
        fn raw(set: &TribleSet) -> Blob<SuccinctArchiveBlob> {
            let source: Blob<SimpleArchive> = set.to_blob();
            SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap()
        }

        let empty = TribleSet::new();
        let canonical_empty = raw(&empty);
        assert_eq!(
            SuccinctArchiveBlob::merge(&[]).unwrap().bytes,
            canonical_empty.bytes
        );
        assert_eq!(
            SuccinctArchiveBlob::merge(&[raw(&empty), raw(&empty)])
                .unwrap()
                .bytes,
            canonical_empty.bytes
        );

        let lower = ordered_id(1);
        let higher = ordered_id(2);
        let shared = ordered_id(3);
        let attribute = ordered_id(10);
        let low_value = ordered_value(0x20);
        let shared_value = ordered_value(0x40);
        let high_value = ordered_value(0x60);
        let shared_fact = Trible::force(&shared, &attribute, &shared_value);

        let left: TribleSet = [Trible::force(&higher, &attribute, &high_value), shared_fact]
            .into_iter()
            .collect();
        let right: TribleSet = [Trible::force(&lower, &attribute, &low_value), shared_fact]
            .into_iter()
            .collect();
        let mut expected_set = left.clone();
        expected_set += right.clone();

        let left_raw = raw(&left);
        let right_raw = raw(&right);
        let segments = vec![
            raw(&empty),
            left_raw.clone(),
            right_raw.clone(),
            left_raw.clone(),
        ];
        let merged = SuccinctArchiveBlob::merge(&segments).unwrap();
        let reversed =
            SuccinctArchiveBlob::merge(&segments.iter().rev().cloned().collect::<Vec<_>>())
                .unwrap();
        let expected_raw = raw(&expected_set);

        let runtime_segments = segments
            .iter()
            .cloned()
            .map(|segment| segment.try_from_blob().unwrap())
            .collect::<Vec<SuccinctArchive<OrderedUniverse>>>();
        let runtime_raw: Blob<SuccinctArchiveBlob> =
            merge_ordered_archives(&runtime_segments).to_blob();

        assert_eq!(merged.bytes, expected_raw.bytes);
        assert_eq!(reversed.bytes, expected_raw.bytes);
        assert_eq!(runtime_raw.bytes, expected_raw.bytes);
        assert_eq!(merged.get_handle(), expected_raw.get_handle());

        let left_attached: SuccinctArchive<OrderedUniverse> = left_raw.try_from_blob().unwrap();
        let merged_attached: SuccinctArchive<OrderedUniverse> = merged.try_from_blob().unwrap();
        let old_code = left_attached
            .domain
            .search(&id_into_value(&higher))
            .unwrap();
        let new_code = merged_attached
            .domain
            .search(&id_into_value(&higher))
            .unwrap();
        assert_ne!(old_code, new_code, "the left domain must be recoded");
        assert_eq!(TribleSet::from(&merged_attached), expected_set);
    }

    #[test]
    fn simple_archive_direct_build_matches_two_step_build() {
        let set = varied_knights();
        let blob: Blob<SimpleArchive> = (&set).to_blob();
        let direct: SuccinctArchive<OrderedUniverse> = blob.clone().try_from_blob().unwrap();
        let decoded: TribleSet = blob.try_from_blob().unwrap();
        let two_step: SuccinctArchive<OrderedUniverse> = (&decoded).into();

        assert_eq!(direct.bytes.as_ref(), two_step.bytes.as_ref());
        assert_eq!(TribleSet::from(&direct), set);
    }

    #[test]
    fn raw_simplearchive_builder_is_canonical_across_layout_boundaries() {
        for rows in [0usize, 1, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1024] {
            let set: TribleSet = (0..rows).map(synthetic_trible).collect();
            let source: Blob<SimpleArchive> = (&set).to_blob();
            let raw = SuccinctArchiveBlob::build_from_simple_archive(&source).unwrap();
            let expected: SuccinctArchive<OrderedUniverse> = (&set).into();

            assert_eq!(raw.bytes.as_ref(), expected.bytes.as_ref(), "{rows} rows");
            assert_eq!(
                raw.get_handle(),
                Blob::<SuccinctArchiveBlob>::new(expected.bytes.clone()).get_handle(),
                "{rows} row handle"
            );
            let attached: SuccinctArchive<OrderedUniverse> = raw.try_from_blob().unwrap();
            assert_eq!(TribleSet::from(&attached), set, "{rows} row roundtrip");
        }
    }

    #[test]
    fn raw_simplearchive_builder_preserves_source_validation_errors() {
        let bad_length = Blob::<SimpleArchive>::new(Bytes::from(vec![0u8; 63]));
        assert_eq!(
            SuccinctArchiveBlob::build_from_simple_archive(&bad_length).unwrap_err(),
            SuccinctArchiveRawBuildError::Source(UnarchiveError::BadArchive)
        );

        let nil = Blob::<SimpleArchive>::new(Bytes::from(vec![0u8; 64]));
        assert_eq!(
            SuccinctArchiveBlob::build_from_simple_archive(&nil).unwrap_err(),
            SuccinctArchiveRawBuildError::Source(UnarchiveError::BadTrible)
        );

        let first = synthetic_trible(1).data;
        let second = synthetic_trible(2).data;
        let mut duplicate = Vec::with_capacity(128);
        duplicate.extend_from_slice(&first);
        duplicate.extend_from_slice(&first);
        let duplicate = Blob::<SimpleArchive>::new(Bytes::from(duplicate));
        assert_eq!(
            SuccinctArchiveBlob::build_from_simple_archive(&duplicate).unwrap_err(),
            SuccinctArchiveRawBuildError::Source(UnarchiveError::BadCanonicalizationRedundancy)
        );

        let (high, low) = if first > second {
            (first, second)
        } else {
            (second, first)
        };
        let mut descending = Vec::with_capacity(128);
        descending.extend_from_slice(&high);
        descending.extend_from_slice(&low);
        let descending = Blob::<SimpleArchive>::new(Bytes::from(descending));
        assert_eq!(
            SuccinctArchiveBlob::build_from_simple_archive(&descending).unwrap_err(),
            SuccinctArchiveRawBuildError::Source(UnarchiveError::BadCanonicalizationOrdering)
        );
    }
}
