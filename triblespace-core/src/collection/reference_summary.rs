//! Canonical unionable Bloom summaries of recursively referenced blobs.
//!
//! Each concrete mapping fixes its bit universe and probe count in the
//! descriptor. The logical value is a set of occupied bit positions; join is
//! set union. Compression never changes that geometry, rehashes members, or
//! discards positions. Lookups consume opaque [`blob_locator`] values, not
//! bearer handles. A positive answer is only a routing hint, never authority.
//!
//! # Complete producer closure required
//!
//! **Derive only at a producer with the complete immutable blob closure of the
//! source. Do not map an incomplete replica.** The producer scans aligned
//! 32-byte candidates inside a canonical `SimpleArchive`, inserts the locator
//! of each actually resident referenced blob, and recursively scans those
//! bytes. The source materialization's own handle is not a reference root.
//! Unrelated inventory, timestamps, metadata fields, and callbacks are not
//! inputs. Reads are passive lookups through the supplied frozen snapshot;
//! the mapping never acquires missing bytes.
//!
//! Under that producer precondition, reachability distributes over source
//! union and so does the Bloom projection. Untyped candidates cannot prove
//! completeness: an absent blob is indistinguishable from an ordinary inline
//! value. A partial producer can therefore publish an incomplete summary;
//! this encoding does not pretend to detect that condition. Consumers fetch
//! already-produced summaries instead of deriving their own partial versions.
//!
//! # Portable canonical bytes
//!
//! The 11-byte header is `log2_bits: u8`, `probes: u8`, `form: u8`, and
//! `occupied_count: u64` in big-endian order. Form 0 stores strictly increasing
//! positions as minimal unsigned LEB128 positive gaps, with the first gap
//! equal to `position + 1`. Form 1 stores the dense bit vector, least-significant
//! bit first in each byte, with zero unused tail bits. Dense is used exactly
//! when its payload is strictly shorter than the gap payload; ties use gaps.
//! Thus sparse leaves and dense joins still have one byte spelling per value.
//!
//! For a locator `L`, probes are `(a + i * b) mod 2^log2_bits`, where `a` and
//! `b` are the first and second little-endian u64 words of `L`, and `b` is made
//! odd. Arithmetic wraps at 64 bits. The locator is already a domain-separated
//! cryptographic image; no extra source-byte hash is needed.

use std::collections::HashSet;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use anybytes::{Bytes, View};
use itertools::Itertools;

use crate::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use crate::blob::encodings::UnknownBlob;
use crate::blob::locator::blob_locator;
use crate::blob::{Blob, BlobEncoding, TryFromBlob};
use crate::id::{ExclusiveId, Id};
use crate::id_hex;
use crate::inline::encodings::hash::Handle;
use crate::inline::encodings::iu256::U256BE;
use crate::inline::Inline;
use crate::macros::entity;
use crate::metadata::{self, MetaDescribe};
use crate::repo::{BlobStoreGet, BlobStoreMeta};
use crate::trible::Fragment;

use super::records::{mapping_algorithm, KIND_COLLECTION_MAPPING};
use super::{
    CollectionDerivation, CollectionEncoding, CollectionOperationError, Cover, TryFromCover,
    TryFromCoverError,
};

const HEADER_LEN: usize = 11;
const SPARSE: u8 = 0;
const DENSE: u8 = 1;

crate::macros::attributes! {
    /// Base-two logarithm of the reference summary's fixed bit universe.
    /// Anchor minted with installed `trible genid` for this encoding.
    "D334569740688AB8CBDA6CAE8785E13A" as pub reference_summary_log2_bits: U256BE;
    /// Number of fixed odd-step Bloom probes per opaque locator.
    /// Anchor minted with installed `trible genid` for this encoding.
    "30AA302E8B844B8023C15A9567A156A4" as pub reference_summary_probes: U256BE;
}

/// Descriptor-fixed Bloom geometry, independent of member size or join order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceSummaryLayout {
    log2_bits: u8,
    probes: u8,
}

impl ReferenceSummaryLayout {
    /// Choose a universe of `2^log2_bits` bits and distinct odd-step probes.
    ///
    /// The portable position space supports `log2_bits <= 32`. The probe count
    /// must be nonzero and no larger than the universe. There is no resizing
    /// based on observed cardinality; another geometry names another mapping.
    pub fn new(log2_bits: u8, probes: u8) -> Result<Self, ReferenceSummaryError> {
        if log2_bits > 32 || probes == 0 || u64::from(probes) > (1_u64 << log2_bits) {
            return Err(ReferenceSummaryError::InvalidLayout { log2_bits, probes });
        }
        Ok(Self { log2_bits, probes })
    }

    /// Base-two logarithm of the fixed bit universe.
    pub fn log2_bits(self) -> u8 {
        self.log2_bits
    }

    /// Fixed number of probes per locator.
    pub fn probes(self) -> u8 {
        self.probes
    }

    fn bit_count(self) -> u64 {
        1_u64 << self.log2_bits
    }

    fn dense_len(self) -> usize {
        self.bit_count().div_ceil(8) as usize
    }

    fn positions(self, locator: [u8; 32]) -> impl Iterator<Item = u32> {
        let base = u64::from_le_bytes(locator[..8].try_into().expect("eight-byte word"));
        let step = u64::from_le_bytes(locator[8..16].try_into().expect("eight-byte word")) | 1;
        let mask = self.bit_count() - 1;
        (0..self.probes)
            .map(move |i| (base.wrapping_add(u64::from(i).wrapping_mul(step)) & mask) as u32)
    }
}

impl Default for ReferenceSummaryLayout {
    /// A 32-bit position universe with four probes; sparse until densely used.
    fn default() -> Self {
        Self {
            log2_bits: 32,
            probes: 4,
        }
    }
}

/// Canonical portable reference-summary collection member.
pub struct ReferenceSummaryBlob;

impl BlobEncoding for ReferenceSummaryBlob {}

impl MetaDescribe for ReferenceSummaryBlob {
    fn describe() -> Fragment {
        // Minted with installed `trible genid` for this encoding.
        let id: Id = id_hex!("7155DDD229E941A84D931370FF66969B");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "reference-summary-v1",
            metadata::description: "Canonical unionable Bloom summary of opaque blob locators. An 11-byte header carries log2 bit count, probe count, sparse/dense form, and big-endian u64 occupied count. Sparse positions use minimal positive-gap unsigned LEB128; dense bits are least-significant-bit first. Dense is chosen only when strictly shorter. Geometry is fixed by the mapping descriptor. A positive match is a routing hint, never authorization.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Complete-producer recursive-reference mapping, version 2.
///
/// Minted with installed `trible genid` on 2026-09-24, when the blob locator
/// changed from a `derive_key` string context to a 32-byte context key.
/// Version 1 (`A8C939AA55A7EC07C12FFCDA1FAA5785`) set the same Bloom bits
/// from the old locators; no populated version 1 collection existed.
pub const REFERENCE_SUMMARY_MAPPING_V2: Id = id_hex!("C0F7F9B5A68660407FDBFD8CF4D6E1AD");

/// Self-description of the complete-producer reference projection.
pub struct ReferenceSummaryMappingV2;

impl MetaDescribe for ReferenceSummaryMappingV2 {
    fn describe() -> Fragment {
        let id = REFERENCE_SUMMARY_MAPPING_V2;
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "reference-summary-mapping-v2",
            metadata::description: "Producer-only projection from canonical SimpleArchive over its complete immutable referenced-blob closure. Scan aligned 32-byte candidates, follow only resident blobs, and insert their opaque blob locators, BLAKE3 of the 32-byte locator context key followed by the handle, into descriptor-fixed odd-step Bloom positions. Never seed the source artifact handle, enumerate ambient inventory, fetch missing bytes, or derive from an incomplete replica. Completeness is a producer obligation, not established by this untyped scan.",
            metadata::tag: metadata::KIND_COLLECTION_MAPPING_ALGORITHM,
        }
    }
}

/// Failure to decode, derive, or join a reference summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceSummaryError {
    /// Geometry cannot be represented or has no usable probe sequence.
    InvalidLayout { log2_bits: u8, probes: u8 },
    /// The header or payload length is inconsistent.
    BadLength,
    /// An unsupported sparse/dense discriminator was supplied.
    UnknownForm(u8),
    /// The declared occupied count disagrees with the payload or universe.
    InvalidCount,
    /// A gap is zero, unterminated, too wide, or not minimally encoded.
    NoncanonicalGap,
    /// A position or dense padding bit lies outside the fixed universe.
    PositionOutOfRange,
    /// The selected sparse/dense form is not the canonical shortest form.
    NoncanonicalForm,
    /// Different descriptor-fixed geometries were mixed.
    LayoutMismatch,
    /// A collection descriptor does not supply the supported mapping geometry.
    InvalidDescriptor(String),
    /// Source bytes are not a canonical `SimpleArchive`.
    InvalidSource(UnarchiveError),
    /// A passive snapshot lookup failed.
    Store(String),
}

impl fmt::Display for ReferenceSummaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLayout { log2_bits, probes } => {
                write!(
                    f,
                    "invalid reference-summary geometry ({log2_bits}, {probes})"
                )
            }
            Self::BadLength => f.write_str("invalid reference-summary payload length"),
            Self::UnknownForm(form) => write!(f, "unknown reference-summary form {form}"),
            Self::InvalidCount => f.write_str("invalid reference-summary occupied count"),
            Self::NoncanonicalGap => f.write_str("noncanonical reference-summary gap"),
            Self::PositionOutOfRange => {
                f.write_str("reference-summary position outside its universe")
            }
            Self::NoncanonicalForm => {
                f.write_str("noncanonical reference-summary sparse/dense choice")
            }
            Self::LayoutMismatch => f.write_str("reference-summary geometries do not match"),
            Self::InvalidDescriptor(source) => {
                write!(f, "invalid reference-summary descriptor: {source}")
            }
            Self::InvalidSource(source) => write!(f, "invalid reference-summary source: {source}"),
            Self::Store(source) => write!(f, "reference-summary snapshot lookup failed: {source}"),
        }
    }
}

impl Error for ReferenceSummaryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSource(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
enum SummaryBits {
    Sparse(Vec<u32>),
    Dense(Bytes),
}

/// A shared byte view of one reference summary.
///
/// Attachment checks framing only. [`Self::query`] prepares membership access:
/// sparse positive-gap bytes need a position index for binary search, while
/// dense bits can be queried directly in their original backing storage.
#[derive(Clone, Debug)]
pub struct ReferenceSummary {
    layout: ReferenceSummaryLayout,
    occupied: u64,
    form: u8,
    payload: Bytes,
}

/// Prepared membership access to one summary or the OR of a summary cover.
///
/// This is query scratch, not a new persisted member. It never serializes or
/// hashes the logical union. Dense members retain their original byte views.
#[derive(Clone, Debug)]
pub struct ReferenceSummaryQuery {
    layout: ReferenceSummaryLayout,
    members: Vec<SummaryBits>,
}

fn dense_positions(bytes: &[u8]) -> impl Iterator<Item = u32> + Clone + '_ {
    bytes.iter().enumerate().flat_map(|(index, byte)| {
        let mut remaining = *byte;
        std::iter::from_fn(move || {
            if remaining == 0 {
                return None;
            }
            let bit = remaining.trailing_zeros();
            remaining &= remaining - 1;
            Some(index as u32 * 8 + bit)
        })
    })
}

fn gap_len(gap: u64) -> usize {
    ((64 - gap.leading_zeros()) as usize).div_ceil(7)
}

fn read_gap(bytes: &[u8], offset: &mut usize) -> Result<u64, ReferenceSummaryError> {
    let mut gap = 0_u64;
    for word in 0..5 {
        let byte = *bytes
            .get(*offset)
            .ok_or(ReferenceSummaryError::NoncanonicalGap)?;
        *offset += 1;
        gap |= u64::from(byte & 127) << (word * 7);
        if byte & 128 == 0 {
            if gap == 0 || (word != 0 && byte == 0) || gap > (1_u64 << 32) {
                return Err(ReferenceSummaryError::NoncanonicalGap);
            }
            return Ok(gap);
        }
    }
    Err(ReferenceSummaryError::NoncanonicalGap)
}

fn write_gap(mut gap: u64, bytes: &mut Vec<u8>) {
    while gap >= 128 {
        bytes.push((gap as u8 & 127) | 128);
        gap >>= 7;
    }
    bytes.push(gap as u8);
}

impl ReferenceSummary {
    /// Attach the encoded bytes without scanning their bit or gap payload.
    ///
    /// Use [`validate_element`] for an explicit canonical-encoding audit.
    pub fn decode(blob: &Blob<ReferenceSummaryBlob>) -> Result<Self, ReferenceSummaryError> {
        let bytes = blob.bytes.as_ref();
        if bytes.len() < HEADER_LEN {
            return Err(ReferenceSummaryError::BadLength);
        }
        let layout = ReferenceSummaryLayout::new(bytes[0], bytes[1])?;
        let occupied =
            u64::from_be_bytes(bytes[3..HEADER_LEN].try_into().expect("eight-byte count"));
        if occupied > layout.bit_count() {
            return Err(ReferenceSummaryError::InvalidCount);
        }
        let payload = blob.bytes.clone().slice(HEADER_LEN..);
        let form = bytes[2];
        match form {
            SPARSE => {
                // Each of the declared gaps occupies one to five bytes.
                // Decoding those gaps is query work, not attachment work.
                if occupied > payload.len() as u64 || payload.len() as u64 > occupied * 5 {
                    return Err(ReferenceSummaryError::InvalidCount);
                }
            }
            DENSE => {
                if payload.len() != layout.dense_len() {
                    return Err(ReferenceSummaryError::BadLength);
                }
            }
            form => return Err(ReferenceSummaryError::UnknownForm(form)),
        }
        Ok(Self {
            layout,
            occupied,
            form,
            payload,
        })
    }

    fn query_bits(&self) -> Result<SummaryBits, ReferenceSummaryError> {
        if self.form == DENSE {
            return Ok(SummaryBits::Dense(self.payload.clone()));
        }
        let mut positions = Vec::with_capacity(self.occupied as usize);
        let mut offset = 0;
        let mut next = 0_u64;
        for _ in 0..self.occupied {
            next += read_gap(&self.payload, &mut offset)?;
            if next > self.layout.bit_count() {
                return Err(ReferenceSummaryError::PositionOutOfRange);
            }
            positions.push((next - 1) as u32);
        }
        if offset != self.payload.len() {
            return Err(ReferenceSummaryError::BadLength);
        }
        Ok(SummaryBits::Sparse(positions))
    }

    /// Prepare binary-search sparse or direct dense membership lookups.
    ///
    /// Keep the returned query for a batch of probes. Sparse gap decoding is
    /// performed once here, never once per locator or when attaching a cover.
    pub fn query(&self) -> Result<ReferenceSummaryQuery, ReferenceSummaryError> {
        Ok(ReferenceSummaryQuery {
            layout: self.layout,
            members: vec![self.query_bits()?],
        })
    }

    /// Geometry carried by this canonical member.
    pub fn layout(&self) -> ReferenceSummaryLayout {
        self.layout
    }

    /// Number of occupied bits, not the number of referenced blobs.
    pub fn occupied_bits(&self) -> u64 {
        self.occupied
    }

    /// Whether no locator has contributed any bit.
    pub fn is_empty(&self) -> bool {
        self.occupied == 0
    }
}

impl ReferenceSummaryQuery {
    /// Whether an opaque locator might be referenced.
    ///
    /// False proves absence only from the encoded set, whose completeness is
    /// the producer's responsibility. True may be a Bloom false positive.
    pub fn contains_locator(&self, locator: [u8; 32]) -> bool {
        self.layout
            .positions(locator)
            .all(|position| self.contains_position(position))
    }

    fn contains_position(&self, position: u32) -> bool {
        self.members.iter().any(|bits| match bits {
            SummaryBits::Sparse(positions) => positions.binary_search(&position).is_ok(),
            SummaryBits::Dense(bytes) => bytes[position as usize / 8] & (1 << (position % 8)) != 0,
        })
    }
}

impl TryFromBlob<ReferenceSummaryBlob> for ReferenceSummary {
    type Error = ReferenceSummaryError;

    fn try_from_blob(blob: Blob<ReferenceSummaryBlob>) -> Result<Self, Self::Error> {
        Self::decode(&blob)
    }
}

fn header(layout: ReferenceSummaryLayout, form: u8, occupied: u64, payload_len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload_len);
    bytes.extend_from_slice(&[layout.log2_bits, layout.probes, form]);
    bytes.extend_from_slice(&occupied.to_be_bytes());
    bytes
}

fn encode_positions(
    layout: ReferenceSummaryLayout,
    positions: impl Iterator<Item = u32> + Clone,
) -> Blob<ReferenceSummaryBlob> {
    let mut occupied = 0;
    let mut sparse_len = 0;
    let mut prior = 0_u64;
    for position in positions.clone() {
        let next = u64::from(position) + 1;
        sparse_len += gap_len(next - prior);
        prior = next;
        occupied += 1;
    }
    let dense = layout.dense_len() < sparse_len;
    let form = if dense { DENSE } else { SPARSE };
    let payload_len = if dense {
        layout.dense_len()
    } else {
        sparse_len
    };
    let mut bytes = header(layout, form, occupied, payload_len);
    if dense {
        bytes.resize(HEADER_LEN + payload_len, 0);
        for position in positions {
            bytes[HEADER_LEN + position as usize / 8] |= 1 << (position % 8);
        }
    } else {
        let mut prior = 0_u64;
        for position in positions {
            let next = u64::from(position) + 1;
            write_gap(next - prior, &mut bytes);
            prior = next;
        }
    }
    Blob::new(Bytes::from_source(bytes))
}

fn encode_dense(layout: ReferenceSummaryLayout, payload: &[u8]) -> Blob<ReferenceSummaryBlob> {
    let occupied = payload
        .iter()
        .map(|byte| u64::from(byte.count_ones()))
        .sum();
    let mut bytes = header(layout, DENSE, occupied, payload.len());
    bytes.extend_from_slice(payload);
    Blob::new(Bytes::from_source(bytes))
}

fn finish(layout: ReferenceSummaryLayout, mut positions: Vec<u32>) -> Blob<ReferenceSummaryBlob> {
    positions.sort_unstable();
    positions.dedup();
    encode_positions(layout, positions.iter().copied())
}

/// Canonical bottom element for one descriptor-fixed geometry.
pub fn empty(layout: ReferenceSummaryLayout) -> Blob<ReferenceSummaryBlob> {
    encode_positions(layout, std::iter::empty())
}

/// Build a canonical summary from opaque locators, independent of input order.
pub fn from_locators(
    layout: ReferenceSummaryLayout,
    locators: impl IntoIterator<Item = [u8; 32]>,
) -> Blob<ReferenceSummaryBlob> {
    finish(
        layout,
        locators
            .into_iter()
            .flat_map(|locator| layout.positions(locator))
            .collect(),
    )
}

/// Validate only the canonical encoding, not producer completeness or authority.
pub fn validate_element(blob: &Blob<ReferenceSummaryBlob>) -> Result<(), ReferenceSummaryError> {
    let summary = ReferenceSummary::decode(blob)?;
    match summary.query_bits()? {
        SummaryBits::Sparse(_) => {
            if summary.payload.len() > summary.layout.dense_len() {
                return Err(ReferenceSummaryError::NoncanonicalForm);
            }
        }
        SummaryBits::Dense(payload) => {
            if summary.layout.log2_bits < 3 && payload[0] >> summary.layout.bit_count() != 0 {
                return Err(ReferenceSummaryError::PositionOutOfRange);
            }
            let actual: u64 = payload
                .iter()
                .map(|byte| u64::from(byte.count_ones()))
                .sum();
            if actual != summary.occupied {
                return Err(ReferenceSummaryError::InvalidCount);
            }
            if summary.occupied <= payload.len() as u64 {
                let mut prior = 0_u64;
                let mut sparse_len = 0;
                for position in dense_positions(&payload) {
                    let next = u64::from(position) + 1;
                    sparse_len += gap_len(next - prior);
                    prior = next;
                    if sparse_len > payload.len() {
                        break;
                    }
                }
                if sparse_len <= payload.len() {
                    return Err(ReferenceSummaryError::NoncanonicalForm);
                }
            }
        }
    }
    Ok(())
}

/// Join two canonical members by union of their occupied positions.
pub fn join(
    low: &Blob<ReferenceSummaryBlob>,
    high: &Blob<ReferenceSummaryBlob>,
) -> Result<Blob<ReferenceSummaryBlob>, ReferenceSummaryError> {
    let left = ReferenceSummary::decode(low)?;
    let right = ReferenceSummary::decode(high)?;
    if left.layout != right.layout {
        return Err(ReferenceSummaryError::LayoutMismatch);
    }
    if low.bytes == high.bytes || right.is_empty() {
        return Ok(low.clone());
    }
    if left.is_empty() {
        return Ok(high.clone());
    }
    match (&left.query_bits()?, &right.query_bits()?) {
        (SummaryBits::Sparse(a), SummaryBits::Sparse(b)) => Ok(encode_positions(
            left.layout,
            a.iter().copied().merge(b.iter().copied()).dedup(),
        )),
        (SummaryBits::Dense(a), SummaryBits::Dense(b)) => {
            let payload: Vec<u8> = a.iter().zip(b.iter()).map(|(a, b)| a | b).collect();
            Ok(encode_dense(left.layout, &payload))
        }
        (SummaryBits::Dense(dense), SummaryBits::Sparse(sparse))
        | (SummaryBits::Sparse(sparse), SummaryBits::Dense(dense)) => {
            let mut payload = dense.as_ref().to_vec();
            for position in sparse {
                payload[*position as usize / 8] |= 1 << (*position % 8);
            }
            // Adding positions cannot shorten positive-gap LEB128: splitting
            // a gap costs at least as many bytes as the original gap. A union
            // containing a canonical dense member therefore stays dense.
            Ok(encode_dense(left.layout, &payload))
        }
    }
}

/// Project one source using only its complete, resident producer closure.
///
/// **Producer-only: do not invoke this on an incomplete replica.** Missing
/// candidates are skipped, because ordinary inline values are not necessarily
/// handles. No completeness certificate can be inferred from that test.
/// Metadata is used only for named-candidate residency; its timestamp and
/// length are irrelevant. A failed read of a reported-resident blob is an
/// error, not a silently omitted reference. The snapshot must be passive:
/// neither metadata nor get may acquire missing bytes.
pub fn derive_element<R>(
    source: &Blob<SimpleArchive>,
    layout: ReferenceSummaryLayout,
    reader: &R,
) -> Result<Blob<ReferenceSummaryBlob>, ReferenceSummaryError>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    // The mapping scans value-sized candidates, not facts or their ordering.
    // It needs the source's row framing, not another canonicality proof.
    let _: View<[[u8; 64]]> = source
        .bytes
        .clone()
        .view()
        .map_err(|_| ReferenceSummaryError::InvalidSource(UnarchiveError::BadArchive))?;
    let mut reached = HashSet::from([source.get_handle().raw]);
    let mut pending = vec![source.clone().transmute::<UnknownBlob>()];
    let mut positions = Vec::new();
    while let Some(blob) = pending.pop() {
        for chunk in blob.bytes.as_ref().chunks_exact(32) {
            let raw = <[u8; 32]>::try_from(chunk).expect("aligned candidate");
            if reached.contains(&raw) {
                continue;
            }
            let handle = Inline::<Handle<UnknownBlob>>::new(raw);
            if reader
                .metadata(handle)
                .map_err(|error| ReferenceSummaryError::Store(error.to_string()))?
                .is_none()
            {
                continue;
            }
            let child: Blob<UnknownBlob> = reader
                .get(handle)
                .map_err(|error| ReferenceSummaryError::Store(error.to_string()))?;
            reached.insert(raw);
            positions.extend(layout.positions(blob_locator(raw)));
            pending.push(child);
        }
    }
    Ok(finish(layout, positions))
}

fn descriptor_layout(
    descriptor: &Fragment,
) -> Result<ReferenceSummaryLayout, CollectionOperationError> {
    let actual = super::descriptor::mapping_algorithm(descriptor.facts())
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
    if actual != Some(REFERENCE_SUMMARY_MAPPING_V2) {
        return Err(CollectionOperationError::Fatal(
            "unexpected reference-summary mapping algorithm".to_owned(),
        ));
    }
    let log2_bits =
        super::descriptor::mapping_argument(descriptor.facts(), reference_summary_log2_bits.id())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
            .ok_or_else(|| {
                CollectionOperationError::Fatal("missing reference-summary log2_bits".to_owned())
            })?;
    let probes =
        super::descriptor::mapping_argument(descriptor.facts(), reference_summary_probes.id())
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?
            .ok_or_else(|| {
                CollectionOperationError::Fatal("missing reference-summary probes".to_owned())
            })?;
    let log2_bits = Inline::<U256BE>::new(log2_bits)
        .try_from_inline::<u8>()
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
    let probes = Inline::<U256BE>::new(probes)
        .try_from_inline::<u8>()
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
    ReferenceSummaryLayout::new(log2_bits, probes)
        .map_err(|error| CollectionOperationError::Fatal(error.to_string()))
}

impl CollectionEncoding for ReferenceSummaryBlob {
    fn validate_descriptor(descriptor: &Fragment) -> Result<(), CollectionOperationError> {
        descriptor_layout(descriptor).map(|_| ())
    }

    fn validate_member<R>(
        descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let layout = descriptor_layout(descriptor)?;
        let decoded = ReferenceSummary::decode(member)
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))?;
        if decoded.layout != layout {
            return Err(CollectionOperationError::Fatal(
                ReferenceSummaryError::LayoutMismatch.to_string(),
            ));
        }
        // An explicit audit; ordinary view construction only attaches bytes.
        validate_element(member).map_err(|error| CollectionOperationError::Fatal(error.to_string()))
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
        let layout = descriptor_layout(descriptor)?;
        if low.bytes.first() != Some(&layout.log2_bits) || low.bytes.get(1) != Some(&layout.probes)
        {
            return Err(CollectionOperationError::Fatal(
                ReferenceSummaryError::LayoutMismatch.to_string(),
            ));
        }
        join(low, high).map_err(|error| CollectionOperationError::Fatal(error.to_string()))
    }
}

impl CollectionDerivation for ReferenceSummaryBlob {
    /// The summary follows only the referenced blobs a host holds, so a
    /// partial replica would publish a smaller summary than the producer's.
    const REPLICA_INDEPENDENT: bool = false;

    type Source = SimpleArchive;
    type Argument = ReferenceSummaryLayout;

    fn fragment(layout: &ReferenceSummaryLayout) -> Fragment {
        entity! { _ @
            metadata::tag: KIND_COLLECTION_MAPPING,
            mapping_algorithm*: ReferenceSummaryMappingV2::describe(),
            reference_summary_log2_bits: layout.log2_bits,
            reference_summary_probes: layout.probes,
        }
    }

    fn bind(
        _source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError> {
        descriptor_layout(target)
    }

    fn map<R>(
        layout: &ReferenceSummaryLayout,
        source: &Blob<SimpleArchive>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        derive_element(source, *layout, reader)
            .map_err(|error| CollectionOperationError::Fatal(error.to_string()))
    }
}

/// A lazy logical union of already-produced summary members.
///
/// Attaching a cover performs no mappings, joins, payload scans, or hashing.
/// Probe bits may be contributed by different members, exactly as in the
/// physical Bloom union. [`Self::query`] prepares the sparse membership indexes
/// when needed. This view only reads the known summary outputs.
#[derive(Clone, Debug)]
pub struct ReferenceSummaryView {
    layout: ReferenceSummaryLayout,
    members: Vec<ReferenceSummary>,
}

impl ReferenceSummaryView {
    /// Geometry fixed by the collection descriptor.
    pub fn layout(&self) -> ReferenceSummaryLayout {
        self.layout
    }

    /// Prepare membership lookups without serializing a merged summary.
    pub fn query(&self) -> Result<ReferenceSummaryQuery, ReferenceSummaryError> {
        Ok(ReferenceSummaryQuery {
            layout: self.layout,
            members: self
                .members
                .iter()
                .map(ReferenceSummary::query_bits)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFromCover<ReferenceSummaryBlob> for ReferenceSummaryView {
    type Error = ReferenceSummaryError;

    fn try_from_cover<R>(
        cover: &Cover<ReferenceSummaryBlob>,
        descriptor: &Fragment,
        reader: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet,
    {
        let layout = descriptor_layout(descriptor).map_err(|error| {
            TryFromCoverError::View(ReferenceSummaryError::InvalidDescriptor(error.to_string()))
        })?;
        let mut members = Vec::new();
        for handle in cover.members() {
            let member = Handle::<ReferenceSummaryBlob>::to_hash(handle);
            let blob = reader
                .get(handle)
                .map_err(|source| TryFromCoverError::MemberGet { member, source })?;
            let decoded = ReferenceSummary::decode(&blob).map_err(TryFromCoverError::View)?;
            if decoded.layout != layout {
                return Err(TryFromCoverError::View(
                    ReferenceSummaryError::LayoutMismatch,
                ));
            }
            members.push(decoded);
        }
        Ok(Self { layout, members })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{IntoBlob, MemoryBlobStore, MemoryBlobStoreSnapshot};
    use crate::collection::{Collection, CollectionHandle};
    use crate::id::ufoid;
    use crate::inline::InlineEncoding;
    use crate::repo::{BlobMetadata, BlobStorePut, SnapshotSource};
    use crate::trible::{Trible, TribleSet};
    use std::cell::RefCell;
    use std::io;

    fn raw_member(
        layout: ReferenceSummaryLayout,
        form: u8,
        occupied: u64,
        payload: &[u8],
    ) -> Blob<ReferenceSummaryBlob> {
        let mut bytes = header(layout, form, occupied, payload.len());
        bytes.extend_from_slice(payload);
        Blob::new(Bytes::from_source(bytes))
    }

    fn locators(count: u64) -> Vec<[u8; 32]> {
        (0..count)
            .map(|i| blob_locator(*blake3::hash(&i.to_le_bytes()).as_bytes()))
            .collect()
    }

    fn source(handles: &[[u8; 32]]) -> Blob<SimpleArchive> {
        let subject = ufoid();
        let mut facts = TribleSet::new();
        for raw in handles {
            facts.insert(&Trible::new(
                &subject,
                &metadata::archive.id(),
                &Inline::<Handle<UnknownBlob>>::new(*raw),
            ));
        }
        facts.to_blob()
    }

    fn descriptor(layout: ReferenceSummaryLayout) -> Fragment {
        entity! { _ @
            metadata::tag: super::super::KIND_COLLECTION_DESCRIPTOR,
            super::super::collection_representation: ReferenceSummaryBlob::id(),
            super::super::collection_mapping*: ReferenceSummaryBlob::fragment(&layout),
        }
    }

    struct ReadSpy {
        inner: MemoryBlobStoreSnapshot,
        gets: RefCell<Vec<[u8; 32]>>,
        metadata: RefCell<Vec<[u8; 32]>>,
        fail_get: bool,
    }

    impl ReadSpy {
        fn new(inner: MemoryBlobStoreSnapshot) -> Self {
            Self {
                inner,
                gets: RefCell::new(Vec::new()),
                metadata: RefCell::new(Vec::new()),
                fail_get: false,
            }
        }
    }

    // Deliberately implements no inventory or acquisition interface.
    impl BlobStoreMeta for ReadSpy {
        type MetaError = Infallible;

        fn metadata<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobMetadata>, Infallible>
        where
            S: BlobEncoding + 'static,
            Handle<S>: InlineEncoding,
        {
            self.metadata.borrow_mut().push(handle.raw);
            self.inner.metadata(handle)
        }
    }

    impl BlobStoreGet for ReadSpy {
        type GetError<E: Error + Send + Sync + 'static> = io::Error;

        fn get<T, S>(&self, handle: Inline<Handle<S>>) -> Result<T, io::Error>
        where
            S: BlobEncoding + 'static,
            T: TryFromBlob<S>,
            Handle<S>: InlineEncoding,
        {
            assert!(
                self.inner.metadata(handle).unwrap().is_some(),
                "no absent-blob fetch"
            );
            self.gets.borrow_mut().push(handle.raw);
            if self.fail_get {
                return Err(io::Error::other("injected resident read failure"));
            }
            self.inner
                .get(handle)
                .map_err(|error| io::Error::other(error.to_string()))
        }
    }

    #[test]
    fn default_geometry_and_probe_rule_are_fixed() {
        assert_eq!(
            ReferenceSummaryLayout::default(),
            ReferenceSummaryLayout::new(32, 4).unwrap()
        );
        assert!(ReferenceSummaryLayout::new(33, 4).is_err());
        assert!(ReferenceSummaryLayout::new(32, 0).is_err());
        assert!(ReferenceSummaryLayout::new(1, 3).is_err());
        assert!(ReferenceSummaryLayout::new(0, 1).is_ok());
        let layout = ReferenceSummaryLayout::new(8, 4).unwrap();
        let mut locator = [0; 32];
        locator[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        locator[8..16].copy_from_slice(&2_u64.to_le_bytes());
        assert_eq!(
            layout.positions(locator).collect::<Vec<_>>(),
            [255, 2, 5, 8]
        );
    }

    #[test]
    fn golden_gap_bytes_cover_zero_large_gaps_and_the_last_position() {
        let layout = ReferenceSummaryLayout::new(8, 1).unwrap();
        let member = encode_positions(layout, [0, 126, 127, 255].into_iter());
        assert_eq!(
            member.bytes.as_ref(),
            &[8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 126, 1, 128, 1]
        );
        let decoded = ReferenceSummary::decode(&member).unwrap();
        assert_eq!(decoded.occupied_bits(), 4);
        let query = decoded.query().unwrap();
        for position in [0, 126, 127, 255] {
            assert!(query.contains_position(position));
        }
        let maximum = encode_positions(ReferenceSummaryLayout::default(), [u32::MAX].into_iter());
        assert_eq!(&maximum.bytes[HEADER_LEN..], &[128, 128, 128, 128, 16]);
        assert!(ReferenceSummary::decode(&maximum)
            .unwrap()
            .query()
            .unwrap()
            .contains_position(u32::MAX));
    }

    #[test]
    fn shortest_form_is_canonical_and_dense_decoding_stays_dense() {
        let layout = ReferenceSummaryLayout::new(3, 1).unwrap();
        let one = encode_positions(layout, [0].into_iter());
        assert_eq!(one.bytes[2], SPARSE, "equal byte lengths choose gaps");
        let two = encode_positions(layout, [0, 1].into_iter());
        assert_eq!(two.bytes[2], DENSE);
        assert_eq!(&two.bytes[HEADER_LEN..], &[3]);
        assert!(matches!(
            ReferenceSummary::decode(&two)
                .unwrap()
                .query_bits()
                .unwrap(),
            SummaryBits::Dense(_)
        ));
        assert!(validate_element(&raw_member(layout, DENSE, 1, &[1])).is_err());
        assert!(validate_element(&raw_member(layout, SPARSE, 2, &[1, 1])).is_err());
        assert_eq!(
            join(&one, &encode_positions(layout, [1].into_iter())).unwrap(),
            two
        );
    }

    #[test]
    fn attachment_retains_payloads_and_defers_sparse_preparation() {
        let layout = ReferenceSummaryLayout::new(8, 1).unwrap();
        for member in [
            encode_positions(layout, [0, 126, 255].into_iter()),
            encode_positions(layout, 0..256),
        ] {
            let decoded = ReferenceSummary::decode(&member).unwrap();
            assert_eq!(
                decoded.payload.as_ptr(),
                member.bytes[HEADER_LEN..].as_ptr()
            );
            assert!(decoded.query().unwrap().contains_position(0));
            if let SummaryBits::Dense(bytes) = decoded.query_bits().unwrap() {
                assert_eq!(bytes.as_ptr(), decoded.payload.as_ptr());
            }
        }

        // The framing is readable; the unterminated sparse gap is diagnosed
        // only when a query actually decodes it, or by an explicit audit.
        let malformed = raw_member(layout, SPARSE, 1, &[128]);
        let decoded = ReferenceSummary::decode(&malformed).unwrap();
        assert!(decoded.query().is_err());
        assert!(validate_element(&malformed).is_err());
    }

    #[test]
    fn dense_attachment_does_not_recount_or_reprove_shortest_form() {
        let layout = ReferenceSummaryLayout::new(8, 1).unwrap();
        let member = raw_member(layout, DENSE, 256, &[0; 32]);
        let decoded = ReferenceSummary::decode(&member).unwrap();
        assert_eq!(decoded.occupied_bits(), 256, "the header is not re-derived");
        assert!(!decoded.query().unwrap().contains_locator([0; 32]));
        assert!(validate_element(&member).is_err());

        let noncanonical = raw_member(ReferenceSummaryLayout::new(3, 1).unwrap(), DENSE, 1, &[1]);
        assert!(ReferenceSummary::decode(&noncanonical)
            .unwrap()
            .query()
            .unwrap()
            .contains_locator([0; 32]));
        assert!(validate_element(&noncanonical).is_err());

        let truncated = raw_member(layout, DENSE, 1, &[1]);
        assert!(ReferenceSummary::decode(&truncated).is_err());
    }

    #[test]
    fn explicit_audit_rejects_noncanonical_members() {
        let layout = ReferenceSummaryLayout::new(8, 1).unwrap();
        let malformed = [
            Blob::new(Bytes::from_source(Vec::<u8>::new())),
            raw_member(layout, 2, 0, &[]),
            raw_member(layout, SPARSE, 257, &[]),
            raw_member(layout, SPARSE, 0, &[1]),
            raw_member(layout, SPARSE, 1, &[0]),
            raw_member(layout, SPARSE, 1, &[128]),
            raw_member(layout, SPARSE, 1, &[129, 0]),
            raw_member(layout, SPARSE, 1, &[128, 128, 128, 128, 32]),
            raw_member(layout, SPARSE, 1, &[129, 2]),
            raw_member(layout, DENSE, 1, &[1]),
            raw_member(layout, DENSE, 256, &[0; 32]),
            raw_member(ReferenceSummaryLayout::new(1, 1).unwrap(), DENSE, 1, &[4]),
        ];
        for member in malformed {
            assert!(validate_element(&member).is_err());
        }
        let other = empty(ReferenceSummaryLayout::new(9, 1).unwrap());
        assert!(matches!(
            join(&empty(layout), &other),
            Err(ReferenceSummaryError::LayoutMismatch)
        ));
    }

    #[test]
    fn exhaustive_small_lattice_has_byte_exact_join_laws() {
        let layout = ReferenceSummaryLayout::new(2, 1).unwrap();
        let members: Vec<_> = (0_u8..16)
            .map(|mask| {
                encode_positions(
                    layout,
                    (0..4).filter(move |position| mask & (1 << position) != 0),
                )
            })
            .collect();
        for a in 0..16 {
            assert_eq!(join(&members[a], &members[a]).unwrap(), members[a]);
            assert_eq!(join(&members[a], &empty(layout)).unwrap(), members[a]);
            for b in 0..16 {
                let ab = join(&members[a], &members[b]).unwrap();
                assert_eq!(ab, members[a | b]);
                assert_eq!(ab, join(&members[b], &members[a]).unwrap());
                for c in 0..16 {
                    assert_eq!(join(&ab, &members[c]).unwrap(), members[a | b | c]);
                    assert_eq!(
                        join(&members[a], &join(&members[b], &members[c]).unwrap()).unwrap(),
                        members[a | b | c]
                    );
                }
            }
        }
    }

    #[test]
    fn locator_membership_survives_all_joins_and_insertion_orders() {
        let locators = locators(96);
        for bits in [4, 8, 12, 32] {
            let layout = ReferenceSummaryLayout::new(bits, 4).unwrap();
            let whole = from_locators(layout, locators.iter().copied());
            let reverse = from_locators(
                layout,
                locators
                    .iter()
                    .rev()
                    .copied()
                    .chain(locators.iter().copied()),
            );
            assert_eq!(whole, reverse);
            let mut joined = empty(layout);
            for chunk in locators.chunks(7) {
                joined = join(&joined, &from_locators(layout, chunk.iter().copied())).unwrap();
            }
            assert_eq!(whole, joined);
            let decoded = ReferenceSummary::decode(&joined).unwrap();
            let query = decoded.query().unwrap();
            for locator in &locators {
                assert!(query.contains_locator(*locator));
            }
            assert!(ReferenceSummary::decode(&empty(layout)).unwrap().is_empty());
            assert!(!ReferenceSummary::decode(&empty(layout))
                .unwrap()
                .query()
                .unwrap()
                .contains_locator(locators[0]));
        }
    }

    #[test]
    fn complete_recursive_projection_is_homomorphic_and_ignores_unrelated_inventory() {
        let layout = ReferenceSummaryLayout::default();
        let mut store = MemoryBlobStore::default();
        let leaf = store
            .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(vec![
                1_u8, 2, 3,
            ])))
            .unwrap();
        let mut child_bytes = leaf.raw.to_vec();
        child_bytes.extend_from_slice(&leaf.raw);
        child_bytes.extend_from_slice(&[9; 7]);
        let child = store
            .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(child_bytes)))
            .unwrap();
        let a = source(&[child.raw]);
        let b = source(&[leaf.raw, child.raw]);
        let ab = super::super::simplearchive_union::join(&a, &b).unwrap();
        let reader = ReadSpy::new(store.snapshot().unwrap());
        let fa = derive_element(&a, layout, &reader).unwrap();
        assert_eq!(
            fa,
            from_locators(layout, [blob_locator(leaf.raw), blob_locator(child.raw)])
        );
        assert_eq!(reader.gets.borrow().len(), 2, "shared child is read once");
        assert!(
            !reader.gets.borrow().contains(&a.get_handle().raw),
            "source is not a root lookup"
        );
        assert_eq!(
            join(&fa, &derive_element(&b, layout, &reader).unwrap()).unwrap(),
            derive_element(&ab, layout, &reader).unwrap()
        );
        for handle in [a.get_handle().raw, ab.get_handle().raw, leaf.raw, child.raw] {
            assert!(
                !fa.bytes.windows(32).any(|window| window == handle),
                "no bearer handle is serialized"
            );
        }
        store
            .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(vec![
                99_u8;
                200
            ])))
            .unwrap();
        store.put::<SimpleArchive, _>(a.clone()).unwrap();
        store.put::<SimpleArchive, _>(ab.clone()).unwrap();
        assert_eq!(
            fa,
            derive_element(&a, layout, &store.snapshot().unwrap()).unwrap()
        );
        let bad_source = Blob::<SimpleArchive>::new(Bytes::from_source(vec![1]));
        assert!(matches!(
            derive_element(&bad_source, layout, &reader),
            Err(ReferenceSummaryError::InvalidSource(_))
        ));
        let mut failing = ReadSpy::new(store.snapshot().unwrap());
        failing.fail_get = true;
        assert!(matches!(
            derive_element(&a, layout, &failing),
            Err(ReferenceSummaryError::Store(_))
        ));
    }

    #[test]
    fn incomplete_replica_cannot_supply_a_canonical_producer_image() {
        let layout = ReferenceSummaryLayout::default();
        let leaf = Blob::<UnknownBlob>::new(Bytes::from_source(vec![1, 2, 3]));
        let child = Blob::<UnknownBlob>::new(Bytes::from_source(leaf.get_handle().raw.to_vec()));
        let source = source(&[child.get_handle().raw]);
        let mut store = MemoryBlobStore::default();
        let absent =
            derive_element(&source, layout, &ReadSpy::new(store.snapshot().unwrap())).unwrap();
        assert_eq!(absent, empty(layout));
        store.put::<UnknownBlob, _>(child.clone()).unwrap();
        let partial =
            derive_element(&source, layout, &ReadSpy::new(store.snapshot().unwrap())).unwrap();
        assert_eq!(
            partial,
            from_locators(layout, [blob_locator(child.get_handle().raw)])
        );
        store.put::<UnknownBlob, _>(leaf.clone()).unwrap();
        let complete =
            derive_element(&source, layout, &ReadSpy::new(store.snapshot().unwrap())).unwrap();
        assert_eq!(
            complete,
            from_locators(
                layout,
                [
                    blob_locator(child.get_handle().raw),
                    blob_locator(leaf.get_handle().raw)
                ]
            )
        );
        assert_ne!(
            partial, complete,
            "the producer precondition is indispensable"
        );
    }

    #[test]
    fn descriptor_geometry_is_explicit_and_mapping_ids_are_opaque() {
        let layout = ReferenceSummaryLayout::default();
        let first = descriptor(layout);
        assert_eq!(
            ReferenceSummaryBlob::bind(&Fragment::empty(), &first).unwrap(),
            layout
        );
        let smaller = descriptor(ReferenceSummaryLayout::new(20, 3).unwrap());
        assert_ne!(first, smaller);
        let mapping_id = ufoid();
        let mapping = entity! { &mapping_id @
            metadata::tag: KIND_COLLECTION_MAPPING,
            metadata::tag: metadata::KIND_MULTI,
            metadata::name: "an extrinsic mapping with harmless annotations",
            mapping_algorithm*: ReferenceSummaryMappingV2::describe(),
            reference_summary_log2_bits: layout.log2_bits,
            reference_summary_probes: layout.probes,
        };
        let extrinsic = entity! { _ @
            metadata::tag: super::super::KIND_COLLECTION_DESCRIPTOR,
            super::super::collection_representation: ReferenceSummaryBlob::id(),
            super::super::collection_mapping*: mapping,
        };
        assert_eq!(
            ReferenceSummaryBlob::bind(&Fragment::empty(), &extrinsic).unwrap(),
            layout
        );
        let mut store = MemoryBlobStore::default();
        let reader = store.snapshot().unwrap();
        assert!(ReferenceSummaryBlob::validate_member(&first, &empty(layout), &reader).is_ok());
        assert!(ReferenceSummaryBlob::validate_member(&smaller, &empty(layout), &reader).is_err());
        assert!(ReferenceSummaryBlob::join_members(
            &smaller,
            &empty(layout),
            &empty(layout),
            &reader
        )
        .is_err());
    }

    #[test]
    fn lazy_cover_view_matches_bit_union_without_source_reads_or_algebra() {
        let layout = ReferenceSummaryLayout::new(4, 2).unwrap();
        let left = encode_positions(layout, [0].into_iter());
        let right = encode_positions(layout, [1].into_iter());
        let locator = [0; 32];
        assert!(!ReferenceSummary::decode(&left)
            .unwrap()
            .query()
            .unwrap()
            .contains_locator(locator));
        assert!(!ReferenceSummary::decode(&right)
            .unwrap()
            .query()
            .unwrap()
            .contains_locator(locator));
        let mut store = MemoryBlobStore::default();
        let low = store.put(left.clone()).unwrap();
        let high = store.put(right.clone()).unwrap();
        let collection = Collection::from_handle(CollectionHandle::new([11; 32]));
        let cover = collection.cover([low, high]);
        let reader = ReadSpy::new(store.snapshot().unwrap());
        let view =
            ReferenceSummaryView::try_from_cover(&cover, &descriptor(layout), &reader).unwrap();
        assert!(
            view.query().unwrap().contains_locator(locator),
            "probe bits may come from different members"
        );
        assert!(ReferenceSummary::decode(&join(&left, &right).unwrap())
            .unwrap()
            .query()
            .unwrap()
            .contains_locator(locator));
        assert_eq!(reader.gets.borrow().len(), 2);
        assert!(
            reader.metadata.borrow().is_empty(),
            "consumer reads known summary outputs only"
        );
        let none = ReferenceSummaryView::try_from_cover(
            &collection.cover([]),
            &descriptor(layout),
            &reader,
        )
        .unwrap();
        assert!(!none.query().unwrap().contains_locator(locator));
    }
}
