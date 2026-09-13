//! A Pile is an append-only collection of blobs, collection records, complete
//! capability proofs, wants, and legacy branches stored in a single file. It
//! is designed as a durable local
//! repository storage that can be safely shared between threads.
//!
//! The pile operates as a **WAL-as-a-DB**: the write-ahead log _is_ the database.
//! All indices and metadata are reconstructed from the log on startup and no
//! additional state is persisted elsewhere.
//!
//! The pile treats its file as an immutable append-only log. Once a record lies
//! below `applied_length` and its bytes have been returned by
//! `get` or `apply_next`, those bytes are
//! assumed permanent. Modifying any part of the pile other than appending new
//! records is undefined behaviour. The un-applied tail may hide a partial
//! append after a crash, so validation and repair only operate on offsets
//! beyond `applied_length`. Each record's [`ValidationState`](crate::repo::pile::ValidationState) is cached for the
//! lifetime of the process under this immutability assumption.
//!
//! For layout and recovery details see the [Pile
//! Format](../../book/src/pile-format.md) chapter of the Tribles Book.

use anybytes::Bytes;
use ed25519_dalek::VerifyingKey;
use hex_literal::hex;
use memmap2::MmapOptions;
use memmap2::MmapRaw;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::IoSlice;
use std::io::Write;
use std::path::Path;
use std::ptr::slice_from_raw_parts;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::blob::BlobEncoding;
use crate::blob::IntoBlob;
use crate::blob::TryFromBlob;
use crate::capability::{
    CapabilityProof, CapabilityProofId, CAPABILITY_PROOF_EDGE_LEN, CAPABILITY_PROOF_HEADER_LEN,
    CAPABILITY_PROOF_MAGIC, MAX_CAPABILITY_PROOF_STEPS,
};
use crate::collection::store::{selectors_match_record, CollectionRead};
pub use crate::collection::LegacyUnsignedCollectionEquation;
use crate::collection::{
    CollectionCommit, CollectionDerive, CollectionHandle, CollectionMerge, CollectionRecord,
    CollectionRecordFingerprint, CollectionRecordSelector, CollectionStore,
};
use crate::id::Id;
use crate::id::RawId;
use crate::inline::encodings::ed25519::{ED25519PublicKey, ED25519RComponent, ED25519SComponent};
use crate::inline::encodings::hash::Blake3;
use crate::inline::encodings::hash::Hash;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::RawInline;
use crate::patch::Entry;
use crate::patch::{IdentitySchema, XorSip128, PATCH};
use crate::prelude::blobencodings::SimpleArchive;
use crate::prelude::inlineencodings::Handle;
use crate::repo::proof::{CapabilityProofRead, CapabilityProofStore};
use crate::repo::{
    SnapshotSource, WantRequest, WANT_REQUEST_BYTES_LEN, WANT_REQUEST_KIND_DERIVE_V1,
};

#[cfg(test)]
mod append_visibility_tests;
mod record_kind;
pub use record_kind::{described_kinds, description_blobs, RecordKind, KIND_PILE_RECORD};

/// Self-description handle of the physical pile frame used for `record`.
///
/// Kept crate-visible so Yard can apply the same physical ownership rule
/// while retaining semantic records across its constituent piles.
pub(crate) fn collection_record_kind(record: CollectionRecord) -> RecordKind {
    Inline::new(match record {
        CollectionRecord::Commit(_) => record_kind::KIND_COLLECTION_COMMIT,
        CollectionRecord::Merge(_) => record_kind::KIND_COLLECTION_MERGE,
        CollectionRecord::Derive(_) => record_kind::KIND_COLLECTION_DERIVE,
    })
}

/// Self-description handle of a physical capability-proof frame.
pub(crate) fn capability_proof_record_kind() -> RecordKind {
    Inline::new(record_kind::KIND_AUTH_PROOF)
}

/// Self-description handle of a physical WANT frame.
pub(crate) fn want_record_kind() -> RecordKind {
    Inline::new(record_kind::KIND_WANT)
}

/// Self-description handle of a physical BLOB frame.
pub(crate) fn blob_record_kind() -> RecordKind {
    Inline::new(record_kind::KIND_BLOB)
}

#[cfg(test)]
pub(crate) fn assert_record_kind_description_resident<R>(reader: &R, kind: RecordKind)
where
    R: crate::repo::BlobStoreGet,
{
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::prelude::{find, pattern};
    use crate::trible::TribleSet;

    let description = reader
        .get::<TribleSet, SimpleArchive>(kind)
        .unwrap_or_else(|_| {
            panic!(
                "record-kind archive {} is absent",
                hex::encode_upper(kind.raw)
            )
        });
    let text_handles = find!(
        (
            name: Inline<Handle<UTF8String>>,
            layout: Inline<Handle<UTF8String>>
        ),
        pattern!(&description, [{
            crate::metadata::name: ?name,
            crate::metadata::description: ?layout
        }])
    )
    .collect::<Vec<_>>();
    assert_eq!(text_handles.len(), 1);
    for (name, layout) in text_handles {
        for handle in [name, layout] {
            assert!(
                reader
                    .get::<anybytes::View<str>, UTF8String>(handle)
                    .is_ok(),
                "record-kind description child {} is absent",
                hex::encode_upper(handle.raw)
            );
        }
    }
}

/// Self-description handle of a physical active-pin frame.
fn pin_head_record_kind() -> RecordKind {
    Inline::new(record_kind::KIND_PIN_HEAD)
}

fn retain_record_kind_if_resident(
    roots: &mut super::RetentionRoots,
    reader: &PileSnapshot,
    kind: RecordKind,
) {
    if reader
        .contains_blob(kind)
        .expect("PileSnapshot residency lookup is infallible")
    {
        roots.retain_recursive(kind);
    }
}

// ---------------------------------------------------------------------------
// The supported legacy surface is exactly what shipped in **v0.46.4** (tagged
// 2026-06-10, the last released version): the three V1 markers below. Those
// are the only records anyone outside this workspace can be holding, so they
// are read forever.
//
// Everything below them was introduced after that release and never shipped.
// Exact retired boundaries remain recognized so stale pile concatenation is
// harmless and explicit migrations can inspect their evidence. They are not a
// writable compatibility surface: do not add writers or assign new semantics.
// ---------------------------------------------------------------------------

const MAGIC_MARKER_BLOB: RawId = hex!("1E08B022FF2F47B6EBACF1D68EB35D96");
const MAGIC_MARKER_BRANCH: RawId = hex!("2BC991A7F5D5D2A3A468C53B0AA03504");
const MAGIC_MARKER_BRANCH_TOMBSTONE: RawId = hex!("E888CC787202D2AE4C654BFE9699C430");
/// Legacy V1 pile-record envelope marker, written 2026-08-11 .. 2026-08-20.
///
/// Minted on 2026-08-11 with `trible genid`:
/// `E5A95E5D8A0BBA8782E46B9C9E73B313`.
///
/// A V1 record placed this marker first, its V3/V4 marker in the next 16 bytes
/// as a semantic record-kind id, and its total span as a count of 256-byte
/// blocks in bytes 32..36. That 36-byte prefix left every subsequent 32-byte
/// field four bytes short of a 32-byte boundary. Read-only now; see
/// [`FRAME_MAGIC`].
const MAGIC_MARKER_ENVELOPE: RawId = hex!("E5A95E5D8A0BBA8782E46B9C9E73B313");

/// Width of the pile-record framing magic.
///
/// 28 bytes is a **sentinel**, not just an identifier. The frame is the one
/// thing a reader must get right before it can find anything else, and a wider
/// constant is correspondingly harder for garbage, a torn write, or a mis-seek
/// to satisfy by accident: a mismatch is 224 bits of evidence that these bytes
/// are not a record.
const FRAME_MAGIC_LEN: usize = 28;

/// The pile-record framing magic.
///
/// Minted on 2026-08-20 as two `trible genid` calls,
/// `0371B249F0626B2ABDDB80E23EA96905` and `9D9656A5EA5A497320351F3BE712CF82`,
/// concatenated and truncated to 28 bytes.
///
/// A record is 28 bytes of magic, a little-endian `u32` block span in `28..32`,
/// a 32-byte record kind in `32..64`, then the kind's body. Three properties
/// follow, and together they are why this is the format rather than a version
/// in a series.
///
/// * **Alignment.** The body starts at byte 64, so every 32-byte field in it
///   is aligned rather than straddling — and since records begin on 256-byte
///   boundaries, the alignment holds at absolute file offsets too.
/// * **Resolvability.** 32 bytes is a blob handle, so the kind can name a
///   description of the record's own layout. A reader meeting an unfamiliar
///   record resolves what it is instead of merely failing to recognise it.
///   See [`record_kind`].
/// * **Skippability.** The span sits early and at a fixed offset, ahead of
///   anything version-specific, so any future reader can cross a record it
///   does not understand without understanding it.
const FRAME_MAGIC: [u8; FRAME_MAGIC_LEN] =
    hex!("0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B");
/// V3 record markers, minted 2026-06-29 via `trible genid`. Legacy V3 records
/// place these first; current records reuse them as envelope kind IDs. Both
/// layouts have a fixed 256-byte header and 256-byte record granularity. Consequences:
///   * blob data starts at a constant `record_start + 256` — reads are
///     position-INDEPENDENT (no offset-derived pad), so a record survives
///     relocation/`cat` and is found correctly regardless of its offset;
///   * because every record is a 256-multiple, a current pile stays 256-aligned
///     throughout under ATOMIC lock-free append (no exclusive lock needed), so
///     `cat a >> b` of two current piles is a valid merge AND the data stays
///     256-aligned for zero-copy GPU aliasing (CUDA/Metal `min_storage_buffer_offset_alignment`).
/// The reader still accepts the original V1 and unenveloped V3 records so
/// existing piles read byte-identical.
const MAGIC_MARKER_BLOB_V3: RawId = hex!("9C33EEB525065A62EAEC4BE43DCC355A");
const MAGIC_MARKER_BRANCH_V3: RawId = hex!("AC363D04AFE1AF17B39581B1E23021D7");
const MAGIC_MARKER_BRANCH_TOMBSTONE_V3: RawId = hex!("D0CBA0C8EAAB4C0C73121C3205671E4F");
/// Retired physical marker pair that encoded blob demand as a weak pin/unpin
/// LWW log (minted 2026-07-01 via `trible genid`). Current replay crosses these
/// records without applying them; only the explicit WANT cutover migration
/// interprets their historical order.
const MAGIC_MARKER_WEAK_PIN_V3: RawId = hex!("8F3EEFEDECD491F63F6EAAA5FD6F3D5E");
const MAGIC_MARKER_WEAK_UNPIN_V3: RawId = hex!("2D76662DFF0187EC36A8C90B12BB8B0D");
/// Retired typed-WANT assertion and retraction markers, minted on 2026-08-13
/// with `trible genid`. Current replay treats them as inert migration input.
const MAGIC_MARKER_WANT_ASSERT_V2: RawId = hex!("9A06797600FA90B8A8259B0ED029EC21");
const MAGIC_MARKER_WANT_RETRACT_V2: RawId = hex!("2D957A780A52E474F58A06D44D6FE46C");
/// Legacy V3 collection-record markers, minted on 2026-08-10 with
/// `trible genid`.
///
/// These physical records predate descriptor-handle collection identities.
/// They remain recognizable for safe replay and conservative rewriting, but
/// are inert: they are never reconstructed as current [`CollectionRecord`]s
/// and never enter [`CollectionStore`]. New writes use the V4 markers below.
const MAGIC_MARKER_COLLECTION_DEFINITION_V3: RawId = hex!("3BE108504E4F5242FB24AA72D6D94CE1");
const MAGIC_MARKER_COLLECTION_COMMIT_V3: RawId = hex!("BB758AA6F79FBFC4D1958592A8956777");
const MAGIC_MARKER_COLLECTION_MERGE_V3: RawId = hex!("CC0108AC1DF4F335AFA856A529C42BE9");
const MAGIC_MARKER_COLLECTION_DERIVE_V3: RawId = hex!("07ECF056F6F015D94389FFF21F851480");
/// Current collection-record markers, minted on 2026-08-11 with
/// `trible genid`.
///
/// V4 collection records carry 32-byte canonical descriptor handles directly.
/// There is deliberately no V4 definition record: descriptors are ordinary
/// `SimpleArchive` blobs named by those handles.
const MAGIC_MARKER_COLLECTION_COMMIT_V4: RawId = hex!("CBF2CF97D52A3486E16C12D70D397C66");
const MAGIC_MARKER_COLLECTION_MERGE_V4: RawId = hex!("9F5D028D4C423620D6957A5F726FA727");
const MAGIC_MARKER_COLLECTION_DERIVE_V4: RawId = hex!("ECFB2EE90ED8042244F7BAC704454BB9");
/// V5 derive: the source field is gone, because the target's descriptor names
/// it. Records under the V4 marker no longer project a collection record — a
/// derivation is a computation with a checkable artifact, so a stale one is
/// recomputed rather than migrated. The decoder recognizes V4 as specifically
/// retired rather than unknown, allowing semantic rewrites to discard it while
/// continuing to fail closed on genuinely unknown record kinds.
///
/// Minted with `trible genid` on 2026-08-20.
const MAGIC_MARKER_COLLECTION_DERIVE_V5: RawId = hex!("ED6B46F7286D4556B076C17B79FD8315");
/// Retired local-cell record markers, minted on 2026-08-10 with `trible genid`.
///
/// These values remain private solely so old piles can be crossed at their
/// known 256-byte boundaries. They decode as opaque migration evidence and
/// never reconstruct operational state.
const MAGIC_MARKER_LOCAL_CELL_V3: RawId = hex!("24264FA9EE46A1ACC0E024AE69774B09");
const MAGIC_MARKER_LOCAL_CELL_TOMBSTONE_V3: RawId = hex!("4FE372AE868D22A44DED7A60D579B651");

const BLOB_HEADER_LEN: usize = std::mem::size_of::<BlobHeader>();
const BLOB_ALIGNMENT: usize = BLOB_HEADER_LEN;
/// GPU storage-buffer binding-offset requirement (CUDA / Metal
/// `min_storage_buffer_offset_alignment`); a current blob record's data start lands here.
const GPU_DATA_ALIGNMENT: usize = 256;
/// Fixed header length and record alignment inherited from V3
/// (== GPU_DATA_ALIGNMENT). Current envelope headers retain this width; blob
/// data follows at `record_start + ENVELOPE_HEADER_LEN`.
const V3_HEADER_LEN: usize = 256;
const ENVELOPE_HEADER_LEN: usize = 256;
/// The generic framing ends here; a canonical proof starts with its kind.
const FRAME_KIND_OFFSET: usize = FRAME_MAGIC_LEN + 4;
/// First byte of a current record's kind-specific body: 28 bytes of magic, a
/// 4-byte span, and a 32-byte record kind. A multiple of 32, which is the
/// whole point of the width choice.
const FRAME_BODY_OFFSET: usize = FRAME_KIND_OFFSET + 32;
const ENVELOPE_BLOCK_LEN: usize = GPU_DATA_ALIGNMENT;
const ENVELOPE_HEADER_BLOCKS: u32 = 1;
/// Post-data padding that rounds a fixed-header record up to a 256-byte block.
fn block_post_pad(data_len: usize) -> usize {
    (ENVELOPE_BLOCK_LEN - (data_len % ENVELOPE_BLOCK_LEN)) % ENVELOPE_BLOCK_LEN
}

/// Largest single blob record we'll write with the concurrent `write_vectored`
/// fast path. Linux caps a single `writev` at `MAX_RW_COUNT` (`INT_MAX &
/// ~(PAGE_SIZE - 1)`, ~2 GiB) and macOS caps it at `INT_MAX`. Below this
/// threshold we rely on kernel append serialization and let concurrent writers
/// hold a shared lock. Readers can still observe an incomplete append and must
/// recheck parse failures behind an exclusive-lock completion barrier. Above
/// it we switch to an exclusive-lock fallback that
/// issues plain `write_all` calls — still append-only, still recoverable
/// via [`Pile::amputate`], just serialized with other writers for the
/// duration of the large append. The margin keeps us comfortably below
/// any platform's single-call ceiling.
const ATOMIC_WRITE_LIMIT: usize = 1 << 30;

/// Payloads at least this large may use BLAKE3's Rayon join strategy when the
/// current pool has more than one worker. Smaller payloads stay on the serial
/// one-shot path to avoid paying scheduling overhead for short validations.
#[cfg(any(feature = "parallel", test))]
const PARALLEL_BLAKE3_THRESHOLD: usize = 1 << 20;

/// Lazily-computed validation status of a blob record in the pile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationState {
    /// The blob's hash matches its stored digest.
    Validated,
    /// The blob's hash does not match — the record is corrupt.
    Invalid,
}

#[cfg(feature = "parallel")]
fn should_parallelize_validation(len: usize) -> bool {
    len >= PARALLEL_BLAKE3_THRESHOLD && rayon::current_num_threads() > 1
}

#[derive(Debug, Clone, Copy)]
enum ValidationStrategy {
    /// Hash on the calling thread.
    Serial,
    /// For a sufficiently large first miss, use BLAKE3's Rayon join strategy.
    ParallelIfLarge,
}

fn classify_validation(
    computed: Inline<Hash<Blake3>>,
    expected: &Inline<Hash<Blake3>>,
) -> ValidationState {
    if computed == *expected {
        ValidationState::Validated
    } else {
        ValidationState::Invalid
    }
}

/// Computes the validation state of one immutable pile payload.
fn compute_validation_state(
    bytes: &Bytes,
    expected: &Inline<Hash<Blake3>>,
    strategy: ValidationStrategy,
) -> ValidationState {
    #[cfg(not(feature = "parallel"))]
    let _ = strategy;

    #[cfg(feature = "parallel")]
    if matches!(strategy, ValidationStrategy::ParallelIfLarge)
        && should_parallelize_validation(bytes.len())
    {
        let mut hasher = blake3::Hasher::new();
        hasher.update_rayon(bytes);
        let computed = Inline::new(*hasher.finalize().as_bytes());
        return classify_validation(computed, expected);
    }

    classify_validation(Hash::<Blake3>::digest(bytes), expected)
}

/// Lazy payload validation stored inline in one physical-occurrence leaf.
///
/// PATCH leaves are refcount-shared by immutable snapshots, so this atomic is
/// one byte inside the existing leaf allocation rather than one heap object or
/// hash-table entry per occurrence. Hashing happens before the compare/exchange:
/// concurrent first misses may duplicate deterministic work, then converge on
/// the first published result without holding a lock while Rayon executes.
#[derive(Debug, Default)]
struct CachedValidation(AtomicU8);

impl CachedValidation {
    const UNKNOWN: u8 = 0;
    const VALIDATED: u8 = 1;
    const INVALID: u8 = 2;

    fn decode(state: u8) -> Option<ValidationState> {
        match state {
            Self::UNKNOWN => None,
            Self::VALIDATED => Some(ValidationState::Validated),
            Self::INVALID => Some(ValidationState::Invalid),
            _ => unreachable!("CachedValidation contains an invalid state"),
        }
    }

    const fn encode(state: ValidationState) -> u8 {
        match state {
            ValidationState::Validated => Self::VALIDATED,
            ValidationState::Invalid => Self::INVALID,
        }
    }

    fn cached(&self) -> Option<ValidationState> {
        Self::decode(self.0.load(Ordering::Acquire))
    }

    fn state(
        &self,
        bytes: &Bytes,
        expected: &Inline<Hash<Blake3>>,
        strategy: ValidationStrategy,
    ) -> ValidationState {
        if let Some(cached) = self.cached() {
            return cached;
        }

        let computed = compute_validation_state(bytes, expected, strategy);
        let encoded = Self::encode(computed);
        match self
            .0
            .compare_exchange(Self::UNKNOWN, encoded, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => computed,
            Err(published) => Self::decode(published)
                .expect("a failed first-publication race must observe a cached result"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    record_offset: usize,
}

impl IndexEntry {
    fn new(record_offset: usize) -> Self {
        Self { record_offset }
    }
}

fn blob_occurrence_key(hash: &RawInline, entry: IndexEntry) -> [u8; 40] {
    let mut key = [0; 40];
    key[..32].copy_from_slice(hash);
    key[32..].copy_from_slice(
        &u64::try_from(entry.record_offset)
            .expect("a pile offset must fit in the portable u64 key")
            .to_be_bytes(),
    );
    key
}

fn blob_occurrence_entry(offset: [u8; 8]) -> IndexEntry {
    IndexEntry::new(
        usize::try_from(u64::from_be_bytes(offset))
            .expect("an indexed pile offset must fit this platform's usize"),
    )
}

mod blob_occurrence_key {
    crate::key_segmentation!(Segments, 40, [32, 8]);
    crate::key_schema!(Schema, Segments, 40, [0, 1]);
}

mod collection_record_collection_key {
    crate::key_segmentation!(Segments, 64, [32, 32]);
    crate::key_schema!(Schema, Segments, 64, [0, 1]);
}

type PileBlobIndex = PATCH<40, blob_occurrence_key::Schema, CachedValidation, XorSip128>;
type CollectionRecordIndex = PATCH<32, IdentitySchema, CollectionRecord, XorSip128>;
type CollectionRecordCollectionIndex =
    PATCH<64, collection_record_collection_key::Schema, (), XorSip128>;
type CapabilityProofIndex = PATCH<32, IdentitySchema, CapabilityProof, XorSip128>;
type LegacyCollectionHeaderIndex = PATCH<V3_HEADER_LEN, IdentitySchema>;

fn collection_record_collection(record: CollectionRecord) -> CollectionHandle {
    match record {
        CollectionRecord::Commit(record) => record.collection(),
        CollectionRecord::Merge(record) => record.collection(),
        CollectionRecord::Derive(record) => record.collection(),
    }
}

fn collection_record_collection_key(record: CollectionRecord) -> [u8; 64] {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&collection_record_collection(record).raw);
    key[32..].copy_from_slice(&record.fingerprint().raw());
    key
}

fn first_blob_occurrence(occurrences: &PileBlobIndex, hash: &RawInline) -> Option<IndexEntry> {
    occurrences
        .first_infix_range(hash, &[u8::MIN; 8], &[u8::MAX; 8])
        .map(blob_occurrence_entry)
}

fn next_blob_occurrence(
    occurrences: &PileBlobIndex,
    hash: &RawInline,
    after: IndexEntry,
) -> Option<IndexEntry> {
    let after = u64::try_from(after.record_offset)
        .expect("a pile offset must fit in the portable u64 key")
        .to_be_bytes();
    occurrences
        .next_infix_after(hash, &after, &[u8::MAX; 8])
        .map(blob_occurrence_entry)
}

fn blob_occurrence_validation<'a>(
    occurrences: &'a PileBlobIndex,
    hash: &RawInline,
    entry: IndexEntry,
) -> &'a CachedValidation {
    occurrences
        .get(&blob_occurrence_key(hash, entry))
        .expect("an enumerated blob occurrence must retain its leaf value")
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BranchHeader {
    magic_marker: RawId,
    branch_id: RawId,
    hash: RawInline,
}

// `BranchHeader` / `BranchTombstoneHeader` have no constructors; these structs
// exist only so the reader can decode legacy V1 records.

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BranchTombstoneHeader {
    magic_marker: RawId,
    branch_id: RawId,
    /// Reserved bytes to preserve 64 byte record alignment.
    reserved: RawInline,
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BlobHeader {
    magic_marker: RawId,
    timestamp: u64,
    length: u64,
    hash: RawInline,
}

impl BlobHeader {
    /// V1 blob constructor — retained only for the legacy-format backward-compat
    /// test (V1 blob records are otherwise read, never written).
    #[cfg(test)]
    fn new(timestamp: u64, length: u64, hash: Inline<Hash<Blake3>>) -> Self {
        Self {
            magic_marker: MAGIC_MARKER_BLOB,
            timestamp,
            length,
            hash: hash.raw,
        }
    }
}

/// V3 blob header — fixed 256 bytes. Same load-bearing fields as V1; the data
/// follows at `record_start + V3_HEADER_LEN` with no offset-derived pre-pad.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BlobHeaderV3 {
    magic_marker: RawId,
    timestamp: u64,
    length: u64,
    hash: RawInline,
    /// Pads the header to V3_HEADER_LEN (256), zeroed. NOT part of the content
    /// hash, so it never affects blob identity or dedup. Deliberately empty:
    /// genuinely useful per-record metadata belongs in tribles (keyed by the
    /// referencing attribute), and the encoding/schema must NOT live here — else
    /// identical bytes would fork into distinct blobs. Fill only when a concrete,
    /// content-independent need names itself.
    reserved: [u8; 192],
}

impl BlobHeaderV3 {
    #[cfg(test)]
    fn new(timestamp: u64, length: u64, hash: Inline<Hash<Blake3>>) -> Self {
        Self {
            magic_marker: MAGIC_MARKER_BLOB_V3,
            timestamp,
            length,
            hash: hash.raw,
            reserved: [0u8; 192],
        }
    }
}

/// V3 branch head — fixed 256 bytes (mirrors `BranchHeader` + reserved pad).
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BranchHeaderV3 {
    magic_marker: RawId,
    branch_id: RawId,
    hash: RawInline,
    reserved: [u8; 192],
}

/// V3 branch tombstone — fixed 256 bytes.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BranchTombstoneHeaderV3 {
    magic_marker: RawId,
    branch_id: RawId,
    reserved: [u8; 224],
}

/// Retired V3 WANT assertion using the weak-pin encoding — fixed 256 bytes and
/// keyed by blob handle (no branch id).
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct WeakPinHeaderV3 {
    magic_marker: RawId,
    handle: RawInline,
    reserved: [u8; 208],
}

/// Retired V3 WANT retraction using the weak-unpin encoding.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct WeakUnpinHeaderV3 {
    magic_marker: RawId,
    handle: RawInline,
    reserved: [u8; 208],
}

/// Legacy V3 collection definition: `(scope, representation, recipe)`.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionDefinitionHeaderV3 {
    magic_marker: RawId,
    scope: RawId,
    representation: RawId,
    recipe: RawId,
    reserved: [u8; 192],
}

/// Legacy V3 signed collection commit using a 16-byte intrinsic definition id.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionCommitHeaderV3 {
    magic_marker: RawId,
    collection: RawId,
    data: RawInline,
    metadata: RawInline,
    public_key: RawInline,
    signature_r: RawInline,
    signature_s: RawInline,
    reserved: [u8; 64],
}

/// Legacy V3 exact join equation using a 16-byte intrinsic definition id.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionMergeHeaderV3 {
    magic_marker: RawId,
    collection: RawId,
    low: RawInline,
    high: RawInline,
    result: RawInline,
    reserved: [u8; 128],
}

/// Legacy V3 mapping equation using 16-byte intrinsic definition ids.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionDeriveHeaderV3 {
    magic_marker: RawId,
    source: RawId,
    target: RawId,
    input: RawInline,
    output: RawInline,
    reserved: [u8; 144],
}

/// V4 signed collection commit. The complete 32-byte descriptor handle bound
/// by the V2 signature transcript is stored directly in the fixed header.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionCommitHeaderV4 {
    magic_marker: RawId,
    collection: RawInline,
    data: RawInline,
    metadata: RawInline,
    public_key: RawInline,
    signature_r: RawInline,
    signature_s: RawInline,
    reserved: [u8; 48],
}

/// V4 exact join equation. Inputs are stored in canonical digest order.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionMergeHeaderV4 {
    magic_marker: RawId,
    collection: RawInline,
    low: RawInline,
    high: RawInline,
    result: RawInline,
    reserved: [u8; 112],
}

/// V4 exact mapping equation between two descriptor-identified collections.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionDeriveHeaderV4 {
    magic_marker: RawId,
    source: RawInline,
    target: RawInline,
    input: RawInline,
    output: RawInline,
    reserved: [u8; 112],
}

// ---------------------------------------------------------------------------
// Legacy V1 envelope (2026-08-11 .. 2026-08-20): 16-byte marker, 16-byte kind,
// 4-byte span. Read-only. Its 36-byte prefix left every 32-byte field four
// bytes off a 32-byte boundary, which is why the V2 framing below replaced it.
// These structs exist so piles written in that window keep reading exactly.
// ---------------------------------------------------------------------------

/// Common prefix of a legacy V1 enveloped record. `span_blocks` is a canonical
/// little-endian `u32` at bytes 32..36, includes the 256-byte header itself,
/// and is never zero.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct EnvelopePrefixV1 {
    magic_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BlobHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    timestamp: [u8; 8],
    length: [u8; 8],
    hash: RawInline,
    reserved: [u8; 172],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BranchHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    branch_id: RawId,
    hash: RawInline,
    reserved: [u8; 172],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BranchTombstoneHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    branch_id: RawId,
    reserved: [u8; 204],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct WantHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    handle: RawInline,
    reserved: [u8; 188],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct TypedWantHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    request_kind: u8,
    field_a: RawInline,
    field_b: RawInline,
    field_c: RawInline,
    reserved: [u8; 123],
}

impl TypedWantHeaderEnvelopeV1 {
    fn request(
        &self,
    ) -> Result<(WantRequest, [u8; WANT_REQUEST_BYTES_LEN]), crate::repo::WantRequestDecodeError>
    {
        decode_retired_want_request(
            self.request_kind,
            &self.field_a,
            &self.field_b,
            &self.field_c,
        )
    }
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionCommitHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    collection: RawInline,
    data: RawInline,
    metadata: RawInline,
    public_key: RawInline,
    signature_r: RawInline,
    signature_s: RawInline,
    reserved: [u8; 28],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionMergeHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    collection: RawInline,
    low: RawInline,
    high: RawInline,
    result: RawInline,
    reserved: [u8; 92],
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionDeriveHeaderEnvelopeV1 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    target: RawInline,
    input: RawInline,
    output: RawInline,
    reserved: [u8; 124],
}

/// Retired V4 derive in the legacy V1 envelope. V4 redundantly named the
/// source descriptor; V5 removed that field and minted a new kind.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionDeriveHeaderEnvelopeV1V4 {
    envelope_marker: RawId,
    record_kind: RawId,
    span_blocks: [u8; 4],
    source: RawInline,
    target: RawInline,
    input: RawInline,
    output: RawInline,
    reserved: [u8; 92],
}

// ---------------------------------------------------------------------------
// Current V2 envelope: 28-byte magic, 4-byte span, 32-byte record kind.
// Fixed record bodies use 32-byte-aligned fields; variable payloads define
// their own canonical grammar after a fixed prefix.
// ---------------------------------------------------------------------------

/// Common prefix of every newly written pile record.
///
/// `span_blocks` is a canonical little-endian `u32` at bytes 28..32, includes
/// the record's first 256-byte block, and is never zero. `record_kind` is the
/// 32-byte handle of the kind's own description archive — see
/// [`record_kind`](crate::repo::pile::record_kind).
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct RecordFrame {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
}

/// Historical nested proof framing, only decoded for inert V1/V2 records.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct RetiredCapabilityProofRecordPrefix {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    length: [u8; 8],
    /// Canonical reserved bytes keeping the variable proof body at byte 96.
    scalar_pad: [u8; 24],
}

#[cfg(test)]
impl RetiredCapabilityProofRecordPrefix {
    fn new(span_blocks: u32, length: u64) -> Self {
        Self {
            magic: FRAME_MAGIC,
            span_blocks: span_blocks.to_le_bytes(),
            record_kind: record_kind::KIND_AUTH_PROOF_V1,
            length: length.to_le_bytes(),
            scalar_pad: [0u8; 24],
        }
    }
}

/// Blob record: `64..72` timestamp, `72..80` length, `96..128` digest.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct BlobRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    timestamp: [u8; 8],
    length: [u8; 8],
    /// Rounds the two scalars up to the next 32-byte boundary so the digest
    /// that follows is aligned. Zeroed and checked like any reserved region.
    scalar_pad: [u8; 16],
    hash: RawInline,
    reserved: [u8; 128],
}

impl BlobRecordHeader {
    fn new(span_blocks: u32, timestamp: u64, length: u64, hash: Inline<Hash<Blake3>>) -> Self {
        Self {
            magic: FRAME_MAGIC,
            span_blocks: span_blocks.to_le_bytes(),
            record_kind: record_kind::KIND_BLOB,
            timestamp: timestamp.to_le_bytes(),
            length: length.to_le_bytes(),
            scalar_pad: [0u8; 16],
            hash: hash.raw,
            reserved: [0u8; 128],
        }
    }
}

/// Pin head: `64..80` pin id, `96..128` head handle.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct PinHeadRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    branch_id: RawId,
    /// Rounds the 16-byte pin id up to the next 32-byte boundary.
    id_pad: [u8; 16],
    hash: RawInline,
    reserved: [u8; 128],
}

impl PinHeadRecordHeader {
    fn new(branch_id: Id, hash: Inline<Handle<SimpleArchive>>) -> Self {
        Self {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_PIN_HEAD,
            branch_id: *branch_id,
            id_pad: [0u8; 16],
            hash: hash.raw,
            reserved: [0u8; 128],
        }
    }
}

/// Pin tombstone: `64..80` pin id.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct PinTombstoneRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    branch_id: RawId,
    reserved: [u8; 176],
}

impl PinTombstoneRecordHeader {
    fn new(branch_id: Id) -> Self {
        Self {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_PIN_TOMBSTONE,
            branch_id: *branch_id,
            reserved: [0u8; 176],
        }
    }
}

/// Retired blob-WANT assertion or retraction: `64..96` blob handle.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct RetiredBlobWantRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    handle: RawInline,
    reserved: [u8; 160],
}

/// Current grow-only WANT: `64` request tag, `96..192` its three fields.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct WantRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    request_kind: u8,
    /// Rounds the one-byte tag up to the next 32-byte boundary.
    kind_pad: [u8; 31],
    field_a: RawInline,
    field_b: RawInline,
    field_c: RawInline,
    reserved: [u8; 64],
}

/// Retired peer-routing evidence: `64..96` team key, `96..128` peer key.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct RetiredPeerEvidenceRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    team_public_key: RawInline,
    peer_public_key: RawInline,
    reserved: [u8; 128],
}

/// Retired physical-store scope: `64..96` team trust-root key.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct RetiredStoreScopeRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    team_public_key: RawInline,
    reserved: [u8; 160],
}

impl WantRecordHeader {
    /// Construct the one physical envelope shared by blob, merge, and derive
    /// requests in the current grow-only WANT set.
    fn new(request: WantRequest) -> Self {
        let bytes = request.to_bytes();
        let mut field_a = [0u8; 32];
        let mut field_b = [0u8; 32];
        let mut field_c = [0u8; 32];
        field_a.copy_from_slice(&bytes[1..33]);
        field_b.copy_from_slice(&bytes[33..65]);
        field_c.copy_from_slice(&bytes[65..97]);
        Self {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_WANT,
            request_kind: bytes[0],
            kind_pad: [0u8; 31],
            field_a,
            field_b,
            field_c,
            reserved: [0u8; 64],
        }
    }

    fn request(&self) -> Result<WantRequest, crate::repo::WantRequestDecodeError> {
        decode_want_request(
            self.request_kind,
            &self.field_a,
            &self.field_b,
            &self.field_c,
        )
    }

    fn retired_request(
        &self,
    ) -> Result<(WantRequest, [u8; WANT_REQUEST_BYTES_LEN]), crate::repo::WantRequestDecodeError>
    {
        decode_retired_want_request(
            self.request_kind,
            &self.field_a,
            &self.field_b,
            &self.field_c,
        )
    }
}

/// Signed collection commit. The tightest record the pile writes: its six
/// 32-byte fields fill `64..256` exactly, so the block has no reserved bytes.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionCommitRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    collection: RawInline,
    data: RawInline,
    metadata: RawInline,
    public_key: RawInline,
    signature_r: RawInline,
    signature_s: RawInline,
}

impl CollectionCommitRecordHeader {
    fn new(record: &CollectionCommit) -> Self {
        let (signature_r, signature_s) = record.signature();
        Self {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_COLLECTION_COMMIT,
            collection: record.collection().raw,
            data: record.data().raw,
            metadata: record.metadata().raw,
            public_key: record.public_key().raw,
            signature_r: signature_r.raw,
            signature_s: signature_s.raw,
        }
    }
}

/// Retired unsigned merge equation, preserved as exact inert evidence.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct LegacyCollectionMergeRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    collection: RawInline,
    low: RawInline,
    high: RawInline,
    result: RawInline,
    reserved: [u8; 64],
}

/// Signed merge equation; the author and signature require a second block.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionMergeRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    collection: RawInline,
    low: RawInline,
    high: RawInline,
    result: RawInline,
    public_key: RawInline,
    signature_r: RawInline,
    signature_s: RawInline,
    reserved: [u8; 224],
}

impl CollectionMergeRecordHeader {
    fn new(record: &CollectionMerge) -> Self {
        let (low, high) = record.inputs();
        let (signature_r, signature_s) = record.signature();
        Self {
            magic: FRAME_MAGIC,
            span_blocks: 2u32.to_le_bytes(),
            record_kind: record_kind::KIND_COLLECTION_MERGE,
            collection: record.collection().raw,
            low: low.raw,
            high: high.raw,
            result: record.result().raw,
            public_key: record.public_key().raw,
            signature_r: signature_r.raw,
            signature_s: signature_s.raw,
            reserved: [0u8; 224],
        }
    }
}

/// Retired unsigned derive equation, preserved as exact inert evidence.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct LegacyCollectionDeriveRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    target: RawInline,
    input: RawInline,
    output: RawInline,
    reserved: [u8; 96],
}

/// Signed derive equation, exactly filling one block.
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
#[repr(C)]
struct CollectionDeriveRecordHeader {
    magic: [u8; FRAME_MAGIC_LEN],
    span_blocks: [u8; 4],
    record_kind: RawInline,
    target: RawInline,
    input: RawInline,
    output: RawInline,
    public_key: RawInline,
    signature_r: RawInline,
    signature_s: RawInline,
}

impl CollectionDeriveRecordHeader {
    fn new(record: &CollectionDerive) -> Self {
        let (input, output) = (record.input(), record.output());
        let (signature_r, signature_s) = record.signature();
        Self {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_COLLECTION_DERIVE,
            target: record.collection().raw,
            input: input.raw,
            output: output.raw,
            public_key: record.public_key().raw,
            signature_r: signature_r.raw,
            signature_s: signature_s.raw,
        }
    }
}

/// Reassemble a canonical [`WantRequest`] from a header's tag and three
/// fields. Shared by both envelope generations: only the field offsets moved.
fn decode_want_request(
    request_kind: u8,
    field_a: &RawInline,
    field_b: &RawInline,
    field_c: &RawInline,
) -> Result<WantRequest, crate::repo::WantRequestDecodeError> {
    let mut bytes = [0u8; WANT_REQUEST_BYTES_LEN];
    bytes[0] = request_kind;
    bytes[1..33].copy_from_slice(field_a);
    bytes[33..65].copy_from_slice(field_b);
    bytes[65..97].copy_from_slice(field_c);
    WantRequest::from_bytes(bytes)
}

/// Decode the retired typed-WANT log, including its short-lived V1 derive
/// shape `(source, target, input)`. The current request no longer repeats the
/// source because the target descriptor names it. Migration retains all three
/// fields in the historical LWW identity, then drops field A only when an
/// active historical key is projected to current `Derive(target, input)`.
fn decode_retired_want_request(
    request_kind: u8,
    field_a: &RawInline,
    field_b: &RawInline,
    field_c: &RawInline,
) -> Result<(WantRequest, [u8; WANT_REQUEST_BYTES_LEN]), crate::repo::WantRequestDecodeError> {
    let mut identity = [0u8; WANT_REQUEST_BYTES_LEN];
    identity[0] = request_kind;
    identity[1..33].copy_from_slice(field_a);
    identity[33..65].copy_from_slice(field_b);
    identity[65..97].copy_from_slice(field_c);
    if request_kind == WANT_REQUEST_KIND_DERIVE_V1 {
        return Ok((
            WantRequest::derive(Inline::new(*field_b), Inline::new(*field_c)),
            identity,
        ));
    }
    decode_want_request(request_kind, field_a, field_b, field_c).map(|request| (request, identity))
}

fn envelope_blocks_for_payload(data_len: usize) -> Option<u32> {
    let payload_blocks = data_len.checked_add(ENVELOPE_BLOCK_LEN - 1)? / ENVELOPE_BLOCK_LEN;
    u32::try_from(payload_blocks)
        .ok()?
        .checked_add(ENVELOPE_HEADER_BLOCKS)
}

fn envelope_blocks_for_prefixed_payload(prefix_len: usize, data_len: usize) -> Option<u32> {
    let record_len = prefix_len.checked_add(data_len)?;
    let blocks = record_len.checked_add(ENVELOPE_BLOCK_LEN - 1)? / ENVELOPE_BLOCK_LEN;
    u32::try_from(blocks).ok()
}

fn prefixed_payload_post_pad(prefix_len: usize, data_len: usize) -> Option<usize> {
    prefix_len.checked_add(data_len).map(block_post_pad)
}

fn collection_record_header(record: &CollectionRecord) -> Vec<u8> {
    match record {
        CollectionRecord::Commit(record) => CollectionCommitRecordHeader::new(record)
            .as_bytes()
            .to_vec(),
        CollectionRecord::Merge(record) => {
            CollectionMergeRecordHeader::new(record).as_bytes().to_vec()
        }
        CollectionRecord::Derive(record) => CollectionDeriveRecordHeader::new(record)
            .as_bytes()
            .to_vec(),
    }
}

// Compile-time guarantee of the fixed record spans (signed MERGE uses two blocks).
const _: () = {
    assert!(std::mem::size_of::<BlobHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<BranchHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<BranchTombstoneHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<WeakPinHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<WeakUnpinHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionDefinitionHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionCommitHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionMergeHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionDeriveHeaderV3>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionCommitHeaderV4>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionMergeHeaderV4>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionDeriveHeaderV4>() == V3_HEADER_LEN);
    assert!(std::mem::size_of::<EnvelopePrefixV1>() == 36);
    assert!(std::mem::size_of::<BlobHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<BranchHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<BranchTombstoneHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<WantHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<TypedWantHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionCommitHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionMergeHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionDeriveHeaderEnvelopeV1>() == ENVELOPE_HEADER_LEN);
    // Current framing is 28 + 4 + 32 == 64. A proof starts at the kind field,
    // sharing it with the frame. Only historical proofs have a nested prefix.
    assert!(std::mem::size_of::<RecordFrame>() == FRAME_BODY_OFFSET);
    assert!(std::mem::size_of::<RetiredCapabilityProofRecordPrefix>() == 96);
    assert!(std::mem::size_of::<BlobRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<PinHeadRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<PinTombstoneRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<RetiredBlobWantRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<WantRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<RetiredPeerEvidenceRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<RetiredStoreScopeRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionCommitRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<LegacyCollectionMergeRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<LegacyCollectionDeriveRecordHeader>() == ENVELOPE_HEADER_LEN);
    assert!(std::mem::size_of::<CollectionMergeRecordHeader>() == 2 * ENVELOPE_BLOCK_LEN);
    assert!(std::mem::size_of::<CollectionDeriveRecordHeader>() == ENVELOPE_HEADER_LEN);
};

/// A single record decoded from a pile file.
///
/// Yielded by [`PileRecords`], the raw record-level view of a pile. The
/// record's header starts at `offset` and the whole record (header + payload +
/// padding) spans `len` bytes, so `offset + len` is the offset of the next
/// record. This is the same decoder the [`Pile`] itself replays on open, so it
/// understands every record format ever written (V1, unenveloped V3/V4, and
/// the generic envelope alike).
#[derive(Debug, Clone, Copy)]
pub struct PileRecord {
    /// Byte offset of the record header within the pile file.
    pub offset: usize,
    /// Total on-disk length of the record (header + payload + padding).
    pub len: usize,
    /// The decoded record content.
    pub content: PileRecordContent,
}

/// Kind of one recognized but semantically inert legacy V3 collection header.
///
/// The raw header bytes remain available through [`PileRecords::bytes`] using
/// the enclosing [`PileRecord`]'s `offset` and `len`. This enum deliberately
/// exposes only the physical kind: V3's 16-byte definition identities and V1
/// commit transcripts must not be mistaken for current descriptor-handle
/// collection authority.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum LegacyCollectionRecordKindV3 {
    /// Legacy standalone collection definition.
    Definition,
    /// Legacy signed commit over a 16-byte definition id.
    Commit,
    /// Legacy merge equation over a 16-byte definition id.
    Merge,
    /// Legacy derive equation between 16-byte definition ids.
    Derive,
}

/// Inert record kind of a record this reader does not interpret.
///
/// The two envelope generations name kinds at different widths, and a decoder
/// that flattened them would be claiming an equivalence the bytes do not have.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub enum OpaqueKind {
    /// A 16-byte kind id from a legacy V1 envelope or a retired fixed-width
    /// unenveloped marker.
    Legacy(RawId),
    /// A 32-byte record kind from the current envelope. It is the handle of a
    /// description archive: a reader that does not know this kind can still
    /// fetch that blob and learn what the record is.
    Described(RawInline),
}

impl AsRef<[u8]> for OpaqueKind {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Legacy(id) => &id[..],
            Self::Described(handle) => &handle[..],
        }
    }
}

impl OpaqueKind {
    /// The kind's bytes, 16 or 32 wide.
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    /// The description handle, when this kind names one.
    pub fn description(&self) -> Option<RecordKind> {
        match self {
            Self::Legacy(_) => None,
            Self::Described(handle) => Some(Inline::new(*handle)),
        }
    }
}

/// Decoded content of a [`PileRecord`], independent of on-disk format version.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum PileRecordContent {
    /// A blob record. The payload bytes live at
    /// `data_offset..data_offset + data_len` in the pile file; trailing
    /// alignment padding after the payload is not content and is not covered
    /// by `hash`.
    Blob {
        /// Insertion timestamp in milliseconds since the Unix epoch.
        timestamp: u64,
        /// Blake3 digest of the payload as recorded in the header.
        hash: Inline<Hash<Blake3>>,
        /// Byte offset of the payload within the pile file.
        data_offset: usize,
        /// Payload length in bytes (excluding padding).
        data_len: usize,
    },
    /// A branch head update.
    Branch {
        /// The branch being updated.
        branch_id: Id,
        /// The new head (a branch-metadata blob handle).
        head: Inline<Handle<SimpleArchive>>,
    },
    /// A branch tombstone (deletion marker).
    BranchTombstone {
        /// The branch being tombstoned.
        branch_id: Id,
    },
    /// One element of the current grow-only local WANT set.
    Want {
        /// The exact canonical request key.
        request: WantRequest,
    },
    /// A retired LWW-log assertion, retained only as raw migration input.
    RetiredWantAssert {
        /// Current projection of the historical request.
        request: WantRequest,
        /// Exact historical key used for LWW resolution before projection.
        identity: [u8; WANT_REQUEST_BYTES_LEN],
    },
    /// A retired LWW-log retraction, retained only as raw migration input.
    RetiredWantRetract {
        /// Current projection of the historical request.
        request: WantRequest,
        /// Exact historical key used for LWW resolution before projection.
        identity: [u8; WANT_REQUEST_BYTES_LEN],
    },
    /// One immutable current collection-algebra record. Three distinct V4
    /// magic markers share this typed raw-inspection surface.
    Collection {
        /// Canonically reconstructed semantic record.
        record: CollectionRecord,
    },
    /// A known unsigned equation, inert to current reads and repair. Its exact
    /// physical bytes and resident dependencies survive conservative rewrites.
    LegacyUnsignedCollectionEquation {
        equation: LegacyUnsignedCollectionEquation,
    },
    /// One canonical complete self-contained prefix-signed capability proof.
    /// Its content id is an exact-body index, not an authority token.
    CapabilityProof {
        /// BLAKE3 identity of the exact canonical proof bytes.
        id: CapabilityProofId,
        /// Byte offset of the proof body within the pile file.
        data_offset: usize,
        /// Exact proof-body length, excluding zero padding.
        data_len: usize,
    },
    /// One structurally valid retired claim- or action-ID-based capability proof.
    ///
    /// Current replay treats it as inert and semantic rewrites drop it. The
    /// dedicated variant lets an old pile remain readable without mistaking
    /// its earlier proof grammar for the current capability-handle grammar.
    RetiredCapabilityProof,
    /// One structurally valid retired PEER routing record.
    ///
    /// Current replay treats it as inert and semantic rewrites drop it. The
    /// dedicated variant keeps the old kind distinguishable from an unknown
    /// record without reconstructing repository state from it.
    RetiredPeerEvidenceV1,
    /// One structurally valid retired STORE_SCOPE assertion.
    ///
    /// Current replay treats it as inert and semantic rewrites drop it. The
    /// dedicated variant keeps the old kind distinguishable from an unknown
    /// record without reconstructing repository state from it.
    RetiredStoreScopeV1,
    /// One structurally valid retired pile-artifact-offer record.
    ///
    /// The kind was retired without reuse. Current replay treats it as inert
    /// and semantic rewrites drop it, exactly like the retired team state, so
    /// a pile that carries them still compacts.
    RetiredArtifactOfferV1,
    /// One recognized legacy V3 collection header.
    ///
    /// Replay treats this as inert physical evidence. It is excluded from
    /// [`CollectionStore`] but retained byte-for-byte by ordinary pile rewrite.
    LegacyCollectionV3 {
        /// The historical physical record kind.
        kind: LegacyCollectionRecordKindV3,
    },
    /// A retired V4 collection derivation.
    ///
    /// V4 redundantly named a source collection that the target descriptor now
    /// determines. It never carried ownership or authoritative application
    /// state, so current replay projects it away and retained rewrites may drop
    /// it. Raw bytes remain available through [`PileRecords`] for forensics.
    RetiredCollectionDeriveV4,
    /// A record whose semantic kind this reader cannot interpret. This covers
    /// structurally valid unknown generic envelopes and the retired local-cell
    /// encodings whose former ownership semantics still require conservative
    /// treatment. Replay deliberately projects it away, while [`PileRecords`]
    /// exposes its exact offset and length so raw migration tooling can
    /// preserve the bytes.
    Opaque {
        /// Inert record kind, in whichever width its framing used.
        kind: OpaqueKind,
    },
}

/// Decodes a current V2 enveloped record: 28-byte magic, 4-byte span, 32-byte
/// record kind, 32-byte-aligned fields from byte 64. A proof includes the kind
/// itself in its canonical bytes, so its value starts at byte 32.
fn decode_enveloped_record(bytes: &[u8], offset: usize) -> Result<PileRecord, ReadError> {
    let corrupt = || ReadError::CorruptPile {
        valid_length: offset,
    };
    let (prefix, _) = RecordFrame::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
    let declared_blocks = u32::from_le_bytes(prefix.span_blocks);
    if prefix.magic != FRAME_MAGIC || declared_blocks == 0 {
        return Err(corrupt());
    }
    let span_blocks = usize::try_from(declared_blocks).map_err(|_| corrupt())?;
    let len = span_blocks
        .checked_mul(ENVELOPE_BLOCK_LEN)
        .ok_or_else(corrupt)?;
    if len < ENVELOPE_HEADER_LEN || bytes.len() < len {
        return Err(corrupt());
    }

    let fixed_header = || {
        if declared_blocks == ENVELOPE_HEADER_BLOCKS {
            Ok(())
        } else {
            Err(corrupt())
        }
    };
    match prefix.record_kind {
        record_kind::KIND_BLOB => {
            let (header, _) =
                BlobRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if nonzero(&[&header.scalar_pad[..], &header.reserved[..]]) {
                return Err(corrupt());
            }
            let data_len =
                usize::try_from(u64::from_le_bytes(header.length)).map_err(|_| corrupt())?;
            let expected_blocks = envelope_blocks_for_payload(data_len).ok_or_else(corrupt)?;
            if declared_blocks != expected_blocks {
                return Err(corrupt());
            }
            let data_offset = offset
                .checked_add(ENVELOPE_HEADER_LEN)
                .ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Blob {
                    timestamp: u64::from_le_bytes(header.timestamp),
                    hash: Inline::new(header.hash),
                    data_offset,
                    data_len,
                },
            })
        }
        record_kind::KIND_PIN_HEAD => {
            fixed_header()?;
            let (header, _) =
                PinHeadRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if nonzero(&[&header.id_pad[..], &header.reserved[..]]) {
                return Err(corrupt());
            }
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Branch {
                    branch_id,
                    head: Inline::<Hash<Blake3>>::new(header.hash).into(),
                },
            })
        }
        record_kind::KIND_PIN_TOMBSTONE => {
            fixed_header()?;
            let (header, _) =
                PinTombstoneRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if nonzero(&[&header.reserved[..]]) {
                return Err(corrupt());
            }
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::BranchTombstone { branch_id },
            })
        }
        record_kind::KIND_WANT => {
            fixed_header()?;
            let (header, _) =
                WantRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if nonzero(&[&header.kind_pad[..], &header.reserved[..]]) {
                return Err(corrupt());
            }
            let request = header.request().map_err(|_| corrupt())?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Want { request },
            })
        }
        record_kind::KIND_BLOB_WANT_ASSERT | record_kind::KIND_BLOB_WANT_RETRACT => {
            fixed_header()?;
            let (header, _) =
                RetiredBlobWantRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if nonzero(&[&header.reserved[..]]) {
                return Err(corrupt());
            }
            let request = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(header.handle));
            let identity = request.to_bytes();
            let content = if prefix.record_kind == record_kind::KIND_BLOB_WANT_ASSERT {
                PileRecordContent::RetiredWantAssert { request, identity }
            } else {
                PileRecordContent::RetiredWantRetract { request, identity }
            };
            Ok(PileRecord {
                offset,
                len,
                content,
            })
        }
        record_kind::KIND_WANT_ASSERT | record_kind::KIND_WANT_RETRACT => {
            fixed_header()?;
            let (header, _) =
                WantRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if nonzero(&[&header.kind_pad[..], &header.reserved[..]]) {
                return Err(corrupt());
            }
            let (request, identity) = header.retired_request().map_err(|_| corrupt())?;
            // Historical typed records never admitted blob requests. Keep that
            // decoder boundary exact even though the current grow-only kind
            // represents all request variants uniformly.
            if matches!(request, WantRequest::Blob { .. }) {
                return Err(corrupt());
            }
            let content = if prefix.record_kind == record_kind::KIND_WANT_ASSERT {
                PileRecordContent::RetiredWantAssert { request, identity }
            } else {
                PileRecordContent::RetiredWantRetract { request, identity }
            };
            Ok(PileRecord {
                offset,
                len,
                content,
            })
        }
        record_kind::KIND_AUTH_PROOF_V1 | record_kind::KIND_AUTH_PROOF_V2 => {
            let (header, _) = RetiredCapabilityProofRecordPrefix::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if nonzero(&[&header.scalar_pad[..]]) {
                return Err(corrupt());
            }
            let data_len =
                usize::try_from(u64::from_le_bytes(header.length)).map_err(|_| corrupt())?;
            let prefix_len = std::mem::size_of::<RetiredCapabilityProofRecordPrefix>();
            let expected_blocks =
                envelope_blocks_for_prefixed_payload(prefix_len, data_len).ok_or_else(corrupt)?;
            if declared_blocks != expected_blocks {
                return Err(corrupt());
            }
            let data_end = prefix_len
                .checked_add(data_len)
                .filter(|end| *end <= len)
                .ok_or_else(corrupt)?;
            if nonzero(&[&bytes[data_end..len]]) {
                return Err(corrupt());
            }
            let body = &bytes[prefix_len..data_end];
            let structural = if prefix.record_kind == record_kind::KIND_AUTH_PROOF_V1 {
                retired_capability_proof_v1_is_structural(body)
            } else {
                crate::capability::legacy_action_proof_is_structural(body)
            };
            if !structural {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::RetiredCapabilityProof,
            })
        }
        record_kind::KIND_AUTH_PROOF => {
            // The kind is the first field of the canonical proof itself.
            let prefix_len = FRAME_KIND_OFFSET;
            let padded = &bytes[prefix_len..len];
            let edges = padded
                .get(CAPABILITY_PROOF_HEADER_LEN..)
                .ok_or_else(corrupt)?;
            // Every edge has a nonzero mode byte, so an all-zero edge can
            // only be padding. Bound traversal before validating the frame.
            let count = edges
                .chunks_exact(CAPABILITY_PROOF_EDGE_LEN)
                .take(MAX_CAPABILITY_PROOF_STEPS + 1)
                .take_while(|edge| edge.iter().any(|byte| *byte != 0))
                .count();
            let data_len = CAPABILITY_PROOF_HEADER_LEN + count * CAPABILITY_PROOF_EDGE_LEN;
            let expected_blocks =
                envelope_blocks_for_prefixed_payload(prefix_len, data_len).ok_or_else(corrupt)?;
            if declared_blocks != expected_blocks || nonzero(&[&padded[data_len..]]) {
                return Err(corrupt());
            }
            let data_end = prefix_len + data_len;
            let proof_bytes = &bytes[prefix_len..data_end];
            CapabilityProof::validate_bytes(proof_bytes).map_err(|_| corrupt())?;
            let data_offset = offset.checked_add(prefix_len).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::CapabilityProof {
                    id: Inline::new(Blake3::digest(proof_bytes)),
                    data_offset,
                    data_len,
                },
            })
        }
        record_kind::KIND_PEER_EVIDENCE => {
            fixed_header()?;
            let (header, _) = RetiredPeerEvidenceRecordHeader::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if nonzero(&[&header.reserved[..]]) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::RetiredPeerEvidenceV1,
            })
        }
        record_kind::KIND_STORE_SCOPE => {
            fixed_header()?;
            let (header, _) = RetiredStoreScopeRecordHeader::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if nonzero(&[&header.reserved[..]]) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::RetiredStoreScopeV1,
            })
        }
        record_kind::KIND_ARTIFACT_OFFER_V1 => {
            // Physical layout only: the body carried an offer nobody reads any
            // more, so replay spends no work interpreting it.
            fixed_header()?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::RetiredArtifactOfferV1,
            })
        }
        record_kind::KIND_COLLECTION_COMMIT => {
            fixed_header()?;
            let (header, _) =
                CollectionCommitRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Collection {
                    record: CollectionRecord::Commit(CollectionCommit::from_parts(
                        Inline::new(header.collection),
                        Inline::new(header.data),
                        Inline::new(header.metadata),
                        Inline::<ED25519PublicKey>::new(header.public_key),
                        Inline::<ED25519RComponent>::new(header.signature_r),
                        Inline::<ED25519SComponent>::new(header.signature_s),
                    )),
                },
            })
        }
        record_kind::KIND_COLLECTION_MERGE => {
            if declared_blocks != 2 {
                return Err(corrupt());
            }
            let (header, _) =
                CollectionMergeRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if nonzero(&[&header.reserved[..]]) || header.high < header.low {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Collection {
                    record: CollectionRecord::Merge(CollectionMerge::from_parts(
                        Inline::new(header.collection),
                        Inline::new(header.low),
                        Inline::new(header.high),
                        Inline::new(header.result),
                        Inline::new(header.public_key),
                        Inline::new(header.signature_r),
                        Inline::new(header.signature_s),
                    )),
                },
            })
        }
        record_kind::KIND_COLLECTION_DERIVE => {
            fixed_header()?;
            let (header, _) =
                CollectionDeriveRecordHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Collection {
                    record: CollectionRecord::Derive(CollectionDerive::from_parts(
                        Inline::new(header.target),
                        Inline::new(header.input),
                        Inline::new(header.output),
                        Inline::new(header.public_key),
                        Inline::new(header.signature_r),
                        Inline::new(header.signature_s),
                    )),
                },
            })
        }
        record_kind::KIND_COLLECTION_MERGE_UNSIGNED => {
            fixed_header()?;
            let (header, _) = LegacyCollectionMergeRecordHeader::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if nonzero(&[&header.reserved[..]]) || header.high < header.low {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::LegacyUnsignedCollectionEquation {
                    equation: LegacyUnsignedCollectionEquation::Merge {
                        collection: Inline::new(header.collection),
                        low: Inline::new(header.low),
                        high: Inline::new(header.high),
                        result: Inline::new(header.result),
                    },
                },
            })
        }
        record_kind::KIND_COLLECTION_DERIVE_UNSIGNED => {
            fixed_header()?;
            let (header, _) = LegacyCollectionDeriveRecordHeader::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if nonzero(&[&header.reserved[..]]) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::LegacyUnsignedCollectionEquation {
                    equation: LegacyUnsignedCollectionEquation::Derive {
                        collection: Inline::new(header.target),
                        input: Inline::new(header.input),
                        output: Inline::new(header.output),
                    },
                },
            })
        }
        kind => Ok(PileRecord {
            offset,
            len,
            content: PileRecordContent::Opaque {
                kind: OpaqueKind::Described(kind),
            },
        }),
    }
}

fn retired_capability_proof_v1_is_structural(bytes: &[u8]) -> bool {
    const ROOT_LEN: usize = 32;
    const EDGE_LEN: usize = 128;
    const DELEGATE_OFFSET: usize = 96;
    const MAX_STEPS: usize = u8::MAX as usize;

    if bytes.len() < ROOT_LEN + EDGE_LEN || (bytes.len() - ROOT_LEN) % EDGE_LEN != 0 {
        return false;
    }
    let steps = (bytes.len() - ROOT_LEN) / EDGE_LEN;
    if steps > MAX_STEPS {
        return false;
    }
    let Ok(root) = <[u8; 32]>::try_from(&bytes[..ROOT_LEN]) else {
        return false;
    };
    if VerifyingKey::from_bytes(&root).is_err() {
        return false;
    }
    bytes[ROOT_LEN..].chunks_exact(EDGE_LEN).all(|edge| {
        let delegate: [u8; 32] = edge[DELEGATE_OFFSET..].try_into().expect("fixed V1 edge");
        VerifyingKey::from_bytes(&delegate).is_ok()
    })
}

/// True when any of the given reserved regions carries a nonzero byte.
///
/// A nonzero reserved byte makes replay fail as corrupt rather than silently
/// assigning meaning to a format extension. The V2 bodies have two such
/// regions where a short scalar is rounded up to the next 32-byte boundary.
fn nonzero(regions: &[&[u8]]) -> bool {
    regions
        .iter()
        .any(|region| region.iter().any(|byte| *byte != 0))
}

/// Decodes a legacy V1 enveloped record: 16-byte marker, 16-byte kind, 4-byte
/// span. Written between 2026-08-11 and 2026-08-20 and read forever after.
fn decode_enveloped_record_v1(bytes: &[u8], offset: usize) -> Result<PileRecord, ReadError> {
    let corrupt = || ReadError::CorruptPile {
        valid_length: offset,
    };
    let (prefix, _) = EnvelopePrefixV1::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
    let declared_blocks = u32::from_le_bytes(prefix.span_blocks);
    if prefix.magic_marker != MAGIC_MARKER_ENVELOPE || declared_blocks == 0 {
        return Err(corrupt());
    }
    let span_blocks = usize::try_from(declared_blocks).map_err(|_| corrupt())?;
    let len = span_blocks
        .checked_mul(ENVELOPE_BLOCK_LEN)
        .ok_or_else(corrupt)?;
    if len < ENVELOPE_HEADER_LEN || bytes.len() < len {
        return Err(corrupt());
    }

    let fixed_header = || {
        if declared_blocks == ENVELOPE_HEADER_BLOCKS {
            Ok(())
        } else {
            Err(corrupt())
        }
    };
    match prefix.record_kind {
        MAGIC_MARKER_BLOB_V3 => {
            let (header, _) =
                BlobHeaderEnvelopeV1::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            let data_len =
                usize::try_from(u64::from_le_bytes(header.length)).map_err(|_| corrupt())?;
            let expected_blocks = envelope_blocks_for_payload(data_len).ok_or_else(corrupt)?;
            if declared_blocks != expected_blocks {
                return Err(corrupt());
            }
            let data_offset = offset
                .checked_add(ENVELOPE_HEADER_LEN)
                .ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Blob {
                    timestamp: u64::from_le_bytes(header.timestamp),
                    hash: Inline::new(header.hash),
                    data_offset,
                    data_len,
                },
            })
        }
        MAGIC_MARKER_BRANCH_V3 => {
            fixed_header()?;
            let (header, _) =
                BranchHeaderEnvelopeV1::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Branch {
                    branch_id,
                    head: Inline::<Hash<Blake3>>::new(header.hash).into(),
                },
            })
        }
        MAGIC_MARKER_BRANCH_TOMBSTONE_V3 => {
            fixed_header()?;
            let (header, _) = BranchTombstoneHeaderEnvelopeV1::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::BranchTombstone { branch_id },
            })
        }
        MAGIC_MARKER_WEAK_PIN_V3 | MAGIC_MARKER_WEAK_UNPIN_V3 => {
            fixed_header()?;
            let (header, _) =
                WantHeaderEnvelopeV1::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            let request = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(header.handle));
            let identity = request.to_bytes();
            let content = if prefix.record_kind == MAGIC_MARKER_WEAK_PIN_V3 {
                PileRecordContent::RetiredWantAssert { request, identity }
            } else {
                PileRecordContent::RetiredWantRetract { request, identity }
            };
            Ok(PileRecord {
                offset,
                len,
                content,
            })
        }
        MAGIC_MARKER_WANT_ASSERT_V2 | MAGIC_MARKER_WANT_RETRACT_V2 => {
            fixed_header()?;
            let (header, _) =
                TypedWantHeaderEnvelopeV1::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            let (request, identity) = header.request().map_err(|_| corrupt())?;
            // Historical typed records never admitted blob requests.
            if matches!(request, WantRequest::Blob { .. }) {
                return Err(corrupt());
            }
            let content = if prefix.record_kind == MAGIC_MARKER_WANT_ASSERT_V2 {
                PileRecordContent::RetiredWantAssert { request, identity }
            } else {
                PileRecordContent::RetiredWantRetract { request, identity }
            };
            Ok(PileRecord {
                offset,
                len,
                content,
            })
        }
        MAGIC_MARKER_COLLECTION_COMMIT_V4 => {
            fixed_header()?;
            let (header, _) = CollectionCommitHeaderEnvelopeV1::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Collection {
                    record: CollectionRecord::Commit(CollectionCommit::from_parts(
                        Inline::new(header.collection),
                        Inline::new(header.data),
                        Inline::new(header.metadata),
                        Inline::<ED25519PublicKey>::new(header.public_key),
                        Inline::<ED25519RComponent>::new(header.signature_r),
                        Inline::<ED25519SComponent>::new(header.signature_s),
                    )),
                },
            })
        }
        MAGIC_MARKER_COLLECTION_MERGE_V4 => {
            fixed_header()?;
            let (header, _) = CollectionMergeHeaderEnvelopeV1::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) || header.high < header.low {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::LegacyUnsignedCollectionEquation {
                    equation: LegacyUnsignedCollectionEquation::Merge {
                        collection: Inline::new(header.collection),
                        low: Inline::new(header.low),
                        high: Inline::new(header.high),
                        result: Inline::new(header.result),
                    },
                },
            })
        }
        MAGIC_MARKER_COLLECTION_DERIVE_V4 => {
            fixed_header()?;
            let (header, _) = CollectionDeriveHeaderEnvelopeV1V4::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::RetiredCollectionDeriveV4,
            })
        }
        MAGIC_MARKER_COLLECTION_DERIVE_V5 => {
            fixed_header()?;
            let (header, _) = CollectionDeriveHeaderEnvelopeV1::try_read_from_prefix(bytes)
                .map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::LegacyUnsignedCollectionEquation {
                    equation: LegacyUnsignedCollectionEquation::Derive {
                        collection: Inline::new(header.target),
                        input: Inline::new(header.input),
                        output: Inline::new(header.output),
                    },
                },
            })
        }
        kind @ (MAGIC_MARKER_LOCAL_CELL_V3 | MAGIC_MARKER_LOCAL_CELL_TOMBSTONE_V3) => {
            fixed_header()?;
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Opaque {
                    kind: OpaqueKind::Legacy(kind),
                },
            })
        }
        kind => Ok(PileRecord {
            offset,
            len,
            content: PileRecordContent::Opaque {
                kind: OpaqueKind::Legacy(kind),
            },
        }),
    }
}

/// Decodes the record starting at the beginning of `bytes`, which is the pile
/// file's content from `offset` onward. This is the single source of truth for
/// record parsing: [`Pile::refresh`]/[`Pile::amputate`] replay records through
/// it, and [`PileRecords`] exposes it for raw inspection.
///
/// An unknown **kind** and an unknown **frame** are different questions with
/// different answers, and conflating them would cost one of the two.
///
/// * An unknown *kind* inside a valid frame is forward compatibility. The
///   frame states the span, so the record has an exact boundary: it yields
///   [`PileRecordContent::Opaque`] and replay crosses it. Its 32-byte kind is
///   a handle, so a reader can go and resolve what it was.
/// * An unknown *frame* is **corruption**. Nothing about the bytes is
///   trustworthy, not even where the next record starts, so this fails at
///   exactly that offset rather than guessing. That is the detection the wide
///   magic buys, and it must stay sharp: never soften it into a skip or a
///   warning. A torn or truncated tail yields
///   [`ReadError::CorruptPile { valid_length: offset }`](ReadError::CorruptPile),
///   which is what [`Pile::amputate`] repairs; bytes that name a legacy marker
///   this reader no longer decodes yield
///   [`ReadError::UnsupportedRecord`], which it deliberately refuses to
///   truncate.
fn decode_record(bytes: &[u8], offset: usize) -> Result<PileRecord, ReadError> {
    let corrupt = || ReadError::CorruptPile {
        valid_length: offset,
    };
    if bytes.len() < FRAME_MAGIC_LEN {
        // Too few bytes to name the current framing. A proper prefix of the
        // current magic is a torn append, not an unknown format — saying
        // `UnsupportedRecord` here would make `amputate` refuse to repair a
        // crash it is exactly meant to repair.
        if bytes.len() < 16 || FRAME_MAGIC.starts_with(bytes) {
            return Err(corrupt());
        }
    } else if bytes[0..FRAME_MAGIC_LEN] == FRAME_MAGIC {
        return decode_enveloped_record(bytes, offset);
    }
    let magic: RawId = bytes[0..16].try_into().unwrap();
    if magic == MAGIC_MARKER_ENVELOPE {
        return decode_enveloped_record_v1(bytes, offset);
    }
    match magic {
        MAGIC_MARKER_BLOB => {
            let (header, _) = BlobHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let data_len = header.length as usize;
            let pad = padding_for_blob(data_len);
            let len = BLOB_HEADER_LEN
                .checked_add(data_len)
                .and_then(|l| l.checked_add(pad))
                .ok_or_else(corrupt)?;
            if bytes.len() < len {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Blob {
                    timestamp: header.timestamp,
                    hash: Inline::new(header.hash),
                    data_offset: offset + BLOB_HEADER_LEN,
                    data_len,
                },
            })
        }
        MAGIC_MARKER_BRANCH => {
            let (header, _) = BranchHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: std::mem::size_of::<BranchHeader>(),
                content: PileRecordContent::Branch {
                    branch_id,
                    head: Inline::<Hash<Blake3>>::new(header.hash).into(),
                },
            })
        }
        MAGIC_MARKER_BRANCH_TOMBSTONE => {
            let (header, _) =
                BranchTombstoneHeader::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: std::mem::size_of::<BranchTombstoneHeader>(),
                content: PileRecordContent::BranchTombstone { branch_id },
            })
        }
        MAGIC_MARKER_BLOB_V3 => {
            // Fixed 256-byte header; data at a constant `record_start +
            // V3_HEADER_LEN` (no offset-derived pad — position-independent),
            // record padded to a 256-byte multiple.
            let (header, _) = BlobHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let data_len = header.length as usize;
            let post_pad = block_post_pad(data_len);
            let len = V3_HEADER_LEN
                .checked_add(data_len)
                .and_then(|l| l.checked_add(post_pad))
                .ok_or_else(corrupt)?;
            if bytes.len() < len {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len,
                content: PileRecordContent::Blob {
                    timestamp: header.timestamp,
                    hash: Inline::new(header.hash),
                    data_offset: offset + V3_HEADER_LEN,
                    data_len,
                },
            })
        }
        MAGIC_MARKER_BRANCH_V3 => {
            let (header, _) = BranchHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::Branch {
                    branch_id,
                    head: Inline::<Hash<Blake3>>::new(header.hash).into(),
                },
            })
        }
        MAGIC_MARKER_BRANCH_TOMBSTONE_V3 => {
            let (header, _) =
                BranchTombstoneHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let branch_id = Id::new(header.branch_id).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::BranchTombstone { branch_id },
            })
        }
        MAGIC_MARKER_LOCAL_CELL_V3 | MAGIC_MARKER_LOCAL_CELL_TOMBSTONE_V3 => {
            if bytes.len() < V3_HEADER_LEN {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::Opaque {
                    kind: OpaqueKind::Legacy(magic),
                },
            })
        }
        MAGIC_MARKER_WEAK_PIN_V3 => {
            let (header, _) =
                WeakPinHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let request = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(header.handle));
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::RetiredWantAssert {
                    request,
                    identity: request.to_bytes(),
                },
            })
        }
        MAGIC_MARKER_WEAK_UNPIN_V3 => {
            let (header, _) =
                WeakUnpinHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            let request = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(header.handle));
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::RetiredWantRetract {
                    request,
                    identity: request.to_bytes(),
                },
            })
        }
        MAGIC_MARKER_COLLECTION_DEFINITION_V3 => {
            let (header, _) =
                CollectionDefinitionHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Id::new(header.scope).ok_or_else(corrupt)?;
            Id::new(header.representation).ok_or_else(corrupt)?;
            Id::new(header.recipe).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::LegacyCollectionV3 {
                    kind: LegacyCollectionRecordKindV3::Definition,
                },
            })
        }
        MAGIC_MARKER_COLLECTION_COMMIT_V3 => {
            let (header, _) =
                CollectionCommitHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Id::new(header.collection).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::LegacyCollectionV3 {
                    kind: LegacyCollectionRecordKindV3::Commit,
                },
            })
        }
        MAGIC_MARKER_COLLECTION_MERGE_V3 => {
            let (header, _) =
                CollectionMergeHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) || header.high < header.low {
                return Err(corrupt());
            }
            Id::new(header.collection).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::LegacyCollectionV3 {
                    kind: LegacyCollectionRecordKindV3::Merge,
                },
            })
        }
        MAGIC_MARKER_COLLECTION_DERIVE_V3 => {
            let (header, _) =
                CollectionDeriveHeaderV3::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Id::new(header.source).ok_or_else(corrupt)?;
            Id::new(header.target).ok_or_else(corrupt)?;
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::LegacyCollectionV3 {
                    kind: LegacyCollectionRecordKindV3::Derive,
                },
            })
        }
        MAGIC_MARKER_COLLECTION_COMMIT_V4 => {
            let (header, _) =
                CollectionCommitHeaderV4::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::Collection {
                    record: CollectionRecord::Commit(CollectionCommit::from_parts(
                        Inline::new(header.collection),
                        Inline::new(header.data),
                        Inline::new(header.metadata),
                        Inline::<ED25519PublicKey>::new(header.public_key),
                        Inline::<ED25519RComponent>::new(header.signature_r),
                        Inline::<ED25519SComponent>::new(header.signature_s),
                    )),
                },
            })
        }
        MAGIC_MARKER_COLLECTION_MERGE_V4 => {
            let (header, _) =
                CollectionMergeHeaderV4::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) || header.high < header.low {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::LegacyUnsignedCollectionEquation {
                    equation: LegacyUnsignedCollectionEquation::Merge {
                        collection: Inline::new(header.collection),
                        low: Inline::new(header.low),
                        high: Inline::new(header.high),
                        result: Inline::new(header.result),
                    },
                },
            })
        }
        MAGIC_MARKER_COLLECTION_DERIVE_V4 => {
            let (header, _) =
                CollectionDeriveHeaderV4::try_read_from_prefix(bytes).map_err(|_| corrupt())?;
            if header.reserved.iter().any(|byte| *byte != 0) {
                return Err(corrupt());
            }
            Ok(PileRecord {
                offset,
                len: V3_HEADER_LEN,
                content: PileRecordContent::RetiredCollectionDeriveV4,
            })
        }
        _ => Err(ReadError::UnsupportedRecord {
            offset,
            marker: magic,
        }),
    }
}

/// Header metadata recovered from the immutable record named by one in-memory
/// blob index entry.
struct IndexedBlobHeader {
    timestamp: u64,
    data_offset: usize,
    data_len: usize,
}

/// Resolves an offset-only index entry through the canonical record decoder
/// without touching or hashing its payload.
fn indexed_blob_header(
    mmap: &Arc<MmapRaw>,
    covered_len: usize,
    entry: IndexEntry,
    expected: &Inline<Hash<Blake3>>,
) -> IndexedBlobHeader {
    assert!(
        entry.record_offset < covered_len,
        "blob index offset lies outside its accepted pile prefix"
    );
    assert!(
        covered_len <= mmap.len(),
        "accepted pile prefix lies outside its mapping"
    );
    let record_bytes = unsafe {
        slice_from_raw_parts(
            mmap.as_ptr().add(entry.record_offset),
            covered_len - entry.record_offset,
        )
        .as_ref()
        .unwrap()
    };
    let record = decode_record(record_bytes, entry.record_offset)
        .expect("indexed blob record changed below the accepted pile prefix");
    let PileRecordContent::Blob {
        timestamp,
        hash,
        data_offset,
        data_len,
    } = record.content
    else {
        panic!("blob index offset no longer names a blob record");
    };
    assert_eq!(
        hash, *expected,
        "blob index key no longer matches its record header"
    );
    IndexedBlobHeader {
        timestamp,
        data_offset,
        data_len,
    }
}

/// Payload and metadata recovered from the immutable record named by one
/// in-memory blob index entry.
struct IndexedBlobRecord {
    bytes: Bytes,
    #[cfg(test)]
    payload_offset: usize,
    timestamp: u64,
}

/// Resolves an offset-only index entry through the canonical record decoder.
///
/// Entries are created only after `decode_record` accepted the complete record,
/// and `covered_len` is the exact accepted prefix captured with this mapping.
/// A failure here therefore means bytes below an applied boundary changed,
/// which violates Pile's append-only safety contract.
fn indexed_blob_record(
    mmap: &Arc<MmapRaw>,
    covered_len: usize,
    entry: IndexEntry,
    expected: &Inline<Hash<Blake3>>,
) -> IndexedBlobRecord {
    let header = indexed_blob_header(mmap, covered_len, entry, expected);
    let bytes = unsafe {
        let slice = slice_from_raw_parts(mmap.as_ptr().add(header.data_offset), header.data_len)
            .as_ref()
            .unwrap();
        Bytes::from_raw_parts(slice, mmap.clone())
    };
    IndexedBlobRecord {
        bytes,
        #[cfg(test)]
        payload_offset: header.data_offset,
        timestamp: header.timestamp,
    }
}

/// Iterator over the raw records of a pile file, in log order.
///
/// This is the record-level view of the append-only log: every blob, complete
/// proof, branch update, branch tombstone, and WANT marker ever
/// appended, including records that later ones supersede (superseded branch
/// heads, tombstoned branches, and retired WANT log entries). It shares its decoder with the [`Pile`]
/// replay path, so V1, unenveloped V3/V4, and generic-envelope records are
/// understood; tools that need
/// history or forensics (reflogs, consolidation, corruption reports) should
/// consume this instead of hand-rolling a parser.
///
/// Unknown envelope kinds are yielded as [`PileRecordContent::Opaque`] with a
/// known boundary. The iterator yields an error and ends for an unknown
/// unenveloped marker or a truncated record: the former surfaces as
/// [`ReadError::UnsupportedRecord`] and the latter as
/// [`ReadError::CorruptPile`].
#[derive(Debug)]
pub struct PileRecords {
    bytes: Bytes,
    offset: usize,
    failed: bool,
}

impl PileRecords {
    /// Opens the pile file at `path` read-only and returns an iterator over
    /// its records. No index is built and nothing is validated eagerly; blob
    /// payloads are not hashed.
    pub fn open(path: &Path) -> Result<Self, ReadError> {
        let file = File::open(path)?;
        let length = file.metadata()?.len();
        let bytes = if length == 0 {
            // Mapping a zero-length file is an error on most platforms; an
            // empty pile simply has no records.
            Bytes::empty()
        } else {
            // SAFETY: the pile file is append-only by contract; existing
            // bytes are never mutated, so the mapping stays valid.
            unsafe { Bytes::map_file(&file)? }
        };
        Ok(Self {
            bytes,
            offset: 0,
            failed: false,
        })
    }

    /// The raw bytes of the pile file, e.g. to inspect a blob payload at the
    /// `data_offset`/`data_len` reported by [`PileRecordContent::Blob`].
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

impl Iterator for PileRecords {
    type Item = Result<PileRecord, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset >= self.bytes.len() {
            return None;
        }
        match decode_record(&self.bytes[self.offset..], self.offset) {
            Ok(record) => {
                self.offset += record.len;
                Some(Ok(record))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }
}

#[derive(Debug)]
enum Applied {
    Blob {
        hash: Inline<Hash<Blake3>>,
    },
    Branch {
        id: Id,
        hash: Inline<Hash<Blake3>>,
    },
    BranchTombstone {
        id: Id,
    },
    Want {
        request: WantRequest,
    },
    RetiredWantState,
    Collection {
        fingerprint: CollectionRecordFingerprint,
    },
    CapabilityProof {
        id: CapabilityProofId,
    },
    RetiredCapabilityProof,
    RetiredTeamState,
    RetiredArtifactOffer,
    LegacyCollectionEvidence,
    RetiredCollectionDeriveV4,
    Opaque,
}

#[derive(Debug)]
/// A grow-only collection of blobs, collection records, complete proofs,
/// wants, and pin heads backed by a single file on disk.
///
/// Branch updates do not verify that referenced blobs exist in the pile, allowing the
/// pile to operate as a head-only store when blob data lives elsewhere.
///
/// [`Pile::refresh`] aborts immediately if the underlying file shrinks below
/// data that has already been applied, preventing undefined behavior from
/// dangling [`Bytes`] handles.
pub struct Pile {
    file: File,
    mmap: Arc<MmapRaw>,
    /// Whether this handle has appended or truncated bytes since its last
    /// successful durability barrier. Refreshing bytes written by another
    /// handle does not make this handle responsible for flushing them.
    dirty: bool,
    /// Every physical blob occurrence keyed by `hash || offset_be`.
    ///
    /// Prefix projection at the 32-byte segment boundary is the semantic blob
    /// set, so duplicate offsets never need a second index. Each existing leaf
    /// carries its own lazy validation byte inline.
    blobs: PileBlobIndex,
    branches: PATCH<16, IdentitySchema, Inline<Handle<SimpleArchive>>>,
    /// Immutable collection records keyed by full-width canonical-byte fingerprint.
    collection_records: CollectionRecordIndex,
    /// Derived selector index keyed by `collection_handle || record_fingerprint`.
    collection_records_by_collection: CollectionRecordCollectionIndex,
    /// Complete canonical proofs keyed by the BLAKE3 identity of exact bytes.
    /// Each value owns its validated mmap-backed view, shared by snapshots and readers.
    capability_proofs: CapabilityProofIndex,
    /// Exact byte-distinct legacy V3 and unsigned collection headers accepted during replay.
    /// They remain inert but are conservatively carried through retained
    /// rewrites so an explicit future migration still has its source evidence.
    legacy_collection_headers: LegacyCollectionHeaderIndex,
    /// Number of structurally valid records whose semantics this reader cannot
    /// safely interpret. This includes unknown generic-envelope kinds and
    /// retired local-cell encodings with former ownership semantics. Known
    /// retired V4 derives are not opaque because they carried no ownership or
    /// authoritative state. Yard reclamation refuses while this is nonzero; a
    /// retained rewrite carries the frames exactly instead (`opaque_frames`).
    opaque_records: usize,
    /// Byte ranges `(offset, len)` of every opaque frame in the applied prefix,
    /// in file order. A retained rewrite copies them by their own length,
    /// because it keeps every resident blob and so cannot orphan whatever an
    /// unknown kind names; a later binary that knows the kind reads them from
    /// the rewritten pile exactly as it would have from the source.
    opaque_frames: Vec<(usize, usize)>,
    /// Current grow-only typed request set. Retired weak-pin and typed LWW-log
    /// records are deliberately absent: they are raw input to the explicit
    /// WANT cutover migration, not live state that stale pile concatenation can
    /// resurrect or retract.
    wants: PATCH<WANT_REQUEST_BYTES_LEN, IdentitySchema>,
    /// Length of the file that has been validated and applied.
    ///
    /// Offsets below this value are guaranteed valid; corruption detection
    /// only operates on the un-applied tail beyond this boundary.
    applied_length: usize,
}

fn padding_for_blob(blob_size: usize) -> usize {
    (BLOB_ALIGNMENT - ((BLOB_HEADER_LEN + blob_size) % BLOB_ALIGNMENT)) % BLOB_ALIGNMENT
}

#[derive(Debug, Clone)]
/// One immutable, coherent observation of a [`Pile`].
///
/// Blob bytes, collection records, and capability proofs all come from the
/// same validated pile prefix. Persistent PATCH roots make both
/// cloning and [`StoreSnapshot::changes_since`](super::StoreSnapshot::changes_since)
/// constant-time in the number of semantic components.
pub struct PileSnapshot {
    instant: hifitime::Epoch,
    mmap: Arc<MmapRaw>,
    covered_len: usize,
    opaque_records: usize,
    /// Physical occurrences keyed by `hash || offset_be`.
    ///
    /// Projecting this relation at its 32-byte segment boundary is the
    /// semantic resident-blob set. Each leaf also carries its own lazy
    /// validation state inline and is shared across immutable snapshots.
    blobs: PileBlobIndex,
    collection_records: CollectionRecordIndex,
    collection_records_by_collection: CollectionRecordCollectionIndex,
    legacy_collection_headers: LegacyCollectionHeaderIndex,
    capability_proofs: CapabilityProofIndex,
    wants: PATCH<WANT_REQUEST_BYTES_LEN, IdentitySchema>,
}

/// Census of retired LWW WANT input relative to the current monotone set.
///
/// This is migration accounting, not repository state. Current replay never
/// consults the retired log; callers must explicitly run the cutover before
/// serving a pile written by a pre-cutover binary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WantCutoverStatus {
    /// Number of retired assertion/retraction frames scanned.
    pub retired_records: usize,
    /// Number of requests active after resolving that retired log in file
    /// order.
    pub resolved_active: usize,
    /// Resolved requests already present under the current monotone marker.
    pub already_current: usize,
    /// Current markers still needed to preserve the retired projection.
    pub missing_current: usize,
}

impl PileSnapshot {
    fn new(
        instant: hifitime::Epoch,
        mmap: Arc<MmapRaw>,
        covered_len: usize,
        opaque_records: usize,
        blobs: PileBlobIndex,
        collection_records: CollectionRecordIndex,
        collection_records_by_collection: CollectionRecordCollectionIndex,
        legacy_collection_headers: LegacyCollectionHeaderIndex,
        capability_proofs: CapabilityProofIndex,
        wants: PATCH<WANT_REQUEST_BYTES_LEN, IdentitySchema>,
    ) -> Self {
        Self {
            instant,
            mmap,
            covered_len,
            opaque_records,
            blobs,
            collection_records,
            collection_records_by_collection,
            legacy_collection_headers,
            capability_proofs,
            wants,
        }
    }

    /// Returns an iterator over all blobs currently stored in the pile.
    ///
    /// The persistent occurrence trie is cloned in constant time. Its
    /// consuming prefix iterator then stops at the hash segment, so listing
    /// neither visits duplicate suffixes nor allocates a handle inventory.
    pub fn iter(&self) -> PileBlobStoreIter {
        PileBlobStoreIter {
            snapshot: self.clone(),
            inner: self.blobs.clone().into_prefixes(),
        }
    }

    /// Number of unknown generic-envelope records in this exact observation.
    pub(crate) const fn opaque_record_count(&self) -> usize {
        self.opaque_records
    }

    /// Exact historical unsigned equations for an explicit endorsement migration.
    /// They are absent from `CollectionRead` and never participate in repair.
    pub fn legacy_unsigned_collection_equations(
        &self,
    ) -> impl Iterator<Item = LegacyUnsignedCollectionEquation> + '_ {
        self.legacy_collection_headers
            .iter_ordered()
            .filter_map(|header| {
                match decode_record(header, 0)
                    .expect("indexed legacy headers were structurally validated")
                    .content
                {
                    PileRecordContent::LegacyUnsignedCollectionEquation { equation } => {
                        Some(equation)
                    }
                    _ => None,
                }
            })
    }

    /// Direct references and resident description roots of retained unsigned evidence.
    pub(crate) fn legacy_unsigned_collection_references(
        &self,
    ) -> impl Iterator<Item = Inline<Handle<UnknownBlob>>> + '_ {
        self.legacy_unsigned_collection_equations()
            .flat_map(|equation| {
                let kind = match equation {
                    LegacyUnsignedCollectionEquation::Merge { .. } => {
                        record_kind::KIND_COLLECTION_MERGE_UNSIGNED
                    }
                    LegacyUnsignedCollectionEquation::Derive { .. } => {
                        record_kind::KIND_COLLECTION_DERIVE_UNSIGNED
                    }
                };
                equation
                    .blob_references()
                    .chain(std::iter::once(Inline::new(kind)))
            })
    }

    /// Returns unvalidated listing metadata for a resident blob.
    ///
    /// This reads only the already-accepted pile record header. Callers that
    /// consume the payload must still use [`BlobStoreGet::get`].
    pub(crate) fn unvalidated_blob_info(
        &self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> Option<super::BlobInfo> {
        let hash: &Inline<Hash<Blake3>> = handle.as_transmute();
        let entry = first_blob_occurrence(&self.blobs, &hash.raw)?;
        let header = indexed_blob_header(&self.mmap, self.covered_len, entry, hash);
        Some(super::BlobInfo {
            handle,
            length: header.data_len as u64,
        })
    }

    /// Resolve one handle to any physical occurrence whose payload validates.
    ///
    /// Physical occurrences are tried in ascending file-offset order.
    /// Validation results live in the shared occurrence leaf, so a corrupt
    /// candidate is hashed at most once after the first result is published.
    fn validated_blob_record<E: Error>(
        &self,
        hash: &Inline<Hash<Blake3>>,
        strategy: ValidationStrategy,
    ) -> Result<IndexedBlobRecord, GetBlobError<E>> {
        let Some(mut candidate) = first_blob_occurrence(&self.blobs, &hash.raw) else {
            return Err(GetBlobError::BlobNotFound(super::MissingBlob {
                handle: Inline::new(hash.raw),
            }));
        };

        let mut first_invalid = None;
        let mut validate = |entry: IndexEntry| {
            let record = indexed_blob_record(&self.mmap, self.covered_len, entry, hash);
            let validation = blob_occurrence_validation(&self.blobs, &hash.raw, entry);
            match validation.state(&record.bytes, hash, strategy) {
                ValidationState::Validated => Some(record),
                ValidationState::Invalid => {
                    first_invalid.get_or_insert_with(|| record.bytes.clone());
                    None
                }
            }
        };

        loop {
            if let Some(record) = validate(candidate) {
                return Ok(record);
            }
            let Some(next) = next_blob_occurrence(&self.blobs, &hash.raw, candidate) else {
                break;
            };
            candidate = next;
        }
        Err(GetBlobError::ValidationError(first_invalid.expect(
            "a present primary candidate was validated and rejected",
        )))
    }

    // metadata moved into BlobStoreMeta impl below
}

impl BlobStoreGet for PileSnapshot {
    type GetError<E: Error + Send + Sync + 'static> = GetBlobError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let hash: &Inline<Hash<Blake3>> = handle.as_transmute();
        let record = self.validated_blob_record(hash, ValidationStrategy::ParallelIfLarge)?;
        // The handle is what we just validated against — reuse it to skip
        // Blake3 recomputation in Blob::new.
        let blob: Blob<S> = Blob::with_handle(record.bytes, handle);
        match blob.try_from_blob() {
            Ok(value) => Ok(value),
            Err(e) => Err(GetBlobError::ConversionError(e)),
        }
    }
}

impl super::BlobChildren for PileSnapshot {}

impl super::StoreSnapshot for PileSnapshot {
    fn instant(&self) -> hifitime::Epoch {
        self.instant
    }

    fn changes_since(&self, previous: &Self) -> super::StoreChanges {
        let mut changes = super::StoreChanges::NONE;
        // A semantic addition and another physical fallback occurrence are
        // both observable blob-store changes, even though only the former
        // appears in `blobs_diff`.
        if !previous.blobs.shares_root(&self.blobs) {
            changes = changes.union(super::StoreChanges::BLOBS);
        }
        if previous.collection_records != self.collection_records {
            changes = changes.union(super::StoreChanges::COLLECTION_RECORDS);
        }
        if previous.capability_proofs != self.capability_proofs {
            changes = changes.union(super::StoreChanges::CAPABILITY_PROOFS);
        }
        if previous.wants != self.wants {
            changes = changes.union(super::StoreChanges::WANTS);
        }
        changes
    }
}

impl super::SnapshotSource for Pile {
    type Snapshot = PileSnapshot;
    type SnapshotError = ReadError;

    fn snapshot_at(
        &mut self,
        instant: hifitime::Epoch,
    ) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.refresh()?;
        Ok(PileSnapshot::new(
            instant,
            self.mmap.clone(),
            self.applied_length,
            self.opaque_records,
            self.blobs.clone(),
            self.collection_records.clone(),
            self.collection_records_by_collection.clone(),
            self.legacy_collection_headers.clone(),
            self.capability_proofs.clone(),
            self.wants.clone(),
        ))
    }
}

/// Error returned when opening or refreshing a [`Pile`].
#[derive(Debug)]
pub enum ReadError {
    /// Underlying I/O failure.
    IoError(std::io::Error),
    /// The pile contains corrupted data starting at `valid_length`.
    CorruptPile {
        /// Byte offset where the first malformed or truncated known record was
        /// found.
        valid_length: usize,
    },
    /// The pile contains a complete unenveloped magic marker this reader does
    /// not know.
    ///
    /// The marker may name a record introduced by a newer binary. Its length
    /// is unknowable to this reader, so it is unsafe to skip or amputate it.
    UnsupportedRecord {
        /// Byte offset where the unsupported record begins.
        offset: usize,
        /// Unrecognized 16-byte record marker.
        marker: RawId,
    },
    /// The pile file exceeds the addressable range.
    FileTooLarge {
        /// Actual file length.
        length: usize,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::IoError(err) => write!(f, "IO error: {err}"),
            ReadError::CorruptPile { valid_length } => {
                write!(f, "Corrupt pile at byte {valid_length}")
            }
            ReadError::UnsupportedRecord { offset, marker } => write!(
                f,
                "Unsupported pile record marker {} at byte {offset}; a newer reader may be required",
                hex::encode_upper(marker)
            ),
            ReadError::FileTooLarge { length } => {
                write!(f, "Pile of length {length} exceeds supported size")
            }
        }
    }
}
impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(err) => Some(err),
            Self::CorruptPile { .. }
            | Self::UnsupportedRecord { .. }
            | Self::FileTooLarge { .. } => None,
        }
    }
}

impl From<std::io::Error> for ReadError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<ReadError> for std::io::Error {
    fn from(err: ReadError) -> Self {
        match err {
            ReadError::IoError(e) => e,
            ReadError::CorruptPile { valid_length } => {
                std::io::Error::other(format!("corrupt pile at byte {valid_length}"))
            }
            ReadError::UnsupportedRecord { offset, marker } => std::io::Error::other(format!(
                "unsupported pile record marker {} at byte {offset}; a newer reader may be required",
                hex::encode_upper(marker)
            )),
            ReadError::FileTooLarge { length } => {
                std::io::Error::other(format!("pile length {length} exceeds supported size"))
            }
        }
    }
}

/// Error returned when appending a blob to a [`Pile`].
#[derive(Debug)]
pub enum InsertError {
    /// Underlying I/O failure.
    IoError(std::io::Error),
    /// System clock error when timestamping the record.
    TimeError(std::time::SystemTimeError),
}

impl std::fmt::Display for InsertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InsertError::IoError(err) => write!(f, "IO error: {err}"),
            InsertError::TimeError(err) => write!(f, "system time error: {err}"),
        }
    }
}
impl std::error::Error for InsertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(err) => Some(err),
            Self::TimeError(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for InsertError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<std::time::SystemTimeError> for InsertError {
    fn from(err: std::time::SystemTimeError) -> Self {
        Self::TimeError(err)
    }
}

impl From<ReadError> for InsertError {
    fn from(err: ReadError) -> Self {
        Self::IoError(err.into())
    }
}

/// Error returned when appending a pin-head update or want marker to a
/// [`Pile`].
pub enum PileWriteError {
    /// Underlying I/O failure.
    IoError(std::io::Error),
}

impl std::error::Error for PileWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(err) => Some(err),
        }
    }
}

impl std::fmt::Debug for PileWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PileWriteError::IoError(err) => write!(f, "IO error: {err}"),
        }
    }
}

impl std::fmt::Display for PileWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PileWriteError::IoError(err) => write!(f, "IO error: {err}"),
        }
    }
}

impl From<std::io::Error> for PileWriteError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<ReadError> for PileWriteError {
    fn from(err: ReadError) -> Self {
        Self::IoError(err.into())
    }
}

/// Failure while appending an immutable native collection record.
#[derive(Debug)]
pub enum CollectionInsertError {
    /// Existing pile state could not be refreshed or decoded.
    Read(ReadError),
    /// The fixed record could not be appended or the file lock released.
    Io(std::io::Error),
    /// A full-width fingerprint already names different canonical fields.
    FingerprintCollision {
        fingerprint: CollectionRecordFingerprint,
    },
    /// Readback observed a record other than the exclusively appended one.
    UnexpectedReadback,
}

impl std::fmt::Display for CollectionInsertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(f, "failed to refresh collection records: {error}"),
            Self::Io(error) => write!(f, "failed to append collection record: {error}"),
            Self::FingerprintCollision { fingerprint } => {
                write!(
                    f,
                    "collection record fingerprint {fingerprint:X} names different fields"
                )
            }
            Self::UnexpectedReadback => {
                f.write_str("collection append read back an unexpected pile record")
            }
        }
    }
}

impl Error for CollectionInsertError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::FingerprintCollision { .. } | Self::UnexpectedReadback => None,
        }
    }
}

impl From<ReadError> for CollectionInsertError {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

impl From<std::io::Error> for CollectionInsertError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Failure while appending one canonical complete capability proof.
#[derive(Debug)]
pub enum CapabilityProofInsertError {
    /// Existing pile state could not be refreshed or decoded.
    Read(ReadError),
    /// The record could not be appended or the file lock released.
    Io(std::io::Error),
    /// An infeasible BLAKE3 collision named different canonical proof bytes.
    IdCollision { id: CapabilityProofId },
    /// Readback observed a record other than the exclusively appended proof.
    UnexpectedReadback,
}

impl std::fmt::Display for CapabilityProofInsertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(f, "failed to refresh capability proofs: {error}"),
            Self::Io(error) => write!(f, "failed to append capability proof: {error}"),
            Self::IdCollision { id } => write!(
                f,
                "capability proof id {} names different bytes",
                hex::encode_upper(id.raw)
            ),
            Self::UnexpectedReadback => {
                f.write_str("capability proof append read back an unexpected pile record")
            }
        }
    }
}

impl Error for CapabilityProofInsertError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::IdCollision { .. } | Self::UnexpectedReadback => None,
        }
    }
}

impl From<ReadError> for CapabilityProofInsertError {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

impl From<std::io::Error> for CapabilityProofInsertError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Error returned when retrieving a blob from a [`Pile`].
#[derive(Debug)]
pub enum GetBlobError<E: Error> {
    /// No blob with the given handle exists in the pile.
    BlobNotFound(super::MissingBlob),
    /// The blob's hash does not match its stored digest.
    ValidationError(Bytes),
    /// The blob was found and valid but deserialization failed.
    ConversionError(E),
}

impl<E: Error> std::fmt::Display for GetBlobError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetBlobError::BlobNotFound(error) => error.fmt(f),
            GetBlobError::ConversionError(err) => write!(f, "Conversion error: {err}"),
            GetBlobError::ValidationError(_) => write!(f, "Validation error"),
        }
    }
}

impl<E: Error + 'static> std::error::Error for GetBlobError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BlobNotFound(error) => Some(error),
            Self::ConversionError(error) => Some(error),
            Self::ValidationError(_) => None,
        }
    }
}

/// Error returned by [`Pile::flush`] and [`Pile::close`].
#[derive(Debug)]
pub enum FlushError {
    /// Underlying I/O failure.
    IoError(std::io::Error),
}

impl From<std::io::Error> for FlushError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl std::fmt::Display for FlushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlushError::IoError(err) => write!(f, "IO error: {err}"),
        }
    }
}

impl std::error::Error for FlushError {}

impl Pile {
    /// Metadata for the exact backing file opened by this handle.
    ///
    /// This is deliberately derived from the held file descriptor rather than
    /// by resolving the original pathname again. Callers that need a
    /// host-local coordination key can therefore use the physical file
    /// identity without a rename or hard-link ambiguity.
    pub fn backing_file_metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    /// Opens an existing pile file. Returns an error if the file does not
    /// exist — create the file first with [`std::fs::File::create`] or
    /// equivalent if you need a fresh pile.
    ///
    /// The returned pile has no in-memory index; callers should invoke
    /// [`Self::refresh`] to load existing data. After a crash left a torn
    /// tail, [`Self::amputate`] loads and **truncates the file at the first
    /// malformed record** — a destructive last resort, not an open path.
    /// Complete opaque envelopes are crossed; unknown unenveloped markers are
    /// refused without truncation.
    pub fn open(path: &Path) -> Result<Self, ReadError> {
        let file = OpenOptions::new().read(true).append(true).open(path)?;
        let length_u64 = file.metadata()?.len();
        let length = usize::try_from(length_u64)
            .map_err(|_| ReadError::FileTooLarge { length: usize::MAX })?;
        let page_size = page_size::get();
        let base_size = page_size * 1024;
        let mapped_size = base_size.max(
            length
                .checked_next_power_of_two()
                .ok_or(ReadError::FileTooLarge { length })?,
        );

        let mmap = MmapOptions::new()
            .len(mapped_size)
            .map_raw_read_only(&file)?;
        let mmap = Arc::new(mmap);

        Ok(Self {
            file,
            mmap,
            dirty: false,
            blobs: PileBlobIndex::new(),
            branches: PATCH::<16, IdentitySchema, Inline<Handle<SimpleArchive>>>::new(),
            collection_records: CollectionRecordIndex::new(),
            collection_records_by_collection: CollectionRecordCollectionIndex::new(),
            capability_proofs: CapabilityProofIndex::new(),
            legacy_collection_headers: LegacyCollectionHeaderIndex::new(),
            opaque_records: 0,
            opaque_frames: Vec::new(),
            wants: PATCH::<WANT_REQUEST_BYTES_LEN, IdentitySchema>::new(),
            applied_length: 0,
        })
    }

    fn ensure_mapped(&mut self, file_len: usize) -> Result<(), ReadError> {
        if file_len <= self.mmap.len() {
            return Ok(());
        }
        let mapped_size = file_len
            .checked_next_power_of_two()
            .ok_or(ReadError::FileTooLarge { length: file_len })?;
        self.mmap = Arc::new(
            MmapOptions::new()
                .len(mapped_size)
                .map_raw_read_only(&self.file)?,
        );
        Ok(())
    }

    /// Refreshes in-memory state from newly appended records.
    ///
    /// Aborts immediately if the underlying pile file has shrunk below the
    /// portion already applied since the last refresh. Truncating validated data
    /// would invalidate existing `Bytes` handles and continuing would result in
    /// undefined behavior.
    ///
    /// This acquires a shared file lock to avoid racing with [`Self::amputate`],
    /// which takes an exclusive lock before truncating. A parse failure is
    /// rechecked once under an exclusive lock with a fresh file length: shared
    /// writers may expose an incomplete record during a single append syscall.
    pub fn refresh(&mut self) -> Result<(), ReadError> {
        self.file.lock_shared()?;
        let res = self.refresh_shared_locked();
        let unlock_res = self.file.unlock();
        res?;
        unlock_res?;
        Ok(())
    }

    /// Applies the next record from disk to in-memory indices.
    ///
    /// Aborts if the pile file is observed to shrink below the portion already
    /// applied, which would otherwise leave existing `Bytes` handles dangling
    /// and lead to undefined behavior.
    fn apply_next(&mut self) -> Result<Option<Applied>, ReadError> {
        let file_len = self.observed_file_len()?;
        self.ensure_mapped(file_len)?;
        self.apply_next_bounded(file_len)
    }

    fn observed_file_len(&self) -> Result<usize, ReadError> {
        usize::try_from(self.file.metadata()?.len())
            .map_err(|_| ReadError::FileTooLarge { length: usize::MAX })
    }

    /// Applies one record from a file-length snapshot already covered by the
    /// current mapping. Keeping the bound stable lets `refresh_locked` replay
    /// a complete observed prefix with one metadata lookup instead of one
    /// syscall per record. Appends after the snapshot are picked up by the
    /// next refresh, while post-write readback continues to use `apply_next`.
    fn apply_next_bounded(&mut self, file_len: usize) -> Result<Option<Applied>, ReadError> {
        if file_len < self.applied_length {
            // Truncation below `applied_length` invalidates previously issued
            // `Bytes` handles, so there is no safe recovery path.
            std::process::abort();
        }
        if file_len == self.applied_length {
            return Ok(None);
        }
        debug_assert!(file_len <= self.mmap.len());
        let start_offset = self.applied_length;
        let slice = unsafe {
            slice_from_raw_parts(
                self.mmap.as_ptr().add(start_offset),
                file_len - start_offset,
            )
            .as_ref()
            .unwrap()
        };
        // Single decoder shared with [`PileRecords`] — understands every
        // record format ever written (V1, unenveloped V3/V4, and envelope).
        let record = decode_record(slice, start_offset)?;
        let next_applied_length = start_offset + record.len;
        let legacy_collection_header = matches!(
            record.content,
            PileRecordContent::LegacyCollectionV3 { .. }
                | PileRecordContent::LegacyUnsignedCollectionEquation { .. }
        )
        .then(|| {
            let mut header = [0u8; V3_HEADER_LEN];
            header.copy_from_slice(&slice[..V3_HEADER_LEN]);
            header
        });
        let applied = match record.content {
            PileRecordContent::Blob { hash, .. } => {
                let candidate = IndexEntry::new(start_offset);
                // Replay is an index construction path, not a payload
                // validation pass. One segmented relation retains every
                // physical fallback; its 32-byte prefix projection is the
                // semantic resident set, and big-endian offsets preserve file
                // order under PATCH's lexicographic infix traversal.
                let key = blob_occurrence_key(&hash.raw, candidate);
                self.blobs
                    .insert(&Entry::with_value(&key, CachedValidation::default()));
                Applied::Blob { hash }
            }
            PileRecordContent::Branch { branch_id, head } => {
                let entry = Entry::with_value(&branch_id.into(), head);
                // Replace existing mapping (if any) with the new head.
                self.branches.replace(&entry);
                Applied::Branch {
                    id: branch_id,
                    hash: head.into(),
                }
            }
            PileRecordContent::BranchTombstone { branch_id } => {
                self.branches.remove(&branch_id.into());
                Applied::BranchTombstone { id: branch_id }
            }
            PileRecordContent::Want { request } => {
                self.wants.insert(&Entry::new(&request.to_bytes()));
                Applied::Want { request }
            }
            PileRecordContent::RetiredWantAssert { .. }
            | PileRecordContent::RetiredWantRetract { .. } => Applied::RetiredWantState,
            PileRecordContent::Collection { record } => {
                let fingerprint = record.fingerprint();
                if let Some(existing) = self.collection_records.get(&fingerprint.raw()) {
                    if existing != &record {
                        return Err(ReadError::CorruptPile {
                            valid_length: start_offset,
                        });
                    }
                } else {
                    self.collection_records
                        .insert(&Entry::with_value(&fingerprint.raw(), record));
                    self.collection_records_by_collection
                        .insert(&Entry::new(&collection_record_collection_key(record)));
                }
                Applied::Collection { fingerprint }
            }
            PileRecordContent::CapabilityProof {
                id,
                data_offset,
                data_len,
            } => {
                // The decoder just validated this exact immutable body and its
                // bounds. Retaining the mapping makes the proof independent of
                // this Pile's lifetime and subsequent mapping replacements.
                let bytes = unsafe {
                    let body = slice_from_raw_parts(self.mmap.as_ptr().add(data_offset), data_len)
                        .as_ref()
                        .unwrap();
                    Bytes::from_raw_parts(body, self.mmap.clone())
                };
                let candidate = CapabilityProof::from_validated_bytes(bytes);
                if let Some(existing) = self.capability_proofs.get(&id.raw) {
                    if existing != &candidate {
                        return Err(ReadError::CorruptPile {
                            valid_length: start_offset,
                        });
                    }
                } else {
                    self.capability_proofs
                        .insert(&Entry::with_value(&id.raw, candidate));
                }
                Applied::CapabilityProof { id }
            }
            PileRecordContent::RetiredCapabilityProof => Applied::RetiredCapabilityProof,
            PileRecordContent::RetiredPeerEvidenceV1 | PileRecordContent::RetiredStoreScopeV1 => {
                Applied::RetiredTeamState
            }
            PileRecordContent::RetiredArtifactOfferV1 => Applied::RetiredArtifactOffer,
            PileRecordContent::LegacyCollectionV3 { .. }
            | PileRecordContent::LegacyUnsignedCollectionEquation { .. } => {
                let header = legacy_collection_header
                    .expect("legacy collection record must retain its physical header");
                self.legacy_collection_headers.insert(&Entry::new(&header));
                Applied::LegacyCollectionEvidence
            }
            PileRecordContent::RetiredCollectionDeriveV4 => Applied::RetiredCollectionDeriveV4,
            PileRecordContent::Opaque { .. } => {
                self.opaque_records = self
                    .opaque_records
                    .checked_add(1)
                    .expect("opaque pile-record count overflow");
                self.opaque_frames
                    .push((start_offset, next_applied_length - start_offset));
                Applied::Opaque
            }
        };
        self.applied_length = next_applied_length;
        Ok(Some(applied))
    }

    /// Replay with a shared lock already held. On a parse failure, replace it
    /// with an exclusive lock and replay once more. The caller must unlock on
    /// every return path; successful recovery retains the stronger lock.
    fn refresh_shared_locked(&mut self) -> Result<(), ReadError> {
        match self.refresh_locked() {
            Err(ReadError::CorruptPile { .. } | ReadError::UnsupportedRecord { .. }) => {
                #[cfg(test)]
                append_visibility_tests::before_exclusive_recheck();
                // Append serialization prevents writers from interleaving, not
                // fstat/mmap from observing a partially completed syscall. Wait
                // for all participating writers, then take a NEW length below.
                // Do not retry the append, truncate, or suppress a stable error.
                self.file.unlock()?;
                self.file.lock()?;
                self.refresh_locked()
            }
            result => result,
        }
    }

    fn refresh_locked(&mut self) -> Result<(), ReadError> {
        // A fixed bound avoids a metadata syscall per record. Under a shared
        // lock this can end inside an in-flight append; refresh_shared_locked
        // confirms a parse failure after excluding all participating writers.
        // Later appends are intentionally left for the next refresh.
        let file_len = self.observed_file_len()?;
        if file_len < self.applied_length {
            std::process::abort();
        }
        self.ensure_mapped(file_len)?;
        loop {
            match self.apply_next_bounded(file_len) {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    /// Amputates the pile's tail: **TRUNCATES the file at the first malformed
    /// or truncated record, destroying everything after it.**
    ///
    /// This is a last-resort surgical recovery for a torn tail left by a
    /// crashed or interrupted append — never a routine open path. Everything
    /// past the malformed record is *gone from disk*. Complete opaque envelopes
    /// are crossed, and a torn one has a known starting boundary. An unknown
    /// unenveloped marker is instead reported as
    /// [`ReadError::UnsupportedRecord`] and is never truncated because its
    /// length is unknowable. If you are not certain the tail is a torn write, take a copy of
    /// the file first and prefer the non-mutating [`Self::refresh`], which
    /// fails loud without touching the file.
    ///
    /// The method first attempts a regular [`Self::refresh`]. If corruption is
    /// detected, it acquires an exclusive lock, re-attempts the refresh and,
    /// upon confirming the corruption, truncates the pile to the last known
    /// good offset. The exclusive lock blocks other readers so truncation
    /// cannot race with [`Self::refresh`].
    pub fn amputate(&mut self) -> Result<(), ReadError> {
        match self.refresh() {
            Ok(()) => Ok(()),
            Err(ReadError::CorruptPile { .. }) => {
                self.amputate_exclusive(None).map(|_truncated| ())
            }
            Err(e) => Err(e),
        }
    }

    /// Amputates only when the malformed record begins at
    /// `expected_valid_length`.
    ///
    /// Unlike checking [`Self::refresh`] before calling [`Self::amputate`],
    /// this compares the observed boundary and truncates under one exclusive
    /// file lock. If the boundary differs, it returns
    /// [`ReadError::CorruptPile`] with the current boundary and leaves the file
    /// unchanged. The returned boolean says whether a tail was truncated; it
    /// is false when the pile was already valid.
    pub fn amputate_at(&mut self, expected_valid_length: usize) -> Result<bool, ReadError> {
        self.amputate_exclusive(Some(expected_valid_length))
    }

    fn amputate_exclusive(
        &mut self,
        expected_valid_length: Option<usize>,
    ) -> Result<bool, ReadError> {
        self.file.lock()?;
        let result = (|| match self.refresh_locked() {
            Ok(()) => Ok(false),
            Err(ReadError::CorruptPile { valid_length })
                if expected_valid_length.is_some_and(|expected| expected != valid_length) =>
            {
                Err(ReadError::CorruptPile { valid_length })
            }
            Err(ReadError::CorruptPile { valid_length }) => {
                self.file.set_len(valid_length as u64)?;
                self.dirty = true;
                self.flush().map_err(|err| match err {
                    FlushError::IoError(err) => ReadError::IoError(err),
                })?;
                self.applied_length = valid_length;
                Ok(true)
            }
            Err(error) => Err(error),
        })();
        let unlock = self.file.unlock().map_err(ReadError::from);
        match (result, unlock) {
            (Ok(truncated), Ok(())) => Ok(truncated),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Persists all writes and metadata to the underlying pile file.
    pub fn flush(&mut self) -> Result<(), FlushError> {
        self.file.sync_all()?;
        self.dirty = false;
        Ok(())
    }

    fn flush_if_dirty(&mut self) -> Result<(), FlushError> {
        if self.dirty {
            self.flush()?;
        }
        Ok(())
    }

    /// Flushes pending mutations made through this handle and consumes the
    /// pile, returning an error if the flush fails.
    pub fn close(mut self) -> Result<(), FlushError> {
        let res = self.flush_if_dirty();

        let mut this = std::mem::ManuallyDrop::new(self);
        unsafe {
            std::ptr::drop_in_place(&mut this.mmap);
            std::ptr::drop_in_place(&mut this.file);
            std::ptr::drop_in_place(&mut this.blobs);
            std::ptr::drop_in_place(&mut this.branches);
            std::ptr::drop_in_place(&mut this.collection_records);
            std::ptr::drop_in_place(&mut this.collection_records_by_collection);
            std::ptr::drop_in_place(&mut this.capability_proofs);
            std::ptr::drop_in_place(&mut this.legacy_collection_headers);
            std::ptr::drop_in_place(&mut this.opaque_frames);
            std::ptr::drop_in_place(&mut this.wants);
        }

        res
    }
}

impl Drop for Pile {
    fn drop(&mut self) {
        eprintln!("warning: Pile dropped without calling close(); data may not be persisted");
    }
}

// Implement the repository storage close trait so callers can call
// `repo.close()` when the repository was created with a `Pile` storage.
impl crate::repo::StorageClose for Pile {
    type Error = FlushError;

    fn close(self) -> Result<(), Self::Error> {
        Pile::close(self)
    }
}

// Generic durability hook: appended records (blobs, branch updates,
// collection records, want markers) are not crash-durable until flushed — see the
// inherent [`Pile::flush`].
impl crate::repo::StorageFlush for Pile {
    type Error = FlushError;

    fn flush(&mut self) -> Result<(), Self::Error> {
        Pile::flush(self)
    }
}

use super::BlobInfo;
use super::BlobStoreGet;
use super::BlobStoreList;
use super::BlobStorePut;
use super::WantStore;

/// Iterator returned by [`PileSnapshot::iter`].
///
/// Iterates over all `(Handle, Blob)` pairs currently stored in the pile.
/// The iterator owns persistent roots rather than a collected handle list, so
/// it can live independently of the [`Pile`] without an O(blob-count) setup.
pub struct PileBlobStoreIter {
    snapshot: PileSnapshot,
    inner: crate::patch::PATCHIntoPrefixSetIterator<
        40,
        32,
        blob_occurrence_key::Schema,
        CachedValidation,
        XorSip128,
    >,
}

impl Iterator for PileBlobStoreIter {
    type Item = Result<(Inline<Handle<UnknownBlob>>, Blob<UnknownBlob>), GetBlobError<Infallible>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.inner.next()?;
        let hash = Inline::<Hash<Blake3>>::new(key);
        match self
            .snapshot
            .validated_blob_record(&hash, ValidationStrategy::ParallelIfLarge)
        {
            Ok(record) => {
                let handle: Inline<Handle<UnknownBlob>> = hash.into();
                let blob = Blob::with_handle(record.bytes, handle);
                Some(Ok((handle, blob)))
            }
            Err(error) => Some(Err(error)),
        }
    }
}

/// Adapter that yields semantic blob information from an occurrence snapshot.
pub struct PileBlobStoreListIter {
    snapshot: PileSnapshot,
    inner: crate::patch::PATCHIntoPrefixSetIterator<
        40,
        32,
        blob_occurrence_key::Schema,
        CachedValidation,
        XorSip128,
    >,
    /// When present, skip projected hashes already present in this old
    /// snapshot. Physical duplicate changes therefore remain semantically
    /// invisible to [`BlobStoreList::blobs_diff`].
    old: Option<PileBlobIndex>,
}

impl Iterator for PileBlobStoreListIter {
    type Item = Result<BlobInfo, GetBlobError<Infallible>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let key = self.inner.next()?;
            if self.old.as_ref().is_some_and(|old| old.has_prefix(&key)) {
                continue;
            }
            let hash = Inline::<Hash<Blake3>>::new(key);
            let handle = hash.into();
            return Some(Ok(self.snapshot.unvalidated_blob_info(handle).expect(
                "key from PATCH iterator must resolve in the same snapshot",
            )));
        }
    }
}

impl BlobStoreList for PileSnapshot {
    type Err = GetBlobError<Infallible>;
    type Iter<'a> = PileBlobStoreListIter;

    fn blobs(&self) -> Self::Iter<'_> {
        PileBlobStoreListIter {
            snapshot: self.clone(),
            inner: self.blobs.clone().into_prefixes(),
            old: None,
        }
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        Ok(self.blobs.has_prefix(&handle.raw))
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<super::BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        Ok(self.unvalidated_blob_info(*handle.as_transmute()))
    }

    /// Cheap PATCH-level set difference between two immutable store snapshots.
    fn blobs_diff(&self, old: &Self) -> Self::Iter<'_> {
        PileBlobStoreListIter {
            snapshot: self.clone(),
            inner: self.blobs.difference(&old.blobs).into_prefixes(),
            old: Some(old.blobs.clone()),
        }
    }
}

/// Deterministic owned snapshot of the pile's native collection records.
pub struct PileCollectionRecordIter {
    keys: crate::patch::PATCHIntoOrderedIterator<32, IdentitySchema, CollectionRecord, XorSip128>,
    lookup: CollectionRecordIndex,
}

/// Deterministic owned snapshot of the pile's complete capability proofs.
pub struct PileCapabilityProofIter {
    keys: crate::patch::PATCHIntoOrderedIterator<32, IdentitySchema, CapabilityProof, XorSip128>,
    lookup: CapabilityProofIndex,
}

impl Iterator for PileCapabilityProofIter {
    type Item = Result<CapabilityProof, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.keys.next()?;
        let proof = self
            .lookup
            .get(&key)
            .expect("proof key from PATCH snapshot must retain its value");
        Some(Ok(proof.clone()))
    }
}

impl Iterator for PileCollectionRecordIter {
    type Item = Result<CollectionRecord, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.keys.next()?;
        let record = *self
            .lookup
            .get(&key)
            .expect("collection key from PATCH snapshot must retain its value");
        debug_assert_eq!(record.fingerprint().raw(), key);
        Some(Ok(record))
    }
}

impl Pile {
    /// Store every blob needed to resolve every record kind this writer emits.
    ///
    /// A record kind is the handle of a description archive, which makes it
    /// resolvable in principle; this makes it resolvable *here*, so a reader
    /// holding nothing but the file can resolve every kind this writer emits.
    /// Retired kinds that this reader only crosses are intentionally absent.
    /// Content addressing makes the call idempotent: a pile that already
    /// carries the descriptions grows by nothing.
    ///
    /// This is not done automatically on every append. A pile is a log, and
    /// silently interleaving the description-blob cohort into someone else's
    /// write would be a surprise; publishing is an explicit act, performed
    /// once per pile — `trible pile migrate <PILE> run record-kind-descriptions` does
    /// it.
    pub fn publish_record_kind_descriptions(&mut self) -> Result<usize, InsertError> {
        let mut stored = 0usize;
        for blob in record_kind::description_blobs() {
            self.put::<UnknownBlob, _>(blob)?;
            stored += 1;
        }
        Ok(stored)
    }

    /// Return the number of unknown generic-envelope records in the coherent
    /// applied prefix. Reclamation must refuse while this is nonzero, because
    /// an older binary cannot compute an unknown kind's retention semantics;
    /// a retained rewrite, which drops no blob, carries the frames exactly.
    pub fn opaque_record_count(&mut self) -> Result<usize, ReadError> {
        self.refresh()?;
        Ok(self.opaque_records)
    }

    /// Copy every byte-distinct inert legacy collection header into
    /// `destination`.
    ///
    /// This is an internal physical-rewrite primitive. Legacy headers do not
    /// participate in the current collection algebra, but reclaim must retain
    /// their exact source evidence for a later explicit migration. The source
    /// is refreshed before the snapshot and destination insertion is
    /// idempotent by exact header bytes.
    pub(crate) fn preserve_legacy_collection_headers_into(
        &mut self,
        destination: &mut Pile,
    ) -> Result<(), CollectionInsertError> {
        self.refresh()?;
        let headers = self.legacy_collection_headers.clone();
        for header in headers.into_iter_ordered() {
            destination.preserve_legacy_collection_header(header)?;
        }
        Ok(())
    }

    /// Append one already-validated legacy collection header if this pile does
    /// not already contain the same physical evidence.
    fn preserve_legacy_collection_header(
        &mut self,
        header: [u8; V3_HEADER_LEN],
    ) -> Result<(), CollectionInsertError> {
        debug_assert!(matches!(
            decode_record(&header, 0),
            Ok(PileRecord {
                content: PileRecordContent::LegacyCollectionV3 { .. }
                    | PileRecordContent::LegacyUnsignedCollectionEquation { .. },
                ..
            })
        ));

        self.file.lock()?;
        let result = (|| {
            self.refresh_locked()?;

            if self.legacy_collection_headers.get(&header).is_some() {
                return Ok(());
            }

            self.dirty = true;
            let written = self.file.write(&header)?;
            if written != V3_HEADER_LEN {
                return Err(CollectionInsertError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write complete legacy collection record",
                )));
            }

            match self.apply_next()? {
                Some(Applied::LegacyCollectionEvidence) => Ok(()),
                Some(_) | None => Err(CollectionInsertError::UnexpectedReadback),
            }
        })();
        let unlock = self.file.unlock();
        result?;
        unlock?;
        Ok(())
    }

    /// Append one frame whose kind this binary does not model, exactly as it
    /// was read, unless this pile already holds a byte-identical opaque frame.
    ///
    /// This is an internal physical-rewrite primitive. The frame is
    /// self-delimiting, so a reader of this pile skips or decodes it exactly
    /// as a reader of the source would; nothing about it is interpreted here.
    fn preserve_opaque_frame(&mut self, frame: &[u8]) -> Result<(), CollectionInsertError> {
        debug_assert!(matches!(
            decode_record(frame, 0),
            Ok(PileRecord {
                content: PileRecordContent::Opaque { .. },
                ..
            })
        ));

        self.file.lock()?;
        let result = (|| {
            self.refresh_locked()?;

            let already = self.opaque_frames.iter().any(|(offset, len)| {
                *len == frame.len() && {
                    let existing = unsafe {
                        slice_from_raw_parts(self.mmap.as_ptr().add(*offset), *len)
                            .as_ref()
                            .expect("mapped opaque frame")
                    };
                    existing == frame
                }
            });
            if already {
                return Ok(());
            }

            self.dirty = true;
            let written = self.file.write(frame)?;
            if written != frame.len() {
                return Err(CollectionInsertError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write complete opaque frame",
                )));
            }

            match self.apply_next()? {
                Some(Applied::Opaque) => Ok(()),
                Some(_) | None => Err(CollectionInsertError::UnexpectedReadback),
            }
        })();
        let unlock = self.file.unlock();
        result?;
        unlock?;
        Ok(())
    }
}

impl CollectionRead for PileSnapshot {
    type RecordsError = ReadError;
    type RecordIter<'a> = PileCollectionRecordIter;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        let keys = self.collection_records.clone().into_iter_ordered();
        Ok(PileCollectionRecordIter {
            keys,
            lookup: self.collection_records.clone(),
        })
    }

    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        Ok(self.collection_records.get(&fingerprint.raw()).copied())
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        if selectors.is_empty() {
            return Ok(Vec::new());
        }
        if selectors
            .iter()
            .all(|selector| matches!(selector, CollectionRecordSelector::Collection(_)))
        {
            let mut ids = Vec::new();
            for selector in selectors {
                let CollectionRecordSelector::Collection(collection) = selector else {
                    unreachable!("selector kinds were checked above");
                };
                self.collection_records_by_collection
                    .infixes(&collection.raw, |fingerprint: &[u8; 32]| {
                        ids.push(*fingerprint)
                    });
            }
            // Infix traversal follows PATCH's structural tree order, while
            // CollectionRead promises deterministic fingerprint order.
            ids.sort_unstable();
            return Ok(ids
                .into_iter()
                .map(|id| {
                    *self
                        .collection_records
                        .get(&id)
                        .expect("collection selector index must reference the primary index")
                })
                .collect());
        }
        Ok(self
            .collection_records
            .iter_ordered()
            .map(|key| {
                *self
                    .collection_records
                    .get(key)
                    .expect("collection key from PATCH must retain its value")
            })
            .filter(|record| selectors_match_record(selectors, *record))
            .collect())
    }
}

impl CollectionStore for Pile {
    type InsertError = CollectionInsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        let fingerprint = record.fingerprint();
        let header = collection_record_header(&record);

        self.file.lock()?;
        let result = (|| {
            self.refresh_locked()?;

            if let Some(existing) = self.collection_records.get(&fingerprint.raw()) {
                return if existing == &record {
                    Ok(())
                } else {
                    Err(CollectionInsertError::FingerprintCollision { fingerprint })
                };
            }

            self.dirty = true;
            let written = self.file.write(&header)?;
            if written != header.len() {
                return Err(CollectionInsertError::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write complete collection record",
                )));
            }

            match self.apply_next()? {
                Some(Applied::Collection {
                    fingerprint: applied,
                }) if applied == fingerprint => Ok(()),
                Some(_) | None => Err(CollectionInsertError::UnexpectedReadback),
            }
        })();
        let unlock = self.file.unlock();
        result?;
        unlock?;
        Ok(())
    }
}

impl CapabilityProofRead for PileSnapshot {
    type ProofsError = ReadError;
    type ProofIter<'a> = PileCapabilityProofIter;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        let keys = self.capability_proofs.clone().into_iter_ordered();
        Ok(PileCapabilityProofIter {
            keys,
            lookup: self.capability_proofs.clone(),
        })
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        Ok(self.capability_proofs.get(&id.raw).cloned())
    }
}

impl CapabilityProofStore for Pile {
    type InsertError = CapabilityProofInsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        let bytes = proof.as_bytes();
        let data_len = bytes.len();
        let prefix_len = FRAME_KIND_OFFSET;
        let span_blocks =
            envelope_blocks_for_prefixed_payload(prefix_len, data_len).ok_or_else(|| {
                CapabilityProofInsertError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "capability proof is too large for the u32 pile-record span",
                ))
            })?;
        let padding = prefixed_payload_post_pad(prefix_len, data_len).ok_or_else(|| {
            CapabilityProofInsertError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "capability proof pile-record size overflows usize",
            ))
        })?;
        let id = proof.id();

        self.file.lock()?;
        let result = (|| {
            self.refresh_locked()?;

            if let Some(existing) = self.capability_proofs.get(&id.raw) {
                return if existing.as_bytes() == bytes {
                    Ok(())
                } else {
                    Err(CapabilityProofInsertError::IdCollision { id })
                };
            }

            let header = RecordFrame {
                magic: FRAME_MAGIC,
                span_blocks: span_blocks.to_le_bytes(),
                record_kind: CAPABILITY_PROOF_MAGIC,
            };
            let zero_buf = [0u8; ENVELOPE_BLOCK_LEN];
            self.dirty = true;
            self.file.write_all(header.as_bytes())?;
            // The common frame already wrote the proof's type identifier.
            self.file
                .write_all(&bytes[CAPABILITY_PROOF_MAGIC.len()..])?;
            if padding > 0 {
                self.file.write_all(&zero_buf[..padding])?;
            }

            match self.apply_next()? {
                Some(Applied::CapabilityProof { id: applied }) if applied == id => Ok(()),
                Some(_) | None => Err(CapabilityProofInsertError::UnexpectedReadback),
            }
        })();
        let unlock = self.file.unlock();
        result?;
        unlock?;
        Ok(())
    }
}

impl Pile {
    /// Refresh once and return the remaining fail-closed condition for a
    /// semantic physical rewrite from that exact applied prefix.
    pub(crate) fn physical_rewrite_guard(&mut self) -> Result<usize, ReadError> {
        self.refresh().map(|()| self.opaque_records)
    }
}

impl BlobStorePut for Pile {
    type PutError = InsertError;

    /// Inserts a blob into the pile and returns its handle.
    ///
    /// For records up to `ATOMIC_WRITE_LIMIT` the append relies on the
    /// kernel's atomic `write_vectored` guarantee, so multiple writers can
    /// hold a shared file lock and proceed concurrently. Larger records
    /// take an exclusive lock and append via plain `write_all`, trading
    /// concurrency for reach — the recovery path
    /// ([`Pile::amputate`]) truncates any partial tail left by a crash,
    /// so a multi-`write` record is still crash-safe. Multiple writers
    /// are safe only on filesystems guaranteeing atomic `write`/`vwrite`
    /// appends; other filesystems may corrupt the pile.
    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.put_impl(item)
    }
}

impl Pile {
    /// Shared blob-append. Writes an enveloped record: a fixed 256-byte header, the blob
    /// data at `record_start + ENVELOPE_HEADER_LEN`, and post-padding to a 256-byte
    /// multiple. Because the envelope has no offset-derived pad, the append uses the atomic
    /// shared-lock fast path for records up to `ATOMIC_WRITE_LIMIT` (no exclusive lock needed —
    /// a fixed header has no start offset to stabilize). The data is
    /// absolutely 256-aligned (zero-copy GPU-aliasable) in a current pile, which
    /// stays 256-aligned because every record span is a count of 256-byte blocks.
    /// Append a blob.
    ///
    /// The insertion timestamp is always the current wall clock. It is a local
    /// fact about this file -- it is never synced, and the one consumer is a
    /// last-resort tie-break in `branch consolidate --by-name`, applied only
    /// after preferring a branch that has a head. A re-encode resetting every
    /// stamp to the moment of the rewrite therefore costs nothing worth
    /// carrying an alternate append path for.
    fn put_impl<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, InsertError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let blob = IntoBlob::to_blob(item);
        let blob_size = blob.bytes.len();
        let padding = block_post_pad(blob_size);
        let span_blocks = envelope_blocks_for_payload(blob_size).ok_or_else(|| {
            InsertError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "blob is too large for the u32 pile-record span",
            ))
        })?;
        let record_size = ENVELOPE_HEADER_LEN
            .checked_add(blob_size)
            .and_then(|size| size.checked_add(padding))
            .ok_or_else(|| {
                InsertError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "blob pile-record size overflows usize",
                ))
            })?;
        let use_atomic = record_size <= ATOMIC_WRITE_LIMIT;

        if use_atomic {
            self.file.lock_shared()?;
        } else {
            // Oversized record: exclude other writers for the duration of
            // the multi-syscall append. Shared readers ([`refresh`]) block
            // until unlock, so they never observe a partially-written tail.
            self.file.lock()?;
        }
        let res = (|| {
            if use_atomic {
                self.refresh_shared_locked().map_err(InsertError::from)?;
            } else {
                self.refresh_locked().map_err(InsertError::from)?;
            }

            let handle: Inline<Handle<S>> = blob.get_handle();
            let hash: Inline<Hash<Blake3>> = handle.into();

            if let Some(mut entry) = first_blob_occurrence(&self.blobs, &hash.raw) {
                loop {
                    let record = indexed_blob_record(&self.mmap, self.applied_length, entry, &hash);
                    let validation = blob_occurrence_validation(&self.blobs, &hash.raw, entry);
                    if matches!(
                        validation.state(&record.bytes, &hash, ValidationStrategy::Serial),
                        ValidationState::Validated
                    ) {
                        return Ok(handle.transmute());
                    }
                    let Some(next) = next_blob_occurrence(&self.blobs, &hash.raw, entry) else {
                        break;
                    };
                    entry = next;
                }
            }
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
            let header = BlobRecordHeader::new(span_blocks, stamp, blob_size as u64, hash);
            let actual_record_size = record_size;
            // post-pad is < 256.
            let zero_buf = [0u8; ENVELOPE_BLOCK_LEN];
            // Mark before entering the syscall: partial writes and later
            // read-back failures must still leave close responsible for the
            // bytes this handle may have appended.
            self.dirty = true;
            if use_atomic {
                let bufs = [
                    IoSlice::new(header.as_bytes()),
                    IoSlice::new(blob.bytes.as_ref()),
                    IoSlice::new(&zero_buf[..padding]),
                ];
                let written = self.file.write_vectored(&bufs)?;
                if written != actual_record_size {
                    return Err(InsertError::IoError(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write blob record",
                    )));
                }
            } else {
                // Separate `write_all` calls — payload dominates, so the extra
                // syscalls for header/padding are negligible. Any partial
                // completion after a crash is caught by `amputate`.
                self.file.write_all(header.as_bytes())?;
                self.file.write_all(blob.bytes.as_ref())?;
                if padding > 0 {
                    self.file.write_all(&zero_buf[..padding])?;
                }
            }

            #[cfg(test)]
            append_visibility_tests::before_blob_readback();
            // The successful append is complete, as are preceding serialized
            // appends. Stop at its hash (or an earlier concurrent duplicate),
            // without parsing a later writer's potentially incomplete tail.
            // A full refresh here would need the same completion barrier as
            // preflight; this bounded-by-content readback does not.
            loop {
                match self.apply_next().map_err(InsertError::from)? {
                    Some(Applied::Blob { hash: h }) => {
                        if h == hash {
                            break;
                        }
                    }
                    Some(Applied::Branch { .. }) => {}
                    Some(Applied::BranchTombstone { .. }) => {}
                    Some(Applied::Want { .. }) => {}
                    Some(Applied::RetiredWantState) => {}
                    Some(Applied::Collection { .. }) => {}
                    Some(Applied::CapabilityProof { .. }) => {}
                    Some(Applied::RetiredCapabilityProof) => {}
                    Some(Applied::RetiredTeamState) => {}
                    Some(Applied::RetiredArtifactOffer) => {}
                    Some(Applied::LegacyCollectionEvidence) => {}
                    Some(Applied::RetiredCollectionDeriveV4) => {}
                    Some(Applied::Opaque) => {}
                    None => {
                        return Err(InsertError::IoError(std::io::Error::other(
                            "blob missing after write",
                        )));
                    }
                }
            }

            Ok(handle.transmute())
        })();
        let unlock_res = self.file.unlock();
        let handle = res?;
        unlock_res?;
        Ok(handle)
    }
}

impl Pile {
    /// Append one legacy pin occurrence while rewriting an existing pile.
    ///
    /// This is deliberately private and unconditional: reframe must replay
    /// head and tombstone occurrences in source order so concatenating the
    /// rewritten log preserves the old LWW semantics. It is not a CAS surface
    /// and must never be used to publish new mutable application state.
    fn append_legacy_pin_record(
        &mut self,
        id: Id,
        head: Option<Inline<Handle<SimpleArchive>>>,
    ) -> Result<(), PileWriteError> {
        self.file.lock()?;
        let result = (|| {
            self.refresh_locked().map_err(PileWriteError::from)?;
            self.dirty = true;
            let written = match head {
                Some(head) => self
                    .file
                    .write(PinHeadRecordHeader::new(id, head).as_bytes()),
                None => self
                    .file
                    .write(PinTombstoneRecordHeader::new(id).as_bytes()),
            }
            .map_err(PileWriteError::IoError)?;
            if written != ENVELOPE_HEADER_LEN {
                return Err(PileWriteError::IoError(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write legacy pin header",
                )));
            }
            match self.apply_next().map_err(PileWriteError::from)? {
                Some(Applied::Branch {
                    id: actual_id,
                    hash,
                }) if matches!(head, Some(expected) if actual_id == id && hash == expected.into()) => {
                    Ok(())
                }
                Some(Applied::BranchTombstone { id: actual_id })
                    if head.is_none() && actual_id == id =>
                {
                    Ok(())
                }
                Some(_) => Err(PileWriteError::IoError(std::io::Error::other(
                    "unexpected record after legacy pin restoration",
                ))),
                None => Err(PileWriteError::IoError(std::io::Error::other(
                    "legacy pin record missing after restoration",
                ))),
            }
        })();
        let unlock_result = self.file.unlock();
        result?;
        unlock_result?;
        Ok(())
    }

    /// Private legacy-record constructor for tests that exercise decoding,
    /// reframe, or physical retention. `previous` documents fixture order but
    /// grants no compare-and-swap behavior.
    #[cfg(test)]
    fn append_legacy_pin_for_test(
        &mut self,
        id: Id,
        _previous: Option<Inline<Handle<SimpleArchive>>>,
        head: Option<Inline<Handle<SimpleArchive>>>,
    ) -> Result<(), PileWriteError> {
        self.append_legacy_pin_record(id, head)
    }

    #[cfg(test)]
    fn legacy_pin_head_for_test(
        &mut self,
        id: Id,
    ) -> Result<Option<Inline<Handle<SimpleArchive>>>, ReadError> {
        self.refresh()?;
        Ok(self.branches.get(&id.into()).copied())
    }
}

/// Iterator over the grow-only typed requests stored in the pile,
/// using the PATCH's ordered key iterator (byte order, deterministic).
pub struct PileWantIter {
    inner: crate::patch::PATCHIntoOrderedIterator<WANT_REQUEST_BYTES_LEN, IdentitySchema, ()>,
}

impl Iterator for PileWantIter {
    type Item = Result<WantRequest, PileWriteError>;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.inner.next()?;
        Some(Ok(WantRequest::from_bytes(bytes).expect(
            "Pile only indexes structurally decoded canonical want requests",
        )))
    }
}

impl Pile {
    fn retired_want_projection(
        &self,
    ) -> Result<(usize, PATCH<WANT_REQUEST_BYTES_LEN, IdentitySchema>), ReadError> {
        let bytes = unsafe {
            slice_from_raw_parts(self.mmap.as_ptr(), self.applied_length)
                .as_ref()
                .expect("Pile mapping pointer is valid for its applied prefix")
        };
        let mut offset = 0usize;
        let mut retired_records = 0usize;
        let mut historical = PATCH::<WANT_REQUEST_BYTES_LEN, IdentitySchema, WantRequest>::new();
        while offset < bytes.len() {
            let record = decode_record(&bytes[offset..], offset)?;
            offset = offset
                .checked_add(record.len)
                .expect("validated pile record boundary fits usize");
            match record.content {
                PileRecordContent::RetiredWantAssert { request, identity } => {
                    retired_records += 1;
                    historical.replace(&Entry::with_value(&identity, request));
                }
                PileRecordContent::RetiredWantRetract { identity, .. } => {
                    retired_records += 1;
                    historical.remove(&identity);
                }
                _ => {}
            }
        }
        // Resolve LWW in the historical key space before forgetting the V1
        // derive source field. Distinct `(source,target,input)` keys may map
        // to one current `Derive(target,input)` set element.
        let mut active = PATCH::<WANT_REQUEST_BYTES_LEN, IdentitySchema>::new();
        for identity in &historical {
            let request = *historical
                .get(identity)
                .expect("historical WANT key from PATCH retains its projection");
            active.insert(&Entry::new(&request.to_bytes()));
        }
        Ok((retired_records, active))
    }

    fn want_cutover_status_from(
        &self,
        retired_records: usize,
        active: &PATCH<WANT_REQUEST_BYTES_LEN, IdentitySchema>,
    ) -> WantCutoverStatus {
        let resolved_active = active.iter().count();
        let already_current = active
            .iter()
            .filter(|request| self.wants.get(request).is_some())
            .count();
        WantCutoverStatus {
            retired_records,
            resolved_active,
            already_current,
            missing_current: resolved_active - already_current,
        }
    }

    /// Inspect retired WANT-log input without making it live repository state.
    ///
    /// The scan resolves historical assertion/retraction order only for
    /// migration accounting. [`WantStore::wants`] continues to expose solely
    /// the fresh grow-only markers.
    pub fn want_cutover_status(&mut self) -> Result<WantCutoverStatus, ReadError> {
        self.refresh()?;
        let (retired_records, active) = self.retired_want_projection()?;
        Ok(self.want_cutover_status_from(retired_records, &active))
    }

    fn append_want_locked(&mut self, request: WantRequest) -> Result<bool, PileWriteError> {
        let key = request.to_bytes();
        if self.wants.get(&key).is_some() {
            return Ok(false);
        }

        self.dirty = true;
        let written = self
            .file
            .write(WantRecordHeader::new(request).as_bytes())
            .map_err(PileWriteError::IoError)?;
        if written != ENVELOPE_HEADER_LEN {
            return Err(PileWriteError::IoError(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write typed want header",
            )));
        }
        match self.apply_next().map_err(PileWriteError::from)? {
            Some(Applied::Want { request: actual }) if actual == request => Ok(true),
            Some(_) => Err(PileWriteError::IoError(std::io::Error::other(
                "unexpected record after typed want write",
            ))),
            None => Err(PileWriteError::IoError(std::io::Error::other(
                "typed want marker missing after write",
            ))),
        }
    }

    /// Resolve every retired LWW WANT frame once and append the final active
    /// projection under the current grow-only marker.
    ///
    /// The exclusive file lock spans refresh, raw scan, and all tiny appends,
    /// so another process cannot insert an old log entry inside the cutover.
    /// Every complete fresh marker is idempotent, so a retry never duplicates
    /// semantic state. A short or torn frame still requires the ordinary
    /// explicit tail-repair step before retrying; it is not silently skipped.
    pub fn migrate_retired_wants(&mut self) -> Result<WantCutoverStatus, PileWriteError> {
        self.file.lock()?;
        let result: Result<WantCutoverStatus, PileWriteError> = (|| {
            self.refresh_locked().map_err(PileWriteError::from)?;
            let (retired_records, active) = self
                .retired_want_projection()
                .map_err(PileWriteError::from)?;
            let status = self.want_cutover_status_from(retired_records, &active);
            for bytes in active.into_iter_ordered() {
                let request = WantRequest::from_bytes(bytes)
                    .expect("retired WANT projection contains canonical request bytes");
                self.append_want_locked(request)?;
            }
            Ok(status)
        })();
        let unlock_result = self.file.unlock();
        let status = result?;
        unlock_result?;
        Ok(status)
    }

    /// Append one current grow-only WANT marker.
    ///
    /// The exact request is the set key, so an already-present request is a
    /// no-op. Otherwise one fixed 256-byte frame is appended and read back
    /// while the exclusive lock is still held. Like other header appends, the
    /// record is not crash-durable until [`Pile::flush`] is called.
    fn write_want_marker(&mut self, request: WantRequest) -> Result<(), PileWriteError> {
        self.file.lock()?;
        let res = (|| {
            self.refresh_locked().map_err(PileWriteError::from)?;
            self.append_want_locked(request).map(|_| ())
        })();
        let unlock_res = self.file.unlock();
        res?;
        unlock_res?;
        Ok(())
    }
}

impl super::PinSnapshotSource for Pile {
    type PinSnapshotError = ReadError;

    fn snapshot_pin_heads(&mut self) -> Result<super::PinSnapshot, Self::PinSnapshotError> {
        // PATCH is persistent, so this is one cheap immutable snapshot. Keep
        // refresh here as the single strict path: failure is returned rather
        // than becoming a partial authorization view.
        self.refresh()?;
        Ok(self.branches.clone())
    }
}

impl WantStore for Pile {
    type WantError = PileWriteError;
    /// Add `request` idempotently; call [`Pile::flush`] to make it
    /// crash-durable.
    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
        self.write_want_marker(request)
    }
}

impl super::WantRead for PileSnapshot {
    type WantsError = PileWriteError;
    type WantIter<'a> = PileWantIter;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        let cloned = self.wants.clone();
        Ok(PileWantIter {
            inner: cloned.into_iter_ordered(),
        })
    }
}

impl crate::repo::BlobStoreMeta for PileSnapshot {
    type MetaError = Infallible;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<crate::repo::BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        let hash: &Inline<Hash<Blake3>> = handle.as_transmute();
        match self.validated_blob_record::<Infallible>(hash, ValidationStrategy::ParallelIfLarge) {
            Ok(record) => Ok(Some(crate::repo::BlobMetadata {
                timestamp: record.timestamp,
                length: record.bytes.len() as u64,
            })),
            Err(GetBlobError::BlobNotFound(_) | GetBlobError::ValidationError(_)) => Ok(None),
            Err(GetBlobError::ConversionError(error)) => match error {},
        }
    }
}

/// How a source pile's active wants participate in a retained rewrite.
///
/// A preserved WANT is an ordinary retained record and therefore owns every
/// resident blob handle it names recursively. Dropping one omits both the
/// record and those structural ownership edges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WantRewritePolicy {
    /// Recreate every active WANT and retain its resident reference closure.
    Preserve,
    /// Omit want markers from the destination.
    Drop,
}

/// Accounting for one whole-pile re-encode into the current framing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PileReframeStats {
    /// Distinct blob payloads copied. Duplicate blob records in the source
    /// collapse to one, which is why this can be lower than the source's blob
    /// record count.
    pub blobs: usize,
    /// Pin head assignments and tombstones replayed, in source order.
    pub pin_updates: usize,
    /// Distinct current monotone WANT records emitted.
    pub wants: usize,
    /// Retired assertion/retraction frames resolved into the current WANT set.
    pub retired_want_records: usize,
    /// Collection-calculus records re-encoded.
    pub collection_records: usize,
    /// Exact retired unsigned equation frames preserved for writer endorsement.
    pub legacy_unsigned_equations: usize,
    /// Earlier definition-ID collection frames preserved as raw evidence only.
    pub legacy_v3_records: usize,
    /// Complete capability proofs re-encoded.
    pub capability_proofs: usize,
    /// Disposable inert records, such as retired capability proofs and team
    /// state. Opaque ownership fails closed before copying.
    pub dropped_inert: usize,
}

/// Failure while re-encoding a pile into the current framing.
#[derive(Debug)]
#[non_exhaustive]
pub enum PileReframeError {
    /// The source could not be read.
    Source(ReadError),
    /// A variable-width record's payload was absent or malformed in the source.
    SourcePayload {
        /// Byte offset of the offending record.
        offset: usize,
    },
    /// An unknown record could carry semantics this rewrite cannot preserve.
    OpaqueRecord {
        /// Byte offset of the unknown record.
        offset: usize,
        /// Exact kind named by the source frame.
        kind: OpaqueKind,
    },
    /// The destination rejected an appended record.
    Destination(InsertError),
    /// A pin update could not be appended.
    Pin(PileWriteError),
    /// A want could not be appended.
    Want(PileWriteError),
    /// A collection record could not be appended.
    Collection(CollectionInsertError),
    /// A complete capability proof could not be appended.
    CapabilityProof(CapabilityProofInsertError),
    /// The destination was not empty, so the re-encode would have mixed
    /// framings instead of producing a clean file.
    DestinationNotEmpty {
        /// Length of the destination at the time of the check.
        length: usize,
    },
    /// The finished destination could not be made durable.
    Flush(FlushError),
}

impl std::fmt::Display for PileReframeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(error) => write!(f, "failed to read source pile: {error}"),
            Self::SourcePayload { offset } => {
                write!(f, "record at byte {offset} has no readable payload")
            }
            Self::OpaqueRecord { offset, kind } => write!(
                f,
                "unknown record kind {} at byte {offset}; refusing semantic reframe",
                hex::encode_upper(kind.as_bytes())
            ),
            Self::Destination(error) => write!(f, "failed to append to destination: {error}"),
            Self::Pin(error) => write!(f, "failed to replay a pin update: {error}"),
            Self::Want(error) => write!(f, "failed to replay a want: {error}"),
            Self::Collection(error) => {
                write!(f, "failed to re-encode a collection record: {error}")
            }
            Self::CapabilityProof(error) => {
                write!(f, "failed to re-encode a capability proof: {error}")
            }
            Self::DestinationNotEmpty { length } => write!(
                f,
                "destination already holds {length} byte(s); reframe requires an empty pile"
            ),
            Self::Flush(error) => write!(f, "failed to flush reframed pile: {error}"),
        }
    }
}

impl Error for PileReframeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::Destination(error) => Some(error),
            Self::Pin(error) | Self::Want(error) => Some(error),
            Self::Collection(error) => Some(error),
            Self::CapabilityProof(error) => Some(error),
            Self::Flush(error) => Some(error),
            Self::SourcePayload { .. }
            | Self::OpaqueRecord { .. }
            | Self::DestinationNotEmpty { .. } => None,
        }
    }
}

/// Re-encode every record of `source` into `destination` under the current
/// framing.
///
/// This is the opt-in semantic rewrite for a pile written before the current
/// frame. Historical records remain structurally readable after cutover so a
/// stale pile concatenation cannot corrupt a current reader, but a reframed
/// destination preserves current live state and the exact unsigned equation
/// evidence needed for a later authorized-writer endorsement.
///
/// The re-encode is **semantic, in source order**, which is what makes it
/// faithful rather than merely byte-preserving:
///
/// * Blob payloads are content-addressed, so copying them changes no identity.
///   Their insertion timestamps are not: a timestamp is a local fact about one
///   file, never synced and never part of a handle, so a rewrite stamps them
///   afresh. Its one consumer is a last-resort tie-break in `branch
///   consolidate --by-name`, which only runs after preferring a branch that
///   has a head, and which degenerates harmlessly to first-wins.
/// * Pins remain a last-writer-wins log and are replayed in order. Retired
///   WANT assertions/retractions are resolved in source order once; only their
///   final active requests are emitted under the current grow-only marker.
///   Current monotone WANTs pass through idempotently and union with that
///   migrated projection.
/// * Collection records are a grow-only set, so order does not
///   matter and re-insertion is idempotent. Every record's signature covers a
///   domain-separated transcript over its fields, not the bytes of its frame,
///   so re-encoding preserves the signed bytes without re-verifying them.
///   Explicit audit remains responsible for reporting invalid signatures.
/// * Retired unsigned equations are inert but their exact source frames are
///   preserved; reframe never manufactures an endorsement.
///   Earlier definition-ID V3 frames are also preserved byte-for-byte without
///   assigning them new collection semantics or GC reference interpretation.
/// * Current self-contained capability proofs are another grow-only
///   content-addressed set. Their exact canonical bodies survive reframing;
///   proof ids are physical selectors and do not stand in for verification.
///   Retired claim-dependent proof records are inert and dropped.
/// * Disposable inert records are dropped and counted: claim-dependent V1
///   capability proofs and retired PEER and STORE_SCOPE state. Opaque kinds,
///   including retired local-cell ownership, fail closed in a full preflight
///   before any destination write.
///
/// `destination` must be empty; a partly-written destination would mix
/// framings, which is exactly what this exists to eliminate.
pub fn reframe_into(
    source: &Path,
    destination: &mut Pile,
) -> Result<PileReframeStats, PileReframeError> {
    let existing = destination
        .refresh()
        .map(|()| destination.applied_length)
        .map_err(PileReframeError::Source)?;
    if existing != 0 {
        return Err(PileReframeError::DestinationNotEmpty { length: existing });
    }

    let mut records = PileRecords::open(source).map_err(PileReframeError::Source)?;
    // Inspect the same immutable prefix we will copy. An unknown kind may own
    // state or references, so discovering one after partial output is too late.
    for record in records.by_ref() {
        let record = record.map_err(PileReframeError::Source)?;
        if let PileRecordContent::Opaque { kind } = record.content {
            return Err(PileReframeError::OpaqueRecord {
                offset: record.offset,
                kind,
            });
        }
    }
    records.offset = 0;
    let mut stats = PileReframeStats::default();
    let mut retired_wants = PATCH::<WANT_REQUEST_BYTES_LEN, IdentitySchema, WantRequest>::new();
    let mut output_wants = PATCH::<WANT_REQUEST_BYTES_LEN, IdentitySchema>::new();
    loop {
        let record = match records.next() {
            None => break,
            Some(record) => record.map_err(PileReframeError::Source)?,
        };
        match record.content {
            PileRecordContent::Blob {
                // The original insertion timestamp is deliberately not carried
                // across. It is a local fact about one file -- never synced,
                // never part of a handle -- and a rewrite is a fresh append.
                timestamp: _,
                data_offset,
                data_len,
                ..
            } => {
                let end = data_offset
                    .checked_add(data_len)
                    .filter(|end| *end <= records.bytes().len())
                    .ok_or(PileReframeError::SourcePayload {
                        offset: record.offset,
                    })?;
                let bytes = records.bytes().slice(data_offset..end);
                destination
                    .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(bytes))
                    .map_err(PileReframeError::Destination)?;
                stats.blobs += 1;
            }
            PileRecordContent::Branch { branch_id, head } => {
                destination
                    .append_legacy_pin_record(branch_id, Some(head))
                    .map_err(PileReframeError::Pin)?;
                stats.pin_updates += 1;
            }
            PileRecordContent::BranchTombstone { branch_id } => {
                destination
                    .append_legacy_pin_record(branch_id, None)
                    .map_err(PileReframeError::Pin)?;
                stats.pin_updates += 1;
            }
            PileRecordContent::Want { request } => {
                destination.want(request).map_err(PileReframeError::Want)?;
                output_wants.insert(&Entry::new(&request.to_bytes()));
            }
            PileRecordContent::RetiredWantAssert { request, identity } => {
                stats.retired_want_records += 1;
                retired_wants.replace(&Entry::with_value(&identity, request));
            }
            PileRecordContent::RetiredWantRetract { identity, .. } => {
                stats.retired_want_records += 1;
                retired_wants.remove(&identity);
            }
            PileRecordContent::Collection { record } => {
                destination
                    .insert(record)
                    .map_err(PileReframeError::Collection)?;
                stats.collection_records += 1;
            }
            PileRecordContent::LegacyUnsignedCollectionEquation { .. }
            | PileRecordContent::LegacyCollectionV3 { .. } => {
                let header = records.bytes()[record.offset..record.offset + V3_HEADER_LEN]
                    .try_into()
                    .expect("validated historical collection frames occupy one block");
                destination
                    .preserve_legacy_collection_header(header)
                    .map_err(PileReframeError::Collection)?;
                if matches!(record.content, PileRecordContent::LegacyCollectionV3 { .. }) {
                    stats.legacy_v3_records += 1;
                } else {
                    stats.legacy_unsigned_equations += 1;
                }
            }
            PileRecordContent::CapabilityProof {
                data_offset,
                data_len,
                ..
            } => {
                let end = data_offset
                    .checked_add(data_len)
                    .filter(|end| *end <= records.bytes().len())
                    .ok_or(PileReframeError::SourcePayload {
                        offset: record.offset,
                    })?;
                // PileRecords already validated this immutable body while
                // decoding the frame; retain its byte owner without reparsing.
                let proof =
                    CapabilityProof::from_validated_bytes(records.bytes().slice(data_offset..end));
                destination
                    .insert_proof(proof)
                    .map_err(PileReframeError::CapabilityProof)?;
                stats.capability_proofs += 1;
            }
            _ => stats.dropped_inert += 1,
        }
    }

    for identity in retired_wants.iter_ordered() {
        let request = *retired_wants
            .get(identity)
            .expect("historical WANT key from PATCH retains its projection");
        destination.want(request).map_err(PileReframeError::Want)?;
        output_wants.insert(&Entry::new(&request.to_bytes()));
    }
    stats.wants = output_wants.iter().count();

    destination.flush().map_err(PileReframeError::Flush)?;
    Ok(stats)
}

/// Deterministic accounting for one retained pile rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PileRewriteStats {
    /// Exact number of resident blobs selected and copied.
    pub retained_blobs: usize,
    /// Number of active legacy strong-pin mappings recreated.
    pub strong_pins: usize,
    /// Number of want markers recreated.
    pub wants: usize,
    /// Number of complete capability proofs preserved.
    pub capability_proofs: usize,
    /// Number of frames of unknown kind carried exactly, by their own length.
    pub opaque_frames: usize,
}

/// Failure while copying one policy-selected pile state into another pile.
#[derive(Debug)]
#[non_exhaustive]
pub enum PileRewriteError {
    /// The source could not produce a coherent store snapshot.
    Source(ReadError),
    /// A selected blob was absent, invalid, or could not be stored.
    Transfer(super::TransferError<Infallible, GetBlobError<Infallible>, InsertError>),
    /// A strong-pin mapping could not be appended to the destination.
    StrongPin(PileWriteError),
    /// The destination already maps a retained pin id to another head.
    StrongPinConflict {
        /// Conflicting pin id.
        id: Id,
        /// Head already present in the destination.
        current: Option<Inline<Handle<SimpleArchive>>>,
    },
    /// A preserved want marker could not be appended.
    Want(PileWriteError),
    /// An immutable collection-algebra record could not be appended.
    Collection(CollectionInsertError),
    /// A complete capability proof could not be appended.
    CapabilityProof(CapabilityProofInsertError),
    /// The completed destination state could not be made durable.
    Flush(FlushError),
}

impl std::fmt::Display for PileRewriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(error) => write!(f, "failed to snapshot source pile: {error}"),
                    Self::Transfer(error) => write!(f, "failed to copy a retained blob: {error}"),
            Self::StrongPin(error) => write!(f, "failed to recreate a strong pin: {error}"),
            Self::StrongPinConflict { id, current } => write!(
                f,
                "destination has conflicting strong pin {id:X} at {current:?}"
            ),
            Self::Want(error) => write!(f, "failed to recreate a want: {error}"),
            Self::Collection(error) => {
                write!(f, "failed to preserve a collection record: {error}")
            }
            Self::CapabilityProof(error) => {
                write!(f, "failed to preserve a capability proof: {error}")
            }
            Self::Flush(error) => write!(f, "failed to flush rewritten pile: {error}"),
        }
    }
}

impl Error for PileRewriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::Transfer(error) => Some(error),
            Self::StrongPin(error) | Self::Want(error) => Some(error),
            Self::Collection(error) => Some(error),
            Self::CapabilityProof(error) => Some(error),
            Self::Flush(error) => Some(error),
            Self::StrongPinConflict { .. } => None,
        }
    }
}

impl Pile {
    /// Copy a policy-selected state into another append-only pile.
    ///
    /// `explicit` is normally produced by a higher-level policy such as
    /// collection resolution. This byte-copy boundary deliberately knows
    /// nothing about collection authorization and does not persist the policy;
    /// callers must recompute and supply its roots on every later rewrite. It
    /// additionally treats every resident active legacy strong-pin head as a
    /// recursive ownership root and recreates the exact pin mapping even when
    /// its head is absent, allowing collection and branch models to coexist
    /// during migration.
    ///
    /// The source is refreshed once; blobs, strong pins, collection records,
    /// current self-contained proofs, inert legacy collection headers, and
    /// wants are then taken from that coherent applied-prefix snapshot. Every
    /// native collection record owns each resident descriptor,
    /// member, input, or output handle it names recursively, independently of
    /// signature validity, admission, or algebraic usefulness. Every canonical
    /// preserved WANT owns each resident handle in its request. Capability
    /// proofs own their resident capability definition blobs, not the opaque
    /// resource identity. Each emitted
    /// non-BLOB frame also owns the resident description of its own record
    /// kind. A BLOB frame does not root itself merely by existing, but once an
    /// independent root selects any BLOB frame for output, that frame owns the
    /// resident description of the BLOB kind. Discarded historical frames do
    /// not contribute roots. Missing
    /// references remain missing and never cause a fetch or make the rewrite
    /// fail merely because a sibling reference is absent. Byte-distinct legacy
    /// V3 collection headers are copied
    /// exactly but remain semantically inert. The destination may already
    /// contain identical blobs, records, proofs, headers, and strong-pin
    /// mappings, making retries idempotent, but a differently mapped
    /// pin or intrinsic-record collision is an error. Missing or invalid explicitly
    /// selected blobs still fail the rewrite rather than silently weakening the
    /// caller's retention policy. One final flush makes blobs and records durable
    /// in append order.
    pub fn rewrite_retained_into(
        &mut self,
        destination: &mut Pile,
        explicit: &super::RetentionRoots,
        wants: WantRewritePolicy,
    ) -> Result<PileRewriteStats, PileRewriteError> {
        let reader = self.snapshot().map_err(PileRewriteError::Source)?;
        let strong_pins = self.branches.clone();
        // Frames whose kind this binary does not model are carried exactly,
        // by their own length, from the observed prefix: this rewrite keeps
        // every resident blob, so it cannot orphan whatever such a frame
        // names, and a binary that knows the kind reads them unchanged. Yard
        // reclamation, which does drop blobs, still refuses on them.
        self.physical_rewrite_guard()
            .map_err(PileRewriteError::Source)?;
        let covered = reader.covered_len;
        let opaque_frames: Vec<(usize, usize)> = self
            .opaque_frames
            .iter()
            .copied()
            .filter(|(offset, len)| offset + len <= covered)
            .collect();
        let collection_records = reader.collection_records.clone();
        let capability_proofs = reader
            .proofs()
            .map_err(PileRewriteError::Source)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(PileRewriteError::Source)?;
        let legacy_collection_headers = self.legacy_collection_headers.clone();
        let source_wants = self.wants.clone();
        let preserved_wants: Vec<_> = if wants == WantRewritePolicy::Preserve {
            source_wants
                .into_iter_ordered()
                .map(|bytes| {
                    WantRequest::from_bytes(bytes)
                        .expect("Pile only indexes structurally decoded canonical want requests")
                })
                .collect()
        } else {
            Vec::new()
        };

        let mut roots = explicit.clone();
        if !strong_pins.is_empty() {
            retain_record_kind_if_resident(&mut roots, &reader, pin_head_record_kind());
        }
        if !capability_proofs.is_empty() {
            retain_record_kind_if_resident(&mut roots, &reader, capability_proof_record_kind());
        }
        for proof in &capability_proofs {
            for handle in proof.blob_references() {
                if reader
                    .contains_blob(handle)
                    .expect("PileSnapshot residency lookup is infallible")
                {
                    roots.retain_recursive(handle);
                }
            }
        }
        if !preserved_wants.is_empty() {
            retain_record_kind_if_resident(&mut roots, &reader, want_record_kind());
        }
        for raw in &strong_pins {
            let head = *strong_pins
                .get(raw)
                .expect("pin key from snapshot must retain its value");
            if reader
                .contains_blob(head)
                .expect("PileSnapshot residency lookup is infallible")
            {
                roots.retain_recursive(head);
            }
        }
        for key in collection_records.iter() {
            let record = collection_records
                .get(key)
                .expect("collection key from PATCH snapshot must retain its value");
            retain_record_kind_if_resident(&mut roots, &reader, collection_record_kind(*record));
            for handle in record.blob_references() {
                if reader
                    .contains_blob(handle)
                    .expect("PileSnapshot residency lookup is infallible")
                {
                    roots.retain_recursive(handle);
                }
            }
        }
        for handle in reader.legacy_unsigned_collection_references() {
            if reader
                .contains_blob(handle)
                .expect("PileSnapshot residency lookup is infallible")
            {
                roots.retain_recursive(handle);
            }
        }
        for request in &preserved_wants {
            for handle in request.blob_references() {
                if reader
                    .contains_blob(handle)
                    .expect("PileSnapshot residency lookup is infallible")
                {
                    roots.retain_recursive(handle);
                }
            }
        }
        let mut keep = roots.expanded(&reader);
        let emits_blob = keep.iter().any(|handle| {
            reader
                .contains_blob(*handle)
                .expect("PileSnapshot residency lookup is infallible")
        });
        if emits_blob {
            retain_record_kind_if_resident(&mut roots, &reader, blob_record_kind());
            keep = roots.expanded(&reader);
        }
        let retained_blobs = keep.len();

        for copied in super::transfer(&reader, destination, keep) {
            copied.map_err(PileRewriteError::Transfer)?;
        }

        destination
            .refresh()
            .map_err(PileWriteError::from)
            .map_err(PileRewriteError::StrongPin)?;
        for raw in &strong_pins {
            let id = Id::new(*raw).expect("Pile never stores a nil strong-pin id");
            let head = *strong_pins
                .get(raw)
                .expect("pin key from snapshot must retain its value");
            match destination.branches.get(raw).copied() {
                Some(current) if current == head => {}
                Some(current) => {
                    return Err(PileRewriteError::StrongPinConflict {
                        id,
                        current: Some(current),
                    });
                }
                None => destination
                    .append_legacy_pin_record(id, Some(head))
                    .map_err(PileRewriteError::StrongPin)?,
            }
        }

        for header in legacy_collection_headers.into_iter_ordered() {
            destination
                .preserve_legacy_collection_header(header)
                .map_err(PileRewriteError::Collection)?;
        }

        for (offset, len) in &opaque_frames {
            let frame = unsafe {
                slice_from_raw_parts(reader.mmap.as_ptr().add(*offset), *len)
                    .as_ref()
                    .expect("mapped opaque frame")
            };
            destination
                .preserve_opaque_frame(frame)
                .map_err(PileRewriteError::Collection)?;
        }

        for key in collection_records.clone().into_iter_ordered() {
            let record = *collection_records
                .get(&key)
                .expect("collection key from PATCH snapshot must retain its value");
            destination
                .insert(record)
                .map_err(PileRewriteError::Collection)?;
        }

        let capability_proof_count = capability_proofs.len();
        for proof in capability_proofs {
            destination
                .insert_proof(proof)
                .map_err(PileRewriteError::CapabilityProof)?;
        }

        for request in &preserved_wants {
            destination.want(*request).map_err(PileRewriteError::Want)?;
        }

        destination.flush().map_err(PileRewriteError::Flush)?;
        Ok(PileRewriteStats {
            retained_blobs,
            strong_pins: strong_pins.len() as usize,
            wants: preserved_wants.len(),
            capability_proofs: capability_proof_count,
            opaque_frames: opaque_frames.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    use tempfile;

    use crate::capability::{
        Capability, CapabilityMode, CapabilityResource, CAPABILITY_PROOF_HEADER_LEN,
        MAX_CAPABILITY_PROOF_STEPS,
    };
    use crate::collection::descriptor::named_for_tests;
    use crate::collection::{
        empty_metadata_handle, AdmissionPolicy, Collection, CollectionHandle, CollectionPolicy,
        CollectionStoreExt, Cover,
    };
    use crate::macros::entity;
    use crate::repo::yard::{Yard, YardCollectError, YardConfig, YardReclaimError};
    use crate::repo::{
        BlobStoreMeta, RetentionRoots, SnapshotSource, StorageClose, StoreChanges, StoreSnapshot,
        WantRead,
    };
    use crate::trible::TribleSet;

    fn fresh_empty_pile_path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::File::create(&path).unwrap();
        path
    }

    fn team_key(seed: u8) -> RawInline {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn retired_peer_record(team_seed: u8, peer_seed: u8) -> Vec<u8> {
        RetiredPeerEvidenceRecordHeader {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_PEER_EVIDENCE,
            team_public_key: team_key(team_seed),
            peer_public_key: team_key(peer_seed),
            reserved: [0; 128],
        }
        .as_bytes()
        .to_vec()
    }

    fn retired_store_scope_record(team_seed: u8) -> Vec<u8> {
        RetiredStoreScopeRecordHeader {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_STORE_SCOPE,
            team_public_key: team_key(team_seed),
            reserved: [0; 160],
        }
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn retired_artifact_offer_envelope_is_a_known_inert_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "retired-offer.pile");
        let mut retired = [0u8; ENVELOPE_HEADER_LEN];
        retired[..FRAME_MAGIC_LEN].copy_from_slice(&FRAME_MAGIC);
        retired[FRAME_MAGIC_LEN..FRAME_BODY_OFFSET - 32]
            .copy_from_slice(&ENVELOPE_HEADER_BLOCKS.to_le_bytes());
        // The pile-artifact-offer-v1 description handle, retired without
        // reuse: a known inert frame, not an opaque one, so a pile that
        // carries thousands of them still replays and compacts.
        retired[FRAME_BODY_OFFSET - 32..FRAME_BODY_OFFSET]
            .copy_from_slice(&record_kind::KIND_ARTIFACT_OFFER_V1);
        retired[FRAME_BODY_OFFSET..FRAME_BODY_OFFSET + 32].fill(4);
        append_test_bytes(&path, &retired);

        let mut pile = Pile::open(&path).unwrap();
        assert_eq!(pile.opaque_record_count().unwrap(), 0);
        pile.close().unwrap();

        let mut records = PileRecords::open(&path).unwrap();
        assert!(matches!(
            records.next().unwrap().unwrap().content,
            PileRecordContent::RetiredArtifactOfferV1
        ));
        assert!(records.next().is_none());
    }

    fn capability_fixture(seed: u8, resource: [u8; 32]) -> CapabilityProof {
        let root = SigningKey::from_bytes(&[seed; 32]);
        let leaf = SigningKey::from_bytes(&[seed.wrapping_add(1); 32]);
        let capability = Inline::new([seed.wrapping_add(2); 32]);
        CapabilityProof::issue_root(
            &root,
            CapabilityResource::new(resource),
            Capability::new(capability, CapabilityMode::InvokeAndDelegate),
            None,
            leaf.verifying_key(),
        )
    }

    fn retired_capability_v1_record(body: &[u8]) -> Vec<u8> {
        let prefix_len = std::mem::size_of::<RetiredCapabilityProofRecordPrefix>();
        let blocks = envelope_blocks_for_prefixed_payload(prefix_len, body.len()).unwrap();
        let mut bytes = RetiredCapabilityProofRecordPrefix::new(blocks, body.len() as u64)
            .as_bytes()
            .to_vec();
        bytes[FRAME_BODY_OFFSET - 32..FRAME_BODY_OFFSET]
            .copy_from_slice(&record_kind::KIND_AUTH_PROOF_V1);
        bytes.extend_from_slice(body);
        bytes.resize(blocks as usize * ENVELOPE_BLOCK_LEN, 0);
        bytes
    }

    fn framed_capability_proof(proof: &[u8]) -> Vec<u8> {
        let blocks = envelope_blocks_for_prefixed_payload(FRAME_KIND_OFFSET, proof.len()).unwrap();
        let mut frame = FRAME_MAGIC.to_vec();
        frame.extend_from_slice(&blocks.to_le_bytes());
        frame.extend_from_slice(proof);
        frame.resize(blocks as usize * ENVELOPE_BLOCK_LEN, 0);
        frame
    }

    #[test]
    fn native_proof_padding_is_unambiguous_for_every_edge_count() {
        let first = capability_fixture(101, [102; 32]);
        let mut body = first.as_bytes()[..CAPABILITY_PROOF_HEADER_LEN].to_vec();
        let mut edge = first.as_bytes()[CAPABILITY_PROOF_HEADER_LEN..].to_vec();
        // Framing must preserve even zero signature bytes, not trim them off
        // with the padding. These records are evidence, not valid authority.
        edge[CAPABILITY_PROOF_EDGE_LEN - 64..].fill(0);
        for count in 1..=MAX_CAPABILITY_PROOF_STEPS {
            body.extend_from_slice(&edge);
            let frame = framed_capability_proof(&body);
            let padding = frame.len() - FRAME_KIND_OFFSET - body.len();
            if count == 1 {
                assert_eq!(padding, 223);
            } else if count == 128 {
                assert_eq!(padding, 0);
            }
            let record = decode_enveloped_record(&frame, 0).unwrap();
            let PileRecordContent::CapabilityProof {
                id,
                data_offset,
                data_len,
            } = record.content
            else {
                panic!("proof decoded as another record kind");
            };
            assert_eq!(data_offset, 32);
            assert_eq!(data_len, body.len());
            assert_eq!(&frame[data_offset..data_offset + data_len], &body);
            assert_eq!(id.raw, Blake3::digest(&body));
        }
        body.extend_from_slice(&edge);
        assert!(decode_enveloped_record(&framed_capability_proof(&body), 0).is_err());
    }

    #[test]
    fn native_proof_rejects_nonzero_padding_gaps_and_nonminimal_frames() {
        let first = capability_fixture(103, [104; 32]);
        let frame = framed_capability_proof(first.as_bytes());
        let padding_start = FRAME_KIND_OFFSET + first.as_bytes().len();
        for index in padding_start..frame.len() {
            let mut bad = frame.clone();
            bad[index] = 1;
            assert!(
                decode_enveloped_record(&bad, 0).is_err(),
                "padding at {index}"
            );
        }
        let mut oversized = frame.clone();
        oversized.extend_from_slice(&[0; ENVELOPE_BLOCK_LEN]);
        oversized[FRAME_MAGIC_LEN..FRAME_KIND_OFFSET].copy_from_slice(&3u32.to_le_bytes());
        assert!(decode_enveloped_record(&oversized, 0).is_err());

        let mut gap = first.as_bytes().to_vec();
        gap.extend_from_slice(&[0; CAPABILITY_PROOF_EDGE_LEN]);
        gap.extend_from_slice(&first.as_bytes()[CAPABILITY_PROOF_HEADER_LEN..]);
        assert!(decode_enveloped_record(&framed_capability_proof(&gap), 0).is_err());
    }

    #[test]
    fn retired_action_proofs_are_readable_but_never_current_authority() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "retired-action-proof.pile");
        let body = crate::capability::LEGACY_ACTION_PROOF_FIXTURE;
        let mut frame = retired_capability_v1_record(&body);
        frame[FRAME_BODY_OFFSET - 32..FRAME_BODY_OFFSET]
            .copy_from_slice(&record_kind::KIND_AUTH_PROOF_V2);
        append_test_bytes(&path, &frame);
        let mut pile = Pile::open(&path).unwrap();
        assert!(matches!(
            PileRecords::open(&path)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .content,
            PileRecordContent::RetiredCapabilityProof
        ));
        assert!(pile.snapshot().unwrap().proofs().unwrap().next().is_none());
        assert!(CapabilityProof::from_bytes(&body).is_err());
        let current = capability_fixture(91, [92; 32]);
        pile.insert_proof(current.clone()).unwrap();
        assert_eq!(
            pile.snapshot()
                .unwrap()
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![current]
        );
        pile.close().unwrap();
    }

    const TEST_UNKNOWN_KIND_A: RawInline = [0xA5; 32];
    const TEST_UNKNOWN_KIND_B: RawInline = [0x5A; 32];

    /// A current-framing record of an unknown kind.
    fn test_envelope_bytes(kind: RawInline, span_blocks: u32, physical_len: usize) -> Vec<u8> {
        assert!(physical_len >= FRAME_BODY_OFFSET);
        let mut bytes = vec![0xC3; physical_len];
        bytes[..FRAME_MAGIC_LEN].copy_from_slice(&FRAME_MAGIC);
        bytes[FRAME_MAGIC_LEN..FRAME_MAGIC_LEN + 4].copy_from_slice(&span_blocks.to_le_bytes());
        bytes[FRAME_BODY_OFFSET - 32..FRAME_BODY_OFFSET].copy_from_slice(&kind);
        bytes
    }

    /// A legacy V1-framing record of the given 16-byte kind.
    fn test_envelope_v1_bytes(kind: RawId, span_blocks: u32, physical_len: usize) -> Vec<u8> {
        assert!(physical_len >= 36);
        let mut bytes = vec![0xC3; physical_len];
        bytes[..16].copy_from_slice(&MAGIC_MARKER_ENVELOPE);
        bytes[16..32].copy_from_slice(&kind);
        bytes[32..36].copy_from_slice(&span_blocks.to_le_bytes());
        bytes
    }

    fn append_test_bytes(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn retired_blob_want_record(
        request: WantRequest,
        asserted: bool,
    ) -> RetiredBlobWantRecordHeader {
        let WantRequest::Blob { handle } = request else {
            panic!("retired blob-WANT fixture requires a blob request")
        };
        RetiredBlobWantRecordHeader {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: if asserted {
                record_kind::KIND_BLOB_WANT_ASSERT
            } else {
                record_kind::KIND_BLOB_WANT_RETRACT
            },
            handle: handle.raw,
            reserved: [0; 160],
        }
    }

    fn retired_typed_want_record(request: WantRequest, asserted: bool) -> WantRecordHeader {
        assert!(!matches!(request, WantRequest::Blob { .. }));
        let bytes = request.to_bytes();
        WantRecordHeader {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: if asserted {
                record_kind::KIND_WANT_ASSERT
            } else {
                record_kind::KIND_WANT_RETRACT
            },
            request_kind: bytes[0],
            kind_pad: [0; 31],
            field_a: bytes[1..33].try_into().unwrap(),
            field_b: bytes[33..65].try_into().unwrap(),
            field_c: bytes[65..97].try_into().unwrap(),
            reserved: [0; 64],
        }
    }

    fn retired_typed_derive_v1_record(
        source: CollectionHandle,
        target: CollectionHandle,
        input: Inline<Hash<Blake3>>,
        asserted: bool,
    ) -> WantRecordHeader {
        WantRecordHeader {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: if asserted {
                record_kind::KIND_WANT_ASSERT
            } else {
                record_kind::KIND_WANT_RETRACT
            },
            request_kind: WANT_REQUEST_KIND_DERIVE_V1,
            kind_pad: [0; 31],
            field_a: source.raw,
            field_b: target.raw,
            field_c: input.raw,
            reserved: [0; 64],
        }
    }

    fn collection_test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn collection_test_hash(byte: u8) -> Inline<Hash<Blake3>> {
        Inline::new([byte; 32])
    }

    fn collection_test_collection(byte: u8) -> CollectionHandle {
        Inline::new([byte; 32])
    }

    fn register_simplearchive_collection(pile: &mut Pile, name: &str) -> Collection<SimpleArchive> {
        let authority = SigningKey::from_bytes(&[0xAA; 32]).verifying_key();
        pile.collection(
            name,
            CollectionPolicy::new(
                AdmissionPolicy::direct(authority),
                AdmissionPolicy::direct(authority),
            ),
        )
        .unwrap()
    }

    fn collection_test_records() -> Vec<CollectionRecord> {
        let source = collection_test_collection(1);
        let target = collection_test_collection(2);
        let key = SigningKey::from_bytes(&[7; 32]);
        vec![
            CollectionRecord::Commit(CollectionCommit::sign(
                &key,
                source,
                collection_test_hash(6),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                source,
                collection_test_hash(6),
                collection_test_hash(7),
                collection_test_hash(8),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                target,
                collection_test_hash(8),
                collection_test_hash(9),
            )),
        ]
    }

    #[test]
    fn native_capability_proof_record_round_trips_and_deduplicates_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "proof.pile");
        let proof = capability_fixture(11, [12; 32]);
        assert_eq!(proof.as_bytes().len(), 257);

        let mut pile = Pile::open(&path).unwrap();
        pile.insert_proof(proof.clone()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 512);
        pile.insert_proof(proof.clone()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 512);
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(snapshot.proof(proof.id()).unwrap(), Some(proof.clone()));
        assert_eq!(snapshot.proof(Inline::new([0; 32])).unwrap(), None);
        assert_eq!(
            snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![proof.clone()]
        );
        pile.close().unwrap();

        let mut records = PileRecords::open(&path).unwrap();
        let record = records.next().unwrap().unwrap();
        let PileRecordContent::CapabilityProof {
            id,
            data_offset,
            data_len,
        } = record.content
        else {
            panic!("native proof decoded as another record kind");
        };
        assert_eq!(id, proof.id());
        assert_eq!(data_offset, 32);
        assert_eq!(data_len, proof.as_bytes().len());
        assert_eq!(
            &records.bytes()[data_offset..data_offset + data_len],
            proof.as_bytes()
        );
        assert!(records.next().is_none());

        let mut reopened = Pile::open(&path).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(
            snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![proof]
        );
        reopened.close().unwrap();
    }

    #[test]
    fn native_proof_views_survive_refresh_mapping_replacement_and_store_close() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "owned-proofs.pile");
        let expected = capability_fixture(81, [82; 32]);
        let later = capability_fixture(83, [84; 32]);
        let mut pile = Pile::open(&path).unwrap();
        pile.insert_proof(expected.clone()).unwrap();

        let snapshot = pile.snapshot().unwrap();
        let proof = snapshot.proof(expected.id()).unwrap().unwrap();
        let repeated = snapshot.proof(expected.id()).unwrap().unwrap();
        let mut proofs = snapshot.proofs().unwrap();
        let mut retained_iterator = snapshot.proofs().unwrap();
        let iterated = proofs.next().unwrap().unwrap();
        assert!(proofs.next().is_none());
        let body_offset = FRAME_KIND_OFFSET;
        assert_eq!(
            proof.as_bytes().as_ptr(),
            pile.mmap.as_ptr().wrapping_add(body_offset),
            "the indexed proof must own the decoded mmap slice, not a copied vector"
        );
        assert_eq!(proof.as_bytes().as_ptr(), repeated.as_bytes().as_ptr());
        assert_eq!(proof.as_bytes().as_ptr(), iterated.as_bytes().as_ptr());
        let original_mapping = Arc::downgrade(&pile.mmap);
        let mapped_len = pile.mmap.len();

        // A real append past the old mapping forces a replacement. The
        // existing proof leaf and its frozen snapshot still own the old view.
        pile.put::<UnknownBlob, _>(Bytes::from_source(vec![7_u8; mapped_len]))
            .unwrap();
        assert!(!Arc::ptr_eq(
            &original_mapping.upgrade().unwrap(),
            &pile.mmap
        ));
        pile.insert_proof(later.clone()).unwrap();
        let refreshed = pile.snapshot().unwrap();
        assert!(snapshot.proof(later.id()).unwrap().is_none());
        assert_eq!(refreshed.proof(later.id()).unwrap(), Some(later));
        assert_eq!(
            refreshed
                .proof(expected.id())
                .unwrap()
                .unwrap()
                .as_bytes()
                .as_ptr(),
            proof.as_bytes().as_ptr()
        );
        let before_duplicate = std::fs::metadata(&path).unwrap().len();
        pile.insert_proof(proof.clone()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before_duplicate);

        drop((snapshot, refreshed, proofs, repeated, iterated));
        pile.close().unwrap();
        assert!(original_mapping.upgrade().is_some());
        assert_eq!(proof, expected);
        proof.verify_signatures().unwrap();
        let after_close = retained_iterator.next().unwrap().unwrap();
        assert_eq!(after_close.as_bytes().as_ptr(), proof.as_bytes().as_ptr());
        assert!(retained_iterator.next().is_none());
        drop((proof, after_close, retained_iterator));
        assert!(original_mapping.upgrade().is_none());
    }

    #[test]
    fn native_capability_proofs_cat_as_an_order_independent_set_union() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = fresh_empty_pile_path(&dir, "proof-a.pile");
        let path_b = fresh_empty_pile_path(&dir, "proof-b.pile");
        let path_ab = dir.path().join("proof-ab.pile");
        let path_ba = dir.path().join("proof-ba.pile");
        let first = capability_fixture(71, [72; 32]);
        let second = capability_fixture(73, [74; 32]);
        let third = capability_fixture(75, [76; 32]);

        let mut a = Pile::open(&path_a).unwrap();
        a.insert_proof(first.clone()).unwrap();
        a.insert_proof(second.clone()).unwrap();
        a.close().unwrap();
        let mut b = Pile::open(&path_b).unwrap();
        b.insert_proof(first.clone()).unwrap();
        b.insert_proof(third.clone()).unwrap();
        b.close().unwrap();

        let bytes_a = std::fs::read(&path_a).unwrap();
        let bytes_b = std::fs::read(&path_b).unwrap();
        let mut ab = bytes_a.clone();
        ab.extend_from_slice(&bytes_b);
        std::fs::write(&path_ab, ab).unwrap();
        let mut ba = bytes_b;
        ba.extend_from_slice(&bytes_a);
        std::fs::write(&path_ba, ba).unwrap();

        let mut expected = vec![first, second, third];
        expected.sort_unstable_by_key(|proof| proof.id().raw);
        for path in [&path_ab, &path_ba] {
            let mut pile = Pile::open(path).unwrap();
            let snapshot = pile.snapshot().unwrap();
            let actual = snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(actual, expected);
            pile.close().unwrap();
        }
    }

    #[test]
    fn retired_capability_proof_v1_is_known_inert() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "retired-proof-v1.pile");
        let bytes = retired_capability_v1_record(&[0; 160]);
        append_test_bytes(&path, &bytes);

        let mut records = PileRecords::open(&path).unwrap();
        assert!(matches!(
            records.next().unwrap().unwrap().content,
            PileRecordContent::RetiredCapabilityProof
        ));
        assert!(records.next().is_none());

        let mut pile = Pile::open(&path).unwrap();
        assert!(pile.snapshot().unwrap().proofs().unwrap().next().is_none());
        pile.close().unwrap();
    }

    #[test]
    fn retired_capability_proof_v1_retains_its_structural_bounds() {
        let dir = tempfile::tempdir().unwrap();

        let invalid_key_path = fresh_empty_pile_path(&dir, "retired-invalid-key.pile");
        let mut invalid_key = [0; 160];
        let mut invalid_signer = [0; 32];
        invalid_signer[0] = 2;
        invalid_key[..32].copy_from_slice(&invalid_signer);
        assert!(VerifyingKey::from_bytes(&invalid_signer).is_err());
        append_test_bytes(
            &invalid_key_path,
            &retired_capability_v1_record(&invalid_key),
        );
        let mut pile = Pile::open(&invalid_key_path).unwrap();
        assert!(matches!(
            pile.refresh(),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));
        pile.close().unwrap();

        let overlong_path = fresh_empty_pile_path(&dir, "retired-overlong.pile");
        let overlong = vec![0; 32 + 128 * (MAX_CAPABILITY_PROOF_STEPS + 1)];
        append_test_bytes(&overlong_path, &retired_capability_v1_record(&overlong));
        let mut pile = Pile::open(&overlong_path).unwrap();
        assert!(matches!(
            pile.refresh(),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));
        pile.close().unwrap();
    }

    #[test]
    fn known_capability_proof_record_rejects_root_only_and_nonzero_padding() {
        let dir = tempfile::tempdir().unwrap();
        let one_edge = capability_fixture(21, [22; 32]);

        let root_only_path = fresh_empty_pile_path(&dir, "root-only.pile");
        let mut root_only = Vec::with_capacity(256);
        root_only.extend_from_slice(
            RecordFrame {
                magic: FRAME_MAGIC,
                span_blocks: 1u32.to_le_bytes(),
                record_kind: CAPABILITY_PROOF_MAGIC,
            }
            .as_bytes(),
        );
        root_only.extend_from_slice(
            &one_edge.as_bytes()[CAPABILITY_PROOF_MAGIC.len()..CAPABILITY_PROOF_HEADER_LEN],
        );
        root_only.resize(256, 0);
        append_test_bytes(&root_only_path, &root_only);
        let mut pile = Pile::open(&root_only_path).unwrap();
        assert!(matches!(
            pile.refresh(),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));
        pile.close().unwrap();

        let padded_path = fresh_empty_pile_path(&dir, "bad-padding.pile");
        let two_edge = one_edge
            .extend(
                &SigningKey::from_bytes(&[22; 32]),
                Capability::new(Inline::new([23; 32]), CapabilityMode::Invoke),
                None,
                SigningKey::from_bytes(&[24; 32]).verifying_key(),
            )
            .unwrap();
        let padding_offset = 32 + two_edge.as_bytes().len();
        let mut pile = Pile::open(&padded_path).unwrap();
        pile.insert_proof(two_edge).unwrap();
        pile.close().unwrap();
        let mut bytes = std::fs::read(&padded_path).unwrap();
        assert_eq!(bytes.len(), 512);
        bytes[padding_offset] = 1;
        std::fs::write(&padded_path, bytes).unwrap();
        let mut pile = Pile::open(&padded_path).unwrap();
        assert!(matches!(
            pile.refresh(),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));
        pile.close().unwrap();
    }

    #[test]
    fn reframe_preserves_native_capability_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "proof-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "proof-destination.pile");
        let proof = capability_fixture(31, [32; 32]);
        let mut source = Pile::open(&source_path).unwrap();
        source.insert_proof(proof.clone()).unwrap();
        source.close().unwrap();

        let mut destination = Pile::open(&destination_path).unwrap();
        let stats = reframe_into(&source_path, &mut destination).unwrap();
        assert_eq!(stats.capability_proofs, 1);
        assert_eq!(stats.dropped_inert, 0);
        let snapshot = destination.snapshot().unwrap();
        assert_eq!(
            snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![proof]
        );
        destination.close().unwrap();
    }

    #[test]
    fn retained_rewrite_preserves_proofs_without_treating_resources_as_blob_roots() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "proof-retention-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "proof-retention-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let valid_attachment = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"valid attachment".to_vec()))
            .unwrap();
        let invalid_attachment = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"invalid attachment".to_vec()))
            .unwrap();
        let definition = source.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        let invalid_definition = source
            .put::<SimpleArchive, _>(
                entity! { crate::metadata::tag: crate::metadata::KIND_BLOB_ENCODING }
                    .facts()
                    .clone(),
            )
            .unwrap();
        let valid_proof = CapabilityProof::issue_root(
            &SigningKey::from_bytes(&[41; 32]),
            CapabilityResource::new(valid_attachment.raw),
            Capability::new(definition, CapabilityMode::Invoke),
            None,
            SigningKey::from_bytes(&[42; 32]).verifying_key(),
        );
        let invalid_source = CapabilityProof::issue_root(
            &SigningKey::from_bytes(&[51; 32]),
            CapabilityResource::new(invalid_attachment.raw),
            Capability::new(invalid_definition, CapabilityMode::Invoke),
            None,
            SigningKey::from_bytes(&[52; 32]).verifying_key(),
        );
        let mut invalid_bytes = invalid_source.as_bytes().to_vec();
        let last = invalid_bytes.len() - 1;
        invalid_bytes[last] ^= 1;
        let invalid_proof = CapabilityProof::from_bytes(&invalid_bytes).unwrap();
        assert!(invalid_proof.verify_signatures().is_err());
        source.insert_proof(valid_proof.clone()).unwrap();
        source.insert_proof(invalid_proof.clone()).unwrap();

        let mut destination = Pile::open(&destination_path).unwrap();
        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.retained_blobs, 2);
        assert_eq!(stats.capability_proofs, 2);

        let reader = destination.snapshot().unwrap();
        assert!(reader.get::<Blob<SimpleArchive>, _>(definition).is_ok());
        assert!(reader
            .get::<Blob<SimpleArchive>, _>(invalid_definition)
            .is_ok());
        assert!(reader
            .get::<Blob<UnknownBlob>, _>(valid_attachment)
            .is_err());
        assert!(reader
            .get::<Blob<UnknownBlob>, _>(invalid_attachment)
            .is_err());
        assert!(
            reader.wants().unwrap().next().is_none(),
            "retention never creates WANTs"
        );
        drop(reader);

        let stored = destination
            .snapshot()
            .unwrap()
            .proofs()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert!(stored.contains(&valid_proof));
        assert!(stored.contains(&invalid_proof));
        source.close().unwrap();
        destination.close().unwrap();
    }

    fn fixed_collection_header(bytes: &[u8]) -> [u8; V3_HEADER_LEN] {
        bytes
            .try_into()
            .expect("collection headers are exactly one fixed pile header")
    }

    fn legacy_collection_test_headers() -> Vec<(LegacyCollectionRecordKindV3, [u8; V3_HEADER_LEN])>
    {
        vec![
            (
                LegacyCollectionRecordKindV3::Definition,
                fixed_collection_header(
                    CollectionDefinitionHeaderV3 {
                        magic_marker: MAGIC_MARKER_COLLECTION_DEFINITION_V3,
                        scope: [1; 16],
                        representation: [2; 16],
                        recipe: [3; 16],
                        reserved: [0; 192],
                    }
                    .as_bytes(),
                ),
            ),
            (
                LegacyCollectionRecordKindV3::Commit,
                fixed_collection_header(
                    CollectionCommitHeaderV3 {
                        magic_marker: MAGIC_MARKER_COLLECTION_COMMIT_V3,
                        collection: [4; 16],
                        data: [5; 32],
                        metadata: [6; 32],
                        public_key: [7; 32],
                        signature_r: [8; 32],
                        signature_s: [9; 32],
                        reserved: [0; 64],
                    }
                    .as_bytes(),
                ),
            ),
            (
                LegacyCollectionRecordKindV3::Merge,
                fixed_collection_header(
                    CollectionMergeHeaderV3 {
                        magic_marker: MAGIC_MARKER_COLLECTION_MERGE_V3,
                        collection: [10; 16],
                        low: [11; 32],
                        high: [12; 32],
                        result: [13; 32],
                        reserved: [0; 128],
                    }
                    .as_bytes(),
                ),
            ),
            (
                LegacyCollectionRecordKindV3::Derive,
                fixed_collection_header(
                    CollectionDeriveHeaderV3 {
                        magic_marker: MAGIC_MARKER_COLLECTION_DERIVE_V3,
                        source: [14; 16],
                        target: [15; 16],
                        input: [16; 32],
                        output: [17; 32],
                        reserved: [0; 144],
                    }
                    .as_bytes(),
                ),
            ),
        ]
    }

    fn legacy_collection_headers_at(
        path: &Path,
    ) -> Vec<(LegacyCollectionRecordKindV3, [u8; V3_HEADER_LEN])> {
        let mut records = PileRecords::open(path).unwrap();
        let mut found = Vec::new();
        while let Some(record) = records.next() {
            let record = record.unwrap();
            let PileRecordContent::LegacyCollectionV3 { kind } = record.content else {
                continue;
            };
            let header = records.bytes()[record.offset..record.offset + record.len]
                .try_into()
                .unwrap();
            found.push((kind, header));
        }
        found
    }

    fn sorted_collection_records(mut records: Vec<CollectionRecord>) -> Vec<CollectionRecord> {
        records.sort_by_key(CollectionRecord::fingerprint);
        records
    }

    #[test]
    fn legacy_collection_header_index_uses_the_full_256_byte_key() {
        let low = [0u8; V3_HEADER_LEN];
        let mut high = low;
        high[V3_HEADER_LEN - 1] = 1;

        let mut index = LegacyCollectionHeaderIndex::new();
        index.insert(&Entry::new(&high));
        index.insert(&Entry::new(&low));
        index.insert(&Entry::new(&high));

        assert_eq!(index.len(), 2);
        assert_eq!(
            index.iter_ordered().copied().collect::<Vec<_>>(),
            vec![low, high]
        );
    }

    fn invalidate_collection_commit(commit: CollectionCommit) -> CollectionCommit {
        let (signature_r, signature_s) = commit.signature();
        let mut forged_r = signature_r.raw;
        forged_r[0] ^= 1;
        let forged = CollectionCommit::from_parts(
            commit.collection(),
            commit.data(),
            commit.metadata(),
            commit.public_key(),
            Inline::new(forged_r),
            signature_s,
        );
        assert!(forged.verify_strict().is_err());
        forged
    }

    #[test]
    fn enveloped_collection_record_headers_are_fixed_zero_padded_and_roundtrip() {
        let records = collection_test_records();
        let expected = [
            // A commit's six 32-byte fields fill 64..256 exactly: the tightest
            // record the pile writes, and the one that fixes the body offset.
            (record_kind::KIND_COLLECTION_COMMIT, 1, None),
            (record_kind::KIND_COLLECTION_MERGE, 2, Some(288usize)),
            (record_kind::KIND_COLLECTION_DERIVE, 1, None),
        ];

        for (record, (kind, blocks, reserved_start)) in records.into_iter().zip(expected) {
            let header = collection_record_header(&record);
            assert_eq!(header.len(), blocks as usize * ENVELOPE_BLOCK_LEN);
            assert_eq!(&header[..FRAME_MAGIC_LEN], FRAME_MAGIC.as_slice());
            assert_eq!(
                u32::from_le_bytes(
                    header[FRAME_MAGIC_LEN..FRAME_BODY_OFFSET - 32]
                        .try_into()
                        .unwrap()
                ),
                blocks
            );
            assert_eq!(
                &header[FRAME_BODY_OFFSET - 32..FRAME_BODY_OFFSET],
                kind.as_slice()
            );

            let decoded = decode_record(&header, 0).unwrap();
            assert_eq!(decoded.len, header.len());
            assert!(matches!(
                decoded.content,
                PileRecordContent::Collection { record: decoded } if decoded == record
            ));

            let Some(reserved_start) = reserved_start else {
                continue;
            };
            assert!(header[reserved_start..].iter().all(|byte| *byte == 0));
            let mut nonzero_padding = header;
            nonzero_padding[reserved_start] = 1;
            assert!(matches!(
                decode_record(&nonzero_padding, 0),
                Err(ReadError::CorruptPile { valid_length: 0 })
            ));
        }
    }

    #[test]
    fn every_current_write_path_uses_the_generic_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "all-enveloped.pile");
        let mut pile = Pile::open(&path).unwrap();

        let blob_data = vec![0x42; ENVELOPE_BLOCK_LEN + 1];
        let blob = pile
            .put::<UnknownBlob, _>(Bytes::from_source(blob_data.clone()))
            .unwrap();

        let branch_id = Id::new([1; 16]).unwrap();
        let branch_head = Inline::<Handle<SimpleArchive>>::new([2; 32]);
        pile.append_legacy_pin_for_test(branch_id, None, Some(branch_head))
            .unwrap();
        pile.append_legacy_pin_for_test(branch_id, Some(branch_head), None)
            .unwrap();

        let wanted = Inline::<Handle<UnknownBlob>>::new([5; 32]);
        pile.want(WantRequest::blob(wanted)).unwrap();
        let collection_records = collection_test_records();
        for record in &collection_records {
            pile.insert(*record).unwrap();
        }
        pile.close().unwrap();

        let expected = [
            (record_kind::KIND_BLOB, 3u32),
            (record_kind::KIND_PIN_HEAD, 1),
            (record_kind::KIND_PIN_TOMBSTONE, 1),
            (record_kind::KIND_WANT, 1),
            (record_kind::KIND_COLLECTION_COMMIT, 1),
            (record_kind::KIND_COLLECTION_MERGE, 2),
            (record_kind::KIND_COLLECTION_DERIVE, 1),
        ];
        let mut records = PileRecords::open(&path).unwrap();
        let decoded = (&mut records).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(decoded.len(), expected.len());
        for (record, (kind, blocks)) in decoded.iter().zip(expected) {
            let raw = &records.bytes()[record.offset..record.offset + record.len];
            assert_eq!(&raw[..FRAME_MAGIC_LEN], FRAME_MAGIC.as_slice());
            assert_eq!(
                u32::from_le_bytes(
                    raw[FRAME_MAGIC_LEN..FRAME_BODY_OFFSET - 32]
                        .try_into()
                        .unwrap()
                ),
                blocks
            );
            assert_eq!(
                &raw[FRAME_BODY_OFFSET - 32..FRAME_BODY_OFFSET],
                kind.as_slice()
            );
            assert_eq!(record.len, blocks as usize * ENVELOPE_BLOCK_LEN);
            // Every 32-byte field of every body starts on a 32-byte boundary
            // of the file, not merely of the record.
            assert_eq!(record.offset % ENVELOPE_BLOCK_LEN, 0);
        }
        let blob_raw = &records.bytes()[decoded[0].offset..decoded[0].offset + decoded[0].len];
        assert_eq!(&blob_raw[28..32], &3u32.to_le_bytes());
        assert_eq!(&blob_raw[72..80], &(blob_data.len() as u64).to_le_bytes());

        let mut reopened = Pile::open(&path).unwrap();
        let fetched: Blob<UnknownBlob> = reopened.snapshot().unwrap().get(blob).unwrap();
        assert_eq!(fetched.bytes.as_ref(), blob_data);
        assert_eq!(reopened.legacy_pin_head_for_test(branch_id).unwrap(), None);
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![WantRequest::blob(wanted)]
        );
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            sorted_collection_records(collection_records)
        );
        reopened.close().unwrap();
    }

    /// A pile written in any older shape re-encodes into one uniformly framed
    /// file, and everything that was live in it stays live.
    #[test]
    fn reframe_re_encodes_every_live_record_and_drops_only_inert_ones() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "mixed.pile");

        // A known retired V4 derivation carries no current state. Unknown
        // opaque ownership is covered by the fail-closed test separately.
        let retired_derive = CollectionDeriveHeaderEnvelopeV1V4 {
            envelope_marker: MAGIC_MARKER_ENVELOPE,
            record_kind: MAGIC_MARKER_COLLECTION_DERIVE_V4,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            source: [1; 32],
            target: [2; 32],
            input: [3; 32],
            output: [4; 32],
            reserved: [0; 92],
        };
        append_test_bytes(&source_path, retired_derive.as_bytes());

        let payloads: Vec<Vec<u8>> = vec![vec![7u8; 5], vec![8u8; ENVELOPE_BLOCK_LEN + 3]];
        let mut handles = Vec::new();
        let mut source = Pile::open(&source_path).unwrap();
        for payload in &payloads {
            handles.push(
                source
                    .put::<UnknownBlob, _>(Bytes::from_source(payload.clone()))
                    .unwrap(),
            );
        }

        // A pin that moves twice and one that ends tombstoned: last-writer-wins
        // survives only if the replay keeps source order.
        let moved = Id::new([21; 16]).unwrap();
        let cleared = Id::new([22; 16]).unwrap();
        let first = Inline::<Handle<SimpleArchive>>::new([31; 32]);
        let second = Inline::<Handle<SimpleArchive>>::new([32; 32]);
        source
            .append_legacy_pin_for_test(moved, None, Some(first))
            .unwrap();
        source
            .append_legacy_pin_for_test(moved, Some(first), Some(second))
            .unwrap();
        source
            .append_legacy_pin_for_test(cleared, None, Some(first))
            .unwrap();
        source
            .append_legacy_pin_for_test(cleared, Some(first), None)
            .unwrap();

        let current_want = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([41; 32]));
        let retired_kept = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([42; 32]));
        let retired_dropped = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([43; 32]));
        let retired_derive_want =
            WantRequest::derive(collection_test_collection(45), collection_test_hash(46));
        source.want(current_want).unwrap();

        let records = collection_test_records();
        for record in &records {
            source.insert(*record).unwrap();
        }
        let source_timestamps: Vec<u64> = {
            let reader = source.snapshot().unwrap();
            handles
                .iter()
                .map(|handle| reader.metadata(*handle).unwrap().unwrap().timestamp)
                .collect()
        };
        source.close().unwrap();
        append_test_bytes(
            &source_path,
            retired_blob_want_record(retired_kept, true).as_bytes(),
        );
        append_test_bytes(
            &source_path,
            retired_blob_want_record(retired_dropped, true).as_bytes(),
        );
        append_test_bytes(
            &source_path,
            retired_blob_want_record(retired_dropped, false).as_bytes(),
        );
        append_test_bytes(
            &source_path,
            retired_typed_derive_v1_record(
                collection_test_collection(44),
                collection_test_collection(45),
                collection_test_hash(46),
                true,
            )
            .as_bytes(),
        );
        append_test_bytes(
            &source_path,
            retired_typed_derive_v1_record(
                collection_test_collection(47),
                collection_test_collection(45),
                collection_test_hash(46),
                false,
            )
            .as_bytes(),
        );

        let dest_path = fresh_empty_pile_path(&dir, "reframed.pile");
        let mut destination = Pile::open(&dest_path).unwrap();
        let stats = reframe_into(&source_path, &mut destination).unwrap();
        assert_eq!(stats.blobs, payloads.len());
        assert_eq!(stats.pin_updates, 4);
        assert_eq!(stats.wants, 3);
        assert_eq!(stats.retired_want_records, 5);
        assert_eq!(stats.collection_records, records.len());
        assert_eq!(stats.dropped_inert, 1);
        destination.close().unwrap();

        // Every record in the result carries the current frame.
        let mut reframed = PileRecords::open(&dest_path).unwrap();
        let decoded = (&mut reframed).collect::<Result<Vec<_>, _>>().unwrap();
        for record in &decoded {
            let raw = &reframed.bytes()[record.offset..record.offset + record.len];
            assert_eq!(&raw[..FRAME_MAGIC_LEN], FRAME_MAGIC.as_slice());
            assert_eq!(record.offset % ENVELOPE_BLOCK_LEN, 0);
        }

        let mut result = Pile::open(&dest_path).unwrap();
        result.refresh().unwrap();
        assert_eq!(result.opaque_record_count().unwrap(), 0);
        assert_eq!(
            result.legacy_pin_head_for_test(moved).unwrap(),
            Some(second)
        );
        assert_eq!(result.legacy_pin_head_for_test(cleared).unwrap(), None);
        assert_eq!(
            result
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![current_want, retired_kept, retired_derive_want]
        );
        assert_eq!(
            result
                .snapshot()
                .unwrap()
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            sorted_collection_records(records)
        );

        // Payload bytes and handles survive. Insertion timestamps do not, and
        // must not be expected to: they are a local fact about a particular
        // file, never synced, and a rewrite is a fresh append.
        let reader = result.snapshot().unwrap();
        let newest_source = source_timestamps.iter().copied().max().unwrap();
        for (handle, payload) in handles.iter().zip(&payloads) {
            let blob: Blob<UnknownBlob> = reader.get(*handle).unwrap();
            assert_eq!(blob.bytes.as_ref(), payload.as_slice());
            assert!(reader.metadata(*handle).unwrap().unwrap().timestamp >= newest_source);
        }
        drop(reader);
        result.close().unwrap();
    }

    /// A signature covers a transcript, not a frame. Prove it rather than
    /// assuming it: a commit re-encoded into a different framing must still
    /// verify against the same key.
    #[test]
    fn reframing_a_signed_commit_does_not_invalidate_it() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "signed.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let signed: Vec<CollectionCommit> = collection_test_records()
            .into_iter()
            .filter_map(|record| match record {
                CollectionRecord::Commit(commit) => Some(commit),
                _ => None,
            })
            .collect();
        assert!(!signed.is_empty());
        for commit in &signed {
            assert!(commit.verify_strict().is_ok());
            source.insert(CollectionRecord::Commit(*commit)).unwrap();
        }
        source.close().unwrap();

        let dest_path = fresh_empty_pile_path(&dir, "signed-reframed.pile");
        let mut destination = Pile::open(&dest_path).unwrap();
        reframe_into(&source_path, &mut destination).unwrap();
        destination.close().unwrap();

        let mut result = Pile::open(&dest_path).unwrap();
        let mut verified = 0usize;
        let snapshot = result.snapshot().unwrap();
        for record in snapshot.records().unwrap() {
            let CollectionRecord::Commit(commit) = record.unwrap() else {
                continue;
            };
            commit
                .verify_strict()
                .expect("a re-encoded commit still verifies");
            verified += 1;
        }
        assert_eq!(verified, signed.len());
        result.close().unwrap();
    }

    /// The point of the 32-byte kind: a reader holding only the file can
    /// resolve what an unfamiliar record *is*, not merely recognise it.
    #[test]
    fn written_record_kinds_resolve_to_their_descriptions() {
        use crate::inline::encodings::genid::GenId;
        use crate::metadata;
        use crate::prelude::find;
        use crate::prelude::pattern;

        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "self-describing.pile");
        let mut pile = Pile::open(&path).unwrap();
        let description_blob_count = description_blobs().len();
        assert_eq!(
            pile.publish_record_kind_descriptions().unwrap(),
            description_blob_count
        );

        let branch_id = Id::new([3; 16]).unwrap();
        pile.append_legacy_pin_for_test(branch_id, None, Some(Inline::new([4; 32])))
            .unwrap();
        pile.want(WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
            [5; 32],
        )))
        .unwrap();
        for record in &collection_test_records() {
            pile.insert(*record).unwrap();
        }
        let reader = pile.snapshot().unwrap();

        let mut records = PileRecords::open(&path).unwrap();
        let decoded = (&mut records).collect::<Result<Vec<_>, _>>().unwrap();
        let mut resolved = 0usize;
        for record in &decoded {
            let raw = &records.bytes()[record.offset..record.offset + record.len];
            assert_eq!(&raw[..FRAME_MAGIC_LEN], FRAME_MAGIC.as_slice());
            let kind: RawInline = raw[FRAME_BODY_OFFSET - 32..FRAME_BODY_OFFSET]
                .try_into()
                .unwrap();
            let description: TribleSet = reader
                .get::<TribleSet, SimpleArchive>(Inline::<Handle<SimpleArchive>>::new(kind))
                .expect("every written record kind resolves in the pile that wrote it");
            let tag: Inline<GenId> = crate::inline::IntoInline::to_inline(KIND_PILE_RECORD);
            let named = find!(
                (name: Inline<Handle<crate::blob::encodings::utf8string::UTF8String>>),
                pattern!(&description, [{
                    metadata::tag: Inline::<GenId>::new(tag.raw),
                    metadata::name: ?name
                }])
            )
            .count();
            assert_eq!(named, 1, "a record kind describes exactly one record kind");
            resolved += 1;
        }
        assert!(resolved >= 17);
        drop(reader);
        pile.close().unwrap();
    }

    #[test]
    fn retained_rewrite_keeps_descriptions_of_every_emitted_non_blob_kind() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "kind-retention-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "kind-retention-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();
        source.publish_record_kind_descriptions().unwrap();

        source
            .append_legacy_pin_for_test(collection_test_id(71), None, Some(Inline::new([72; 32])))
            .unwrap();
        source
            .want(WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
                [73; 32],
            )))
            .unwrap();
        let collection_records = collection_test_records();
        for record in collection_records.iter().copied() {
            source.insert(record).unwrap();
        }
        let proof = capability_fixture(74, [75; 32]);
        source.insert_proof(proof).unwrap();

        source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Preserve,
            )
            .unwrap();

        let reader = destination.snapshot().unwrap();
        let mut expected = vec![
            pin_head_record_kind(),
            want_record_kind(),
            capability_proof_record_kind(),
        ];
        expected.extend(collection_records.into_iter().map(collection_record_kind));
        for kind in expected {
            assert_record_kind_description_resident(&reader, kind);
        }
        assert_record_kind_description_resident(&reader, blob_record_kind());

        drop(reader);
        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn blob_frames_do_not_self_root_the_blob_kind_description() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "blob-kind-source.pile");
        let empty_destination_path = fresh_empty_pile_path(&dir, "blob-kind-empty.pile");
        let rooted_destination_path = fresh_empty_pile_path(&dir, "blob-kind-rooted.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut empty_destination = Pile::open(&empty_destination_path).unwrap();
        let mut rooted_destination = Pile::open(&rooted_destination_path).unwrap();
        source.publish_record_kind_descriptions().unwrap();
        let payload = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"independently rooted".to_vec()))
            .unwrap();

        let stats = source
            .rewrite_retained_into(
                &mut empty_destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();

        assert_eq!(stats.retained_blobs, 0);
        assert!(!empty_destination
            .snapshot()
            .unwrap()
            .contains_blob(blob_record_kind())
            .unwrap());

        let mut roots = RetentionRoots::new();
        roots.retain_direct(payload);
        source
            .rewrite_retained_into(&mut rooted_destination, &roots, WantRewritePolicy::Drop)
            .unwrap();
        let reader = rooted_destination.snapshot().unwrap();
        assert!(reader.contains_blob(payload).unwrap());
        assert_record_kind_description_resident(&reader, blob_record_kind());
        drop(reader);

        empty_destination.close().unwrap();
        rooted_destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn dropped_wants_do_not_root_their_historical_kind_description() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "dropped-want-kind-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "dropped-want-kind-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();
        source.publish_record_kind_descriptions().unwrap();
        source
            .want(WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
                [76; 32],
            )))
            .unwrap();

        source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();

        let reader = destination.snapshot().unwrap();
        assert!(reader.wants().unwrap().next().is_none());
        assert!(!reader.contains_blob(want_record_kind()).unwrap());
        assert!(!reader.contains_blob(blob_record_kind()).unwrap());
        drop(reader);
        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn envelope_numeric_fields_are_canonical_little_endian() {
        let header = BlobRecordHeader::new(
            0x0102_0304,
            0x1112_1314_1516_1718,
            0x2122_2324_2526_2728,
            collection_test_hash(9),
        );
        let bytes = header.as_bytes();
        assert_eq!(&bytes[28..32], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&bytes[64..72], &0x1112_1314_1516_1718u64.to_le_bytes());
        assert_eq!(&bytes[72..80], &0x2122_2324_2526_2728u64.to_le_bytes());

        assert_eq!(envelope_blocks_for_payload(0), Some(1));
        assert_eq!(envelope_blocks_for_payload(255), Some(2));
        assert_eq!(envelope_blocks_for_payload(256), Some(2));
        assert_eq!(envelope_blocks_for_payload(257), Some(3));
        #[cfg(target_pointer_width = "64")]
        {
            let largest_payload = (u32::MAX as usize - 1) * ENVELOPE_BLOCK_LEN;
            assert_eq!(envelope_blocks_for_payload(largest_payload), Some(u32::MAX));
            assert_eq!(envelope_blocks_for_payload(largest_payload + 1), None);
        }
        assert_eq!(envelope_blocks_for_payload(usize::MAX), None);
    }

    #[test]
    fn legacy_v4_commit_remains_current_and_unsigned_equations_are_inert() {
        for record in collection_test_records() {
            let mut header = [0u8; V3_HEADER_LEN];
            match record {
                CollectionRecord::Commit(commit) => {
                    let (signature_r, signature_s) = commit.signature();
                    header.copy_from_slice(
                        CollectionCommitHeaderV4 {
                            magic_marker: MAGIC_MARKER_COLLECTION_COMMIT_V4,
                            collection: commit.collection().raw,
                            data: commit.data().raw,
                            metadata: commit.metadata().raw,
                            public_key: commit.public_key().raw,
                            signature_r: signature_r.raw,
                            signature_s: signature_s.raw,
                            reserved: [0; 48],
                        }
                        .as_bytes(),
                    );
                }
                CollectionRecord::Merge(merge) => {
                    let (low, high) = merge.inputs();
                    header.copy_from_slice(
                        CollectionMergeHeaderV4 {
                            magic_marker: MAGIC_MARKER_COLLECTION_MERGE_V4,
                            collection: merge.collection().raw,
                            low: low.raw,
                            high: high.raw,
                            result: merge.result().raw,
                            reserved: [0; 112],
                        }
                        .as_bytes(),
                    );
                }
                CollectionRecord::Derive(derive) => {
                    let (input, output) = (derive.input(), derive.output());
                    header.copy_from_slice(
                        CollectionDeriveHeaderV4 {
                            magic_marker: MAGIC_MARKER_COLLECTION_DERIVE_V4,
                            // legacy fixture: V4 named a source, V5 does not
                            source: [0; 32],
                            target: derive.collection().raw,
                            input: input.raw,
                            output: output.raw,
                            reserved: [0; 112],
                        }
                        .as_bytes(),
                    );
                }
            }

            let original = header;
            let decoded = decode_record(&header, 0).unwrap();
            assert_eq!(decoded.len, V3_HEADER_LEN);
            match record {
                CollectionRecord::Derive(_) => assert!(matches!(
                    decoded.content,
                    PileRecordContent::RetiredCollectionDeriveV4
                )),
                CollectionRecord::Merge(merge) => {
                    let (low, high) = merge.inputs();
                    let expected = LegacyUnsignedCollectionEquation::Merge {
                        collection: merge.collection(),
                        low,
                        high,
                        result: merge.result(),
                    };
                    assert!(matches!(decoded.content,
                        PileRecordContent::LegacyUnsignedCollectionEquation { equation }
                            if equation == expected
                    ));
                }
                CollectionRecord::Commit(_) => assert!(matches!(
                    decoded.content,
                    PileRecordContent::Collection { record: decoded } if decoded == record
                )),
            }
            assert_eq!(header, original);
        }
    }

    #[test]
    fn signed_native_replay_and_reframe_preserve_bad_signature_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "signed-audit-source.pile");
        for record in collection_test_records() {
            let mut header = collection_record_header(&record);
            // Alter S, not framing or MERGE padding. Raw replay is deliberately
            // structural; checked dense ingress is a different boundary.
            header[FRAME_BODY_OFFSET + record.to_bytes().len() - 2] ^= 1;
            append_test_bytes(&source_path, &header);
        }
        let mut source = Pile::open(&source_path).unwrap();
        let evidence = source
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(evidence.len(), 3);
        for record in &evidence {
            assert!(record.verify_strict().is_err());
            assert!(CollectionRecord::from_bytes(&record.to_bytes()).is_err());
        }
        let destination_path = fresh_empty_pile_path(&dir, "signed-audit-reframed.pile");
        let mut destination = Pile::open(&destination_path).unwrap();
        let stats = reframe_into(&source_path, &mut destination).unwrap();
        assert_eq!(stats.collection_records, 3);
        assert_eq!(
            destination
                .snapshot()
                .unwrap()
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            evidence
        );
        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn reframe_rejects_opaque_ownership_before_any_output() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "opaque-reframe-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "opaque-reframe-destination.pile");
        append_test_bytes(
            &source_path,
            &collection_record_header(&collection_test_records()[0]),
        );
        append_test_bytes(
            &source_path,
            &test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, ENVELOPE_BLOCK_LEN),
        );
        let mut destination = Pile::open(&destination_path).unwrap();
        assert!(matches!(
            reframe_into(&source_path, &mut destination),
            Err(PileReframeError::OpaqueRecord {
                offset: ENVELOPE_BLOCK_LEN,
                ..
            })
        ));
        assert_eq!(std::fs::metadata(&destination_path).unwrap().len(), 0);
        destination.close().unwrap();
    }

    #[test]
    fn unsigned_equations_survive_rewrite_with_resident_dependency_closure() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "unsigned-source.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let child = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"legacy child".to_vec()))
            .unwrap();
        let input = source
            .put::<UnknownBlob, _>(Bytes::from_source(child.raw.to_vec()))
            .unwrap();
        let output = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"legacy output".to_vec()))
            .unwrap();
        let collection = source
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        let orphan = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"unowned".to_vec()))
            .unwrap();
        source.close().unwrap();
        let merge = LegacyCollectionMergeRecordHeader {
            magic: FRAME_MAGIC,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            record_kind: record_kind::KIND_COLLECTION_MERGE_UNSIGNED,
            collection: collection.raw,
            low: [0; 32],
            high: input.raw,
            result: output.raw,
            reserved: [0; 64],
        };
        let derive = CollectionDeriveHeaderEnvelopeV1 {
            envelope_marker: MAGIC_MARKER_ENVELOPE,
            record_kind: MAGIC_MARKER_COLLECTION_DERIVE_V5,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            target: collection.raw,
            input: input.raw,
            output: output.raw,
            reserved: [0; 124],
        };
        append_test_bytes(&source_path, merge.as_bytes());
        append_test_bytes(&source_path, derive.as_bytes());
        let mut source = Pile::open(&source_path).unwrap();
        let before = source.snapshot().unwrap();
        assert_eq!(before.legacy_unsigned_collection_equations().count(), 2);
        assert!(before.records().unwrap().next().is_none());
        assert_eq!(before.opaque_record_count(), 0);
        let original_headers = [
            fixed_collection_header(merge.as_bytes()),
            fixed_collection_header(derive.as_bytes()),
        ];
        for retained in [false, true] {
            let path = fresh_empty_pile_path(
                &dir,
                if retained {
                    "unsigned-retained.pile"
                } else {
                    "unsigned-reframed.pile"
                },
            );
            let mut destination = Pile::open(&path).unwrap();
            if retained {
                source
                    .rewrite_retained_into(
                        &mut destination,
                        &RetentionRoots::new(),
                        WantRewritePolicy::Drop,
                    )
                    .unwrap();
            } else {
                let stats = reframe_into(&source_path, &mut destination).unwrap();
                assert_eq!(stats.legacy_unsigned_equations, 2);
                assert_eq!(stats.collection_records, 0);
            }
            let reader = destination.snapshot().unwrap();
            assert!(reader.records().unwrap().next().is_none());
            assert_eq!(reader.legacy_unsigned_collection_equations().count(), 2);
            for handle in [child, input, output, collection.transmute()] {
                assert!(reader.contains_blob(handle).unwrap());
            }
            assert_eq!(reader.contains_blob(orphan).unwrap(), !retained);
            for header in original_headers {
                assert!(reader.legacy_collection_headers.get(&header).is_some());
            }
            drop(reader);
            destination.close().unwrap();
        }
        source.close().unwrap();
    }

    #[test]
    fn opaque_envelopes_are_raw_visible_and_writers_cross_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "opaque-crossing.pile");
        let header_only = test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, ENVELOPE_BLOCK_LEN);
        let multi_block = test_envelope_bytes(TEST_UNKNOWN_KIND_B, 2, 2 * ENVELOPE_BLOCK_LEN);

        // Hold an already-refreshed writer while another descriptor appends
        // both future record kinds. Its next write must refresh across both.
        let mut pile = Pile::open(&path).unwrap();
        pile.refresh().unwrap();
        {
            let mut external = OpenOptions::new().append(true).open(&path).unwrap();
            external.write_all(&header_only).unwrap();
            external.write_all(&multi_block).unwrap();
            external.sync_all().unwrap();
        }
        let known_payload = b"known after opaque".to_vec();
        let known = pile
            .put::<UnknownBlob, _>(Bytes::from_source(known_payload.clone()))
            .unwrap();
        let branch_id = Id::new([9; 16]).unwrap();
        pile.append_legacy_pin_for_test(branch_id, None, Some(known.transmute()))
            .unwrap();
        pile.close().unwrap();

        let mut records = PileRecords::open(&path).unwrap();
        let decoded = (&mut records).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(decoded.len(), 4);
        assert!(matches!(
            decoded[0],
            PileRecord {
                len: ENVELOPE_BLOCK_LEN,
                content: PileRecordContent::Opaque {
                    kind: OpaqueKind::Described(TEST_UNKNOWN_KIND_A)
                },
                ..
            }
        ));
        assert!(matches!(
            decoded[1],
            PileRecord {
                len,
                content: PileRecordContent::Opaque {
                    kind: OpaqueKind::Described(TEST_UNKNOWN_KIND_B)
                },
                ..
            } if len == 2 * ENVELOPE_BLOCK_LEN
        ));
        assert!(matches!(decoded[2].content, PileRecordContent::Blob { .. }));
        assert!(matches!(
            decoded[3].content,
            PileRecordContent::Branch { .. }
        ));
        assert_eq!(&records.bytes()[..ENVELOPE_BLOCK_LEN], &header_only);
        assert_eq!(
            &records.bytes()[ENVELOPE_BLOCK_LEN..3 * ENVELOPE_BLOCK_LEN],
            &multi_block
        );

        let mut reopened = Pile::open(&path).unwrap();
        reopened.refresh().unwrap();
        assert_eq!(reopened.opaque_records, 2);
        let fetched: Blob<UnknownBlob> = reopened.snapshot().unwrap().get(known).unwrap();
        assert_eq!(fetched.bytes.as_ref(), known_payload);
        assert_eq!(
            reopened.legacy_pin_head_for_test(branch_id).unwrap(),
            Some(known.transmute())
        );
        reopened.close().unwrap();
    }

    #[test]
    fn retired_local_cell_records_are_opaque_migration_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "retired-local-cells.pile");
        let mut unenveloped = [0u8; V3_HEADER_LEN];
        unenveloped[..16].copy_from_slice(&MAGIC_MARKER_LOCAL_CELL_V3);
        let enveloped = test_envelope_v1_bytes(
            MAGIC_MARKER_LOCAL_CELL_TOMBSTONE_V3,
            ENVELOPE_HEADER_BLOCKS,
            ENVELOPE_HEADER_LEN,
        );
        append_test_bytes(&path, &unenveloped);
        append_test_bytes(&path, &enveloped);

        let mut records = PileRecords::open(&path).unwrap();
        let decoded = (&mut records).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(matches!(
            decoded[0].content,
            PileRecordContent::Opaque {
                kind: OpaqueKind::Legacy(MAGIC_MARKER_LOCAL_CELL_V3)
            }
        ));
        assert!(matches!(
            decoded[1].content,
            PileRecordContent::Opaque {
                kind: OpaqueKind::Legacy(MAGIC_MARKER_LOCAL_CELL_TOMBSTONE_V3)
            }
        ));
        assert_eq!(decoded[0].len, V3_HEADER_LEN);
        assert_eq!(decoded[1].len, ENVELOPE_HEADER_LEN);

        let mut pile = Pile::open(&path).unwrap();
        pile.refresh().unwrap();
        assert_eq!(pile.opaque_record_count().unwrap(), 2);
        pile.close().unwrap();
    }

    #[test]
    fn retired_v4_derive_is_known_inert_and_does_not_block_retention() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "retired-v4-derive.pile");
        let destination_path = fresh_empty_pile_path(&dir, "retired-v4-destination.pile");
        let header = CollectionDeriveHeaderEnvelopeV1V4 {
            envelope_marker: MAGIC_MARKER_ENVELOPE,
            record_kind: MAGIC_MARKER_COLLECTION_DERIVE_V4,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            source: [1; 32],
            target: [2; 32],
            input: [3; 32],
            output: [4; 32],
            reserved: [0; 92],
        };
        append_test_bytes(&source_path, header.as_bytes());

        let mut records = PileRecords::open(&source_path).unwrap();
        let decoded = records.next().unwrap().unwrap();
        assert_eq!(decoded.len, ENVELOPE_HEADER_LEN);
        assert!(matches!(
            decoded.content,
            PileRecordContent::RetiredCollectionDeriveV4
        ));
        assert!(records.next().is_none());

        let mut source = Pile::open(&source_path).unwrap();
        assert_eq!(source.opaque_record_count().unwrap(), 0);
        assert!(source
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .next()
            .is_none());
        let mut destination = Pile::open(&destination_path).unwrap();
        source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        destination.close().unwrap();
        source.close().unwrap();
        assert_eq!(std::fs::metadata(destination_path).unwrap().len(), 0);
    }

    #[test]
    fn truncated_retired_unenveloped_cell_is_corrupt_not_an_applied_record() {
        for kind in [
            MAGIC_MARKER_LOCAL_CELL_V3,
            MAGIC_MARKER_LOCAL_CELL_TOMBSTONE_V3,
        ] {
            for len in [16usize, 17, V3_HEADER_LEN - 1] {
                let mut bytes = vec![0u8; len];
                bytes[..16].copy_from_slice(&kind);
                assert!(matches!(
                    decode_record(&bytes, 37),
                    Err(ReadError::CorruptPile { valid_length: 37 })
                ));
            }
        }
    }

    #[test]
    fn retired_enveloped_cell_requires_its_historical_fixed_span() {
        for kind in [
            MAGIC_MARKER_LOCAL_CELL_V3,
            MAGIC_MARKER_LOCAL_CELL_TOMBSTONE_V3,
        ] {
            let bytes = test_envelope_v1_bytes(kind, 2, 2 * ENVELOPE_BLOCK_LEN);
            assert!(matches!(
                decode_record(&bytes, 41),
                Err(ReadError::CorruptPile { valid_length: 41 })
            ));
        }
    }

    #[test]
    fn opaque_projection_preserves_branches_and_cutover_resolves_retired_want_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "opaque-lww.pile");
        let opaque = test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, ENVELOPE_BLOCK_LEN);
        let mut pile = Pile::open(&path).unwrap();

        let branch_cleared = Id::new([11; 16]).unwrap();
        let branch_restored = Id::new([12; 16]).unwrap();
        let branch_head = Inline::<Handle<SimpleArchive>>::new([13; 32]);
        pile.append_legacy_pin_for_test(branch_cleared, None, Some(branch_head))
            .unwrap();
        append_test_bytes(&path, &opaque);
        pile.append_legacy_pin_for_test(branch_cleared, Some(branch_head), None)
            .unwrap();
        append_test_bytes(
            &path,
            PinTombstoneRecordHeader::new(branch_restored).as_bytes(),
        );
        append_test_bytes(&path, &opaque);
        pile.append_legacy_pin_for_test(branch_restored, None, Some(branch_head))
            .unwrap();

        let want_retracted = Inline::<Handle<UnknownBlob>>::new([17; 32]);
        let want_restored = Inline::<Handle<UnknownBlob>>::new([18; 32]);
        append_test_bytes(
            &path,
            retired_blob_want_record(WantRequest::blob(want_retracted), true).as_bytes(),
        );
        append_test_bytes(&path, &opaque);
        append_test_bytes(
            &path,
            retired_blob_want_record(WantRequest::blob(want_retracted), false).as_bytes(),
        );
        append_test_bytes(
            &path,
            retired_blob_want_record(WantRequest::blob(want_restored), false).as_bytes(),
        );
        append_test_bytes(&path, &opaque);
        append_test_bytes(
            &path,
            retired_blob_want_record(WantRequest::blob(want_restored), true).as_bytes(),
        );
        pile.close().unwrap();

        let mut reopened = Pile::open(&path).unwrap();
        reopened.refresh().unwrap();
        assert_eq!(reopened.opaque_record_count().unwrap(), 4);
        assert_eq!(
            reopened.legacy_pin_head_for_test(branch_cleared).unwrap(),
            None
        );
        assert_eq!(
            reopened.legacy_pin_head_for_test(branch_restored).unwrap(),
            Some(branch_head)
        );
        assert!(reopened
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .next()
            .is_none());
        assert_eq!(
            reopened.want_cutover_status().unwrap(),
            WantCutoverStatus {
                retired_records: 4,
                resolved_active: 1,
                already_current: 0,
                missing_current: 1,
            }
        );
        reopened.migrate_retired_wants().unwrap();
        let wants = reopened
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(wants, vec![WantRequest::blob(want_restored)]);
        reopened.close().unwrap();
    }

    #[test]
    fn legacy_v3_and_enveloped_piles_concatenate_without_reframing() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_path = fresh_empty_pile_path(&dir, "legacy-v3.pile");
        let current_path = fresh_empty_pile_path(&dir, "enveloped.pile");
        let merged_path = dir.path().join("mixed-cat.pile");

        let legacy_payload = b"legacy V3".to_vec();
        let legacy_handle =
            Blob::<UnknownBlob>::new(Bytes::from_source(legacy_payload.clone())).get_handle();
        append_v3_blob_candidate(&legacy_path, legacy_handle.into(), &legacy_payload, 17);

        let current_payload = b"current envelope".to_vec();
        let mut current = Pile::open(&current_path).unwrap();
        let current_handle = current
            .put::<UnknownBlob, _>(Bytes::from_source(current_payload.clone()))
            .unwrap();
        current.close().unwrap();

        let mut merged = std::fs::read(&legacy_path).unwrap();
        merged.extend_from_slice(&std::fs::read(&current_path).unwrap());
        std::fs::write(&merged_path, merged).unwrap();

        let mut pile = Pile::open(&merged_path).unwrap();
        pile.refresh().unwrap();
        let reader = pile.snapshot().unwrap();
        let legacy: Blob<UnknownBlob> = reader.get(legacy_handle).unwrap();
        let current: Blob<UnknownBlob> = reader.get(current_handle).unwrap();
        assert_eq!(legacy.bytes.as_ref(), legacy_payload);
        assert_eq!(current.bytes.as_ref(), current_payload);
        drop(reader);
        pile.close().unwrap();

        let mut records = PileRecords::open(&merged_path).unwrap();
        let decoded = (&mut records).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(
            &records.bytes()[decoded[0].offset..decoded[0].offset + 16],
            MAGIC_MARKER_BLOB_V3.as_slice()
        );
        assert_eq!(
            &records.bytes()[decoded[1].offset..decoded[1].offset + FRAME_MAGIC_LEN],
            FRAME_MAGIC.as_slice()
        );
    }

    #[test]
    fn envelope_span_rejects_zero_maximum_truncation_and_kind_mismatch() {
        let complete_header = test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, ENVELOPE_HEADER_LEN);
        for truncated_at in [0usize, 1, 15, 16, 27, 28, 31, 32, 63, 64, 255] {
            assert!(matches!(
                decode_record(&complete_header[..truncated_at], 11),
                Err(ReadError::CorruptPile { valid_length: 11 })
            ));
        }

        for malformed in [
            test_envelope_bytes(TEST_UNKNOWN_KIND_A, 0, ENVELOPE_BLOCK_LEN),
            test_envelope_bytes(TEST_UNKNOWN_KIND_A, u32::MAX, ENVELOPE_BLOCK_LEN),
            test_envelope_bytes(TEST_UNKNOWN_KIND_A, 2, 2 * ENVELOPE_BLOCK_LEN - 1),
            test_envelope_bytes(record_kind::KIND_PIN_HEAD, 2, 2 * ENVELOPE_BLOCK_LEN),
        ] {
            assert!(matches!(
                decode_record(&malformed, 17),
                Err(ReadError::CorruptPile { valid_length: 17 })
            ));
        }

        let prefix_only = test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, FRAME_BODY_OFFSET);
        assert!(matches!(
            decode_record(&prefix_only, 23),
            Err(ReadError::CorruptPile { valid_length: 23 })
        ));

        let hash = collection_test_hash(7);
        let mut wrong_blob_span = vec![0u8; 2 * ENVELOPE_BLOCK_LEN];
        wrong_blob_span[..ENVELOPE_HEADER_LEN].copy_from_slice(
            BlobRecordHeader::new(1, 42, (ENVELOPE_BLOCK_LEN + 1) as u64, hash).as_bytes(),
        );
        assert!(matches!(
            decode_record(&wrong_blob_span, 29),
            Err(ReadError::CorruptPile { valid_length: 29 })
        ));
    }

    #[test]
    fn amputation_crosses_complete_opaque_and_truncates_torn_opaque_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "opaque-amputation.pile");
        let complete = test_envelope_bytes(TEST_UNKNOWN_KIND_A, 2, 2 * ENVELOPE_BLOCK_LEN);
        let torn = test_envelope_bytes(TEST_UNKNOWN_KIND_B, 2, ENVELOPE_BLOCK_LEN);
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&complete).unwrap();
            file.write_all(&torn).unwrap();
        }

        let mut pile = Pile::open(&path).unwrap();
        assert!(matches!(
            pile.refresh(),
            Err(ReadError::CorruptPile { valid_length })
                if valid_length == complete.len()
        ));
        pile.amputate().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            complete.len() as u64
        );
        pile.refresh().unwrap();
        assert_eq!(pile.opaque_records, 1);
        pile.close().unwrap();

        let mut records = PileRecords::open(&path).unwrap();
        let only = records.next().unwrap().unwrap();
        assert_eq!(only.len, complete.len());
        assert!(matches!(
            only.content,
            PileRecordContent::Opaque {
                kind: OpaqueKind::Described(TEST_UNKNOWN_KIND_A)
            }
        ));
        assert!(records.next().is_none());
    }

    #[test]
    fn amputation_at_refuses_a_stale_boundary_before_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "boundary-guarded-amputation.pile");
        let complete = test_envelope_bytes(TEST_UNKNOWN_KIND_A, 2, 2 * ENVELOPE_BLOCK_LEN);
        let torn = test_envelope_bytes(TEST_UNKNOWN_KIND_B, 2, ENVELOPE_BLOCK_LEN);
        let mut bytes = complete.clone();
        bytes.extend_from_slice(&torn);
        std::fs::write(&path, &bytes).unwrap();

        let mut pile = Pile::open(&path).unwrap();
        assert!(matches!(
            pile.amputate_at(0),
            Err(ReadError::CorruptPile { valid_length })
                if valid_length == complete.len()
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);

        assert!(pile.amputate_at(complete.len()).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), complete);
        pile.close().unwrap();
    }

    #[test]
    fn opaque_frames_are_carried_by_rewrite_and_refused_by_yard() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "opaque-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "opaque-destination.pile");
        std::fs::write(
            &source_path,
            test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, ENVELOPE_BLOCK_LEN),
        )
        .unwrap();

        let mut source = Pile::open(&source_path).unwrap();
        let retained = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"possibly owned".to_vec()))
            .unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();
        destination
            .put::<UnknownBlob, _>(Bytes::from_source(b"sentinel".to_vec()))
            .unwrap();
        destination.flush().unwrap();
        let destination_before = std::fs::read(&destination_path).unwrap();

        // The rewrite carries the unknown frame exactly, by its length, and
        // says so; a second rewrite finds it already there and adds nothing.
        let frame = test_envelope_bytes(TEST_UNKNOWN_KIND_A, 1, ENVELOPE_BLOCK_LEN);
        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.opaque_frames, 1);
        let destination_after = std::fs::read(&destination_path).unwrap();
        assert!(destination_after.starts_with(&destination_before));
        assert_eq!(&destination_after[destination_before.len()..], &frame[..]);
        assert_eq!(destination.opaque_records, 1);
        assert_eq!(
            destination.opaque_frames,
            vec![(destination_before.len(), frame.len())]
        );
        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.opaque_frames, 1);
        assert_eq!(std::fs::read(&destination_path).unwrap(), destination_after);
        let fetched: Blob<UnknownBlob> = source.snapshot().unwrap().get(retained).unwrap();
        assert_eq!(fetched.bytes.as_ref(), b"possibly owned");
        destination.close().unwrap();
        source.close().unwrap();
        let mut reopened = Pile::open(&destination_path).unwrap();
        reopened.refresh().unwrap();
        assert_eq!(reopened.opaque_records, 1);
        assert_eq!(
            reopened.opaque_frames,
            vec![(destination_before.len(), frame.len())]
        );
        reopened.close().unwrap();

        // The fence is Yard-wide: an opaque record in the young generation
        // may own a known blob physically resident only in an older one.
        let old_path = fresh_empty_pile_path(&dir, "opaque-owned-old.pile");
        let mut old = Pile::open(&old_path).unwrap();
        let cross_generation = old
            .put::<UnknownBlob, _>(Bytes::from_source(
                b"possibly owned across generations".to_vec(),
            ))
            .unwrap();
        old.close().unwrap();
        let young_before = std::fs::read(&source_path).unwrap();
        let old_before = std::fs::read(&old_path).unwrap();
        let mut yard = Yard::open([&source_path, &old_path], YardConfig::default()).unwrap();
        assert!(matches!(
            yard.collect(&RetentionRoots::new()),
            Err(YardCollectError::OpaqueRecords { count: 1 })
        ));
        assert!(matches!(
            yard.compact(&RetentionRoots::new()),
            Err(YardCollectError::OpaqueRecords { count: 1 })
        ));
        assert!(matches!(
            yard.reclaim(),
            Err(YardReclaimError::OpaqueRecords { count: 1 })
        ));
        assert_eq!(std::fs::read(&source_path).unwrap(), young_before);
        assert_eq!(std::fs::read(&old_path).unwrap(), old_before);
        let fetched: Blob<UnknownBlob> = yard.snapshot().unwrap().get(retained).unwrap();
        assert_eq!(fetched.bytes.as_ref(), b"possibly owned");
        let fetched: Blob<UnknownBlob> = yard.snapshot().unwrap().get(cross_generation).unwrap();
        assert_eq!(fetched.bytes.as_ref(), b"possibly owned across generations");
        yard.close().unwrap();
    }

    #[test]
    fn legacy_v3_collection_headers_are_inert_and_preserved_by_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "legacy-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "legacy-destination.pile");
        let expected = legacy_collection_test_headers();

        {
            let mut file = OpenOptions::new().append(true).open(&source_path).unwrap();
            for (_, header) in &expected {
                file.write_all(header).unwrap();
            }
        }

        assert_eq!(
            legacy_collection_headers_at(&source_path)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected.iter().copied().collect::<BTreeSet<_>>()
        );

        let mut malformed = expected[0].1;
        malformed[64] = 1;
        assert!(matches!(
            decode_record(&malformed, 0),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));

        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();
        assert_eq!(source.snapshot().unwrap().records().unwrap().count(), 0);

        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.retained_blobs, 0);
        assert_eq!(
            destination.snapshot().unwrap().records().unwrap().count(),
            0
        );

        let rewritten = legacy_collection_headers_at(&destination_path);
        assert_eq!(
            rewritten.into_iter().collect::<BTreeSet<_>>(),
            expected.iter().copied().collect::<BTreeSet<_>>()
        );

        let once = std::fs::metadata(&destination_path).unwrap().len();
        source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(std::fs::metadata(&destination_path).unwrap().len(), once);

        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn reframe_preserves_earlier_v3_collection_evidence_without_interpreting_it() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "v3-reframe-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "v3-reframe-destination.pile");
        let expected = legacy_collection_test_headers();
        for (_, header) in &expected {
            append_test_bytes(&source_path, header);
        }
        let mut destination = Pile::open(&destination_path).unwrap();
        let stats = reframe_into(&source_path, &mut destination).unwrap();
        assert_eq!(stats.legacy_v3_records, expected.len());
        assert_eq!(stats.legacy_unsigned_equations, 0);
        assert_eq!(stats.collection_records, 0);
        assert_eq!(stats.dropped_inert, 0);
        assert!(destination
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .next()
            .is_none());
        assert_eq!(
            legacy_collection_headers_at(&destination_path)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected.into_iter().collect::<BTreeSet<_>>()
        );
        destination.close().unwrap();
    }

    #[test]
    fn yard_reclaim_preserves_inert_legacy_v3_collection_headers() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "legacy-yard.pile");
        let expected = legacy_collection_test_headers();

        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            for (_, header) in &expected {
                file.write_all(header).unwrap();
            }
        }

        let mut yard = Yard::open([&path], YardConfig::default()).unwrap();
        yard.reclaim().unwrap();
        yard.close().unwrap();

        assert_eq!(
            legacy_collection_headers_at(&path)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn native_collection_records_replay_in_fingerprint_order_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "collections.pile");
        let records = collection_test_records();
        let expected = sorted_collection_records(records.clone());

        let mut pile = Pile::open(&path).unwrap();
        for record in records {
            pile.insert(record).unwrap();
        }
        pile.close().unwrap();

        let mut reopened = Pile::open(&path).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        let actual = snapshot
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            snapshot.record(expected[1].fingerprint()).unwrap(),
            Some(expected[1])
        );
        assert_eq!(
            snapshot
                .record(CollectionRecordFingerprint::from_raw([0xff; 32]))
                .unwrap(),
            None
        );
        reopened.close().unwrap();
    }

    #[test]
    fn native_collection_record_insert_is_physically_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "idempotent.pile");
        let record = collection_test_records()[0];
        let mut pile = Pile::open(&path).unwrap();

        pile.insert(record).unwrap();
        let once = std::fs::metadata(&path).unwrap().len();
        pile.insert(record).unwrap();
        let twice = std::fs::metadata(&path).unwrap().len();

        assert_eq!(once, ENVELOPE_HEADER_LEN as u64);
        assert_eq!(twice, once);
        assert_eq!(pile.snapshot().unwrap().records().unwrap().count(), 1);
        pile.close().unwrap();
    }

    #[test]
    fn collection_selector_indexes_variants_and_isolates_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "collection-selector.pile");
        let collection = collection_test_collection(40);
        let unrelated_collection = collection_test_collection(41);
        let key = SigningKey::from_bytes(&[42; 32]);
        let records = vec![
            CollectionRecord::Commit(CollectionCommit::sign(
                &key,
                collection,
                collection_test_hash(43),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection,
                collection_test_hash(43),
                collection_test_hash(44),
                collection_test_hash(45),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection,
                collection_test_hash(45),
                collection_test_hash(46),
            )),
        ];
        let unrelated = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            unrelated_collection,
            collection_test_hash(45),
            collection_test_hash(47),
        ));
        let selector = BTreeSet::from([CollectionRecordSelector::Collection(collection)]);

        let mut pile = Pile::open(&path).unwrap();
        pile.insert(unrelated).unwrap();
        let before = pile.snapshot().unwrap();
        for record in records.iter().rev().copied() {
            pile.insert(record).unwrap();
        }
        pile.insert(records[0]).unwrap();

        assert!(before.select_records(&selector).unwrap().is_empty());
        let after = pile.snapshot().unwrap();
        assert_eq!(
            after.select_records(&selector).unwrap(),
            sorted_collection_records(records.clone())
        );

        let collection_union = BTreeSet::from([
            CollectionRecordSelector::Collection(collection),
            CollectionRecordSelector::Collection(unrelated_collection),
        ]);
        let mut expected_union = records.clone();
        expected_union.push(unrelated);
        let selected_union = after.select_records(&collection_union).unwrap();
        assert_eq!(selected_union, sorted_collection_records(expected_union));

        let mixed = BTreeSet::from([
            CollectionRecordSelector::Collection(collection),
            CollectionRecordSelector::Fingerprint(unrelated.fingerprint()),
        ]);
        let mut expected_mixed = records;
        expected_mixed.push(unrelated);
        assert_eq!(
            after.select_records(&mixed).unwrap(),
            sorted_collection_records(expected_mixed)
        );

        drop(after);
        drop(before);
        pile.close().unwrap();

        let mut reopened = Pile::open(&path).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .select_records(&selector)
                .unwrap()
                .len(),
            3
        );
        reopened.close().unwrap();
    }

    #[test]
    fn native_collection_records_cat_as_an_order_independent_set_union() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = fresh_empty_pile_path(&dir, "a.pile");
        let path_b = fresh_empty_pile_path(&dir, "b.pile");
        let path_ab = dir.path().join("ab.pile");
        let path_ba = dir.path().join("ba.pile");
        let records = collection_test_records();

        let mut a = Pile::open(&path_a).unwrap();
        a.insert(records[0]).unwrap();
        a.insert(records[1]).unwrap();
        a.close().unwrap();
        let mut b = Pile::open(&path_b).unwrap();
        b.insert(records[0]).unwrap();
        b.insert(records[2]).unwrap();
        b.close().unwrap();

        let bytes_a = std::fs::read(&path_a).unwrap();
        let bytes_b = std::fs::read(&path_b).unwrap();
        let mut ab = bytes_a.clone();
        ab.extend_from_slice(&bytes_b);
        std::fs::write(&path_ab, ab).unwrap();
        let mut ba = bytes_b;
        ba.extend_from_slice(&bytes_a);
        std::fs::write(&path_ba, ba).unwrap();

        let expected = sorted_collection_records(records.clone());
        let source_expected = sorted_collection_records(records[..2].to_vec());
        let target_expected = vec![records[2]];
        let source_selector = BTreeSet::from([CollectionRecordSelector::Collection(
            collection_test_collection(1),
        )]);
        let target_selector = BTreeSet::from([CollectionRecordSelector::Collection(
            collection_test_collection(2),
        )]);
        for path in [&path_ab, &path_ba] {
            let mut pile = Pile::open(path).unwrap();
            let snapshot = pile.snapshot().unwrap();
            let actual = snapshot
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                snapshot.select_records(&source_selector).unwrap(),
                source_expected
            );
            assert_eq!(
                snapshot.select_records(&target_selector).unwrap(),
                target_expected
            );
            pile.close().unwrap();
        }
    }

    #[test]
    fn collection_selection_survives_insert_reopen_and_concatenation() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = fresh_empty_pile_path(&dir, "selection-a.pile");
        let path_b = fresh_empty_pile_path(&dir, "selection-b.pile");
        let path_ab = dir.path().join("selection-ab.pile");
        let path_ba = dir.path().join("selection-ba.pile");
        let target = collection_test_collection(2);
        let input = collection_test_hash(8);
        let records = collection_test_records();
        let first = records[2];
        let conflicting = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            input,
            collection_test_hash(10),
        ));
        let unrelated = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            collection_test_collection(3),
            input,
            collection_test_hash(11),
        ));
        let exact = [CollectionRecordSelector::Operation(WantRequest::derive(
            target, input,
        ))]
        .into_iter()
        .collect();

        let mut a = Pile::open(&path_a).unwrap();
        for record in [records[0], records[1], first, unrelated] {
            a.insert(record).unwrap();
        }
        assert_eq!(
            a.snapshot().unwrap().select_records(&exact).unwrap(),
            vec![first]
        );
        a.close().unwrap();

        let mut reopened = Pile::open(&path_a).unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().select_records(&exact).unwrap(),
            vec![first]
        );
        reopened.close().unwrap();

        let mut b = Pile::open(&path_b).unwrap();
        for record in [first, conflicting] {
            b.insert(record).unwrap();
        }
        b.close().unwrap();

        let bytes_a = std::fs::read(&path_a).unwrap();
        let bytes_b = std::fs::read(&path_b).unwrap();
        let mut ab = bytes_a.clone();
        ab.extend_from_slice(&bytes_b);
        std::fs::write(&path_ab, ab).unwrap();
        let mut ba = bytes_b;
        ba.extend_from_slice(&bytes_a);
        std::fs::write(&path_ba, ba).unwrap();

        let mut expected = vec![first, conflicting];
        expected.sort_unstable_by_key(CollectionRecord::fingerprint);
        for path in [&path_ab, &path_ba] {
            let mut pile = Pile::open(path).unwrap();
            let snapshot = pile.snapshot().unwrap();
            assert_eq!(snapshot.select_records(&exact).unwrap(), expected);
            assert!(!snapshot
                .select_records(&exact)
                .unwrap()
                .contains(&unrelated));
            pile.close().unwrap();
        }
    }

    #[test]
    fn native_collection_record_torn_tail_is_detected_and_amputated() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "torn.pile");
        let mut pile = Pile::open(&path).unwrap();
        pile.insert(collection_test_records()[0]).unwrap();
        pile.close().unwrap();

        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len((ENVELOPE_HEADER_LEN - 1) as u64)
            .unwrap();
        let mut reopened = Pile::open(&path).unwrap();
        assert!(matches!(
            reopened.refresh(),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));
        reopened.amputate().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        reopened.close().unwrap();
    }

    #[test]
    fn retained_rewrite_composes_explicit_roots_strong_pins_and_wants() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();

        let legacy_attachment = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"legacy attachment".to_vec()))
            .unwrap();
        let legacy_head = source
            .put::<SimpleArchive, _>(Blob::<SimpleArchive>::new(Bytes::from_source(
                legacy_attachment.raw.to_vec(),
            )))
            .unwrap();
        let pin_id = Id::new([9; 16]).unwrap();
        source
            .append_legacy_pin_for_test(pin_id, None, Some(legacy_head))
            .unwrap();

        let collection_attachment = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"collection attachment".to_vec()))
            .unwrap();
        let collection_data = source
            .put::<UnknownBlob, _>(Bytes::from_source(collection_attachment.raw.to_vec()))
            .unwrap();

        let obsolete_input = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"obsolete input".to_vec()))
            .unwrap();
        let collection_record = source
            .put::<UnknownBlob, _>(Bytes::from_source(obsolete_input.raw.to_vec()))
            .unwrap();
        let want_target = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"want target".to_vec()))
            .unwrap();
        source.want(WantRequest::blob(want_target)).unwrap();
        let orphan = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"orphan".to_vec()))
            .unwrap();
        source.flush().unwrap();

        let mut explicit = RetentionRoots::new();
        explicit.retain_recursive(collection_data);
        // This caller-selected descriptive blob is deliberately a direct root,
        // so its hash-shaped bytes do not become structural ownership edges.
        explicit.retain_direct(collection_record);

        let stats = source
            .rewrite_retained_into(&mut destination, &explicit, WantRewritePolicy::Preserve)
            .unwrap();
        assert_eq!(
            stats,
            PileRewriteStats {
                retained_blobs: 6,
                strong_pins: 1,
                wants: 1,
                capability_proofs: 0,
                opaque_frames: 0,
            }
        );

        let reader = destination.snapshot().unwrap();
        for retained in [
            legacy_attachment,
            legacy_head.transmute(),
            collection_attachment,
            collection_data,
            collection_record,
            want_target,
        ] {
            assert!(reader.get::<Blob<UnknownBlob>, _>(retained).is_ok());
        }
        for collected in [obsolete_input, orphan] {
            assert!(reader.get::<Blob<UnknownBlob>, _>(collected).is_err());
        }
        assert_eq!(
            destination.legacy_pin_head_for_test(pin_id).unwrap(),
            Some(legacy_head)
        );
        assert_eq!(
            destination
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![WantRequest::blob(want_target)]
        );

        drop(reader);
        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn retained_rewrite_keeps_invalid_commit_resident_references() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "invalid-commit-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "invalid-commit-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();

        let forged_data = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"forged ownership data".to_vec()))
            .unwrap();
        let metadata_facts: TribleSet = entity! {
            crate::metadata::tag: collection_test_id(20)
        }
        .into();
        let forged_metadata = source
            .put::<SimpleArchive, _>(metadata_facts.to_blob())
            .unwrap();
        let descriptor = named_for_tests("forged", collection_test_id(22));
        let descriptor_handle = source
            .put::<SimpleArchive, _>(crate::blob::IntoBlob::<SimpleArchive>::to_blob(
                descriptor.into_facts(),
            ))
            .unwrap();
        let invalid = invalidate_collection_commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[24; 32]),
            descriptor_handle,
            Inline::<Hash<Blake3>>::new(forged_data.raw),
            forged_metadata,
        ));
        let records = vec![CollectionRecord::Commit(invalid)];
        for record in records.iter().copied() {
            source.insert(record).unwrap();
        }
        source.flush().unwrap();

        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.retained_blobs, 3);
        assert_eq!(
            destination
                .snapshot()
                .unwrap()
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            sorted_collection_records(records),
        );

        let reader = destination.snapshot().unwrap();
        assert!(matches!(
            reader.get::<Blob<UnknownBlob>, _>(forged_data),
            Ok(_)
        ));
        assert!(matches!(
            reader.get::<Blob<SimpleArchive>, _>(forged_metadata),
            Ok(_)
        ));
        assert!(matches!(
            reader.get::<Blob<SimpleArchive>, _>(descriptor_handle),
            Ok(_)
        ));

        drop(reader);
        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn retained_rewrite_preserves_valid_dangling_commit_without_demanding_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "dangling-commit-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "dangling-commit-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();

        let missing_descriptor = collection_test_collection(25);
        let missing_data = collection_test_hash(28);
        let missing_metadata = Inline::<Handle<SimpleArchive>>::new([29; 32]);
        let commit = CollectionCommit::sign(
            &SigningKey::from_bytes(&[30; 32]),
            missing_descriptor,
            missing_data,
            missing_metadata,
        );
        commit.verify_strict().unwrap();
        let records = vec![CollectionRecord::Commit(commit)];
        for record in records.iter().copied() {
            source.insert(record).unwrap();
        }
        source.flush().unwrap();

        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.retained_blobs, 0);
        assert_eq!(
            destination
                .snapshot()
                .unwrap()
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            sorted_collection_records(records),
        );

        let reader = destination.snapshot().unwrap();
        assert!(!reader
            .contains_blob(Handle::<UnknownBlob>::from_hash(missing_data))
            .unwrap());
        assert!(!reader.contains_blob(missing_metadata).unwrap());
        assert!(!reader.contains_blob(missing_descriptor).unwrap());

        drop(reader);
        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn retained_rewrite_preserves_dangling_legacy_pin_without_demanding_head() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "dangling-pin-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "dangling-pin-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();

        let pin_id = Id::new([31; 16]).unwrap();
        let missing_head = Inline::<Handle<SimpleArchive>>::new([32; 32]);
        source
            .append_legacy_pin_for_test(pin_id, None, Some(missing_head))
            .unwrap();
        source.flush().unwrap();

        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.retained_blobs, 0);
        assert_eq!(stats.strong_pins, 1);
        assert_eq!(
            destination.legacy_pin_head_for_test(pin_id).unwrap(),
            Some(missing_head)
        );

        let reader = destination.snapshot().unwrap();
        assert!(!reader.contains_blob(missing_head).unwrap());

        drop(reader);
        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn retained_rewrite_still_fails_loud_for_missing_explicit_root() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "missing-explicit-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "missing-explicit-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();
        let missing = Inline::<Handle<UnknownBlob>>::new([31; 32]);
        let mut explicit = RetentionRoots::new();
        explicit.retain_recursive(missing);

        let error = source
            .rewrite_retained_into(&mut destination, &explicit, WantRewritePolicy::Drop)
            .unwrap_err();
        assert!(matches!(
            error,
            PileRewriteError::Transfer(crate::repo::TransferError::Load(
                GetBlobError::BlobNotFound(_)
            ))
        ));

        destination.close().unwrap();
        source.close().unwrap();
    }

    #[test]
    fn retained_rewrite_preserves_native_records_and_their_owned_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "collection-source.pile");
        let destination_path = fresh_empty_pile_path(&dir, "collection-destination.pile");
        let mut source = Pile::open(&source_path).unwrap();
        let mut destination = Pile::open(&destination_path).unwrap();

        let attachment = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"owned attachment".to_vec()))
            .unwrap();
        let data = source
            .put::<UnknownBlob, _>(Bytes::from_source(attachment.raw.to_vec()))
            .unwrap();
        let metadata = source
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        assert_eq!(metadata, empty_metadata_handle());
        let orphan = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"unowned".to_vec()))
            .unwrap();
        let equation_owned = source
            .put::<UnknownBlob, _>(Bytes::from_source(b"equation-owned".to_vec()))
            .unwrap();

        let descriptor = named_for_tests("retained", collection_test_id(11));
        let descriptor_handle = source
            .put::<SimpleArchive, _>(crate::blob::IntoBlob::<SimpleArchive>::to_blob(
                descriptor.into_facts(),
            ))
            .unwrap();
        let key = SigningKey::from_bytes(&[13; 32]);
        let commit = CollectionCommit::sign(
            &key,
            descriptor_handle,
            Inline::<Hash<Blake3>>::new(data.raw),
            metadata,
        );
        commit.verify_strict().unwrap();
        let records = vec![
            CollectionRecord::Commit(commit),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                descriptor_handle,
                Inline::new(equation_owned.raw),
                collection_test_hash(15),
                collection_test_hash(16),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection_test_collection(17),
                collection_test_hash(16),
                collection_test_hash(18),
            )),
        ];
        for record in records.iter().copied() {
            source.insert(record).unwrap();
        }
        source.flush().unwrap();

        let stats = source
            .rewrite_retained_into(
                &mut destination,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.retained_blobs, 5);

        let actual_records = destination
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual_records, sorted_collection_records(records));
        let reader = destination.snapshot().unwrap();
        for retained in [
            attachment,
            data,
            metadata.transmute(),
            descriptor_handle.transmute(),
            equation_owned,
        ] {
            assert!(reader.get::<Blob<UnknownBlob>, _>(retained).is_ok());
        }
        assert!(reader.get::<Blob<UnknownBlob>, _>(orphan).is_err());

        drop(reader);
        destination.close().unwrap();
        source.close().unwrap();
    }

    fn append_v3_blob_candidate(
        path: &Path,
        hash: Inline<Hash<Blake3>>,
        payload: &[u8],
        timestamp: u64,
    ) -> usize {
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        let record_offset = file.metadata().unwrap().len() as usize;
        let header = BlobHeaderV3::new(timestamp, payload.len() as u64, hash);
        file.write_all(header.as_bytes()).unwrap();
        file.write_all(payload).unwrap();
        file.write_all(&vec![0; block_post_pad(payload.len())])
            .unwrap();
        file.sync_all().unwrap();
        record_offset
    }

    #[test]
    fn blob_occurrence_relation_groups_and_orders_offsets() {
        let hash = [0xA5; 32];
        let other_hash = [0x5A; 32];
        let mut occurrences = PileBlobIndex::new();
        for (key_hash, offset) in [
            (hash, 65_536usize),
            (other_hash, 17),
            (hash, 1),
            (hash, 256),
        ] {
            let key = blob_occurrence_key(&key_hash, IndexEntry::new(offset));
            occurrences.insert(&Entry::with_value(&key, CachedValidation::default()));
        }

        assert_eq!(occurrences.len(), 4);
        assert_eq!(occurrences.segmented_len(&hash), 3);
        assert_eq!(occurrences.segmented_len(&other_hash), 1);
        assert_eq!(
            occurrences
                .iter_prefix_count::<32>()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([(hash, 3), (other_hash, 1)])
        );

        let first = first_blob_occurrence(&occurrences, &hash).unwrap();
        let second = next_blob_occurrence(&occurrences, &hash, first).unwrap();
        let third = next_blob_occurrence(&occurrences, &hash, second).unwrap();
        assert_eq!(first.record_offset, 1);
        assert_eq!(second.record_offset, 256);
        assert_eq!(third.record_offset, 65_536);
        assert!(next_blob_occurrence(&occurrences, &hash, third).is_none());
    }

    #[test]
    fn semantic_blob_frontier_is_independent_of_occurrence_order_and_multiplicity() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = fresh_empty_pile_path(&dir, "semantic-a.pile");
        let path_b = fresh_empty_pile_path(&dir, "semantic-b.pile");
        let payload_a = b"semantic a";
        let payload_b = b"semantic b";
        let hash_a: Inline<Hash<Blake3>> =
            Blob::<UnknownBlob>::new(Bytes::from_source(payload_a.to_vec()))
                .get_handle()
                .into();
        let hash_b: Inline<Hash<Blake3>> =
            Blob::<UnknownBlob>::new(Bytes::from_source(payload_b.to_vec()))
                .get_handle()
                .into();

        append_v3_blob_candidate(&path_a, hash_a, payload_a, 1);
        append_v3_blob_candidate(&path_a, hash_b, payload_b, 2);
        append_v3_blob_candidate(&path_a, hash_a, payload_a, 3);
        append_v3_blob_candidate(&path_b, hash_b, payload_b, 4);
        append_v3_blob_candidate(&path_b, hash_a, payload_a, 5);

        let mut pile_a = Pile::open(&path_a).unwrap();
        let mut pile_b = Pile::open(&path_b).unwrap();
        let snapshot_a = pile_a.snapshot().unwrap();
        let snapshot_b = pile_b.snapshot().unwrap();

        assert_eq!(snapshot_a.blobs.len(), 3);
        assert_eq!(snapshot_b.blobs.len(), 2);
        let semantic_a = snapshot_a.blobs.prefix_set::<32>();
        let semantic_b = snapshot_b.blobs.prefix_set::<32>();
        assert_eq!(
            semantic_a.iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([hash_a.raw, hash_b.raw])
        );
        assert_eq!(
            semantic_a.iter().collect::<BTreeSet<_>>(),
            semantic_b.iter().collect::<BTreeSet<_>>()
        );
        assert!(snapshot_a.blobs_diff(&snapshot_b).next().is_none());
        assert!(snapshot_b.blobs_diff(&snapshot_a).next().is_none());

        drop(snapshot_a);
        drop(snapshot_b);
        pile_a.close().unwrap();
        pile_b.close().unwrap();
    }

    #[test]
    fn payload_validation_matches_and_rejects_around_parallel_threshold() {
        for strategy in [
            ValidationStrategy::Serial,
            ValidationStrategy::ParallelIfLarge,
        ] {
            for len in [
                PARALLEL_BLAKE3_THRESHOLD - 1,
                PARALLEL_BLAKE3_THRESHOLD,
                PARALLEL_BLAKE3_THRESHOLD + 1,
            ] {
                let bytes = Bytes::from_source(
                    (0..len)
                        .map(|position| (position.wrapping_mul(131) % 251) as u8)
                        .collect::<Vec<_>>(),
                );
                let expected = Hash::<Blake3>::digest(&bytes);

                assert!(matches!(
                    compute_validation_state(&bytes, &expected, strategy),
                    ValidationState::Validated
                ));

                let mut wrong = expected;
                wrong.raw[0] ^= 1;
                assert!(matches!(
                    compute_validation_state(&bytes, &wrong, strategy),
                    ValidationState::Invalid
                ));
            }
        }
    }

    #[test]
    fn payload_validation_keeps_the_first_cached_result() {
        let bytes = Bytes::from_source(vec![0x5A; PARALLEL_BLAKE3_THRESHOLD]);
        let expected = Hash::<Blake3>::digest(&bytes);
        let cache = CachedValidation::default();
        assert!(matches!(
            cache.state(&bytes, &expected, ValidationStrategy::Serial),
            ValidationState::Validated
        ));

        let mut wrong = expected;
        wrong.raw[0] ^= 1;
        assert!(matches!(
            cache.state(&bytes, &wrong, ValidationStrategy::ParallelIfLarge),
            ValidationState::Validated
        ));
        assert_eq!(cache.cached(), Some(ValidationState::Validated));
    }

    #[test]
    fn replay_keeps_inline_validation_lazy_and_snapshots_share_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "sparse-validation.pile");

        let (first, second) = {
            let mut writer = Pile::open(&path).unwrap();
            let first = writer
                .put::<UnknownBlob, _>(Bytes::from_source(b"first".to_vec()))
                .unwrap();
            let second = writer
                .put::<UnknownBlob, _>(Bytes::from_source(b"second".to_vec()))
                .unwrap();
            writer.close().unwrap();
            (first, second)
        };

        let mut replay = Pile::open(&path).unwrap();
        replay.refresh().unwrap();
        let first_entry = first_blob_occurrence(&replay.blobs, &first.raw).unwrap();
        let second_entry = first_blob_occurrence(&replay.blobs, &second.raw).unwrap();
        assert_eq!(
            blob_occurrence_validation(&replay.blobs, &first.raw, first_entry).cached(),
            None
        );
        assert_eq!(
            blob_occurrence_validation(&replay.blobs, &second.raw, second_entry).cached(),
            None
        );

        let reader = replay.snapshot().unwrap();
        let cloned = reader.clone();
        assert!(std::ptr::eq(
            blob_occurrence_validation(&reader.blobs, &first.raw, first_entry),
            blob_occurrence_validation(&cloned.blobs, &first.raw, first_entry),
        ));
        let _: Blob<UnknownBlob> = reader.get(first).unwrap();
        assert_eq!(
            blob_occurrence_validation(&replay.blobs, &first.raw, first_entry).cached(),
            Some(ValidationState::Validated)
        );
        let _: Blob<UnknownBlob> = cloned.get(first).unwrap();
        assert_eq!(
            blob_occurrence_validation(&replay.blobs, &first.raw, first_entry).cached(),
            Some(ValidationState::Validated)
        );
        assert_eq!(
            blob_occurrence_validation(&replay.blobs, &second.raw, second_entry).cached(),
            None
        );

        drop(reader);
        drop(cloned);
        replay.close().unwrap();
    }

    #[test]
    fn cover_availability_does_not_validate_a_cold_simplearchive_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "cold-cover-availability.pile");
        let mut pile = Pile::open(&path).unwrap();
        let blob = Blob::<SimpleArchive>::new(Bytes::from_source(Vec::<u8>::new()));
        let handle = pile.put::<SimpleArchive, _>(blob).unwrap();
        let occurrence = first_blob_occurrence(&pile.blobs, &handle.raw).unwrap();
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &handle.raw, occurrence).cached(),
            None,
        );

        let collection = register_simplearchive_collection(&mut pile, "cold-cover-availability");
        let cover = Cover::from_members(collection, [handle]);
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(cover.available(&snapshot).unwrap(), cover);
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &handle.raw, occurrence).cached(),
            None,
        );

        let materialized = cover.materialize::<TribleSet, _>(&snapshot).unwrap();
        assert!(materialized.is_empty());
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &handle.raw, occurrence).cached(),
            Some(ValidationState::Validated),
        );

        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn structural_cover_availability_does_not_bypass_materialize_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "corrupt-cover-availability.pile");
        let expected = Blob::<SimpleArchive>::new(Bytes::from_source(Vec::<u8>::new()));
        let handle = expected.get_handle();
        append_v3_blob_candidate(&path, handle.into(), b"not the empty archive", 1);

        let mut pile = Pile::open(&path).unwrap();
        let collection = register_simplearchive_collection(&mut pile, "corrupt-cover-availability");
        let cover = Cover::from_members(collection, [handle]);
        let snapshot = pile.snapshot().unwrap();
        let occurrence = first_blob_occurrence(&snapshot.blobs, &handle.raw).unwrap();
        assert_eq!(cover.available(&snapshot).unwrap(), cover);
        assert_eq!(
            blob_occurrence_validation(&snapshot.blobs, &handle.raw, occurrence).cached(),
            None,
        );
        assert!(cover.materialize::<TribleSet, _>(&snapshot).is_err());
        assert_eq!(
            blob_occurrence_validation(&snapshot.blobs, &handle.raw, occurrence).cached(),
            Some(ValidationState::Invalid),
        );

        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn corrupt_compacted_root_does_not_shadow_valid_finer_materialization() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "corrupt-compacted-cover.pile");
        let a_facts: TribleSet = entity! {
            crate::metadata::tag: collection_test_id(92)
        }
        .into();
        let b_facts: TribleSet = entity! {
            crate::metadata::tag: collection_test_id(93)
        }
        .into();
        let expected = a_facts.clone() + b_facts.clone();
        let a = a_facts.to_blob();
        let b = b_facts.to_blob();
        let c = expected.clone().to_blob();
        let a_handle = a.get_handle();
        let b_handle = b.get_handle();
        let c_handle = c.get_handle();

        let mut pile = Pile::open(&path).unwrap();
        let collection = register_simplearchive_collection(&mut pile, "corrupt-compacted-cover");
        pile.put::<SimpleArchive, _>(a).unwrap();
        pile.put::<SimpleArchive, _>(b).unwrap();
        pile.insert(CollectionRecord::Merge(CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            collection.handle(),
            Handle::<SimpleArchive>::to_hash(a_handle),
            Handle::<SimpleArchive>::to_hash(b_handle),
            Handle::<SimpleArchive>::to_hash(c_handle),
        )))
        .unwrap();
        pile.close().unwrap();

        append_v3_blob_candidate(&path, c_handle.into(), b"corrupt compacted archive", 3);
        let mut pile = Pile::open(&path).unwrap();
        let cover = Cover::from_members(collection, [a_handle, b_handle]);
        let snapshot = pile.snapshot().unwrap();
        assert_eq!(cover.available(&snapshot).unwrap(), cover);
        assert_eq!(
            cover.materialize::<TribleSet, _>(&snapshot).unwrap(),
            expected,
        );

        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn duplicate_replay_keeps_payload_validation_lazy() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "offset-validation.pile");
        let payload = b"target";
        let handle = Blob::<UnknownBlob>::new(Bytes::from_source(payload.to_vec())).get_handle();
        let hash: Inline<Hash<Blake3>> = handle.into();

        let first = append_v3_blob_candidate(&path, hash, payload, 1);
        let second = append_v3_blob_candidate(&path, hash, b"bad-02", 2);
        let third = append_v3_blob_candidate(&path, hash, b"bad-03", 3);

        let mut pile = Pile::open(&path).unwrap();
        pile.refresh().unwrap();
        assert_eq!(
            first_blob_occurrence(&pile.blobs, &hash.raw)
                .unwrap()
                .record_offset,
            first
        );
        assert_eq!(pile.blobs.segmented_len(&hash.raw), 3);
        for offset in [first, second, third] {
            assert_eq!(
                blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(offset))
                    .cached(),
                None
            );
        }

        let reader = pile.snapshot().unwrap();
        let blob: Blob<UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(blob.bytes.as_ref(), payload);
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(first)).cached(),
            Some(ValidationState::Validated)
        );
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(second)).cached(),
            None
        );
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(third)).cached(),
            None
        );
        drop(reader);
        pile.close().unwrap();
    }

    #[test]
    fn cold_replay_recovers_from_corrupt_primary_with_valid_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "all-invalid.pile");
        let payload = b"target";
        let handle = Blob::<UnknownBlob>::new(Bytes::from_source(payload.to_vec())).get_handle();
        let hash: Inline<Hash<Blake3>> = handle.into();

        let first = append_v3_blob_candidate(&path, hash, b"bad-01", 1);
        let second = append_v3_blob_candidate(&path, hash, payload, 2);
        let third = append_v3_blob_candidate(&path, hash, b"bad-03", 3);
        let mut pile = Pile::open(&path).unwrap();
        pile.refresh().unwrap();
        for offset in [first, second, third] {
            assert_eq!(
                blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(offset))
                    .cached(),
                None
            );
        }
        let reader = pile.snapshot().unwrap();
        let blob: Blob<UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(blob.bytes.as_ref(), payload);
        let metadata = reader
            .metadata(handle)
            .unwrap()
            .expect("valid fallback metadata");
        assert_eq!(metadata.timestamp, 2);
        assert_eq!(metadata.length, payload.len() as u64);
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(first)).cached(),
            Some(ValidationState::Invalid)
        );
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(second)).cached(),
            Some(ValidationState::Validated)
        );
        assert_eq!(
            blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(third)).cached(),
            None
        );
        drop(reader);
        pile.close().unwrap();
    }

    #[test]
    fn all_invalid_duplicates_fail_after_lazy_exhaustion() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "all-invalid.pile");
        let expected = b"target";
        let handle = Blob::<UnknownBlob>::new(Bytes::from_source(expected.to_vec())).get_handle();
        let hash: Inline<Hash<Blake3>> = handle.into();

        let first = append_v3_blob_candidate(&path, hash, b"bad-01", 1);
        let second = append_v3_blob_candidate(&path, hash, b"bad-02", 2);
        let third = append_v3_blob_candidate(&path, hash, b"bad-03", 3);
        let mut pile = Pile::open(&path).unwrap();
        pile.refresh().unwrap();
        for offset in [first, second, third] {
            assert_eq!(
                blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(offset))
                    .cached(),
                None
            );
        }

        let reader = pile.snapshot().unwrap();
        assert!(matches!(
            reader.get::<Blob<UnknownBlob>, UnknownBlob>(handle),
            Err(GetBlobError::ValidationError(_))
        ));
        assert!(reader.metadata(handle).unwrap().is_none());
        for offset in [first, second, third] {
            assert_eq!(
                blob_occurrence_validation(&pile.blobs, &hash.raw, IndexEntry::new(offset))
                    .cached(),
                Some(ValidationState::Invalid)
            );
        }
        drop(reader);
        pile.close().unwrap();
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_validation_dispatch_respects_threshold_and_current_pool() {
        let bytes = Bytes::from_source(vec![0xA5; PARALLEL_BLAKE3_THRESHOLD]);
        let expected = Hash::<Blake3>::digest(&bytes);

        let one_worker = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        one_worker.install(|| {
            assert!(!should_parallelize_validation(PARALLEL_BLAKE3_THRESHOLD));
            assert!(matches!(
                compute_validation_state(&bytes, &expected, ValidationStrategy::ParallelIfLarge),
                ValidationState::Validated
            ));
        });

        let two_workers = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        two_workers.install(|| {
            assert!(!should_parallelize_validation(
                PARALLEL_BLAKE3_THRESHOLD - 1
            ));
            assert!(should_parallelize_validation(PARALLEL_BLAKE3_THRESHOLD));
            assert!(matches!(
                compute_validation_state(&bytes, &expected, ValidationStrategy::ParallelIfLarge),
                ValidationState::Validated
            ));
            assert!(matches!(
                compute_validation_state(&bytes, &expected, ValidationStrategy::Serial),
                ValidationState::Validated
            ));
        });
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn large_reader_get_uses_parallel_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "large-reader.pile");
        let payload = vec![0xC3; PARALLEL_BLAKE3_THRESHOLD + 17];

        let mut writer = Pile::open(&path).unwrap();
        let handle: Inline<Handle<UnknownBlob>> =
            writer.put(Bytes::from_source(payload.clone())).unwrap();
        writer.close().unwrap();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();

        let mut replayed = Pile::open(&path).unwrap();
        let reader = replayed.snapshot().unwrap();
        pool.install(|| {
            let blob = reader
                .get::<Blob<UnknownBlob>, UnknownBlob>(handle)
                .unwrap();
            assert_eq!(blob.bytes.as_ref(), payload.as_slice());
        });
        drop(reader);
        replayed.close().unwrap();
    }

    #[test]
    fn open() {
        const RECORD_LEN: usize = 1 << 10; // 1k
        const RECORD_COUNT: usize = 1 << 12; // 4k

        let mut rng = rand::thread_rng();
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_pile = fresh_empty_pile_path(&tmp_dir, "test.pile");
        let mut pile: Pile = Pile::open(&tmp_pile).unwrap();

        (0..RECORD_COUNT).for_each(|_| {
            let mut record = Vec::with_capacity(RECORD_LEN);
            rng.fill_bytes(&mut record);

            let data: Blob<UnknownBlob> = Blob::new(Bytes::from_source(record));
            pile.put::<UnknownBlob, _>(data).unwrap();
        });

        pile.close().unwrap();

        let mut reopened: Pile = Pile::open(&tmp_pile).unwrap();
        reopened.amputate().unwrap();
        reopened.close().unwrap();
    }

    #[test]
    fn put_enveloped_256_aligned_roundtrip() {
        // Every current record is a 256-byte multiple with the data at a fixed
        // header offset, so plain `put` yields absolutely 256-aligned
        // (GPU-aliasable) data in a current pile.
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "v3.pile");
        // Sizes around the 64/256 boundaries to exercise the post-pad.
        let sizes = [1usize, 7, 33, 64, 100, 192, 255, 256, 257, 1000, 4096];
        let mut hashes = Vec::new();
        let mut datas: Vec<Vec<u8>> = Vec::new();
        {
            let mut pile: Pile = Pile::open(&path).unwrap();
            for &sz in &sizes {
                let data: Vec<u8> = (0..sz).map(|i| (i % 251) as u8).collect();
                let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
                let h = pile.put::<UnknownBlob, _>(blob).unwrap();
                let hash: Inline<Hash<Blake3>> = h.into();
                hashes.push(hash);
                datas.push(data);
            }
            pile.close().unwrap();
        }
        // Reopen fresh — the scan rebuilds the index from enveloped records.
        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        for (hash, expected) in hashes.iter().zip(&datas) {
            let entry = first_blob_occurrence(&pile.blobs, &hash.raw)
                .expect("enveloped blob missing after reopen");
            let record = indexed_blob_record(&pile.mmap, pile.applied_length, entry, hash);
            assert_eq!(
                record.payload_offset % GPU_DATA_ALIGNMENT,
                0,
                "enveloped data offset {} not {GPU_DATA_ALIGNMENT}-aligned (size {})",
                record.payload_offset,
                expected.len()
            );
            assert_eq!(
                record.bytes.as_ref(),
                &expected[..],
                "enveloped roundtrip mismatch (size {})",
                expected.len()
            );
        }
        pile.close().unwrap();
    }

    /// The whole point of uniform current framing: `cat a.pile >> b.pile` is a valid merge —
    /// every record from both piles is found and byte-correct, the data stays
    /// 256-aligned, and `amputate()` does not truncate the concatenation as
    /// corrupt. This is what an offset-derived pad could never survive.
    #[test]
    fn enveloped_cat_merge_preserves_all_blobs_and_alignment() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = fresh_empty_pile_path(&dir, "a.pile");
        let path_b = fresh_empty_pile_path(&dir, "b.pile");
        let sizes = [1usize, 33, 100, 256, 257, 1000, 4096];
        let mut handles: Vec<(Inline<Hash<Blake3>>, Vec<u8>)> = Vec::new();

        {
            let mut a: Pile = Pile::open(&path_a).unwrap();
            for (k, &sz) in sizes.iter().enumerate() {
                let data: Vec<u8> = (0..sz).map(|i| ((i + k) % 251) as u8).collect();
                let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
                let h: Inline<Hash<Blake3>> = a.put::<UnknownBlob, _>(blob).unwrap().into();
                handles.push((h, data));
            }
            a.close().unwrap();
        }
        {
            let mut b: Pile = Pile::open(&path_b).unwrap();
            for (k, &sz) in sizes.iter().enumerate() {
                // Distinct content so no hash collisions with pile A.
                let data: Vec<u8> = (0..sz).map(|i| ((i + k + 128) % 251) as u8).collect();
                let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
                let h: Inline<Hash<Blake3>> = b.put::<UnknownBlob, _>(blob).unwrap().into();
                handles.push((h, data));
            }
            b.close().unwrap();
        }

        // Each current pile is a whole number of 256-byte units — the precondition
        // that makes the appended pile land on a 256-aligned offset.
        assert_eq!(
            std::fs::metadata(&path_a).unwrap().len() % ENVELOPE_BLOCK_LEN as u64,
            0
        );
        assert_eq!(
            std::fs::metadata(&path_b).unwrap().len() % ENVELOPE_BLOCK_LEN as u64,
            0
        );

        // cat a.pile >> b.pile
        {
            let a_bytes = std::fs::read(&path_a).unwrap();
            let mut bf = std::fs::OpenOptions::new()
                .append(true)
                .open(&path_b)
                .unwrap();
            bf.write_all(&a_bytes).unwrap();
            bf.sync_all().unwrap();
        }
        let merged_len = std::fs::metadata(&path_b).unwrap().len();

        let mut merged: Pile = Pile::open(&path_b).unwrap();
        merged.amputate().unwrap();
        assert_eq!(
            std::fs::metadata(&path_b).unwrap().len(),
            merged_len,
            "cat-merged pile was truncated — cat is not a valid framed merge"
        );
        for (hash, expected) in &handles {
            let entry =
                first_blob_occurrence(&merged.blobs, &hash.raw).expect("blob lost after cat-merge");
            let record = indexed_blob_record(&merged.mmap, merged.applied_length, entry, hash);
            assert_eq!(
                record.payload_offset % ENVELOPE_BLOCK_LEN,
                0,
                "post-cat data offset not 256-aligned"
            );
            assert_eq!(
                record.bytes.as_ref(),
                &expected[..],
                "blob bytes wrong after cat-merge"
            );
        }
        // Still 256-aligned, so it can be cat'd again.
        assert_eq!(
            std::fs::metadata(&path_b).unwrap().len() % ENVELOPE_BLOCK_LEN as u64,
            0
        );
        merged.close().unwrap();
    }

    /// Existing V1 piles remain readable unchanged by the current reader.
    #[test]
    fn v3_reader_still_reads_legacy_v1_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "legacy_v1.pile");
        let data = vec![9u8; 40];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle: Inline<Handle<UnknownBlob>> = blob.get_handle();
        let hash: Inline<Hash<Blake3>> = handle.into();
        // Hand-write a legacy V1 blob record: 64-byte header + data + 64-pad.
        {
            let header = BlobHeader::new(42, data.len() as u64, hash);
            let pad = padding_for_blob(data.len());
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(header.as_bytes()).unwrap();
            f.write_all(&data).unwrap();
            f.write_all(&vec![0u8; pad]).unwrap();
            f.sync_all().unwrap();
        }
        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        let reader = pile.snapshot().unwrap();
        let fetched: Blob<UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(
            fetched.bytes.as_ref(),
            data.as_slice(),
            "legacy V1 blob not read by the current reader"
        );
        pile.close().unwrap();
    }

    #[test]
    fn recover_shrink() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        {
            let mut pile: Pile = Pile::open(&path).unwrap();
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 20]));
            pile.put::<UnknownBlob, _>(blob).unwrap();
            pile.close().unwrap();
        }

        // Corrupt by removing some bytes from the end
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        file.set_len(len - 10).unwrap();

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        pile.close().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn refresh_corrupt_reports_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        {
            let mut pile: Pile = Pile::open(&path).unwrap();
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 20]));
            pile.put::<UnknownBlob, _>(blob).unwrap();
            pile.close().unwrap();
        }

        let file_len = std::fs::metadata(&path).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(file_len - 10)
            .unwrap();

        let mut pile: Pile = Pile::open(&path).unwrap();
        match pile.refresh() {
            Err(ReadError::CorruptPile { valid_length }) => assert_eq!(valid_length, 0),
            other => panic!("unexpected result: {other:?}"),
        }
        pile.close().unwrap();
    }

    #[test]
    fn bounded_replay_stops_at_its_observed_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "bounded-refresh.pile");

        let (first, second) = {
            let mut writer = Pile::open(&path).unwrap();
            let first = writer
                .put::<UnknownBlob, _>(Bytes::from_source(b"first".to_vec()))
                .unwrap();
            let second = writer
                .put::<UnknownBlob, _>(Bytes::from_source(b"second".to_vec()))
                .unwrap();
            writer.close().unwrap();
            (first, second)
        };

        let first_end = {
            let mut records = PileRecords::open(&path).unwrap();
            let record = records.next().unwrap().unwrap();
            record.offset + record.len
        };

        let mut replay = Pile::open(&path).unwrap();
        assert!(matches!(
            replay.apply_next_bounded(first_end).unwrap(),
            Some(Applied::Blob { hash }) if hash.raw == first.raw
        ));
        assert!(replay.apply_next_bounded(first_end).unwrap().is_none());
        assert_eq!(replay.applied_length, first_end);
        assert!(replay.blobs.has_prefix(&first.raw));
        assert!(!replay.blobs.has_prefix(&second.raw));

        replay.refresh().unwrap();
        assert!(replay.blobs.has_prefix(&second.raw));
        replay.close().unwrap();
    }

    #[test]
    fn unknown_magic_reports_unsupported_without_amputation() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        {
            let mut pile: Pile = Pile::open(&path).unwrap();
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 20]));
            pile.put::<UnknownBlob, _>(blob).unwrap();
            pile.close().unwrap();
        }

        let valid_len = std::fs::metadata(&path).unwrap().len() as usize;
        let unknown_marker = [0xA5u8; 16];
        let mut unknown_record = [0u8; V3_HEADER_LEN];
        unknown_record[..16].copy_from_slice(&unknown_marker);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&unknown_record)
            .unwrap();
        let length_with_unknown_record = std::fs::metadata(&path).unwrap().len();

        let mut pile: Pile = Pile::open(&path).unwrap();
        assert!(matches!(
            pile.refresh(),
            Err(ReadError::UnsupportedRecord { offset, marker })
                if offset == valid_len && marker == unknown_marker
        ));
        assert!(matches!(
            pile.amputate(),
            Err(ReadError::UnsupportedRecord { offset, marker })
                if offset == valid_len && marker == unknown_marker
        ));
        pile.close().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            length_with_unknown_record,
            "amputation must preserve a record whose marker this reader does not know"
        );
    }

    #[test]
    fn decoder_distinguishes_unknown_magic_from_truncated_known_record() {
        let unknown_marker = [0xA5u8; 16];
        assert!(matches!(
            decode_record(&unknown_marker, ENVELOPE_BLOCK_LEN),
            Err(ReadError::UnsupportedRecord { offset, marker })
                if offset == ENVELOPE_BLOCK_LEN && marker == unknown_marker
        ));

        assert!(matches!(
            decode_record(&MAGIC_MARKER_BLOB_V3, ENVELOPE_BLOCK_LEN),
            Err(ReadError::CorruptPile { valid_length })
                if valid_length == ENVELOPE_BLOCK_LEN
        ));
    }

    #[test]
    fn refresh_partial_header_reports_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        {
            let mut pile: Pile = Pile::open(&path).unwrap();
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 20]));
            pile.put::<UnknownBlob, _>(blob).unwrap();
            pile.close().unwrap();
        }

        let file_len = std::fs::metadata(&path).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(file_len + 8)
            .unwrap();

        let mut pile: Pile = Pile::open(&path).unwrap();
        match pile.refresh() {
            Err(ReadError::CorruptPile { valid_length }) => {
                assert_eq!(valid_length as u64, file_len)
            }
            other => panic!("unexpected result: {other:?}"),
        }
        pile.close().unwrap();
    }

    #[test]
    fn refresh_length_beyond_file_reports_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        {
            let mut pile: Pile = Pile::open(&path).unwrap();
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 20]));
            pile.put::<UnknownBlob, _>(blob).unwrap();
            pile.close().unwrap();
        }

        use std::io::Seek;
        use std::io::SeekFrom;
        use std::io::Write;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // The blob record's declared payload length lives at 72..80.
        file.seek(SeekFrom::Start(72)).unwrap();
        file.write_all(&(1_000_000u64).to_le_bytes()).unwrap();
        file.flush().unwrap();
        drop(file);

        let mut pile: Pile = Pile::open(&path).unwrap();
        match pile.refresh() {
            Err(ReadError::CorruptPile { valid_length }) => assert_eq!(valid_length, 0),
            other => panic!("unexpected result: {other:?}"),
        }
        pile.close().unwrap();
    }

    #[test]
    fn amputate_truncates_length_beyond_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        {
            let mut pile: Pile = Pile::open(&path).unwrap();
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 20]));
            pile.put::<UnknownBlob, _>(blob).unwrap();
            pile.close().unwrap();
        }

        use std::io::Seek;
        use std::io::SeekFrom;
        use std::io::Write;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // The blob record's declared payload length lives at 72..80.
        file.seek(SeekFrom::Start(72)).unwrap();
        file.write_all(&(1_000_000u64).to_le_bytes()).unwrap();
        file.flush().unwrap();
        drop(file);

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        pile.close().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn put_and_get_preserves_blob_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let data = vec![42u8; 100];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();

        {
            let reader = pile.snapshot().unwrap();
            let fetched: Blob<UnknownBlob> = reader.get(handle).unwrap();
            assert_eq!(fetched.bytes.as_ref(), data.as_slice());
        }

        pile.close().unwrap();

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        let reader = pile.snapshot().unwrap();
        let fetched: Blob<UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(fetched.bytes.as_ref(), data.as_slice());
        pile.close().unwrap();
    }

    #[test]
    fn iter_lists_all_blobs_handles() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blobs = vec![vec![1u8; 3], vec![2u8; 4], vec![3u8; 5]];
        let mut expected = HashMap::new();
        for data in blobs {
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
            let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
            expected.insert(handle, data);
        }
        pile.flush().unwrap();

        let reader = pile.snapshot().unwrap();
        for item in reader.iter() {
            let (handle, blob) = item.expect("infallible iteration");
            let data = expected.remove(&handle).unwrap();
            assert_eq!(blob.bytes.as_ref(), data.as_slice());
        }
        assert!(expected.is_empty());

        pile.close().unwrap();
    }

    #[test]
    fn blobs_diff_returns_only_new_handles() {
        use crate::repo::BlobStoreList;
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();

        // Stage three baseline blobs and snapshot the reader.
        let mut baseline_handles: HashSet<Inline<Handle<UnknownBlob>>> = HashSet::new();
        for data in [vec![1u8; 3], vec![2u8; 4], vec![3u8; 5]] {
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data));
            let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
            baseline_handles.insert(handle);
        }
        let baseline = pile.snapshot().unwrap();

        // Stage two more blobs after taking the baseline snapshot.
        let mut new_handles: HashSet<Inline<Handle<UnknownBlob>>> = HashSet::new();
        for data in [vec![4u8; 6], vec![5u8; 7]] {
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data));
            let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
            new_handles.insert(handle);
        }

        // Diff the current reader against the baseline.
        let current = pile.snapshot().unwrap();
        let diffed: HashSet<Inline<Handle<UnknownBlob>>> = current
            .blobs_diff(&baseline)
            .map(|r| r.expect("infallible diff iter").handle)
            .collect();

        // Diff should equal exactly the new blobs — none of the baseline ones.
        assert_eq!(diffed, new_handles);
        for h in &baseline_handles {
            assert!(!diffed.contains(h), "baseline blob leaked into diff");
        }

        // Round-trip sanity: diffing a reader against itself yields nothing.
        let empty: HashSet<_> = current
            .blobs_diff(&current)
            .map(|r| r.expect("infallible").handle)
            .collect();
        assert!(empty.is_empty());

        pile.close().unwrap();
    }

    #[test]
    fn duplicate_occurrence_changes_physical_snapshot_but_not_semantic_diff() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "duplicate-diff.pile");
        let payload = b"same semantic blob";
        let handle = Blob::<UnknownBlob>::new(Bytes::from_source(payload.to_vec())).get_handle();
        let hash: Inline<Hash<Blake3>> = handle.into();

        let first = append_v3_blob_candidate(&path, hash, payload, 1);
        let mut pile = Pile::open(&path).unwrap();
        let baseline = pile.snapshot().unwrap();
        assert_eq!(baseline.blobs.len(), 1);
        assert_eq!(baseline.blobs.segmented_len(&hash.raw), 1);
        assert_eq!(baseline.blobs().count(), 1);
        assert_eq!(baseline.iter().count(), 1);

        let second = append_v3_blob_candidate(&path, hash, payload, 2);
        let current = pile.snapshot().unwrap();
        assert!(second > first);
        assert_eq!(baseline.blobs.len(), 1);
        assert_eq!(current.blobs.len(), 2);
        assert!(!baseline.blobs.shares_root(&current.blobs));
        assert_eq!(baseline.blobs.segmented_len(&hash.raw), 1);
        assert_eq!(current.blobs.segmented_len(&hash.raw), 2);
        assert_eq!(
            baseline.blobs.prefix_set::<32>().iter().collect::<Vec<_>>(),
            current.blobs.prefix_set::<32>().iter().collect::<Vec<_>>()
        );
        assert_eq!(current.changes_since(&baseline), StoreChanges::BLOBS);
        assert_eq!(current.blobs().count(), 1);
        assert_eq!(current.iter().count(), 1);

        assert!(current.blobs_diff(&baseline).next().is_none());
        assert!(baseline.blobs_diff(&current).next().is_none());

        pile.close().unwrap();
    }

    #[test]
    fn keyed_blob_info_reports_index_length_without_payload_access() {
        use crate::repo::BlobStoreList;

        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");
        let mut pile = Pile::open(&path).unwrap();
        let handle = pile
            .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(vec![7u8; 13])))
            .unwrap();
        let reader = pile.snapshot().unwrap();

        let info = BlobStoreList::blob_info(&reader, handle)
            .unwrap()
            .expect("stored blob has keyed information");
        assert_eq!(info.handle, handle);
        assert_eq!(info.length, 13);

        let absent = Inline::<Handle<UnknownBlob>>::new([0xA5; 32]);
        assert!(BlobStoreList::blob_info(&reader, absent).unwrap().is_none());
        pile.close().unwrap();
    }

    #[test]
    fn metadata_reflects_length_and_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let data = vec![9u8; 10];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
        pile.flush().unwrap();

        let reader = pile.snapshot().unwrap();
        let metadata = reader.metadata(handle).unwrap().expect("metadata");
        assert_eq!(metadata.length, data.len() as u64);
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(metadata.timestamp >= before && metadata.timestamp <= after);
        pile.close().unwrap();
    }

    #[test]
    fn listing_reports_header_lengths() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let first = pile
            .put::<UnknownBlob, _>(Blob::new(Bytes::from_source(vec![1u8; 3])))
            .unwrap();
        let second = pile
            .put::<UnknownBlob, _>(Blob::new(Bytes::from_source(vec![2u8; 17])))
            .unwrap();
        let reader = pile.snapshot().unwrap();
        let listed: HashMap<_, _> = reader
            .blobs()
            .map(|result| {
                let info = result.expect("infallible listing");
                (info.handle, info.length)
            })
            .collect();

        assert_eq!(listed.get(&first), Some(&3));
        assert_eq!(listed.get(&second), Some(&17));
        pile.close().unwrap();
    }

    #[test]
    fn metadata_returns_none_for_unflushed_blob() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let reader = pile.snapshot().unwrap();

        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 4]));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();

        assert!(reader.metadata(handle).unwrap().is_none());

        pile.flush().unwrap();
        let reader = pile.snapshot().unwrap();
        assert!(reader.metadata(handle).unwrap().is_some());
        pile.close().unwrap();
    }

    #[test]
    fn blob_after_branch_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();

        let branch_id = Id::new([1; 16]).unwrap();
        let head = Inline::<Handle<SimpleArchive>>::new([2; 32]);
        pile.append_legacy_pin_for_test(branch_id, None, Some(head))
            .unwrap();

        let data = vec![3u8; 8];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
        pile.flush().unwrap();

        let stored: Blob<UnknownBlob> = pile.snapshot().unwrap().get(handle).unwrap();
        assert_eq!(stored.bytes.as_ref(), &data[..]);
        pile.close().unwrap();
    }

    #[test]
    fn insert_after_branch_preserves_head() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blob1: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 5]));
        let handle1 = pile.put::<UnknownBlob, _>(blob1).unwrap();

        let branch_id = Id::new([1u8; 16]).unwrap();
        pile.append_legacy_pin_for_test(branch_id, None, Some(handle1.transmute()))
            .unwrap();

        let blob2: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![2u8; 5]));
        pile.put::<UnknownBlob, _>(blob2).unwrap();
        pile.close().unwrap();

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        let head = pile.legacy_pin_head_for_test(branch_id).unwrap();
        assert_eq!(head, Some(handle1.transmute()));
        pile.close().unwrap();
    }

    #[test]
    fn branch_update_survives_manual_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let branch_id = Id::new([1u8; 16]).unwrap();

        let handle = {
            let mut pile: Pile = Pile::open(&path).unwrap();
            let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![3u8; 5]));
            let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
            pile.append_legacy_pin_for_test(branch_id, None, Some(handle.transmute()))
                .unwrap();
            pile.flush().unwrap();
            std::mem::forget(pile);
            handle
        };

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        assert_eq!(
            pile.legacy_pin_head_for_test(branch_id).unwrap(),
            Some(handle.transmute())
        );
        assert!(std::fs::metadata(&path).unwrap().len() > 0);
        pile.close().unwrap();
    }

    #[test]
    fn branch_tombstone_removes_head_and_listing() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 5]));
        let h = pile.put::<UnknownBlob, _>(blob).unwrap();
        let branch_id = Id::new([7u8; 16]).unwrap();
        pile.append_legacy_pin_for_test(branch_id, None, Some(h.transmute()))
            .unwrap();
        pile.flush().unwrap();

        assert_eq!(
            pile.legacy_pin_head_for_test(branch_id).unwrap(),
            Some(h.transmute())
        );

        pile.append_legacy_pin_for_test(branch_id, Some(h.transmute()), None)
            .unwrap();
        pile.flush().unwrap();

        assert_eq!(pile.legacy_pin_head_for_test(branch_id).unwrap(), None);
        pile.refresh().unwrap();
        let branches: HashSet<Id> = pile
            .branches
            .iter_ordered()
            .map(|raw| Id::new(*raw).expect("legacy pin ids are non-nil"))
            .collect();
        assert!(!branches.contains(&branch_id));
        pile.close().unwrap();
    }

    #[test]
    fn metadata_returns_length_and_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![7u8; 32]));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
        pile.close().unwrap();

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        let reader = pile.snapshot().unwrap();
        let meta = reader.metadata(handle).unwrap().expect("metadata");
        assert_eq!(meta.length, 32);
        assert!(meta.timestamp > 0);
        pile.close().unwrap();
    }

    #[test]
    fn iter_lists_all_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blob1: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 4]));
        let h1 = pile.put::<UnknownBlob, _>(blob1).unwrap();
        let blob2: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![2u8; 4]));
        let h2 = pile.put::<UnknownBlob, _>(blob2).unwrap();
        pile.flush().unwrap();

        let reader = pile.snapshot().unwrap();
        let handles: Vec<_> = reader
            .iter()
            .map(|res| res.expect("infallible iteration").0)
            .collect();
        assert!(handles.contains(&h1));
        assert!(handles.contains(&h2));
        assert_eq!(handles.len(), 2);
        pile.close().unwrap();
    }

    #[test]
    fn refresh_errors_on_malformed_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(vec![1u8; 4]));
        pile.put::<UnknownBlob, _>(blob).unwrap();
        pile.flush().unwrap();

        use std::io::Write;
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(b"garbage").unwrap();
            file.sync_all().unwrap();
        }

        assert!(pile.refresh().is_err());
        pile.close().unwrap();
    }

    #[test]
    fn amputate_truncates_corrupt_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let data = vec![1u8; 4];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
        pile.flush().unwrap();

        use std::io::Write;
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            file.write_all(b"garbage").unwrap();
            file.sync_all().unwrap();
        }

        pile.amputate().unwrap();

        // Blobs are written as enveloped records (fixed 256-byte header, padded to a
        // 256-byte multiple).
        let expected_len =
            (super::ENVELOPE_HEADER_LEN + data.len() + super::block_post_pad(data.len())) as u64;
        assert_eq!(std::fs::metadata(&path).unwrap().len(), expected_len);

        let reader = pile.snapshot().unwrap();
        let fetched: Blob<UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(fetched.bytes.as_ref(), data.as_slice());
        pile.close().unwrap();
    }

    #[test]
    fn refresh_replaces_corrupt_blob_with_new_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile1: Pile = Pile::open(&path).unwrap();
        let mut pile2: Pile = Pile::open(&path).unwrap();

        let data = vec![1u8; 4];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle = pile1.put(blob).unwrap();
        pile1.flush().unwrap();
        pile1.refresh().unwrap();
        let before_replacement = pile1.snapshot().unwrap();

        // Corrupt the first enveloped blob's payload (the fixed header is 256 bytes).
        use std::io::Seek;
        use std::io::SeekFrom;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(ENVELOPE_HEADER_LEN as u64))
            .unwrap();
        file.write_all(&[9u8; 4]).unwrap();
        file.sync_all().unwrap();

        // Append a valid copy using the second pile which hasn't seen the first one.
        let blob_dup: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        pile2.put::<UnknownBlob, _>(blob_dup).unwrap();
        pile2.flush().unwrap();

        // Refresh the first pile; it should replace the corrupted blob with the new one.
        let after_replacement = pile1.snapshot().unwrap();
        assert_eq!(
            after_replacement.changes_since(&before_replacement),
            StoreChanges::BLOBS,
            "same-handle backing replacement changes observable blob access",
        );
        let reader = pile1.snapshot().unwrap();
        let fetched: Blob<UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(fetched.bytes.as_ref(), data.as_slice());
        pile1.close().unwrap();
        pile2.close().unwrap();
    }

    #[test]
    fn snapshot_changes_separate_external_wants_from_inventory_membership() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "revision.pile");
        let mut observer = Pile::open(&path).unwrap();
        let mut writer = Pile::open(&path).unwrap();

        let instant = hifitime::Epoch::from_tai_seconds(10.0);
        let empty = observer.snapshot_at(instant).unwrap();
        let later_instant = hifitime::Epoch::from_tai_seconds(20.0);
        let unchanged = observer.snapshot_at(later_instant).unwrap();
        assert_eq!(empty.clone().instant(), instant);
        assert_eq!(unchanged.instant(), later_instant);
        assert_eq!(unchanged.changes_since(&empty), StoreChanges::NONE);
        writer
            .want(WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
                [0xA1; 32],
            )))
            .unwrap();
        writer.flush().unwrap();
        let after_external_want = observer.snapshot().unwrap();
        assert_eq!(
            after_external_want.changes_since(&empty),
            StoreChanges::WANTS
        );
        assert!(empty.wants().unwrap().next().is_none());
        assert_eq!(after_external_want.wants().unwrap().count(), 1);

        writer
            .put::<UnknownBlob, _>(Blob::new(Bytes::from_source(vec![0xB2; 17])))
            .unwrap();
        writer.flush().unwrap();
        let after_external_blob = observer.snapshot().unwrap();
        assert_eq!(
            after_external_blob.changes_since(&after_external_want),
            StoreChanges::BLOBS,
        );

        writer.insert(collection_test_records()[0]).unwrap();
        writer.flush().unwrap();
        let after_external_record = observer.snapshot().unwrap();
        assert_eq!(
            after_external_record.changes_since(&after_external_blob),
            StoreChanges::COLLECTION_RECORDS,
        );

        let proof = capability_fixture(81, [82; 32]);
        writer.insert_proof(proof).unwrap();
        writer.flush().unwrap();
        let after_external_proof = observer.snapshot().unwrap();
        assert_eq!(
            after_external_proof.changes_since(&after_external_record),
            StoreChanges::CAPABILITY_PROOFS,
        );

        observer.close().unwrap();
        writer.close().unwrap();
    }

    #[test]
    fn put_duplicate_blob_does_not_grow_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let data = vec![9u8; 32];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle1 = pile.put::<UnknownBlob, _>(blob).unwrap();
        pile.flush().unwrap();
        let len_after_first = std::fs::metadata(&path).unwrap().len();

        let blob_dup: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data));
        let handle2 = pile.put(blob_dup).unwrap();
        pile.flush().unwrap();
        let len_after_second = std::fs::metadata(&path).unwrap().len();

        assert_eq!(handle1, handle2);
        assert_eq!(len_after_first, len_after_second);
        pile.close().unwrap();
    }

    #[test]
    fn iterator_reflects_snapshot_occurrence_relation() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blob1: Blob<UnknownBlob> = Blob::new(Bytes::from_source(b"hello".as_slice()));
        let blob2: Blob<UnknownBlob> = Blob::new(Bytes::from_source(b"world".as_slice()));
        let handle1 = pile.put::<UnknownBlob, _>(blob1).unwrap();
        let handle2 = pile.put::<UnknownBlob, _>(blob2).unwrap();
        pile.flush().unwrap();

        let mut reader = pile.snapshot().unwrap();
        let hash1: Inline<Hash<Blake3>> = handle1.into();
        let entry = first_blob_occurrence(&reader.blobs, &hash1.raw).unwrap();
        reader.blobs.remove(&blob_occurrence_key(&hash1.raw, entry));

        let mut iter = reader.iter();
        assert_eq!(iter.next().unwrap().unwrap().0, handle2);
        assert!(iter.next().is_none());
        pile.close().unwrap();
    }

    #[test]
    fn metadata_reports_blob_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let mut pile: Pile = Pile::open(&path).unwrap();
        let data = vec![7u8; 16];
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();
        pile.flush().unwrap();

        let reader = pile.snapshot().unwrap();
        let meta = reader.metadata(handle).unwrap().expect("metadata");
        assert_eq!(meta.length, data.len() as u64);
        pile.close().unwrap();
    }

    /// Durable wants survive close + reopen; the scan rebuilds the grow-only
    /// set from its current on-disk markers.
    #[test]
    fn want_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        // A want may name a blob that is not present in the pile.
        let wanted: Inline<Handle<UnknownBlob>> =
            Blob::<UnknownBlob>::new(Bytes::from_source(vec![7u8; 21])).get_handle();

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.want(WantRequest::blob(wanted)).unwrap();
        let pinned: HashSet<_> = pile
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(pinned.contains(&WantRequest::blob(wanted)));
        pile.close().unwrap();

        let mut reopened: Pile = Pile::open(&path).unwrap();
        reopened.amputate().unwrap();
        let pinned: HashSet<_> = reopened
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(pinned.len(), 1);
        assert!(
            pinned.contains(&WantRequest::blob(wanted)),
            "want lost across reopen — restart amnesia"
        );
        reopened.close().unwrap();
    }

    #[test]
    fn typed_operation_wants_roundtrip_as_exact_enveloped_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "typed-wants.pile");
        let source = collection_test_collection(31);
        let target = collection_test_collection(32);
        let merge = WantRequest::merge(source, collection_test_hash(34), collection_test_hash(33));
        let derive = WantRequest::derive(target, collection_test_hash(35));

        let mut pile = Pile::open(&path).unwrap();
        pile.want(merge).unwrap();
        pile.want(derive).unwrap();
        pile.flush().unwrap();
        assert_eq!(
            pile.snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![merge, derive]
        );
        pile.close().unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (2 * ENVELOPE_HEADER_LEN) as u64
        );
        let records = PileRecords::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(matches!(
            records[0].content,
            PileRecordContent::Want { request } if request == merge
        ));
        assert!(matches!(
            records[1].content,
            PileRecordContent::Want { request } if request == derive
        ));

        let mut reopened = Pile::open(&path).unwrap();
        reopened.refresh().unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![merge, derive]
        );
        reopened.close().unwrap();
    }

    #[test]
    fn typed_wants_union_without_retraction() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "typed-want-set.pile");
        let source = collection_test_collection(41);
        let target = collection_test_collection(42);
        let input = collection_test_hash(43);
        let merge = WantRequest::merge(source, input, collection_test_hash(44));
        let derive = WantRequest::derive(target, input);

        let mut pile = Pile::open(&path).unwrap();
        pile.want(merge).unwrap();
        pile.want(derive).unwrap();
        assert_eq!(
            pile.snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![merge, derive]
        );
        pile.close().unwrap();

        let mut reopened = Pile::open(&path).unwrap();
        reopened.refresh().unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![merge, derive]
        );
        reopened.close().unwrap();
    }

    #[test]
    fn blob_wants_use_the_same_current_marker_as_operation_wants() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "blob-want-projection.pile");
        let handle = Inline::<Handle<UnknownBlob>>::new([47; 32]);

        let mut pile = Pile::open(&path).unwrap();
        pile.want(WantRequest::blob(handle)).unwrap();
        pile.close().unwrap();

        let records = PileRecords::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(matches!(
            records[0].content,
            PileRecordContent::Want { request }
                if request == WantRequest::blob(handle)
        ));
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn current_want_marker_accepts_blob_but_rejects_retired_derive_tag() {
        let request = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([48; 32]));
        let header = WantRecordHeader::new(request);
        assert!(matches!(
            decode_record(header.as_bytes(), 0).unwrap().content,
            PileRecordContent::Want { request: actual } if actual == request
        ));

        let mut header = retired_typed_derive_v1_record(
            collection_test_collection(49),
            collection_test_collection(50),
            collection_test_hash(51),
            true,
        );
        header.record_kind = record_kind::KIND_WANT;
        assert!(matches!(
            decode_record(header.as_bytes(), 0),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));

        let target = collection_test_collection(52);
        let input = collection_test_hash(53);
        let legacy = TypedWantHeaderEnvelopeV1 {
            envelope_marker: MAGIC_MARKER_ENVELOPE,
            record_kind: MAGIC_MARKER_WANT_ASSERT_V2,
            span_blocks: ENVELOPE_HEADER_BLOCKS.to_le_bytes(),
            request_kind: WANT_REQUEST_KIND_DERIVE_V1,
            field_a: collection_test_collection(51).raw,
            field_b: target.raw,
            field_c: input.raw,
            reserved: [0; 123],
        };
        assert!(matches!(
            decode_record(legacy.as_bytes(), 0).unwrap().content,
            PileRecordContent::RetiredWantAssert { request, .. }
                if request == WantRequest::derive(target, input)
        ));
    }

    #[test]
    fn retired_wants_are_inert_until_idempotent_additive_cutover() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let a = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([61; 32]));
        let b = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([62; 32]));
        let merge = WantRequest::merge(
            collection_test_collection(63),
            collection_test_hash(64),
            collection_test_hash(65),
        );
        let derive = WantRequest::derive(collection_test_collection(67), collection_test_hash(68));

        // Resolve the retired log as: a active, b inactive, merge active, and
        // one short-lived DERIVE_V1 request active. The latter carried
        // `(source, target, input)` and must migrate to `(target, input)`.
        for record in [
            retired_blob_want_record(a, true).as_bytes().to_vec(),
            retired_blob_want_record(a, false).as_bytes().to_vec(),
            retired_blob_want_record(a, true).as_bytes().to_vec(),
            retired_blob_want_record(b, true).as_bytes().to_vec(),
            retired_blob_want_record(b, false).as_bytes().to_vec(),
            retired_typed_want_record(merge, true).as_bytes().to_vec(),
            retired_typed_derive_v1_record(
                collection_test_collection(66),
                collection_test_collection(67),
                collection_test_hash(68),
                true,
            )
            .as_bytes()
            .to_vec(),
            // A retraction with another historical source has the same
            // current projection but is a distinct old LWW key. It must not
            // cancel the active source-66 assertion above.
            retired_typed_derive_v1_record(
                collection_test_collection(69),
                collection_test_collection(67),
                collection_test_hash(68),
                false,
            )
            .as_bytes()
            .to_vec(),
        ] {
            append_test_bytes(&path, &record);
        }

        let mut pile = Pile::open(&path).unwrap();
        assert!(pile.snapshot().unwrap().wants().unwrap().next().is_none());
        // One request already has a fresh marker; cutover appends only the two
        // missing positives rather than rewriting the pile.
        pile.want(merge).unwrap();
        let before = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            pile.want_cutover_status().unwrap(),
            WantCutoverStatus {
                retired_records: 8,
                resolved_active: 3,
                already_current: 1,
                missing_current: 2,
            }
        );
        let migrated = pile.migrate_retired_wants().unwrap();
        assert_eq!(migrated.missing_current, 2);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            before + 2 * ENVELOPE_HEADER_LEN as u64
        );
        let expected = vec![a, merge, derive];
        assert_eq!(
            pile.snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            expected
        );
        assert_eq!(pile.want_cutover_status().unwrap().missing_current, 0);
        let after_first = std::fs::metadata(&path).unwrap().len();
        pile.migrate_retired_wants().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), after_first);
        pile.close().unwrap();

        // A stale pre-cutover pile concatenated later cannot retract or
        // resurrect current demand: retired frames remain inert forever.
        append_test_bytes(&path, retired_blob_want_record(a, false).as_bytes());
        append_test_bytes(&path, retired_blob_want_record(b, true).as_bytes());
        let mut reopened: Pile = Pile::open(&path).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            expected
        );
        reopened.close().unwrap();
    }

    /// Re-adding an existing set element is a no-op append.
    #[test]
    fn want_noop_does_not_grow_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        let h: Inline<Handle<UnknownBlob>> =
            Blob::<UnknownBlob>::new(Bytes::from_source(vec![3u8; 5])).get_handle();

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.want(WantRequest::blob(h)).unwrap();
        let len_after_pin = std::fs::metadata(&path).unwrap().len();
        assert_eq!(len_after_pin, ENVELOPE_HEADER_LEN as u64);

        pile.want(WantRequest::blob(h)).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len_after_pin);
        pile.close().unwrap();
    }

    /// Mixed pile: a legacy V1 blob, enveloped blobs, branch records, and want
    /// markers interleaved — the scan walks every record kind cleanly and
    /// each index (blobs, branches, wants) resolves correctly.
    #[test]
    fn mixed_v1_enveloped_branch_and_weak_markers_interleave() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "mixed.pile");

        // Hand-write a legacy V1 blob record first (64-byte header + pad).
        let v1_data = vec![9u8; 40];
        let v1_blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(v1_data.clone()));
        let v1_handle: Inline<Handle<UnknownBlob>> = v1_blob.get_handle();
        {
            let v1_hash: Inline<Hash<Blake3>> = v1_handle.into();
            let header = BlobHeader::new(42, v1_data.len() as u64, v1_hash);
            let pad = padding_for_blob(v1_data.len());
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(header.as_bytes()).unwrap();
            f.write_all(&v1_data).unwrap();
            f.write_all(&vec![0u8; pad]).unwrap();
            f.sync_all().unwrap();
        }

        let branch_id = Id::new([5u8; 16]).unwrap();
        let want: Inline<Handle<UnknownBlob>> =
            Blob::<UnknownBlob>::new(Bytes::from_source(vec![11u8; 13])).get_handle();
        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();

        // Interleave: want, enveloped blob, branch head, then another blob.
        pile.want(WantRequest::blob(want)).unwrap();
        let d1 = vec![1u8; 300];
        let b1: Blob<UnknownBlob> = Blob::new(Bytes::from_source(d1.clone()));
        let h1 = pile.put::<UnknownBlob, _>(b1).unwrap();
        pile.append_legacy_pin_for_test(branch_id, None, Some(h1.transmute()))
            .unwrap();
        let d2 = vec![2u8; 77];
        let b2: Blob<UnknownBlob> = Blob::new(Bytes::from_source(d2.clone()));
        let h2 = pile.put::<UnknownBlob, _>(b2).unwrap();
        pile.close().unwrap();

        // Fresh scan must walk the whole interleaved sequence.
        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();

        let reader = pile.snapshot().unwrap();
        let got_v1: Blob<UnknownBlob> = reader.get(v1_handle).unwrap();
        assert_eq!(got_v1.bytes.as_ref(), v1_data.as_slice());
        let got1: Blob<UnknownBlob> = reader.get(h1).unwrap();
        assert_eq!(got1.bytes.as_ref(), d1.as_slice());
        let got2: Blob<UnknownBlob> = reader.get(h2).unwrap();
        assert_eq!(got2.bytes.as_ref(), d2.as_slice());
        drop(reader);

        assert_eq!(
            pile.legacy_pin_head_for_test(branch_id).unwrap(),
            Some(h1.transmute())
        );

        let pinned: HashSet<_> = pile
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(pinned.len(), 1);
        assert!(pinned.contains(&WantRequest::blob(want)));
        pile.close().unwrap();
    }

    /// [`PileRecords`] walks a mixed legacy/current pile record-by-record: every
    /// record kind appears in log order, offsets tile the file exactly, blob
    /// payloads are addressable through `data_offset`/`data_len`, and an
    /// unknown-marker tail surfaces as `Err(UnsupportedRecord)` — never a
    /// silent stop.
    #[test]
    fn pile_records_walks_mixed_pile_and_fails_loud() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "records.pile");

        // Hand-write a legacy V1 blob record first (64-byte header + pad).
        let v1_data = vec![9u8; 40];
        let v1_blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(v1_data.clone()));
        let v1_handle: Inline<Handle<UnknownBlob>> = v1_blob.get_handle();
        {
            let v1_hash: Inline<Hash<Blake3>> = v1_handle.into();
            let header = BlobHeader::new(42, v1_data.len() as u64, v1_hash);
            let pad = padding_for_blob(v1_data.len());
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(header.as_bytes()).unwrap();
            f.write_all(&v1_data).unwrap();
            f.write_all(&vec![0u8; pad]).unwrap();
            f.sync_all().unwrap();
        }

        let branch_id = Id::new([5u8; 16]).unwrap();
        let want: Inline<Handle<UnknownBlob>> =
            Blob::<UnknownBlob>::new(Bytes::from_source(vec![11u8; 13])).get_handle();

        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        let d1 = vec![1u8; 300];
        let b1: Blob<UnknownBlob> = Blob::new(Bytes::from_source(d1.clone()));
        let h1 = pile.put::<UnknownBlob, _>(b1).unwrap();
        pile.append_legacy_pin_for_test(branch_id, None, Some(h1.transmute()))
            .unwrap();
        pile.want(WantRequest::blob(want)).unwrap();
        pile.append_legacy_pin_for_test(branch_id, Some(h1.transmute()), None)
            .unwrap();
        pile.close().unwrap();

        let mut records = PileRecords::open(&path).unwrap();
        let bytes = records.bytes().clone();
        let decoded: Vec<PileRecord> = (&mut records)
            .map(|r| r.expect("well-formed pile decodes cleanly"))
            .collect();

        // Records tile the file: each starts where the previous ended.
        let mut expected_offset = 0;
        for record in &decoded {
            assert_eq!(record.offset, expected_offset);
            expected_offset += record.len;
        }
        assert_eq!(expected_offset, bytes.len());

        // Exact sequence: V1 blob, enveloped blob, branch set, current WANT,
        // branch tombstone.
        assert_eq!(decoded.len(), 5);
        match decoded[0].content {
            PileRecordContent::Blob {
                timestamp,
                hash,
                data_offset,
                data_len,
            } => {
                assert_eq!(timestamp, 42);
                assert_eq!(hash, v1_handle.into());
                assert_eq!(data_offset, BLOB_HEADER_LEN);
                assert_eq!(&bytes[data_offset..data_offset + data_len], &v1_data[..]);
            }
            other => panic!("expected V1 blob record, got {other:?}"),
        }
        match decoded[1].content {
            PileRecordContent::Blob {
                hash,
                data_offset,
                data_len,
                ..
            } => {
                assert_eq!(hash, h1.into());
                assert_eq!(data_offset, decoded[1].offset + ENVELOPE_HEADER_LEN);
                assert_eq!(&bytes[data_offset..data_offset + data_len], &d1[..]);
            }
            other => panic!("expected enveloped blob record, got {other:?}"),
        }
        match decoded[2].content {
            PileRecordContent::Branch {
                branch_id: bid,
                head,
            } => {
                assert_eq!(bid, branch_id);
                assert_eq!(head, h1.transmute());
            }
            other => panic!("expected branch record, got {other:?}"),
        }
        match decoded[3].content {
            PileRecordContent::Want { request } => {
                assert_eq!(request, WantRequest::blob(want))
            }
            other => panic!("expected current WANT record, got {other:?}"),
        }
        match decoded[4].content {
            PileRecordContent::BranchTombstone { branch_id: bid } => {
                assert_eq!(bid, branch_id)
            }
            other => panic!("expected branch tombstone record, got {other:?}"),
        }

        // An unknown unenveloped record marker is an error at its offset, then
        // the iterator ends. Its length is unknowable, so it must not be called
        // corruption.
        let unknown_offset = std::fs::metadata(&path).unwrap().len() as usize;
        let unknown_marker = [0xFFu8; 16];
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(&unknown_marker).unwrap();
            f.sync_all().unwrap();
        }
        let mut records = PileRecords::open(&path).unwrap();
        let mut ok = 0;
        let err = loop {
            match records.next() {
                Some(Ok(_)) => ok += 1,
                Some(Err(e)) => break e,
                None => panic!("iterator ended without reporting the corrupt tail"),
            }
        };
        assert_eq!(ok, 5);
        match err {
            ReadError::UnsupportedRecord { offset, marker } => {
                assert_eq!(offset, unknown_offset);
                assert_eq!(marker, unknown_marker);
            }
            other => panic!("expected UnsupportedRecord, got {other:?}"),
        }
        assert!(records.next().is_none(), "iterator must end after an error");
    }

    #[test]
    fn retired_team_records_remain_readable_but_are_not_repository_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "retired-team-state.pile");
        let mut observer = Pile::open(&path).unwrap();
        let before = observer.snapshot().unwrap();

        let mut bytes = retired_peer_record(1, 2);
        bytes.extend_from_slice(&retired_store_scope_record(3));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();

        let after = observer.snapshot().unwrap();
        assert_eq!(after.changes_since(&before), StoreChanges::NONE);
        assert_eq!(observer.opaque_record_count().unwrap(), 0);
        let records = PileRecords::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(matches!(
            records[0].content,
            PileRecordContent::RetiredPeerEvidenceV1
        ));
        assert!(matches!(
            records[1].content,
            PileRecordContent::RetiredStoreScopeV1
        ));
        observer.close().unwrap();
    }

    #[test]
    fn retired_team_records_only_validate_physical_layout() {
        let mut scope = retired_store_scope_record(4);
        scope[96] = 1;
        assert!(matches!(
            decode_record(&scope, 0),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));

        let mut peer = retired_peer_record(5, 6);
        peer[128] = 1;
        assert!(matches!(
            decode_record(&peer, 0),
            Err(ReadError::CorruptPile { valid_length: 0 })
        ));

        // These bytes no longer carry authentication or routing semantics, so
        // replay does not spend crypto work interpreting historical fields.
        let mut arbitrary = retired_peer_record(7, 8);
        arbitrary[64..128].fill(0xFF);
        assert!(matches!(
            decode_record(&arbitrary, 0).unwrap().content,
            PileRecordContent::RetiredPeerEvidenceV1
        ));
    }

    #[test]
    fn semantic_rewrites_drop_retired_team_records() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = fresh_empty_pile_path(&dir, "source.pile");
        let reframe_path = fresh_empty_pile_path(&dir, "reframed.pile");
        let rewrite_path = fresh_empty_pile_path(&dir, "rewritten.pile");

        let mut bytes = retired_peer_record(7, 8);
        bytes.extend_from_slice(&retired_store_scope_record(9));
        std::fs::write(&source_path, bytes).unwrap();

        let mut reframed = Pile::open(&reframe_path).unwrap();
        let stats = reframe_into(&source_path, &mut reframed).unwrap();
        assert_eq!(stats.dropped_inert, 2);
        reframed.close().unwrap();
        assert_eq!(std::fs::metadata(&reframe_path).unwrap().len(), 0);

        let mut source = Pile::open(&source_path).unwrap();
        let mut rewritten = Pile::open(&rewrite_path).unwrap();
        let stats = source
            .rewrite_retained_into(
                &mut rewritten,
                &RetentionRoots::new(),
                WantRewritePolicy::Drop,
            )
            .unwrap();
        assert_eq!(stats.retained_blobs, 0);
        source.close().unwrap();
        rewritten.close().unwrap();
        assert_eq!(std::fs::metadata(&rewrite_path).unwrap().len(), 0);
    }

    // recover_grow test removed as growth strategy no longer exists

    /// Exercise the `ATOMIC_WRITE_LIMIT` fallback: an oversized blob must
    /// still round-trip correctly through the exclusive-lock multi-write
    /// path. Marked `#[ignore]` because the test allocates ~1 GiB and
    /// writes ~2 GiB to disk; run explicitly with
    /// `cargo test --release -- --ignored put_and_get_oversized_blob`.
    #[test]
    #[ignore]
    fn put_and_get_oversized_blob() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh_empty_pile_path(&dir, "pile.pile");

        // Slightly over the threshold so we land in the non-atomic branch.
        let size = ATOMIC_WRITE_LIMIT + 1_024;
        let mut data = vec![0u8; size];
        // Sprinkle some non-trivial pattern so `Bytes` equality has teeth.
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(7);
        }

        let mut pile: Pile = Pile::open(&path).unwrap();
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(data.clone()));
        let handle = pile.put::<UnknownBlob, _>(blob).unwrap();

        {
            let reader = pile.snapshot().unwrap();
            let fetched: Blob<UnknownBlob> = reader.get(handle).unwrap();
            assert_eq!(fetched.bytes.len(), size);
            assert_eq!(fetched.bytes.as_ref(), data.as_slice());
        }

        pile.close().unwrap();

        // Round-trip across open+amputate to ensure the on-disk record
        // is fully self-describing and recoverable.
        let mut pile: Pile = Pile::open(&path).unwrap();
        pile.amputate().unwrap();
        let reader = pile.snapshot().unwrap();
        let fetched: Blob<UnknownBlob> = reader.get(handle).unwrap();
        assert_eq!(fetched.bytes.as_ref(), data.as_slice());
        pile.close().unwrap();
    }
}
