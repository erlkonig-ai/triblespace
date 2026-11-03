use crate::blob::Blob;
use crate::blob::BlobEncoding;
use crate::blob::TryFromBlob;
use crate::id::ExclusiveId;
use crate::id::Id;
use crate::id_hex;
use crate::inline::Encodes;
use crate::macros::entity;
use crate::metadata;
use crate::metadata::MetaDescribe;
#[cfg(any(test, feature = "parallel"))]
use crate::patch::hash_key;
use crate::patch::ArchiveEntry;
use crate::patch::ArchiveOwner;
use crate::trible::Fragment;
use crate::trible::RawTrible;
use crate::trible::Trible;
use crate::trible::TribleSet;
#[cfg(feature = "parallel")]
use crate::trible::TRIBLE_LEN;

use anybytes::view::ViewError;
use anybytes::Bytes;
use anybytes::View;
use std::ptr::NonNull;
use std::sync::Arc;

/// Canonical trible sequence stored as raw 64-byte entries.
///
/// The simplest portable archive format — a flat byte array of tribles
/// in canonical EAV order with no compression. Used for commits,
/// streaming, hashing, and audit trails where byte-for-byte stability
/// matters.
pub struct SimpleArchive;

impl BlobEncoding for SimpleArchive {}

impl MetaDescribe for SimpleArchive {
    fn describe() -> Fragment {
        let id: Id = id_hex!("8F4A27C8581DADCBA1ADA8BA228069B6");
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "simplearchive",
                metadata::description: "Canonical trible sequence stored as raw 64-byte entries. This is the simplest portable archive format and preserves the exact trible ordering expected by the canonicalization rules.\n\nUse SimpleArchive for export, import, streaming, hashing, or audit trails where you want a byte-for-byte stable representation. Prefer SuccinctArchiveBlob when you need compact indexed storage and fast offline queries, and keep a SimpleArchive around if you want a source of truth that can be re-indexed or validated.",
                metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

/// Collects the canonical EAV rows into a `Vec<Trible>`.
///
/// The vector is 16-byte aligned by its element type, so the archive bytes
/// built from it always satisfy the alignment that `ArchiveEntry` and a
/// `[Trible]` view require. An empty set encodes as empty bytes.
fn encode_rows(source: &TribleSet) -> Blob<SimpleArchive> {
    let mut tribles: Vec<Trible> = Vec::with_capacity(source.len());
    tribles.extend(source.iter_ordered().copied());
    let bytes: Bytes = tribles.into();
    Blob::new(bytes)
}

impl Encodes<TribleSet> for SimpleArchive
where
    crate::inline::encodings::hash::Handle<SimpleArchive>: crate::inline::InlineEncoding,
{
    type Output = Blob<SimpleArchive>;
    fn encode(source: TribleSet) -> Blob<SimpleArchive> {
        encode_rows(&source)
    }
}

impl Encodes<&TribleSet> for SimpleArchive
where
    crate::inline::encodings::hash::Handle<SimpleArchive>: crate::inline::InlineEncoding,
{
    type Output = Blob<SimpleArchive>;
    fn encode(source: &TribleSet) -> Blob<SimpleArchive> {
        encode_rows(source)
    }
}

impl Encodes<Fragment> for SimpleArchive
where
    crate::inline::encodings::hash::Handle<SimpleArchive>: crate::inline::InlineEncoding,
{
    type Output = Blob<SimpleArchive>;

    fn encode(source: Fragment) -> Blob<SimpleArchive> {
        <SimpleArchive as Encodes<TribleSet>>::encode(source.into_facts())
    }
}

impl Encodes<&Fragment> for SimpleArchive
where
    crate::inline::encodings::hash::Handle<SimpleArchive>: crate::inline::InlineEncoding,
{
    type Output = Blob<SimpleArchive>;

    fn encode(source: &Fragment) -> Blob<SimpleArchive> {
        <SimpleArchive as Encodes<&TribleSet>>::encode(source.facts())
    }
}

/// Error returned when deserializing a [`SimpleArchive`] blob into a [`TribleSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnarchiveError {
    /// The blob length is not a multiple of 64 bytes.
    BadArchive,
    /// A 64-byte entry has a nil entity or attribute.
    BadTrible,
    /// The archive contains duplicate tribles.
    BadCanonicalizationRedundancy,
    /// The tribles are not in ascending canonical order.
    BadCanonicalizationOrdering,
}

impl std::fmt::Display for UnarchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnarchiveError::BadArchive => write!(f, "The archive is malformed or invalid."),
            UnarchiveError::BadTrible => write!(f, "A trible in the archive is malformed."),
            UnarchiveError::BadCanonicalizationRedundancy => {
                write!(f, "The archive contains redundant tribles.")
            }
            UnarchiveError::BadCanonicalizationOrdering => {
                write!(f, "The tribles in the archive are not in canonical order.")
            }
        }
    }
}

impl std::error::Error for UnarchiveError {}

/// Archive rows proven canonical: every row is a well-formed [`Trible`], and
/// the rows are strictly increasing in byte order, so they are also free of
/// duplicates.
///
/// This is the shape the bytes of a [`SimpleArchive`] blob must have. The only
/// way to obtain one is to validate bytes, so holding a `CanonicalTribles` is
/// proof that the check ran. The rows stay where they are: the value is a
/// zero-copy view into the source bytes and keeps them alive.
///
/// The checks run in a fixed order, and that order decides which error a bad
/// archive reports:
///
/// 1. the length is a whole number of 64-byte rows and the base is 16-byte
///    aligned, or [`UnarchiveError::BadArchive`];
/// 2. no row has a nil entity or attribute, checked over the whole archive,
///    or [`UnarchiveError::BadTrible`];
/// 3. each row is greater than the one before it, or
///    [`UnarchiveError::BadCanonicalizationRedundancy`] for an equal row and
///    [`UnarchiveError::BadCanonicalizationOrdering`] for a smaller one.
///
/// Empty input is canonical whatever its address.
#[derive(Clone, Debug)]
pub struct CanonicalTribles {
    rows: View<[Trible]>,
}

impl CanonicalTribles {
    /// Validates `bytes` as a canonical trible sequence.
    pub fn validate(bytes: Bytes) -> Result<Self, UnarchiveError> {
        Self::validate_with(bytes, |_, _| {})
    }

    /// Validates `bytes` and calls `visit(index, trible)` for each row, in
    /// order, once the row has passed the ordering check against the row
    /// before it.
    ///
    /// This lets a caller fuse per-row work (hashing, indexing) into the
    /// ordering pass instead of reading the rows a second time. On an error
    /// `visit` has seen every row before the offending one, so whatever it
    /// built is a prefix the caller should discard.
    pub fn validate_with<F>(bytes: Bytes, mut visit: F) -> Result<Self, UnarchiveError>
    where
        F: FnMut(usize, &Trible),
    {
        let rows = view_rows(bytes)?;
        check_increasing(&rows, &mut visit)?;
        Ok(Self { rows })
    }

    /// Validates `bytes` with the ordering pass split across the rayon pool,
    /// and returns `map(trible)` for every row in archive order.
    ///
    /// The rows are cut into one contiguous run per worker. The seams between
    /// runs are checked before any run, so an ordering error that straddles
    /// two runs is reported as such; each run then proves its own interior.
    /// Ordering is transitive, so the two together are exactly the check
    /// [`Self::validate`] performs, and the errors are the same kinds.
    #[cfg(feature = "parallel")]
    pub fn par_validate_map<T, F>(bytes: Bytes, map: F) -> Result<(Self, Vec<T>), UnarchiveError>
    where
        T: Clone + Default + Send,
        F: Fn(&Trible) -> T + Sync,
    {
        use rayon::prelude::*;

        let rows = view_rows(bytes)?;
        let run_len = parallel_run_len(rows.len());
        for seam in rows.chunks(run_len).collect::<Vec<_>>().windows(2) {
            let last = seam[0].last().expect("non-empty run").as_raw();
            let first = seam[1].first().expect("non-empty run").as_raw();
            if last == first {
                return Err(UnarchiveError::BadCanonicalizationRedundancy);
            }
            if last > first {
                return Err(UnarchiveError::BadCanonicalizationOrdering);
            }
        }

        let mut mapped = vec![T::default(); rows.len()];
        rows.par_chunks(run_len)
            .zip(mapped.par_chunks_mut(run_len))
            .try_for_each(|(run, out)| {
                check_increasing(run, |index, trible| out[index] = map(trible))
            })?;
        Ok((Self { rows }, mapped))
    }

    /// The rows as tribles.
    pub fn as_tribles(&self) -> &[Trible] {
        &self.rows
    }

    /// The rows as their raw 64-byte representation.
    pub fn as_rows(&self) -> &[RawTrible] {
        zerocopy::transmute_ref!(self.as_tribles())
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// The zerocopy view: size and alignment, then the row rule on every row.
fn view_rows(bytes: Bytes) -> Result<View<[Trible]>, UnarchiveError> {
    // An empty archive has no row to misalign, so it gets an aligned base
    // rather than being judged by wherever its empty slice happens to point.
    let bytes = if bytes.is_empty() {
        Bytes::from(Vec::<Trible>::new())
    } else {
        bytes
    };
    bytes.view().map_err(|err| match err {
        ViewError::Alignment(_) | ViewError::Size(_) => UnarchiveError::BadArchive,
        ViewError::Validity(_) => UnarchiveError::BadTrible,
    })
}

/// One pass proving `rows` strictly increasing in byte order, calling `visit`
/// on each row once it has been compared with its predecessor.
#[inline]
fn check_increasing(
    rows: &[Trible],
    mut visit: impl FnMut(usize, &Trible),
) -> Result<(), UnarchiveError> {
    let mut previous: Option<&RawTrible> = None;
    for (index, trible) in rows.iter().enumerate() {
        let row = trible.as_raw();
        if let Some(previous) = previous {
            if previous == row {
                return Err(UnarchiveError::BadCanonicalizationRedundancy);
            }
            if previous > row {
                return Err(UnarchiveError::BadCanonicalizationOrdering);
            }
        }
        previous = Some(row);
        visit(index, trible);
    }
    Ok(())
}

/// Rows per contiguous run when a linear pass is split across the rayon pool.
#[cfg(feature = "parallel")]
fn parallel_run_len(rows: usize) -> usize {
    rows.div_ceil(rayon::current_num_threads().max(1)).max(1)
}

/// A copy of `bytes` whose base is not 16-byte aligned, for tests that a
/// reader refuses such input with [`UnarchiveError::BadArchive`] instead of
/// decoding it.
#[cfg(test)]
pub(crate) fn misaligned_copy(bytes: &[u8]) -> Bytes {
    let mut backing = vec![0u8; bytes.len() + 16];
    let base = backing.as_ptr() as usize;
    let offset = (1..16)
        .find(|offset| (base + offset) % 16 != 0)
        .expect("an unaligned offset below 16");
    backing[offset..offset + bytes.len()].copy_from_slice(bytes);
    let misaligned = Bytes::from(backing).slice(offset..offset + bytes.len());
    assert_ne!(misaligned.as_ptr() as usize % 16, 0);
    assert_eq!(&misaligned[..], bytes);
    misaligned
}

/// Below this many tribles, serial unarchive wins (rayon overhead
/// dominates).
#[cfg(feature = "parallel")]
const PARALLEL_UNARCHIVE_THRESHOLD: usize = 4096;

impl TryFromBlob<SimpleArchive> for TribleSet {
    type Error = UnarchiveError;

    fn try_from_blob(blob: Blob<SimpleArchive>) -> Result<Self, Self::Error> {
        try_from_archive_bytes(blob.bytes)
    }
}

/// Decode canonical `SimpleArchive` bytes into a [`TribleSet`].
///
/// Identical to `TribleSet::try_from_blob`, minus the handle. A caller that
/// computed the bytes itself and only wants to query them should not pay a
/// Blake3 pass to name a value it is about to consume; naming is what
/// [`Blob::new`] is for, and it is a separate decision.
///
/// The bytes are validated as [`CanonicalTribles`], which fixes the errors:
/// see there for the order of the checks. Bytes whose base is not 16-byte
/// aligned are refused with [`UnarchiveError::BadArchive`].
pub fn try_from_archive_bytes(bytes: Bytes) -> Result<TribleSet, UnarchiveError> {
    try_from_bytes_inner(bytes, /*archive_backed:*/ true)
}

/// Decode a [`SimpleArchive`] blob into a [`TribleSet`] forcing the
/// heap-`Leaf` ingest path (no `LocalLeaf`). Below the parallel threshold this
/// isolates leaf representation on the same serial decoder; above it this is
/// an end-to-end heap-online baseline for the public bottom-up decoder.
pub fn try_from_blob_heap_only(blob: Blob<SimpleArchive>) -> Result<TribleSet, UnarchiveError> {
    try_from_bytes_inner(blob.bytes, /*archive_backed:*/ false)
}

fn try_from_bytes_inner(bytes: Bytes, archive_backed: bool) -> Result<TribleSet, UnarchiveError> {
    #[cfg(feature = "parallel")]
    {
        if bytes.len() / TRIBLE_LEN >= PARALLEL_UNARCHIVE_THRESHOLD {
            return parallel_unarchive(bytes, archive_backed);
        }
    }

    serial_unarchive(bytes, archive_backed)
}

/// The archive allocation as the owner every `LocalLeaf` retains, when the
/// decode is archive-backed.
fn archive_owner(bytes: &Bytes, archive_backed: bool) -> Option<Arc<dyn ArchiveOwner>> {
    archive_backed.then(|| Arc::new(bytes.clone()) as Arc<dyn ArchiveOwner>)
}

/// Insert one validated archive row: as an `ArchiveEntry` (LocalLeaf-backed)
/// when `owner` is `Some`, as a heap `Leaf` otherwise.
#[inline]
fn insert_row(set: &mut TribleSet, trible: &Trible, owner: Option<&Arc<dyn ArchiveOwner>>) {
    match owner {
        Some(owner) => {
            // SAFETY: `trible` lies in the immutable archive bytes that
            // `owner` keeps alive, and a `&Trible` is 16-byte aligned by its
            // type.
            let entry = unsafe { ArchiveEntry::new(NonNull::from(trible.as_raw()), owner) };
            set.insert_archive(&entry);
        }
        None => set.insert(trible),
    }
}

/// Serial decode: the canonical check and the index inserts in one pass over
/// the rows, after the zerocopy view has checked the row rule.
fn serial_unarchive(bytes: Bytes, archive_backed: bool) -> Result<TribleSet, UnarchiveError> {
    let owner = archive_owner(&bytes, archive_backed);
    let mut tribles = TribleSet::new();
    CanonicalTribles::validate_with(bytes, |_, trible| {
        insert_row(&mut tribles, trible, owner.as_ref())
    })?;
    Ok(tribles)
}

/// Whether every row of an archive this long has an ordinal the partition
/// metadata can carry.
#[cfg(any(test, feature = "parallel"))]
#[inline]
fn archive_rows_fit_ordinals(rows: usize) -> bool {
    u32::try_from(rows).is_ok()
}

/// Parallel unarchive: validate and hash the blob in worker-sized runs, then
/// build each of the six indexes over the whole archive at once.
///
/// The six PATCH builds partition their own rows across workers, so the
/// decoder no longer chops the archive into per-worker chunks and unions the
/// resulting sets back together. That union was the price of the chunking, not
/// of the decode: the four value-first orders interleave across any row range,
/// so every chunk boundary put the same keys in the same subtries and left the
/// reduce to walk them again. One build per order visits each key once.
#[cfg(feature = "parallel")]
fn parallel_unarchive(bytes: Bytes, archive_backed: bool) -> Result<TribleSet, UnarchiveError> {
    use rayon::prelude::*;

    let owner = archive_owner(&bytes, archive_backed);
    // Row ordinals index the whole archive, so the `u32` bound is on the
    // archive rather than on a chunk of it.
    let bottom_up = owner.is_some() && archive_rows_fit_ordinals(bytes.len() / TRIBLE_LEN);

    if !bottom_up {
        // The heap-Leaf decode, and an archive too long to address with u32
        // ordinals, keep the established online worker: per run, reduced
        // through `TribleSet::union`.
        let (canonical, _) = CanonicalTribles::par_validate_map(bytes, |_| ())?;
        let run_len = parallel_run_len(canonical.len());
        let sets: Vec<TribleSet> = canonical
            .as_tribles()
            .par_chunks(run_len)
            .map(|run| {
                let mut set = TribleSet::new();
                for trible in run {
                    insert_row(&mut set, trible, owner.as_ref());
                }
                set
            })
            .collect();
        return Ok(sets.into_par_iter().reduce(TribleSet::new, |a, b| a + b));
    }

    let owner = owner.expect("bottom-up eligibility requires an archive owner");
    let (canonical, hashes) =
        CanonicalTribles::par_validate_map(bytes, |trible| hash_key(&trible.as_raw()[..]))?;

    // One bottom-up build per index order, over the whole archive.
    // SAFETY: `canonical` proves well-formed, distinct rows (and `&[Trible]`
    // their alignment); its rows lie in the bytes `owner` keeps alive and
    // never mutates; `hashes` corresponds index-for-index to those rows; and
    // `bottom_up` proves every row ordinal fits u32.
    Ok(unsafe { TribleSet::from_archive_partition(canonical.as_tribles(), &hashes, &owner) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::IntoBlob;
    use crate::macros::entity;
    use crate::metadata;
    use crate::patch::{KeySchema, PATCH};
    use crate::trible::{AEVOrder, AVEOrder, EAVOrder, EVAOrder, VAEOrder, VEAOrder};
    use std::hint::black_box;

    fn fixture_row(index: usize) -> [u8; 64] {
        const FACTS_PER_ENTITY: usize = 8;
        let entity = index / FACTS_PER_ENTITY + 1;
        let attribute = index % FACTS_PER_ENTITY + 1;
        let mut row = [0u8; 64];
        row[8..16].copy_from_slice(&(entity as u64).to_be_bytes());
        row[24..32].copy_from_slice(&(attribute as u64).to_be_bytes());

        let mut state = index as u64 ^ 0x9e37_79b9_7f4a_7c15;
        for chunk in row[32..].chunks_exact_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            mixed ^= mixed >> 31;
            chunk.copy_from_slice(&mixed.to_be_bytes());
        }
        row
    }

    fn fixture_blob(len: usize) -> Blob<SimpleArchive> {
        let rows: Vec<[u8; 64]> = (0..len).map(fixture_row).collect();
        assert!(rows.windows(2).all(|pair| pair[0] < pair[1]));
        let bytes: Bytes = rows.into();
        Blob::new(bytes)
    }

    #[test]
    fn fragment_encoding_archives_only_content_facts() {
        let fragment = entity! { _ @
            metadata::description: "content",
        };
        assert!(!fragment.metafacts().is_empty());

        let expected = fragment.facts().to_blob();
        let owned: Blob<SimpleArchive> = fragment.clone().to_blob();
        let borrowed: Blob<SimpleArchive> = (&fragment).to_blob();

        assert_eq!(owned, expected);
        assert_eq!(borrowed, expected);
    }

    fn blob_from_rows(rows: Vec<[u8; 64]>) -> Blob<SimpleArchive> {
        Blob::new(Bytes::from(rows))
    }

    fn serial_for_test(blob: Blob<SimpleArchive>) -> Result<TribleSet, UnarchiveError> {
        serial_unarchive(blob.bytes, /*archive_backed:*/ true)
    }

    fn bottom_up_for_test(blob: Blob<SimpleArchive>) -> Result<TribleSet, UnarchiveError> {
        let mut hashes = Vec::new();
        let canonical = CanonicalTribles::validate_with(blob.bytes.clone(), |_, trible| {
            hashes.push(hash_key(&trible.as_raw()[..]))
        })?;
        let owner: Arc<dyn ArchiveOwner> = Arc::new(blob.bytes.clone());
        // SAFETY: `canonical` proves well-formed, distinct, aligned rows in
        // the bytes `owner` retains, and `hashes` was built from those rows.
        Ok(unsafe { TribleSet::from_archive_partition(canonical.as_tribles(), &hashes, &owner) })
    }

    fn assert_index_parity<O: KeySchema<64>>(
        candidate: &PATCH<64, O>,
        baseline: &PATCH<64, O>,
        len: usize,
    ) {
        assert_eq!(candidate.len(), len as u64);
        assert_eq!(
            candidate.iter_ordered().copied().collect::<Vec<_>>(),
            baseline.iter_ordered().copied().collect::<Vec<_>>(),
        );
        assert_eq!(candidate.root_hash(), baseline.root_hash());
        assert_eq!(
            candidate.branch_fanout_histogram(),
            baseline.branch_fanout_histogram(),
        );
        assert_eq!(candidate.node_stats().0, baseline.node_stats().0);
    }

    fn assert_all_six_parity(candidate: &TribleSet, baseline: &TribleSet, len: usize) {
        assert_index_parity::<EAVOrder>(&candidate.eav, &baseline.eav, len);
        assert_index_parity::<EVAOrder>(&candidate.eva, &baseline.eva, len);
        assert_index_parity::<AEVOrder>(&candidate.aev, &baseline.aev, len);
        assert_index_parity::<AVEOrder>(&candidate.ave, &baseline.ave, len);
        assert_index_parity::<VEAOrder>(&candidate.vea, &baseline.vea, len);
        assert_index_parity::<VAEOrder>(&candidate.vae, &baseline.vae, len);
    }

    /// An archive skewed the way a real collection is: a handful of
    /// attributes with one carrying most rows, a heavy-tailed entity
    /// distribution, and values that mostly share a long prefix. That shape
    /// is what drives the value-first orders into one enormous, deeply-shared
    /// subtrie — the node the decoder now splits across workers.
    fn skewed_rows(len: usize) -> Vec<[u8; 64]> {
        let mut rows = Vec::with_capacity(len);
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for index in 0..len {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            mixed ^= mixed >> 31;

            let mut row = [0u8; 64];
            // Three attributes, one of them carrying eight rows in ten.
            let attribute: u64 = match index % 10 {
                0 => 2,
                1 => 3,
                _ => 1,
            };
            row[24..32].copy_from_slice(&attribute.to_be_bytes());
            // A quarter of every fact hangs off one entity.
            let entity: u64 = if index % 4 == 0 {
                1
            } else {
                index as u64 / 3 + 2
            };
            row[8..16].copy_from_slice(&entity.to_be_bytes());
            if index % 3 == 0 {
                for chunk in row[32..].chunks_exact_mut(8) {
                    mixed = mixed.wrapping_mul(0x2545_f491_4f6c_dd1d).rotate_left(17);
                    chunk.copy_from_slice(&mixed.to_be_bytes());
                }
            } else {
                // Values that agree for 24 bytes and diverge in the last 8,
                // so the representative prefix has to be walked out.
                row[32..56].copy_from_slice(&[0x5a; 24]);
                row[56..64].copy_from_slice(&(index as u64).to_be_bytes());
            }
            rows.push(row);
        }
        rows.sort_unstable();
        rows.dedup();
        rows
    }

    #[test]
    fn bottom_up_matches_serial_on_a_skewed_archive_above_the_parallel_split() {
        let rows = skewed_rows(48_000);
        let len = rows.len();
        #[cfg(feature = "parallel")]
        assert!(
            PATCH::<64, EAVOrder>::partition_workers(len) > 1,
            "the fixture must reach the concurrent partition pass",
        );
        let blob = blob_from_rows(rows);
        let baseline = serial_for_test(blob.clone()).unwrap();
        let candidate = bottom_up_for_test(blob).unwrap();
        assert_all_six_parity(&candidate, &baseline, len);
    }

    #[test]
    fn bottom_up_all_six_matches_serial_topology_and_lifetime() {
        for len in [0usize, 1, 2, 3, 257, 8_192] {
            let blob = fixture_blob(len);
            let baseline = serial_for_test(blob.clone()).unwrap();
            let candidate = bottom_up_for_test(blob.clone()).unwrap();
            assert_all_six_parity(&candidate, &baseline, len);

            if len > 1 {
                for stats in [
                    candidate.eav.node_stats(),
                    candidate.eva.node_stats(),
                    candidate.aev.node_stats(),
                    candidate.ave.node_stats(),
                    candidate.vea.node_stats(),
                    candidate.vae.node_stats(),
                ] {
                    assert_eq!(stats.2, 0, "bottom-up build materialized heap leaves");
                    assert_eq!(stats.3, len as u64, "bottom-up build lost LocalLeaves");
                }
            }

            let survivor = candidate.clone();
            drop(candidate);
            drop(baseline);
            drop(blob);
            black_box(vec![0xa5u8; len.saturating_mul(64).min(1 << 20)]);
            assert_eq!(survivor.eav.iter_ordered().count(), len);
            assert_eq!(survivor.eva.iter_ordered().count(), len);
            assert_eq!(survivor.aev.iter_ordered().count(), len);
            assert_eq!(survivor.ave.iter_ordered().count(), len);
            assert_eq!(survivor.vea.iter_ordered().count(), len);
            assert_eq!(survivor.vae.iter_ordered().count(), len);
        }
    }

    #[test]
    fn bottom_up_root_owner_guards_cover_every_local_leaf() {
        let set = bottom_up_for_test(fixture_blob(8_192)).unwrap();
        let guards = [
            set.eav.owner_guard(),
            set.eva.owner_guard(),
            set.aev.owner_guard(),
            set.ave.owner_guard(),
            set.vea.owner_guard(),
            set.vae.owner_guard(),
        ];
        assert!(
            guards[1..].iter().all(|guard| guard.ptr_eq(&guards[0])),
            "the six archive indexes duplicated their owner cover",
        );
        for stats in [
            set.eav.archive_owner_guard_stats(),
            set.eva.archive_owner_guard_stats(),
            set.aev.archive_owner_guard_stats(),
            set.ave.archive_owner_guard_stats(),
            set.vea.archive_owner_guard_stats(),
            set.vae.archive_owner_guard_stats(),
        ] {
            assert!(stats.0, "archive PATCH has no root owner guard");
            assert_eq!(stats.1, 8_192, "not every archive row remained local");
        }
    }

    #[test]
    fn bottom_up_full_byte_fanout_matches_serial() {
        let rows = (0u16..=255)
            .map(|byte| {
                let mut row = [0u8; 64];
                row[0] = byte as u8;
                if byte == 0 {
                    row[15] = 1;
                }
                row[31] = 1;
                row
            })
            .collect::<Vec<_>>();
        assert!(rows.windows(2).all(|pair| pair[0] < pair[1]));
        let blob = blob_from_rows(rows);
        let baseline = serial_for_test(blob.clone()).unwrap();
        let candidate = bottom_up_for_test(blob).unwrap();
        assert_all_six_parity(&candidate, &baseline, 256);
        assert_eq!(candidate.eav.branch_fanout_histogram()[256], 1);
    }

    #[cfg(feature = "proptest")]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn arbitrary_canonical_rows_match_serial_in_all_six_orders(
                raw_rows in prop::collection::vec(
                    prop::collection::vec(any::<u8>(), 64),
                    0..128,
                ),
                shared_prefix_len in 0usize..64,
            ) {
                let mut rows = raw_rows
                    .into_iter()
                    .map(|bytes| {
                        let mut row: [u8; 64] = bytes.try_into().expect("fixed row width");
                        row[..shared_prefix_len].fill(0x5a);
                        if row[..16].iter().all(|byte| *byte == 0) {
                            row[15] = 1;
                        }
                        if row[16..32].iter().all(|byte| *byte == 0) {
                            row[31] = 1;
                        }
                        row
                    })
                    .collect::<Vec<_>>();
                rows.sort_unstable();
                rows.dedup();

                let len = rows.len();
                let blob = blob_from_rows(rows);
                let serial = serial_for_test(blob.clone()).unwrap();
                let bottom_up = bottom_up_for_test(blob).unwrap();
                assert_all_six_parity(&bottom_up, &serial, len);
            }
        }
    }

    #[test]
    fn bottom_up_validates_canonical_eav_input() {
        let first = fixture_row(0);
        let second = fixture_row(1);
        assert_eq!(
            bottom_up_for_test(blob_from_rows(vec![first, first])).unwrap_err(),
            UnarchiveError::BadCanonicalizationRedundancy,
        );
        assert_eq!(
            bottom_up_for_test(blob_from_rows(vec![second, first])).unwrap_err(),
            UnarchiveError::BadCanonicalizationOrdering,
        );
        let mut invalid = first;
        invalid[..16].fill(0);
        assert_eq!(
            bottom_up_for_test(blob_from_rows(vec![invalid])).unwrap_err(),
            UnarchiveError::BadTrible,
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn production_archive_matches_serial_and_retains_source() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap()
            .install(|| {
                for len in [0usize, 1, 2, 3, 257, 4_095, 4_096, 8_192] {
                    let blob = fixture_blob(len);
                    let baseline = serial_for_test(blob.clone()).unwrap();
                    let candidate = TribleSet::try_from_blob(blob.clone()).unwrap();
                    assert_all_six_parity(&candidate, &baseline, len);

                    let survivor = candidate.clone();
                    drop(candidate);
                    drop(baseline);
                    drop(blob);
                    black_box(vec![0x5au8; len.saturating_mul(64).min(1 << 20)]);
                    assert_eq!(survivor.eav.iter_ordered().count(), len);
                    assert_eq!(survivor.eva.iter_ordered().count(), len);
                    assert_eq!(survivor.aev.iter_ordered().count(), len);
                    assert_eq!(survivor.ave.iter_ordered().count(), len);
                    assert_eq!(survivor.vea.iter_ordered().count(), len);
                    assert_eq!(survivor.vae.iter_ordered().count(), len);
                }
            });
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn production_archive_preserves_errors_and_boundary_precedence() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap()
            .install(|| {
                fn assert_public_error(rows: Vec<[u8; 64]>, expected: UnarchiveError) {
                    assert_eq!(
                        TribleSet::try_from_blob(blob_from_rows(rows)).unwrap_err(),
                        expected,
                    );
                }

                let len = PARALLEL_UNARCHIVE_THRESHOLD;
                let chunk_size = len.div_ceil(rayon::current_num_threads());

                let mut duplicate_inside = (0..len).map(fixture_row).collect::<Vec<_>>();
                duplicate_inside[1] = duplicate_inside[0];
                assert_public_error(
                    duplicate_inside,
                    UnarchiveError::BadCanonicalizationRedundancy,
                );

                let mut duplicate = (0..len).map(fixture_row).collect::<Vec<_>>();
                duplicate[chunk_size] = duplicate[chunk_size - 1];
                assert_public_error(duplicate, UnarchiveError::BadCanonicalizationRedundancy);

                let mut descending_inside = (0..len).map(fixture_row).collect::<Vec<_>>();
                descending_inside.swap(0, 1);
                assert_public_error(
                    descending_inside,
                    UnarchiveError::BadCanonicalizationOrdering,
                );

                let mut descending = (0..len).map(fixture_row).collect::<Vec<_>>();
                descending.swap(chunk_size - 1, chunk_size);
                assert_public_error(descending, UnarchiveError::BadCanonicalizationOrdering);

                let invalid = (0..len)
                    .map(|index| {
                        let mut row = [0u8; 64];
                        row[31] = 1;
                        row[56..64].copy_from_slice(&((index + 1) as u64).to_be_bytes());
                        row
                    })
                    .collect();
                assert_public_error(invalid, UnarchiveError::BadTrible);

                // The row rule is checked over the whole archive before any
                // ordering, so a nil row wins over an inversion at a seam.
                // (The serial decoder already reported this input as
                // BadTrible; the parallel one used to say Ordering.)
                let mut invalid_and_descending = (0..len).map(fixture_row).collect::<Vec<_>>();
                invalid_and_descending[0][..16].fill(0);
                invalid_and_descending.swap(chunk_size - 1, chunk_size);
                assert_public_error(invalid_and_descending, UnarchiveError::BadTrible);

                // Among ordering errors, the seams are still checked first: a
                // seam duplicate wins over an inversion inside the first run.
                let mut inside_and_seam = (0..len).map(fixture_row).collect::<Vec<_>>();
                inside_and_seam.swap(0, 1);
                inside_and_seam[chunk_size] = inside_and_seam[chunk_size - 1];
                assert_public_error(
                    inside_and_seam,
                    UnarchiveError::BadCanonicalizationRedundancy,
                );

                let malformed = Blob::new(Bytes::from(vec![0u8; 63]));
                assert_eq!(
                    TribleSet::try_from_blob(malformed).unwrap_err(),
                    UnarchiveError::BadArchive,
                );
            });
    }

    #[test]
    fn archive_row_ordinal_limit_is_exact() {
        assert!(archive_rows_fit_ordinals(u32::MAX as usize));
        #[cfg(target_pointer_width = "64")]
        assert!(!archive_rows_fit_ordinals(u32::MAX as usize + 1));
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_heap_only_fallback_keeps_heap_leaves() {
        let len = PARALLEL_UNARCHIVE_THRESHOLD;
        let blob = fixture_blob(len);
        let archive_backed = TribleSet::try_from_blob(blob.clone()).unwrap();
        let heap_only = try_from_blob_heap_only(blob).unwrap();
        assert_all_six_parity(&heap_only, &archive_backed, len);

        for stats in [
            heap_only.eav.node_stats(),
            heap_only.eva.node_stats(),
            heap_only.aev.node_stats(),
            heap_only.ave.node_stats(),
            heap_only.vea.node_stats(),
            heap_only.vae.node_stats(),
        ] {
            assert_eq!(stats.2, len as u64, "heap fallback lost heap Leaves");
            assert_eq!(stats.3, 0, "heap fallback created LocalLeaves");
        }
    }

    #[test]
    fn canonical_tribles_accepts_empty_input_at_any_address() {
        assert!(CanonicalTribles::validate(Bytes::empty())
            .unwrap()
            .is_empty());
        let rows = [fixture_row(0)];
        let backing = Bytes::from(rows.to_vec());
        for offset in 0..=3 {
            let empty = backing.slice(offset..offset);
            let canonical = CanonicalTribles::validate(empty).unwrap();
            assert_eq!(canonical.len(), 0);
            assert!(canonical.as_tribles().is_empty());
            assert!(canonical.as_rows().is_empty());
        }
    }

    #[test]
    fn canonical_tribles_refuses_a_misaligned_base_as_bad_archive() {
        let rows: Vec<[u8; 64]> = (0..3).map(fixture_row).collect();
        let tribles: Vec<Trible> = rows
            .iter()
            .map(|row| Trible::force_raw(*row).unwrap())
            .collect();
        let aligned = Bytes::from(tribles);
        assert_eq!(
            CanonicalTribles::validate(aligned).unwrap().as_rows(),
            &rows[..]
        );

        // A misaligned copy of the same rows: the base of a `Vec<u8>` is
        // not promised, so the assert below keeps the test honest.
        let mut backing = vec![0u8; 3 * 64 + 1];
        backing[1..].copy_from_slice(rows.as_flattened());
        let misaligned = Bytes::from(backing).slice(1..);
        assert_ne!(misaligned.as_ptr() as usize % 16, 0);
        assert_eq!(&misaligned[..], rows.as_flattened());
        assert_eq!(
            CanonicalTribles::validate(misaligned).unwrap_err(),
            UnarchiveError::BadArchive,
        );
    }

    #[test]
    fn canonical_tribles_refuses_a_partial_row_as_bad_archive() {
        let mut bytes = Bytes::from(vec![fixture_row(0), fixture_row(1)]);
        assert!(bytes.take_suffix(1).is_some());
        assert_eq!(
            CanonicalTribles::validate(bytes).unwrap_err(),
            UnarchiveError::BadArchive,
        );
    }

    #[test]
    fn canonical_tribles_refuses_nil_entity_or_attribute_as_bad_trible() {
        for nil in [0..16, 16..32] {
            let mut invalid = fixture_row(1);
            invalid[nil].fill(0);
            assert_eq!(
                CanonicalTribles::validate(Bytes::from(vec![fixture_row(0), invalid])).unwrap_err(),
                UnarchiveError::BadTrible,
            );
        }
    }

    #[test]
    fn canonical_tribles_refuses_duplicate_and_descending_rows() {
        let (first, second) = (fixture_row(0), fixture_row(1));
        assert_eq!(
            CanonicalTribles::validate(Bytes::from(vec![first, second, second])).unwrap_err(),
            UnarchiveError::BadCanonicalizationRedundancy,
        );
        assert_eq!(
            CanonicalTribles::validate(Bytes::from(vec![second, first])).unwrap_err(),
            UnarchiveError::BadCanonicalizationOrdering,
        );
    }

    #[test]
    fn canonical_tribles_checks_the_row_rule_before_ordering() {
        // A descending pair followed by a nil row: the whole-archive row rule
        // runs first, so the nil row is what is reported.
        let mut nil = fixture_row(2);
        nil[..16].fill(0);
        assert_eq!(
            CanonicalTribles::validate(Bytes::from(vec![fixture_row(1), fixture_row(0), nil]))
                .unwrap_err(),
            UnarchiveError::BadTrible,
        );
    }

    #[test]
    fn canonical_tribles_round_trips_an_encoded_set() {
        let mut set = TribleSet::new();
        for index in 0..100 {
            set.insert(&Trible::force_raw(fixture_row(index * 7 % 100)).unwrap());
        }
        let blob: Blob<SimpleArchive> = (&set).to_blob();
        let mut visited = Vec::new();
        let canonical = CanonicalTribles::validate_with(blob.bytes.clone(), |index, trible| {
            visited.push((index, *trible))
        })
        .unwrap();

        assert_eq!(canonical.len(), set.len());
        assert_eq!(canonical.as_rows().as_flattened(), &blob.bytes[..]);
        let ordered: Vec<Trible> = set.iter_ordered().copied().collect();
        assert_eq!(canonical.as_tribles(), &ordered[..]);
        assert_eq!(
            visited,
            ordered.iter().copied().enumerate().collect::<Vec<_>>()
        );
        for (trible, row) in canonical.as_tribles().iter().zip(canonical.as_rows()) {
            assert_eq!(trible.as_raw(), row);
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn canonical_tribles_parallel_map_matches_serial_and_errors() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build()
            .unwrap()
            .install(|| {
                for len in [0usize, 1, 2, 5, 1_000] {
                    let blob = fixture_blob(len);
                    let mut serial = Vec::new();
                    let canonical = CanonicalTribles::validate_with(blob.bytes.clone(), |_, t| {
                        serial.push(hash_key(&t.as_raw()[..]))
                    })
                    .unwrap();
                    let (parallel, hashes) =
                        CanonicalTribles::par_validate_map(blob.bytes.clone(), |t| {
                            hash_key(&t.as_raw()[..])
                        })
                        .unwrap();
                    assert_eq!(parallel.as_rows(), canonical.as_rows());
                    assert_eq!(hashes, serial);
                }

                let len = 1_000;
                let run_len = parallel_run_len(len);
                let mut seam_duplicate: Vec<[u8; 64]> = (0..len).map(fixture_row).collect();
                seam_duplicate[run_len] = seam_duplicate[run_len - 1];
                let mut inside_descending: Vec<[u8; 64]> = (0..len).map(fixture_row).collect();
                inside_descending.swap(1, 2);
                let mut nil: Vec<[u8; 64]> = (0..len).map(fixture_row).collect();
                nil[len - 1][16..32].fill(0);
                for (rows, expected) in [
                    (
                        seam_duplicate,
                        UnarchiveError::BadCanonicalizationRedundancy,
                    ),
                    (
                        inside_descending,
                        UnarchiveError::BadCanonicalizationOrdering,
                    ),
                    (nil, UnarchiveError::BadTrible),
                ] {
                    let bytes = Bytes::from(rows);
                    assert_eq!(
                        CanonicalTribles::validate(bytes.clone()).unwrap_err(),
                        expected
                    );
                    assert_eq!(
                        CanonicalTribles::par_validate_map(bytes, |_| ()).unwrap_err(),
                        expected,
                    );
                }
            });
    }
}
