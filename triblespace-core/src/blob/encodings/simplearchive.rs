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
#[cfg(feature = "parallel")]
use zerocopy::{IntoBytes, TryFromBytes};

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
/// The rows of `source` in archive order, in a heap allocation that is
/// 16-aligned by its type.
fn ordered_rows(source: &TribleSet) -> Bytes {
    let mut tribles: Vec<Trible> = Vec::with_capacity(source.len());
    tribles.extend(source.iter_ordered().copied());
    tribles.into()
}

fn encode_rows(source: &TribleSet) -> Blob<SimpleArchive> {
    Blob::new(ordered_rows(source))
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
/// This is the shape the bytes of a [`SimpleArchive`] blob must have. It is a
/// dynamically sized type over `[Trible]`, the way `str` is over `[u8]`: it is
/// bit-identical to the rows it wraps and adds only the ordering invariant.
/// It is held behind a reference, or as a zero-copy [`View<CanonicalTribles>`]
/// that borrows the rows where they lie and keeps the source bytes alive.
/// [`SimpleArchive`] stays the encoding marker, as `UTF8String` does for
/// `View<str>`, so decoding a blob in place is
///
/// ```
/// # use triblespace_core::blob::{Blob, IntoBlob};
/// # use triblespace_core::blob::encodings::simplearchive::{CanonicalTribles, SimpleArchive};
/// # use triblespace_core::trible::TribleSet;
/// # use anybytes::View;
/// # let blob: Blob<SimpleArchive> = TribleSet::new().to_blob();
/// let rows: View<CanonicalTribles> = blob.try_from_blob().unwrap();
/// # assert!(rows.is_empty());
/// ```
///
/// next to `blob.try_from_blob::<TribleSet>()`, which builds the indexes.
///
/// Every safe way to obtain one checks the ordering: [`Self::from_tribles`]
/// for rows that are already tribles, and [`Self::validate`],
/// [`Self::validate_with`], [`Self::par_validate_map`] and the
/// [`TryFromBlob`] impl for bytes. Holding one is therefore proof that the
/// check ran. The type deliberately implements neither zerocopy's
/// `TryFromBytes` nor `FromBytes` (nor `KnownLayout`): either would make
/// anybytes' generic `Bytes::view` a safe constructor that skips the
/// ordering check. It implements only `Immutable` and `IntoBytes`, which
/// read a value and never build one.
///
/// ```compile_fail,E0277
/// use anybytes::Bytes;
/// use triblespace_core::blob::encodings::simplearchive::CanonicalTribles;
///
/// let _ = Bytes::empty().view::<CanonicalTribles>();
/// ```
///
/// The byte checks run in a fixed order, and that order decides which error
/// a bad archive reports:
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
#[derive(Debug, zerocopy::Immutable, zerocopy::IntoBytes)]
#[repr(transparent)]
pub struct CanonicalTribles([Trible]);

impl CanonicalTribles {
    /// Checks that `rows` are strictly increasing in byte order.
    ///
    /// The rows are already tribles, so the row rule holds by type and only
    /// the third check applies: an equal neighbour is
    /// [`UnarchiveError::BadCanonicalizationRedundancy`] and a smaller one
    /// [`UnarchiveError::BadCanonicalizationOrdering`].
    pub fn from_tribles(rows: &[Trible]) -> Result<&Self, UnarchiveError> {
        check_increasing(rows, |_, _| {})?;
        // SAFETY: `check_increasing` just proved the rows strictly increasing.
        Ok(unsafe { Self::from_tribles_unchecked(rows) })
    }

    /// The rows of `set` as a canonical archive, without the ordering pass.
    ///
    /// A `TribleSet`'s EAV index iterates in key order, which is the rows'
    /// byte order, and holds each row once, so its rows are strictly
    /// increasing by construction (the trible goldens pin this). The rows
    /// are copied once into aligned storage; zerocopy's row check still
    /// runs, one read per row. Arbitrary bytes go through [`Self::validate`].
    pub fn from_set(set: &TribleSet) -> View<Self> {
        let rows = view_rows(ordered_rows(set))
            .expect("a Vec<Trible> is aligned and holds only valid tribles");
        debug_assert!(
            check_increasing(&rows, |_: usize, _: &Trible| {}).is_ok(),
            "TribleSet::iter_ordered must yield strictly increasing rows"
        );
        // SAFETY: the rows are `set`'s EAV index in key order, which is
        // strictly increasing byte order with no repeats (see above).
        let canonical = unsafe { Self::from_tribles_unchecked(&rows) };
        rows.field_to_view(canonical)
            .expect("the canonical rows are the bytes of the view")
    }

    /// Wraps `rows` without checking them. This is the only place a
    /// `CanonicalTribles` comes into being.
    ///
    /// # Safety
    ///
    /// `rows` must be strictly increasing in byte order (each row greater
    /// than the one before it). Code that holds a `CanonicalTribles` relies
    /// on that, as code that holds a `str` relies on UTF-8.
    unsafe fn from_tribles_unchecked(rows: &[Trible]) -> &Self {
        // SAFETY: `CanonicalTribles` is `repr(transparent)` over `[Trible]`,
        // so the two have the same layout and the same pointer metadata (the
        // row count), and the cast keeps the borrow's lifetime. The ordering
        // invariant is the caller's obligation.
        unsafe { &*(rows as *const [Trible] as *const Self) }
    }

    /// Validates `bytes` as a canonical trible sequence.
    pub fn validate(bytes: Bytes) -> Result<View<Self>, UnarchiveError> {
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
    pub fn validate_with<F>(bytes: Bytes, mut visit: F) -> Result<View<Self>, UnarchiveError>
    where
        F: FnMut(usize, &Trible),
    {
        let rows = view_rows(bytes)?;
        check_increasing(&rows, &mut visit)?;
        // SAFETY: `check_increasing` just proved the rows strictly increasing.
        let canonical = unsafe { Self::from_tribles_unchecked(&rows) };
        Ok(rows
            .field_to_view(canonical)
            .expect("the canonical rows are the bytes of the view"))
    }

    /// Validates `bytes` with the row rule and the ordering pass split across
    /// the rayon pool, and returns `map(trible)` for every row in archive
    /// order.
    ///
    /// Size and alignment are checked once, up front. The rows are then cut
    /// into one contiguous run per worker. The seams between runs are checked
    /// before any run, so an ordering error that straddles two runs is
    /// reported as such; each run then checks the row rule on its own rows
    /// and proves its own interior ordering. Ordering is transitive, so
    /// together this is exactly the check [`Self::validate`] performs, and
    /// the errors are the same kinds in the same precedence: an ordering
    /// error is reported only once no row anywhere breaks the row rule.
    #[cfg(feature = "parallel")]
    pub fn par_validate_map<T, F>(
        bytes: Bytes,
        map: F,
    ) -> Result<(View<Self>, Vec<T>), UnarchiveError>
    where
        T: Clone + Default + Send,
        F: Fn(&Trible) -> T + Sync,
    {
        use rayon::prelude::*;

        let rows = view_aligned_rows(bytes)?;
        let run_len = parallel_run_len(rows.len());
        let runs = check_seams(&rows, run_len).and_then(|()| {
            let mut mapped = vec![T::default(); rows.len()];
            rows.par_chunks(run_len)
                .zip(mapped.par_chunks_mut(run_len))
                .try_for_each(|(run, out)| {
                    check_increasing(row_rule(run)?, |index, trible| out[index] = map(trible))
                })
                .map(|()| mapped)
        });
        let mapped = match runs {
            Ok(mapped) => mapped,
            Err(UnarchiveError::BadTrible) => return Err(UnarchiveError::BadTrible),
            // A seam error skips the runs and a failing run stops the
            // others, so an ordering error has not seen every row. The row
            // rule takes precedence, so it is checked over the rest before
            // the ordering error is reported. This is the error path only.
            Err(ordering) => {
                rows.par_chunks(run_len)
                    .try_for_each(|run| row_rule(run).map(|_| ()))?;
                return Err(ordering);
            }
        };

        // SAFETY: `AlignedRow` and `Trible` have the same size and alignment
        // (asserted at compile time), and every row has passed `row_rule`,
        // zerocopy's validity check for `Trible`: the runs were all checked
        // to completion and together cover `rows`.
        let tribles: &[Trible] =
            unsafe { std::slice::from_raw_parts(rows.as_ptr().cast::<Trible>(), rows.len()) };
        debug_assert!(<[Trible]>::try_ref_from_bytes(tribles.as_bytes()).is_ok());
        // SAFETY: the seams were checked and every run proved its own interior
        // strictly increasing, and the runs cover `rows` contiguously, so by
        // transitivity the whole sequence is strictly increasing.
        let canonical = unsafe { Self::from_tribles_unchecked(tribles) };
        debug_assert!(Self::from_tribles(tribles).is_ok());
        let canonical = rows
            .field_to_view(canonical)
            .expect("the canonical rows are the bytes of the aligned rows");
        Ok((canonical, mapped))
    }

    /// The rows as tribles.
    pub fn as_tribles(&self) -> &[Trible] {
        &self.0
    }

    /// The rows as their raw 64-byte representation.
    pub fn as_rows(&self) -> &[RawTrible] {
        zerocopy::transmute_ref!(self.as_tribles())
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The zero-copy decode of a [`SimpleArchive`] blob: the rows in place,
/// validated as [`CanonicalTribles::validate`] does, with the same errors.
impl TryFromBlob<SimpleArchive> for View<CanonicalTribles> {
    type Error = UnarchiveError;

    fn try_from_blob(blob: Blob<SimpleArchive>) -> Result<Self, Self::Error> {
        CanonicalTribles::validate(blob.bytes)
    }
}

/// The zerocopy view: size and alignment, then the row rule on every row.
///
/// This is the first two checks of [`CanonicalTribles`] without the ordering
/// pass, for readers that accept rows in any order.
pub(crate) fn view_rows(bytes: Bytes) -> Result<View<[Trible]>, UnarchiveError> {
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

/// A canonical archive row before the row rule is checked: the 64 bytes of a
/// [`Trible`] at its alignment, with no validity of its own, so a view of
/// these checks size and alignment only.
#[cfg(feature = "parallel")]
#[derive(zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable, zerocopy::IntoBytes)]
#[repr(C, align(16))]
struct AlignedRow(RawTrible);

#[cfg(feature = "parallel")]
const _: () = {
    assert!(std::mem::size_of::<AlignedRow>() == std::mem::size_of::<Trible>());
    assert!(std::mem::align_of::<AlignedRow>() == std::mem::align_of::<Trible>());
};

/// The first check of [`CanonicalTribles`] alone: size and alignment, with
/// the same empty exemption as [`view_rows`].
#[cfg(feature = "parallel")]
fn view_aligned_rows(bytes: Bytes) -> Result<View<[AlignedRow]>, UnarchiveError> {
    let bytes = if bytes.is_empty() {
        Bytes::from(Vec::<Trible>::new())
    } else {
        bytes
    };
    bytes.view().map_err(|err| match err {
        ViewError::Alignment(_) | ViewError::Size(_) => UnarchiveError::BadArchive,
        ViewError::Validity(_) => unreachable!("AlignedRow has no invalid bit patterns"),
    })
}

/// The row rule on one run of aligned rows, which yields them as tribles.
#[cfg(feature = "parallel")]
#[inline]
fn row_rule(run: &[AlignedRow]) -> Result<&[Trible], UnarchiveError> {
    <[Trible]>::try_ref_from_bytes(run.as_bytes()).map_err(|_| UnarchiveError::BadTrible)
}

/// The ordering check across the seams between consecutive runs of
/// `run_len` rows.
#[cfg(feature = "parallel")]
fn check_seams(rows: &[AlignedRow], run_len: usize) -> Result<(), UnarchiveError> {
    for seam in rows.chunks(run_len).collect::<Vec<_>>().windows(2) {
        let last = &seam[0].last().expect("non-empty run").0;
        let first = &seam[1].first().expect("non-empty run").0;
        if last == first {
            return Err(UnarchiveError::BadCanonicalizationRedundancy);
        }
        if last > first {
            return Err(UnarchiveError::BadCanonicalizationOrdering);
        }
    }
    Ok(())
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

    fn tribles(rows: &[[u8; 64]]) -> Vec<Trible> {
        rows.iter()
            .map(|row| Trible::force_raw(*row).expect("fixture rows are valid tribles"))
            .collect()
    }

    #[test]
    fn canonical_tribles_from_tribles_wraps_the_rows_in_place() {
        let empty = CanonicalTribles::from_tribles(&[]).unwrap();
        assert!(empty.is_empty());

        let rows = tribles(&(0..5).map(fixture_row).collect::<Vec<_>>());
        let canonical = CanonicalTribles::from_tribles(&rows).unwrap();
        assert_eq!(canonical.len(), rows.len());
        assert_eq!(canonical.as_tribles(), &rows[..]);
        assert!(std::ptr::eq(canonical.as_tribles(), &rows[..]));
        assert_eq!(
            zerocopy::IntoBytes::as_bytes(canonical),
            zerocopy::IntoBytes::as_bytes(&rows[..])
        );
    }

    /// Every safe constructor of `CanonicalTribles` runs the ordering check
    /// and reports the same error for the same rows.
    #[test]
    fn canonical_tribles_every_constructor_refuses_bad_ordering() {
        let (a, b, c) = (fixture_row(0), fixture_row(1), fixture_row(2));
        let cases = [
            (vec![a, a], UnarchiveError::BadCanonicalizationRedundancy),
            (vec![a, b, b], UnarchiveError::BadCanonicalizationRedundancy),
            (vec![b, a], UnarchiveError::BadCanonicalizationOrdering),
            (vec![a, c, b], UnarchiveError::BadCanonicalizationOrdering),
            // An equal pair before a smaller row: the first offence wins.
            (vec![b, b, a], UnarchiveError::BadCanonicalizationRedundancy),
        ];
        for (rows, expected) in cases {
            let typed = tribles(&rows);
            assert_eq!(
                CanonicalTribles::from_tribles(&typed).unwrap_err(),
                expected
            );
            let bytes = Bytes::from(rows.clone());
            assert_eq!(
                CanonicalTribles::validate(bytes.clone()).unwrap_err(),
                expected
            );
            let mut visited = 0;
            assert_eq!(
                CanonicalTribles::validate_with(bytes.clone(), |_, _| visited += 1).unwrap_err(),
                expected
            );
            assert!(visited < rows.len(), "visit saw the offending row");
            assert_eq!(
                Blob::<SimpleArchive>::new(bytes.clone())
                    .try_from_blob::<View<CanonicalTribles>>()
                    .unwrap_err(),
                expected
            );
            #[cfg(feature = "parallel")]
            assert_eq!(
                CanonicalTribles::par_validate_map(bytes.clone(), |_| ()).unwrap_err(),
                expected
            );
            assert_eq!(
                TribleSet::try_from_blob(Blob::new(bytes)).unwrap_err(),
                expected
            );
        }
    }

    /// The zero-copy decode of a blob is its rows in place, in the order and
    /// with the content the indexing decode reads.
    #[test]
    fn zero_copy_decode_matches_tribleset_decode() {
        for len in [0usize, 1, 2, 257, PARALLEL_THRESHOLD_FOR_TESTS + 1] {
            let blob = fixture_blob(len);
            let set: TribleSet = blob.clone().try_from_blob().unwrap();
            let view: View<CanonicalTribles> = blob.clone().try_from_blob().unwrap();
            let decoded: Vec<Trible> = set.iter_ordered().copied().collect();
            assert_eq!(view.len(), len);
            assert_eq!(view.as_tribles(), &decoded[..]);
            assert_eq!(view.as_rows().as_flattened(), &blob.bytes[..]);
            if len > 0 {
                assert_eq!(view.as_tribles().as_ptr().cast::<u8>(), blob.bytes.as_ptr());
            }
            // The view hands its bytes back unchanged.
            assert_eq!(&view.clone().bytes()[..], &blob.bytes[..]);
        }
        let set: TribleSet = (0..100)
            .map(|index| Trible::force_raw(fixture_row(index * 7 % 100)).unwrap())
            .fold(TribleSet::new(), |mut set, trible| {
                set.insert(&trible);
                set
            });
        let blob: Blob<SimpleArchive> = (&set).to_blob();
        let view: View<CanonicalTribles> = blob.try_from_blob().unwrap();
        assert_eq!(
            view.as_tribles(),
            &set.iter_ordered().copied().collect::<Vec<_>>()[..]
        );
    }

    /// `from_set` gives exactly the rows and bytes a checked decode of the
    /// set's archive gives, for empty, single and large sets, and inserts in
    /// any order.
    #[test]
    fn from_set_matches_the_checked_decode_of_its_archive() {
        for len in [0usize, 1, 2, 257, PARALLEL_THRESHOLD_FOR_TESTS + 1] {
            let set: TribleSet = (0..len)
                .rev()
                .map(|index| Trible::force_raw(fixture_row(index)).unwrap())
                .fold(TribleSet::new(), |mut set, trible| {
                    set.insert(&trible);
                    set
                });
            let fast = CanonicalTribles::from_set(&set);
            let blob: Blob<SimpleArchive> = (&set).to_blob();
            let checked: View<CanonicalTribles> = blob.clone().try_from_blob().unwrap();
            assert_eq!(fast.len(), set.len());
            assert_eq!(fast.as_tribles(), checked.as_tribles());
            assert_eq!(&fast.clone().bytes()[..], &blob.bytes[..]);
            if len > 0 {
                assert_eq!(fast.as_tribles().as_ptr() as usize % 16, 0);
            }
        }
    }

    /// The decode keeps the other errors exactly as the byte checks report
    /// them.
    #[test]
    fn zero_copy_decode_keeps_archive_and_trible_errors() {
        let rows: Vec<[u8; 64]> = (0..3).map(fixture_row).collect();
        let decode = |bytes: Bytes| {
            Blob::<SimpleArchive>::new(bytes).try_from_blob::<View<CanonicalTribles>>()
        };
        assert_eq!(
            decode(misaligned_copy(rows.as_flattened())).unwrap_err(),
            UnarchiveError::BadArchive
        );
        let mut partial = Bytes::from(rows.clone());
        assert!(partial.take_suffix(1).is_some());
        assert_eq!(decode(partial).unwrap_err(), UnarchiveError::BadArchive);
        let mut nil = rows;
        nil[2][16..32].fill(0);
        nil.swap(0, 1);
        assert_eq!(
            decode(Bytes::from(nil)).unwrap_err(),
            UnarchiveError::BadTrible
        );
        assert!(decode(Bytes::empty()).unwrap().is_empty());
    }

    /// The encoding marker and its metadata are untouched by the zero-copy
    /// face: the schema id and the described metadata stay byte-identical.
    #[test]
    fn simple_archive_schema_identity_is_golden() {
        assert_eq!(
            <SimpleArchive as MetaDescribe>::id(),
            id_hex!("8F4A27C8581DADCBA1ADA8BA228069B6")
        );
        let described: Blob<SimpleArchive> = SimpleArchive::describe().facts().to_blob();
        let handle: String = described
            .get_handle()
            .raw
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();
        println!("GOLDEN simplearchive metadata handle = {handle}");
        assert_eq!(handle, SIMPLE_ARCHIVE_METADATA_HANDLE);
    }

    const SIMPLE_ARCHIVE_METADATA_HANDLE: &str =
        "37AFF68935E6B442A470F775E1B84C33939810C205ADE4521B8175DCA6A42D7D";

    #[cfg(feature = "parallel")]
    const PARALLEL_THRESHOLD_FOR_TESTS: usize = PARALLEL_UNARCHIVE_THRESHOLD;
    #[cfg(not(feature = "parallel"))]
    const PARALLEL_THRESHOLD_FOR_TESTS: usize = 4096;

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

    /// The parallel path checks the row rule inside each run, so a nil row
    /// that only a later run sees must still be reported, and must still win
    /// over an ordering error that an earlier run or a seam meets first.
    #[cfg(feature = "parallel")]
    #[test]
    fn canonical_tribles_parallel_reports_a_nil_row_in_a_later_run_as_bad_trible() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build()
            .unwrap()
            .install(|| {
                let len = PARALLEL_UNARCHIVE_THRESHOLD;
                let run_len = parallel_run_len(len);
                assert!(2 * run_len + 1 < len, "three runs");
                let canonical = || (0..len).map(fixture_row).collect::<Vec<_>>();

                let mut nil_in_second_run = canonical();
                nil_in_second_run[run_len + 1][..16].fill(0);

                let mut nil_later_descending_first = canonical();
                nil_later_descending_first.swap(1, 2);
                nil_later_descending_first[run_len + 1][..16].fill(0);

                let mut nil_later_duplicate_first = canonical();
                nil_later_duplicate_first[1] = nil_later_duplicate_first[0];
                nil_later_duplicate_first[2 * run_len + 1][16..32].fill(0);

                let mut nil_later_seam_duplicate = canonical();
                nil_later_seam_duplicate[run_len] = nil_later_seam_duplicate[run_len - 1];
                nil_later_seam_duplicate[2 * run_len + 1][16..32].fill(0);

                for rows in [
                    nil_in_second_run,
                    nil_later_descending_first,
                    nil_later_duplicate_first,
                    nil_later_seam_duplicate,
                ] {
                    let bytes = Bytes::from(rows);
                    assert_eq!(
                        CanonicalTribles::validate(bytes.clone()).unwrap_err(),
                        UnarchiveError::BadTrible,
                    );
                    assert_eq!(
                        CanonicalTribles::par_validate_map(bytes.clone(), |_| ()).unwrap_err(),
                        UnarchiveError::BadTrible,
                    );
                    assert_eq!(
                        try_from_archive_bytes(bytes.clone()).unwrap_err(),
                        UnarchiveError::BadTrible,
                    );
                    assert_eq!(
                        try_from_blob_heap_only(Blob::new(bytes)).unwrap_err(),
                        UnarchiveError::BadTrible,
                    );
                }
            });
    }

    /// Size and alignment are checked once, before the runs, on the parallel
    /// path too: they win over a nil row, and empty input is canonical at any
    /// address.
    #[cfg(feature = "parallel")]
    #[test]
    fn canonical_tribles_parallel_keeps_archive_errors_and_the_empty_exemption() {
        let backing = Bytes::from(vec![fixture_row(0)]);
        for offset in 0..=3 {
            let (canonical, mapped) =
                CanonicalTribles::par_validate_map(backing.slice(offset..offset), |_| 1u8).unwrap();
            assert!(canonical.is_empty());
            assert!(mapped.is_empty());
        }

        let mut rows: Vec<[u8; 64]> = (0..5).map(fixture_row).collect();
        rows[3][..16].fill(0);
        let misaligned = misaligned_copy(rows.as_flattened());
        assert_eq!(
            CanonicalTribles::par_validate_map(misaligned, |_| ()).unwrap_err(),
            UnarchiveError::BadArchive,
        );
        let mut partial = Bytes::from(rows);
        assert!(partial.take_suffix(1).is_some());
        assert_eq!(
            CanonicalTribles::par_validate_map(partial, |_| ()).unwrap_err(),
            UnarchiveError::BadArchive,
        );
    }
}
