//! Canonical TribleSet set union over
//! [`SimpleArchive`](crate::blob::encodings::simplearchive::SimpleArchive)
//! elements.
//!
//! This is the first concrete production collection encoding. A collection
//! pairs a UTF-8 name and immutable collection policy with the existing
//! `SimpleArchive` representation. Every element is an exact, canonical EAV-ordered stream of
//! 64-byte tribles. Its join is ordinary set union, so canonical output bytes
//! and their Blake3 identity are associative, commutative, and idempotent.
//!
//! Joins and publication operate directly on the canonical byte streams. They
//! deliberately do not construct [`crate::trible::TribleSet`] or PATCH indexes;
//! query-time decoding keeps its independently optimized path. The explicit
//! [`validate_merge`](crate::collection::simplearchive_union::validate_merge)
//! helper is for producer checks, network ingress, and offline audits. Warm
//! collection resolution trusts stored equations and never invokes it.

#[cfg(test)]
use super::policy::CollectionPolicy;
use super::records::RecordDecodeError;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::error::Error;
use std::fmt;

use anybytes::{Bytes, View};
use ed25519_dalek::SigningKey;

use crate::blob::encodings::simplearchive::{SimpleArchive, UnarchiveError};
use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::id::Id;
#[cfg(test)]
use crate::id_hex;
use crate::inline::encodings::hash::Handle;
#[cfg(test)]
use crate::inline::encodings::hash::{Blake3, Hash};
#[cfg(test)]
use crate::inline::Inline;
use crate::metadata::MetaDescribe;
use crate::repo::{BlobStorePut, SnapshotSource};
use crate::trible::{Fragment, Trible, TRIBLE_LEN};

use super::descriptor as descriptor_facts;
use super::{
    Collection, CollectionCommit, CollectionCommitError, CollectionData, CollectionEncoding,
    CollectionHandle, CollectionMerge, CollectionOperationError, CollectionRecord, CollectionStore,
};

mod view;
pub use view::FactViewError;

impl CollectionEncoding for SimpleArchive {
    fn validate_member<R>(
        _descriptor: &Fragment,
        member: &Blob<Self>,
        _reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        validate_element(member)
            .map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }

    fn join_members<R>(
        _descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        _reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: crate::repo::BlobStoreGet + crate::repo::BlobStoreMeta,
    {
        join(low, high).map_err(|source| CollectionOperationError::Fatal(source.to_string()))
    }
}

/// The collection endpoint involved in a validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElementRole {
    /// Data introduced by a signed commit.
    CommitData,
    /// Canonically lower merge input.
    MergeLow,
    /// Canonically higher merge input.
    MergeHigh,
    /// Claimed merge output.
    MergeResult,
}

impl fmt::Display for ElementRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitData => write!(f, "commit data"),
            Self::MergeLow => write!(f, "merge low input"),
            Self::MergeHigh => write!(f, "merge high input"),
            Self::MergeResult => write!(f, "merge result"),
        }
    }
}

/// Failure to validate a commit or merge against this concrete collection kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimpleArchiveUnionValidationError {
    /// The descriptor does not carry a field this check needs.
    Malformed(RecordDecodeError),
    /// The descriptor names another blob representation.
    WrongRepresentation { expected: Id, actual: Id },
    /// The record belongs to another collection descriptor.
    WrongCollection {
        expected: CollectionHandle,
        actual: CollectionHandle,
    },
    /// The supplied blob's trusted cached identity differs from the record.
    EndpointMismatch {
        role: ElementRole,
        expected: CollectionData,
        actual: CollectionData,
    },
    /// An endpoint is not a canonical `SimpleArchive` element.
    InvalidElement {
        role: ElementRole,
        source: UnarchiveError,
    },
    /// The claimed result is not the exact canonical union of the two inputs.
    WrongMergeResult,
}

impl fmt::Display for SimpleArchiveUnionValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed collection descriptor: {error}"),
            Self::WrongRepresentation { expected, actual } => write!(
                f,
                "collection representation {actual:X} does not match SimpleArchive {expected:X}"
            ),
            Self::WrongCollection { expected, actual } => write!(
                f,
                "record collection {} does not match descriptor {}",
                hex::encode_upper(actual.raw),
                hex::encode_upper(expected.raw),
            ),
            Self::EndpointMismatch {
                role,
                expected,
                actual,
            } => write!(
                f,
                "{role} handle {} does not match claimed {}",
                hex::encode_upper(actual.raw),
                hex::encode_upper(expected.raw),
            ),
            Self::InvalidElement { role, source } => {
                write!(f, "{role} is not a canonical SimpleArchive: {source}")
            }
            Self::WrongMergeResult => {
                write!(f, "merge result is not the exact canonical input union")
            }
        }
    }
}

impl Error for SimpleArchiveUnionValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidElement { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A canonical `SimpleArchive` collection commit whose bytes have not been
/// published.
///
/// Preparation consumes one [`Fragment`] exactly once, retaining its canonical
/// data, metadata, and embedded blobs. It touches no store and needs no signing
/// key. Call [`Self::stage_for`] with an already typed collection to write every
/// dependency and sign the resulting commit over the handles the store itself
/// returned. Dropping a prepared value has no storage effect.
#[derive(Clone, Debug)]
#[must_use = "a prepared collection commit has no effect until it is staged and finalized"]
pub struct PreparedCollectionCommit {
    embedded: Vec<Blob<UnknownBlob>>,
    data: Blob<SimpleArchive>,
    metadata: Blob<SimpleArchive>,
}

impl PreparedCollectionCommit {
    /// Prepare one self-contained fact fragment entirely in memory.
    ///
    /// Facts become collection data and metafacts become commit metadata. The
    /// fragment's shared blob store may back handles in either set; those
    /// attachments are retained in canonical handle order for staging. Fragment
    /// exports are not serialized.
    pub fn from_fragment(fragment: Fragment) -> Self {
        let (_, facts, metafacts, mut blobs) = fragment.into_parts();

        let mut embedded: Vec<Blob<UnknownBlob>> = blobs
            .snapshot()
            .expect("MemoryBlobStore::snapshot is infallible")
            .into_iter()
            .map(|(_, blob)| blob)
            .collect();
        embedded.sort_unstable_by_key(|blob| blob.get_handle().raw);

        Self {
            embedded,
            data: crate::blob::IntoBlob::to_blob(facts),
            metadata: crate::blob::IntoBlob::to_blob(metafacts),
        }
    }

    /// Stage every dependency against an already typed collection and sign the
    /// withheld commit.
    ///
    /// The exact store-call order is embedded fragment blobs (in handle order),
    /// data, and metadata. Every handle the signed commit names is returned by
    /// one of those writes, so its complete dependency closure is present before
    /// publication. The descriptor and its attachment closure must already be
    /// resident; this operation never registers or rewrites them.
    ///
    /// On success the returned value retains the same mutable store borrow, so
    /// a caller may append unsigned `MERGE` or `DERIVE` artifacts through
    /// [`StagedCollectionCommit::store_mut`] before consuming the value with
    /// [`StagedCollectionCommit::finalize`].
    pub fn stage_for<'store, S>(
        self,
        store: &'store mut S,
        collection: Collection<SimpleArchive>,
        signing_key: &SigningKey,
    ) -> Result<StagedCollectionCommit<'store, S>, CollectionCommitError<S::PutError, S::InsertError>>
    where
        S: BlobStorePut + CollectionStore,
    {
        let Self {
            embedded,
            data,
            metadata,
        } = self;
        for blob in embedded {
            store
                .put::<UnknownBlob, _>(blob)
                .map_err(CollectionCommitError::DependencyPut)?;
        }
        let data_handle = store
            .put::<SimpleArchive, _>(data)
            .map_err(CollectionCommitError::DependencyPut)?;
        let metadata_handle = store
            .put::<SimpleArchive, _>(metadata)
            .map_err(CollectionCommitError::DependencyPut)?;

        let commit = CollectionCommit::sign(
            signing_key,
            collection.handle(),
            Handle::<SimpleArchive>::to_hash(data_handle),
            metadata_handle,
        );
        Ok(StagedCollectionCommit { store, commit })
    }
}

/// A canonical commit whose complete dependency set has been written first.
///
/// This type holds the exact store borrow used for staging, so reproducible
/// unsigned equations and their artifacts can be appended before the source
/// membership root becomes visible. Only consuming
/// [`finalize`](Self::finalize) appends the signed `COMMIT` record. Drop is
/// deliberately inert and never auto-finalizes.
#[must_use = "dropping a staged collection commit leaves its dependencies inert; call finalize to publish it"]
pub struct StagedCollectionCommit<'store, S>
where
    S: BlobStorePut + CollectionStore,
{
    store: &'store mut S,
    commit: CollectionCommit,
}

impl<'store, S> StagedCollectionCommit<'store, S>
where
    S: BlobStorePut + CollectionStore,
{
    /// Inspect the exact commit that remains withheld from the store.
    pub fn commit(&self) -> &CollectionCommit {
        &self.commit
    }

    /// Borrow the staged publication's destination for intervening artifacts.
    ///
    /// Writes performed here occur after the dependency writes and before the
    /// final commit append. The caller remains responsible for validity and
    /// dependency ordering.
    pub fn store_mut(&mut self) -> &mut S {
        self.store
    }

    /// Append the canonical signed commit last.
    ///
    /// This is the sole visibility boundary. If the insert fails,
    /// backend-specific recovery may be required before deterministic replay.
    /// Durability remains an explicit caller-selected store operation.
    pub fn finalize(
        self,
    ) -> Result<CollectionCommit, CollectionCommitError<S::PutError, S::InsertError>> {
        let Self { store, commit } = self;
        store
            .insert(CollectionRecord::Commit(commit))
            .map_err(CollectionCommitError::RecordInsert)?;
        Ok(commit)
    }
}

/// Describe this collection kind as a named root under one authority.
///
/// This is the one home for what a `SimpleArchive` set-union collection *is*:
/// the encoding description names both its canonical bytes and intra-encoding
/// join. Everything else about a particular collection -- which one it is --
/// is the name and authority passed in.
/// Authority is mandatory and participates directly in descriptor identity.
///
/// It returns the facts, not a handle. Getting a handle means putting the
/// blob, and `put` gives you the handle back, so a stored descriptor is a
/// side effect of naming one rather than a second thing to remember. Hashing
/// a descriptor you never stored would leave a phantom collection: records
/// that reference it, and nothing that can decode what they reference.
#[cfg(test)]
pub(crate) fn descriptor(name: &str, policy: CollectionPolicy) -> Fragment {
    super::descriptor::naming::<SimpleArchive>(name, policy)
}

/// Validate one canonical `SimpleArchive` collection element without decoding
/// it into query indexes.
pub fn validate_element(blob: &Blob<SimpleArchive>) -> Result<(), UnarchiveError> {
    canonical_rows(blob).map(|_| ())
}

/// Compute the exact canonical union of two `SimpleArchive` elements.
///
/// Both inputs are validated before an identity fast path or output allocation
/// is taken. Equal and empty inputs reuse their immutable bytes but recompute
/// the returned handle; every other case performs one lexicographic two-pointer
/// merge and emits shared rows once.
pub fn join(
    left: &Blob<SimpleArchive>,
    right: &Blob<SimpleArchive>,
) -> Result<Blob<SimpleArchive>, UnarchiveError> {
    let left_rows = canonical_rows(left)?;
    let right_rows = canonical_rows(right)?;
    Ok(join_canonical_rows(left, right, &left_rows, &right_rows))
}

/// Compute one canonical union over many `SimpleArchive` elements.
///
/// Each input is validated before output construction. The error carries the
/// zero-based input position so callers can retain the identity of a malformed
/// member. A heap merge keeps one current row per input and writes the result
/// once, avoiding the intermediate archives produced by repeated two-way
/// joins.
pub(crate) fn join_many<'a>(
    elements: impl IntoIterator<Item = &'a Blob<SimpleArchive>>,
) -> Result<Blob<SimpleArchive>, (usize, UnarchiveError)> {
    Ok(Blob::new(join_many_bytes(elements)?))
}

/// Compute the canonical union's bytes without naming them.
///
/// Same output as [`join_many`], minus the Blake3 pass that turns bytes into a
/// handle. Naming a blob is a separate act from computing one, and a caller
/// that decodes the union and drops it — `snapshot_from_observation` does —
/// pays a fifth of the merge for a handle it never reads.
pub(crate) fn join_many_bytes<'a>(
    elements: impl IntoIterator<Item = &'a Blob<SimpleArchive>>,
) -> Result<Bytes, (usize, UnarchiveError)> {
    let elements: Vec<_> = elements.into_iter().collect();
    let mut element_rows = Vec::with_capacity(elements.len());
    for (index, element) in elements.iter().enumerate() {
        element_rows.push(canonical_rows(element).map_err(|source| (index, source))?);
    }

    match elements.as_slice() {
        [] => return Ok(Bytes::from(Vec::<[u8; TRIBLE_LEN]>::new())),
        // Canonical bytes are already the union of themselves; `join_many`
        // renames them, which is what `normalize_blob` did here before.
        [element] => return Ok(element.bytes.clone()),
        _ => {}
    }

    let slices: Vec<&[[u8; TRIBLE_LEN]]> = element_rows.iter().map(|rows| &rows[..]).collect();

    #[cfg(feature = "parallel")]
    {
        if let Some(union) = parallel_merge_canonical(&slices) {
            return Ok(Bytes::from(union));
        }
    }

    Ok(Bytes::from(merge_canonical_range(&slices, None, None)))
}

/// Heap-merge the rows of every input that fall in `[low, high)`.
///
/// `None` bounds are open. Inputs are canonical — sorted and distinct — so one
/// pass with one live row per input emits the range's union in order, and the
/// only duplicates it can see are equal rows from different inputs.
fn merge_canonical_range(
    slices: &[&[[u8; TRIBLE_LEN]]],
    low: Option<&[u8; TRIBLE_LEN]>,
    high: Option<&[u8; TRIBLE_LEN]>,
) -> Vec<[u8; TRIBLE_LEN]> {
    let mut cursors = Vec::with_capacity(slices.len());
    let mut capacity = 0usize;
    for rows in slices {
        let start = match low {
            Some(low) => rows.partition_point(|row| row < low),
            None => 0,
        };
        let end = match high {
            Some(high) => rows.partition_point(|row| row < high),
            None => rows.len(),
        };
        capacity = capacity.saturating_add(end.saturating_sub(start));
        cursors.push((start, end));
    }

    let mut union = Vec::with_capacity(capacity);
    let mut heap = BinaryHeap::with_capacity(slices.len());
    for (element, (start, end)) in cursors.iter().copied().enumerate() {
        if start < end {
            heap.push(Reverse((slices[element][start], element, start)));
        }
    }

    let mut previous = None;
    while let Some(Reverse((row, element, index))) = heap.pop() {
        if previous != Some(row) {
            union.push(row);
            previous = Some(row);
        }
        let next = index + 1;
        if next < cursors[element].1 {
            heap.push(Reverse((slices[element][next], element, next)));
        }
    }
    union
}

/// Rows below which a partitioned merge is not worth its splitter search.
#[cfg(feature = "parallel")]
const PARALLEL_MERGE_THRESHOLD: usize = 1 << 16;

/// Merge canonical inputs by disjoint key range, one range per worker.
///
/// The serial heap merge is one thread deciding 26 M times which of 404
/// streams is next, and that decision is exactly what a key range makes
/// independent: partitions cover disjoint key intervals, so each worker's
/// output is a complete, deduplicated, sorted run and concatenating the runs in
/// range order reproduces the serial result byte for byte. Splitters are chosen
/// by regular sampling, so they affect balance only — never the output.
///
/// Returns `None` when the input is too small to be worth partitioning, leaving
/// the caller on the serial path.
#[cfg(feature = "parallel")]
fn parallel_merge_canonical(slices: &[&[[u8; TRIBLE_LEN]]]) -> Option<Vec<[u8; TRIBLE_LEN]>> {
    use rayon::prelude::*;

    let total: usize = slices.iter().map(|rows| rows.len()).sum();
    let workers = rayon::current_num_threads();
    if total < PARALLEL_MERGE_THRESHOLD || workers < 2 {
        return None;
    }

    // Regular sampling: every input contributes candidates at even offsets, so
    // one huge member cannot alone decide the cut points and a skewed member
    // cannot hide a dense key range from the sample.
    let per_input = workers.min(64);
    let mut samples = Vec::with_capacity(slices.len().saturating_mul(per_input));
    for rows in slices {
        if rows.is_empty() {
            continue;
        }
        for step in 1..per_input {
            let index = rows.len().saturating_mul(step) / per_input;
            if index < rows.len() {
                samples.push(rows[index]);
            }
        }
    }
    samples.sort_unstable();
    samples.dedup();
    if samples.is_empty() {
        return None;
    }

    let cuts = workers.min(samples.len() + 1);
    let mut splitters = Vec::with_capacity(cuts.saturating_sub(1));
    for step in 1..cuts {
        let index = samples.len().saturating_mul(step) / cuts;
        let candidate = samples[index.min(samples.len() - 1)];
        if splitters.last() != Some(&candidate) {
            splitters.push(candidate);
        }
    }
    if splitters.is_empty() {
        return None;
    }

    let mut bounds: Vec<(Option<[u8; TRIBLE_LEN]>, Option<[u8; TRIBLE_LEN]>)> =
        Vec::with_capacity(splitters.len() + 1);
    let mut low = None;
    for splitter in splitters {
        bounds.push((low, Some(splitter)));
        low = Some(splitter);
    }
    bounds.push((low, None));

    let runs: Vec<Vec<[u8; TRIBLE_LEN]>> = bounds
        .par_iter()
        .map(|(low, high)| merge_canonical_range(slices, low.as_ref(), high.as_ref()))
        .collect();

    let mut union = Vec::with_capacity(runs.iter().map(Vec::len).sum());
    for run in runs {
        union.extend_from_slice(&run);
    }
    Some(union)
}

/// Validate a discovered commit as one canonical root of this collection.
///
/// This binds the concrete descriptor, record collection, endpoint identity,
/// and element bytes in one check. The record's strict self-signature and the
/// caller's authorization policy remain separate admission prerequisites.
pub fn validate_commit(
    descriptor: &Fragment,
    commit: &CollectionCommit,
    data_blob: &Blob<SimpleArchive>,
) -> Result<(), SimpleArchiveUnionValidationError> {
    validate_member(descriptor, commit.collection(), commit.data(), data_blob)
}

/// Validate one payload member against an exact collection descriptor.
///
/// A [`crate::collection::Cover`] deliberately erases which signed commit
/// admitted a payload. This is the corresponding data-lattice boundary: bind
/// the descriptor identity and payload hash directly, without inventing or
/// selecting a provenance claim merely to validate the bytes.
pub(crate) fn validate_member(
    descriptor: &Fragment,
    collection: CollectionHandle,
    member: CollectionData,
    data_blob: &Blob<SimpleArchive>,
) -> Result<(), SimpleArchiveUnionValidationError> {
    validate_descriptor(descriptor)?;
    let expected: CollectionHandle =
        crate::blob::IntoBlob::<SimpleArchive>::to_blob(descriptor.facts().clone()).get_handle();
    validate_collection(expected, collection)?;
    validate_endpoint(ElementRole::CommitData, member, data_blob)
}

/// Validate a claimed exact union without materializing another result blob.
///
/// All endpoints are first bound to their record hashes and validated as
/// canonical archives. The expected two-way union is then compared row-for-row
/// with `result`, using constant auxiliary space.
pub fn validate_merge(
    descriptor: &Fragment,
    claim: &CollectionMerge,
    low: &Blob<SimpleArchive>,
    high: &Blob<SimpleArchive>,
    result: &Blob<SimpleArchive>,
) -> Result<(), SimpleArchiveUnionValidationError> {
    validate_descriptor(descriptor)?;
    let collection: CollectionHandle =
        crate::blob::IntoBlob::<SimpleArchive>::to_blob(descriptor.facts().clone()).get_handle();
    validate_collection(collection, claim.collection())?;

    let (expected_low, expected_high) = claim.inputs();
    validate_handle(ElementRole::MergeLow, expected_low, low)?;
    validate_handle(ElementRole::MergeHigh, expected_high, high)?;
    validate_handle(ElementRole::MergeResult, claim.result(), result)?;

    let low_rows = canonical_rows(low).map_err(|source| {
        SimpleArchiveUnionValidationError::InvalidElement {
            role: ElementRole::MergeLow,
            source,
        }
    })?;
    let high_rows = canonical_rows(high).map_err(|source| {
        SimpleArchiveUnionValidationError::InvalidElement {
            role: ElementRole::MergeHigh,
            source,
        }
    })?;
    let result_rows = canonical_rows(result).map_err(|source| {
        SimpleArchiveUnionValidationError::InvalidElement {
            role: ElementRole::MergeResult,
            source,
        }
    })?;

    if !UnionRows::new(&low_rows, &high_rows).eq(result_rows.iter()) {
        return Err(SimpleArchiveUnionValidationError::WrongMergeResult);
    }
    Ok(())
}

fn validate_descriptor(descriptor: &Fragment) -> Result<(), SimpleArchiveUnionValidationError> {
    let expected_representation = <SimpleArchive as MetaDescribe>::id();
    let representation = descriptor_facts::representation(descriptor.facts())?;
    if representation != expected_representation {
        return Err(SimpleArchiveUnionValidationError::WrongRepresentation {
            expected: expected_representation,
            actual: representation,
        });
    }
    Ok(())
}

fn validate_collection(
    expected: CollectionHandle,
    actual: CollectionHandle,
) -> Result<(), SimpleArchiveUnionValidationError> {
    if actual != expected {
        return Err(SimpleArchiveUnionValidationError::WrongCollection { expected, actual });
    }
    Ok(())
}

fn validate_endpoint(
    role: ElementRole,
    expected: CollectionData,
    blob: &Blob<SimpleArchive>,
) -> Result<(), SimpleArchiveUnionValidationError> {
    validate_handle(role, expected, blob)?;
    validate_element(blob)
        .map_err(|source| SimpleArchiveUnionValidationError::InvalidElement { role, source })
}

fn validate_handle(
    role: ElementRole,
    expected: CollectionData,
    blob: &Blob<SimpleArchive>,
) -> Result<(), SimpleArchiveUnionValidationError> {
    let actual = Handle::<SimpleArchive>::to_hash(blob.get_handle());
    if actual != expected {
        return Err(SimpleArchiveUnionValidationError::EndpointMismatch {
            role,
            expected,
            actual,
        });
    }
    Ok(())
}

fn join_canonical_rows(
    left: &Blob<SimpleArchive>,
    right: &Blob<SimpleArchive>,
    left_rows: &[[u8; TRIBLE_LEN]],
    right_rows: &[[u8; TRIBLE_LEN]],
) -> Blob<SimpleArchive> {
    if left.bytes == right.bytes || right_rows.is_empty() {
        return Blob::new(left.bytes.clone());
    }
    if left_rows.is_empty() {
        return Blob::new(right.bytes.clone());
    }

    let mut rows = Vec::with_capacity(left_rows.len() + right_rows.len());
    rows.extend(UnionRows::new(left_rows, right_rows).copied());
    Blob::new(Bytes::from(rows))
}

fn canonical_rows(blob: &Blob<SimpleArchive>) -> Result<View<[[u8; TRIBLE_LEN]]>, UnarchiveError> {
    let rows: View<[[u8; TRIBLE_LEN]]> = blob
        .bytes
        .clone()
        .view()
        .map_err(|_| UnarchiveError::BadArchive)?;
    let mut previous: Option<&[u8; TRIBLE_LEN]> = None;
    for row in rows.iter() {
        if Trible::as_transmute_force_raw(row).is_none() {
            return Err(UnarchiveError::BadTrible);
        }
        if let Some(previous) = previous {
            if previous == row {
                return Err(UnarchiveError::BadCanonicalizationRedundancy);
            }
            if previous > row {
                return Err(UnarchiveError::BadCanonicalizationOrdering);
            }
        }
        previous = Some(row);
    }
    Ok(rows)
}

struct UnionRows<'a> {
    left: &'a [[u8; TRIBLE_LEN]],
    right: &'a [[u8; TRIBLE_LEN]],
    left_index: usize,
    right_index: usize,
}

impl<'a> UnionRows<'a> {
    fn new(left: &'a [[u8; TRIBLE_LEN]], right: &'a [[u8; TRIBLE_LEN]]) -> Self {
        Self {
            left,
            right,
            left_index: 0,
            right_index: 0,
        }
    }
}

impl<'a> Iterator for UnionRows<'a> {
    type Item = &'a [u8; TRIBLE_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        match (
            self.left.get(self.left_index),
            self.right.get(self.right_index),
        ) {
            (Some(left), Some(right)) => match left.cmp(right) {
                std::cmp::Ordering::Less => {
                    self.left_index += 1;
                    Some(left)
                }
                std::cmp::Ordering::Equal => {
                    self.left_index += 1;
                    self.right_index += 1;
                    Some(left)
                }
                std::cmp::Ordering::Greater => {
                    self.right_index += 1;
                    Some(right)
                }
            },
            (Some(left), None) => {
                self.left_index += 1;
                Some(left)
            }
            (None, Some(right)) => {
                self.right_index += 1;
                Some(right)
            }
            (None, None) => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.left.len() - self.left_index;
        let right = self.right.len() - self.right_index;
        (left.max(right), left.checked_add(right))
    }
}

impl std::iter::FusedIterator for UnionRows<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, BTreeSet};
    use std::convert::Infallible;

    use ed25519_dalek::SigningKey;
    use hex_literal::hex;

    use crate::blob::encodings::rawbytes::RawBytes;
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::blob::{BlobEncoding, IntoBlob};
    use crate::collection::descriptor::identity_for_tests;
    use crate::collection::{
        discover_collection_records, empty_metadata_handle, resolve_collection_semantics,
        CollectionClaimValidation, CollectionDerive, CollectionStoreExt,
    };
    use crate::inline::InlineEncoding;
    use crate::macros::entity;
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::pile::Pile;
    use crate::repo::{BlobStoreGet, SnapshotSource};
    use crate::trible::TribleSet;

    /// The one team every collection in these tests belongs to.
    fn test_team() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[1; 32]).verifying_key()
    }

    /// One named root of this collection kind.
    fn root(name: &str) -> Fragment {
        super::descriptor(
            name,
            CollectionPolicy::new(
                crate::collection::AdmissionPolicy::direct(test_team()),
                crate::collection::AdmissionPolicy::direct(test_team()),
            ),
        )
    }

    /// The same anchor as `root("first")`, but naming a different physical
    /// encoding: a collection this implementation does not accept.
    fn test_naming(representation: Id) -> Fragment {
        crate::collection::descriptor::named_for_tests("first", representation)
    }

    mod fragment_ns {
        use crate::prelude::*;

        attributes! {
            // Test-only sentinel attributes; these are not protocol ids.
            "DD00000000000000DD00000000000031" unsafe as pub text: inlineencodings::Handle<blobencodings::UTF8String>;
            "DD00000000000000DD00000000000032" unsafe as pub payload: inlineencodings::Handle<blobencodings::RawBytes>;
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProbeFailure(usize);

    impl fmt::Display for ProbeFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "injected failure at operation {}", self.0)
        }
    }

    impl Error for ProbeFailure {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ProbeEvent {
        Put([u8; 32]),
        Insert(CollectionRecord),
    }

    #[derive(Default)]
    struct ProbeStore {
        events: Vec<ProbeEvent>,
        records: BTreeMap<CollectionRecord, CollectionRecord>,
        fail_at: Option<usize>,
        // The probe records the sequence of staged commit operations while a
        // real in-memory backend supplies coherent snapshots for assertions.
        repo: MemoryRepo,
    }

    impl ProbeStore {
        // This probe fails before an operation takes effect, so it exercises
        // publication ordering at trait-operation boundaries. BlobStorePut
        // does not promise that a real backend cannot leave torn physical I/O.
        fn attempt(&mut self, event: ProbeEvent) -> Result<(), ProbeFailure> {
            self.events.push(event);
            let operation = self.events.len();
            if self.fail_at == Some(operation) {
                return Err(ProbeFailure(operation));
            }
            Ok(())
        }
    }

    impl crate::repo::SnapshotSource for ProbeStore {
        type Snapshot = <MemoryRepo as crate::repo::SnapshotSource>::Snapshot;
        type SnapshotError = Infallible;

        fn snapshot_at(
            &mut self,
            instant: hifitime::Epoch,
        ) -> Result<Self::Snapshot, Self::SnapshotError> {
            crate::repo::SnapshotSource::snapshot_at(&mut self.repo, instant)
        }
    }

    impl BlobStorePut for ProbeStore {
        type PutError = ProbeFailure;

        fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
        where
            S: BlobEncoding + 'static,
            T: IntoBlob<S>,
            Handle<S>: InlineEncoding,
        {
            let blob: Blob<S> = item.to_blob();
            let handle = blob.get_handle();
            self.attempt(ProbeEvent::Put(handle.raw))?;
            self.repo.blobs.insert(blob.clone());
            Ok(handle)
        }
    }

    impl CollectionStore for ProbeStore {
        type InsertError = ProbeFailure;

        fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
            self.attempt(ProbeEvent::Insert(record))?;
            self.records.entry(record).or_insert(record);
            CollectionStore::insert(&mut self.repo, record)
                .expect("MemoryRepo insertion is infallible");
            Ok(())
        }
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn row(entity: u8, attribute: u8, value: u8) -> [u8; TRIBLE_LEN] {
        let mut row = [value; TRIBLE_LEN];
        row[..16].fill(entity);
        row[16..32].fill(attribute);
        row
    }

    fn archive(rows: impl IntoIterator<Item = [u8; TRIBLE_LEN]>) -> Blob<SimpleArchive> {
        let mut facts = TribleSet::new();
        for row in rows {
            facts.insert(&Trible::force_raw(row).unwrap());
        }
        facts.to_blob()
    }

    fn raw_archive(rows: Vec<[u8; TRIBLE_LEN]>) -> Blob<SimpleArchive> {
        Blob::new(Bytes::from(rows))
    }

    fn data(blob: &Blob<SimpleArchive>) -> CollectionData {
        Inline::<Hash<Blake3>>::new(Blake3::digest(&blob.bytes))
    }

    fn ordered_inputs<'a>(
        left: &'a Blob<SimpleArchive>,
        right: &'a Blob<SimpleArchive>,
    ) -> (&'a Blob<SimpleArchive>, &'a Blob<SimpleArchive>) {
        if data(left) <= data(right) {
            (left, right)
        } else {
            (right, left)
        }
    }

    fn put_event<S>(blob: &Blob<S>) -> ProbeEvent
    where
        S: BlobEncoding,
        Handle<S>: InlineEncoding,
    {
        ProbeEvent::Put(blob.get_handle().raw)
    }

    fn insert_event(record: CollectionRecord) -> ProbeEvent {
        ProbeEvent::Insert(record)
    }

    fn fragment_fixture() -> (
        Fragment,
        Inline<Handle<UTF8String>>,
        Inline<Handle<RawBytes>>,
    ) {
        let text: Blob<UTF8String> = String::from("a self-contained content blob").to_blob();
        let text_handle = text.get_handle();
        let mut content = entity! { fragment_ns::text: text };

        let payload: Blob<RawBytes> = vec![0, 1, 2, 3, 0xFE, 0xFF].to_blob();
        let payload_handle = payload.get_handle();
        let metadata = entity! { fragment_ns::payload: payload };
        content.describe_with(metadata);

        (content, text_handle, payload_handle)
    }

    fn embedded_put_events(fragment: &Fragment) -> Vec<ProbeEvent> {
        let mut blobs = fragment.blobs().clone();
        let mut handles: Vec<_> = blobs
            .snapshot()
            .expect("memory store snapshot is infallible")
            .iter()
            .map(|(handle, _)| handle.raw)
            .collect();
        handles.sort_unstable();
        handles.into_iter().map(ProbeEvent::Put).collect()
    }

    fn register_collection<S>(store: &mut S, descriptor: &Fragment) -> Collection<SimpleArchive>
    where
        S: BlobStorePut + CollectionStore,
        S::PutError: fmt::Debug,
    {
        store
            .register_collection::<SimpleArchive>(descriptor.clone())
            .unwrap()
    }

    #[test]
    fn prepared_fragment_is_canonical_idempotent_and_commits_after_caller_artifacts() {
        let source_descriptor = root("first");
        let target = root("second");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let (fragment, _text_handle, _payload_handle) = fragment_fixture();
        let embedded = embedded_put_events(&fragment);
        let content_archive: Blob<SimpleArchive> = fragment.facts().clone().to_blob();
        let metadata_archive: Blob<SimpleArchive> = fragment.metafacts().clone().to_blob();
        let expected = CollectionCommit::sign(
            &signing_key,
            identity_for_tests(&source_descriptor),
            data(&content_archive),
            metadata_archive.get_handle(),
        );

        let prepared = PreparedCollectionCommit::from_fragment(fragment.clone());
        let repeated = PreparedCollectionCommit::from_fragment(fragment);

        let derive = CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&target),
            expected.data(),
            Inline::new([0x42; 32]),
        );
        let derive_record = CollectionRecord::Derive(derive);
        let commit_record = CollectionRecord::Commit(expected);
        let mut sequence = [
            embedded,
            vec![put_event(&content_archive), put_event(&metadata_archive)],
        ]
        .concat();
        sequence.push(insert_event(derive_record));
        sequence.push(insert_event(commit_record));

        let mut store = ProbeStore::default();
        let source = register_collection(&mut store, &source_descriptor);
        store.events.clear();
        let mut signed = Vec::new();
        for prepared in [prepared, repeated] {
            let mut staged = prepared
                .stage_for(&mut store, source, &signing_key)
                .unwrap();
            assert_eq!(staged.commit(), &expected);
            signed.push(*staged.commit());
            staged.store_mut().insert(derive_record).unwrap();
            assert_eq!(staged.finalize().unwrap(), expected);
        }
        assert_eq!(signed[0], signed[1]);
        assert_eq!(signed[0].to_bytes(), signed[1].to_bytes());

        let mut expected_events = sequence.clone();
        expected_events.extend(sequence);
        assert_eq!(store.events, expected_events);
        assert!(store
            .records
            .contains_key(&CollectionRecord::Derive(derive)));
        assert!(store
            .records
            .contains_key(&CollectionRecord::Commit(expected)));
        validate_commit(&source_descriptor, &expected, &content_archive).unwrap();
    }

    #[test]
    fn staged_fragment_is_not_a_discoverable_commit_and_drop_is_inert() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("staged-only.pile");
        std::fs::File::create(&path).unwrap();

        let descriptor = root("first");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let (fragment, text_handle, payload_handle) = fragment_fixture();
        let expected_content: Blob<SimpleArchive> = fragment.facts().clone().to_blob();
        let expected_metadata: Blob<SimpleArchive> = fragment.metafacts().clone().to_blob();
        let prepared = PreparedCollectionCommit::from_fragment(fragment);

        let mut pile = Pile::open(&path).unwrap();
        let collection = register_collection(&mut pile, &descriptor);
        let mut staged = prepared
            .stage_for(&mut pile, collection, &signing_key)
            .unwrap();
        let withheld = *staged.commit();
        {
            let reader = staged.store_mut().snapshot().unwrap();
            let discovered = discover_collection_records(&reader).unwrap();
            assert!(discovered.commits().is_empty());
            assert!(discovered.merges().is_empty());
            assert!(discovered.derives().is_empty());
            let descriptor_blob: Blob<SimpleArchive> =
                reader.get(identity_for_tests(&descriptor)).unwrap();
            assert_eq!(
                <TribleSet as crate::blob::TryFromBlob<SimpleArchive>>::try_from_blob(
                    descriptor_blob
                )
                .unwrap(),
                *descriptor.facts()
            );

            let resolution = resolve_collection_semantics(
                &discovered,
                &std::collections::BTreeMap::new(),
                &BTreeSet::new(),
                |_| Ok::<_, Infallible>(CollectionClaimValidation::<()>::Pending),
            )
            .unwrap();
            assert!(resolution.admitted_claims().is_empty());
            assert!(resolution
                .semantics()
                .members(identity_for_tests(&descriptor))
                .is_none());
            let content: Blob<SimpleArchive> = reader
                .get::<Blob<SimpleArchive>, SimpleArchive>(withheld.data().transmute())
                .unwrap();
            let metadata: Blob<SimpleArchive> = reader.get(withheld.metadata()).unwrap();
            let text: View<str> = reader.get::<View<str>, UTF8String>(text_handle).unwrap();
            let payload: Bytes = reader.get::<Bytes, RawBytes>(payload_handle).unwrap();
            assert_eq!(content, expected_content);
            assert_eq!(metadata, expected_metadata);
            assert_eq!(&*text, "a self-contained content blob");
            assert_eq!(&*payload, &[0, 1, 2, 3, 0xFE, 0xFF]);
        }

        // Drop deliberately does not cross the visibility boundary. Explicit
        // close still succeeds and preserves only the staged dependencies.
        drop(staged);
        pile.close().unwrap();

        let mut reopened = Pile::open(&path).unwrap();
        let reader = reopened.snapshot().unwrap();
        let discovered = discover_collection_records(&reader).unwrap();
        assert!(discovered.commits().is_empty());
        assert!(!discovered
            .commits()
            .iter()
            .any(|commit| *commit == withheld));
        let descriptor_blob: Blob<SimpleArchive> =
            reader.get(identity_for_tests(&descriptor)).unwrap();
        assert_eq!(
            <TribleSet as crate::blob::TryFromBlob<SimpleArchive>>::try_from_blob(descriptor_blob)
                .unwrap(),
            *descriptor.facts()
        );
        drop(reader);
        reopened.close().unwrap();
    }

    #[test]
    fn staging_for_registered_collection_does_not_rewrite_its_descriptor() {
        let descriptor = root("attached descriptor name");
        let name_handle = descriptor_facts::name(descriptor.facts())
            .unwrap()
            .expect("root descriptor name");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let prepared = PreparedCollectionCommit::from_fragment(Fragment::empty());
        let mut store = MemoryRepo::default();
        let collection = register_collection(&mut store, &descriptor);

        let mut staged = prepared
            .stage_for(&mut store, collection, &signing_key)
            .unwrap();
        let commit = *staged.commit();
        {
            let reader = staged.store_mut().snapshot().unwrap();
            let name: View<str> = reader.get(name_handle).unwrap();
            assert_eq!(&*name, "attached descriptor name");
        }
        let snapshot = staged.store_mut().snapshot().unwrap();
        assert!(discover_collection_records(&snapshot)
            .unwrap()
            .commits()
            .is_empty());
        drop(snapshot);
        staged.finalize().unwrap();

        let snapshot = store.snapshot().unwrap();
        let discovered = discover_collection_records(&snapshot).unwrap();
        assert_eq!(discovered.commits(), &[commit]);
    }

    #[test]
    fn fragment_without_metafacts_still_stages_the_canonical_empty_metadata_archive() {
        let descriptor = root("first");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let empty_archive: Blob<SimpleArchive> = TribleSet::new().to_blob();

        let prepared = PreparedCollectionCommit::from_fragment(Fragment::empty());

        assert_eq!(prepared.metadata.get_handle(), empty_metadata_handle());
        assert_eq!(prepared.metadata, empty_archive);

        let mut store = ProbeStore::default();
        let collection = register_collection(&mut store, &descriptor);
        store.events.clear();
        let staged = prepared
            .stage_for(&mut store, collection, &signing_key)
            .unwrap();
        assert_eq!(staged.commit().metadata(), empty_metadata_handle());
        drop(staged);
        assert_eq!(
            store
                .events
                .iter()
                .filter(|event| **event == ProbeEvent::Put(empty_metadata_handle().raw))
                .count(),
            2,
            "empty data and empty metadata are both staged explicitly"
        );
    }

    #[test]
    fn staged_commit_withholds_the_record_until_finalize() {
        let descriptor = root("first");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let (fragment, _, _) = fragment_fixture();
        let prepared = PreparedCollectionCommit::from_fragment(fragment);
        let mut store = MemoryRepo::default();
        let collection = register_collection(&mut store, &descriptor);

        let mut staged = prepared
            .stage_for(&mut store, collection, &signing_key)
            .unwrap();
        let commit = *staged.commit();
        let snapshot = staged.store_mut().snapshot().unwrap();
        assert!(discover_collection_records(&snapshot)
            .unwrap()
            .commits()
            .is_empty());
        drop(snapshot);
        staged.finalize().unwrap();

        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            discover_collection_records(&snapshot).unwrap().commits(),
            &[commit]
        );
    }

    #[test]
    fn staged_finalize_insert_failure_withholds_commit() {
        let descriptor = root("first");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let prepared = PreparedCollectionCommit::from_fragment(Fragment::empty());
        // Empty data, empty metadata, then COMMIT.
        let insert_at = 3;
        let mut store = ProbeStore::default();
        let collection = register_collection(&mut store, &descriptor);
        store.events.clear();
        store.fail_at = Some(insert_at);
        let staged = prepared
            .stage_for(&mut store, collection, &signing_key)
            .unwrap();
        let commit = *staged.commit();

        assert!(matches!(
            staged.finalize(),
            Err(CollectionCommitError::RecordInsert(ProbeFailure(at))) if at == insert_at
        ));
        assert!(!store
            .records
            .contains_key(&CollectionRecord::Commit(commit)));
    }

    #[test]
    fn descriptor_and_empty_element_are_golden() {
        let descriptor = root("first");
        assert_eq!(
            <SimpleArchive as MetaDescribe>::id(),
            id_hex!("8F4A27C8581DADCBA1ADA8BA228069B6")
        );
        assert_eq!(
            crate::collection::descriptor::policy(descriptor.facts()).unwrap(),
            CollectionPolicy::new(
                crate::collection::AdmissionPolicy::direct(test_team()),
                crate::collection::AdmissionPolicy::direct(test_team()),
            )
        );
        let name = crate::collection::descriptor::name(descriptor.facts())
            .unwrap()
            .unwrap();
        let mut blobs = descriptor.blobs().clone();
        let reader = blobs.snapshot().unwrap();
        let name: View<str> = reader.get(name).unwrap();
        assert_eq!(&*name, "first");
        assert_eq!(
            IntoBlob::<SimpleArchive>::to_blob(descriptor.facts().clone()).get_handle(),
            identity_for_tests(&descriptor)
        );

        let empty: Blob<SimpleArchive> = TribleSet::new().to_blob();
        validate_element(&empty).unwrap();
        assert!(empty.bytes.is_empty());
        assert_eq!(
            empty.get_handle().raw,
            hex!("AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262")
        );
    }

    #[test]
    fn element_validation_matches_simplearchive_canonical_rules() {
        let first = row(1, 1, 1);
        let second = row(2, 1, 2);
        validate_element(&raw_archive(vec![first, second])).unwrap();
        assert_eq!(
            validate_element(&Blob::new(vec![0_u8; TRIBLE_LEN - 1].into())),
            Err(UnarchiveError::BadArchive)
        );

        let mut nil_entity = first;
        nil_entity[..16].fill(0);
        assert_eq!(
            validate_element(&raw_archive(vec![nil_entity])),
            Err(UnarchiveError::BadTrible)
        );
        assert_eq!(
            validate_element(&raw_archive(vec![first, first])),
            Err(UnarchiveError::BadCanonicalizationRedundancy)
        );
        assert_eq!(
            validate_element(&raw_archive(vec![second, first])),
            Err(UnarchiveError::BadCanonicalizationOrdering)
        );
    }

    #[test]
    fn join_obeys_empty_idempotent_commutative_and_associative_laws() {
        let empty = archive([]);
        let a = archive([row(1, 1, 1), row(3, 1, 3)]);
        let b = archive([row(2, 1, 2), row(3, 1, 3)]);
        let c = archive([row(1, 2, 4), row(4, 1, 5)]);

        assert_eq!(join(&empty, &a).unwrap(), a);
        assert_eq!(join(&a, &empty).unwrap(), a);
        assert_eq!(join(&a, &a).unwrap(), a);
        assert_eq!(join(&a, &b).unwrap(), join(&b, &a).unwrap());

        let left_associated = join(&join(&a, &b).unwrap(), &c).unwrap();
        let right_associated = join(&a, &join(&b, &c).unwrap()).unwrap();
        assert_eq!(left_associated, right_associated);
        assert_eq!(left_associated.bytes.len(), 5 * TRIBLE_LEN);
    }

    #[test]
    fn join_many_unions_overlaps_in_one_canonical_stream() {
        let empty = archive([]);
        let a = archive([row(1, 1, 1), row(3, 1, 3)]);
        let b = archive([row(2, 1, 2), row(3, 1, 3)]);
        let c = archive([row(1, 2, 4), row(4, 1, 5)]);

        assert_eq!(join_many(std::iter::empty()).unwrap(), empty);
        assert_eq!(join_many([&a]).unwrap(), a);

        let expected = join(&join(&a, &b).unwrap(), &c).unwrap();
        assert_eq!(join_many([&c, &empty, &a, &b, &a]).unwrap(), expected);
    }

    /// One canonical archive of `count` rows drawn from a deterministic
    /// sequence, so overlapping members really do share rows.
    fn strided_archive(offset: u64, stride: u64, count: usize) -> Blob<SimpleArchive> {
        let mut rows: Vec<[u8; TRIBLE_LEN]> = Vec::with_capacity(count);
        for step in 0..count as u64 {
            let key = offset + step * stride;
            let mut row = [0u8; TRIBLE_LEN];
            // A nonzero entity and attribute are what `Trible` demands; the
            // value half carries the scrambled key so the rows are spread over
            // the whole ordering rather than clustered under one prefix.
            row[8..16].copy_from_slice(&(key % 977 + 1).to_be_bytes());
            row[24..32].copy_from_slice(&(key % 31 + 1).to_be_bytes());
            let mut mixed = key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            mixed ^= mixed >> 29;
            row[32..40].copy_from_slice(&mixed.to_be_bytes());
            row[40..48].copy_from_slice(&key.to_be_bytes());
            rows.push(row);
        }
        rows.sort_unstable();
        rows.dedup();
        raw_archive(rows)
    }

    /// The union any correct implementation must produce: every input row,
    /// sorted and deduplicated by the standard library.
    fn sort_dedup_oracle(elements: &[&Blob<SimpleArchive>]) -> Vec<[u8; TRIBLE_LEN]> {
        let mut rows: Vec<[u8; TRIBLE_LEN]> = Vec::new();
        for element in elements {
            let view: View<[[u8; TRIBLE_LEN]]> = element.bytes.clone().view().unwrap();
            rows.extend_from_slice(&view);
        }
        rows.sort_unstable();
        rows.dedup();
        rows
    }

    /// The partitioned merge is a performance decision, so it owes byte
    /// identity to the answer it replaced — not merely the same set.
    ///
    /// Sizes are deliberately unequal and the strides deliberately overlap:
    /// regular sampling has to survive one member large enough to dominate the
    /// sample and duplicates dense enough to straddle a partition boundary. The
    /// row count clears `PARALLEL_MERGE_THRESHOLD` so the parallel path is the
    /// one under test.
    #[test]
    fn join_many_partitioned_merge_matches_the_sorted_oracle_byte_for_byte() {
        let big = strided_archive(0, 1, 90_000);
        let overlapping = strided_archive(0, 2, 45_000);
        let shifted = strided_archive(1, 3, 30_000);
        let disjoint = strided_archive(1_000_000, 1, 12_000);
        let tiny = strided_archive(7, 500, 3);
        let empty = archive([]);
        let elements = [&big, &overlapping, &shifted, &disjoint, &tiny, &empty];

        let expected = sort_dedup_oracle(&elements);
        assert!(
            expected.len() > PARALLEL_MERGE_THRESHOLD,
            "the fixture must clear the partitioning threshold",
        );

        let union = join_many(elements).unwrap();
        let rows: View<[[u8; TRIBLE_LEN]]> = union.bytes.clone().view().unwrap();
        assert_eq!(&rows[..], &expected[..]);

        // The serial range merge is the same function the partitions call, so
        // agreeing with it pins the partition seams specifically.
        let views: Vec<View<[[u8; TRIBLE_LEN]]>> = elements
            .iter()
            .map(|element| element.bytes.clone().view().unwrap())
            .collect();
        let slices: Vec<&[[u8; TRIBLE_LEN]]> = views.iter().map(|view| &view[..]).collect();
        assert_eq!(merge_canonical_range(&slices, None, None), expected);

        // Order of arrival cannot matter: the union is commutative.
        let shuffled = join_many([&tiny, &disjoint, &empty, &shifted, &overlapping, &big]).unwrap();
        assert_eq!(shuffled, union);
    }

    #[test]
    fn join_many_reports_the_malformed_input_position() {
        let valid = archive([row(1, 1, 1)]);
        let invalid = raw_archive(vec![row(3, 1, 3), row(2, 1, 2)]);

        assert_eq!(
            join_many([&valid, &invalid, &valid]),
            Err((1, UnarchiveError::BadCanonicalizationOrdering)),
        );
    }

    #[test]
    fn commit_validation_binds_descriptor_collection_handle_and_structure() {
        let descriptor = root("first");
        let blob = archive([row(1, 1, 1)]);
        let commit = CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            data(&blob),
            empty_metadata_handle(),
        );
        validate_commit(&descriptor, &commit, &blob).unwrap();

        let wrong_representation = test_naming(id(9));
        assert!(matches!(
            validate_commit(&wrong_representation, &commit, &blob),
            Err(SimpleArchiveUnionValidationError::WrongRepresentation { .. })
        ));

        let other_descriptor = root("second");
        assert_eq!(
            validate_commit(&other_descriptor, &commit, &blob),
            Err(SimpleArchiveUnionValidationError::WrongCollection {
                expected: identity_for_tests(&other_descriptor),
                actual: identity_for_tests(&descriptor),
            })
        );

        let other_blob = archive([row(2, 1, 2)]);
        assert!(matches!(
            validate_commit(&descriptor, &commit, &other_blob),
            Err(SimpleArchiveUnionValidationError::EndpointMismatch {
                role: ElementRole::CommitData,
                ..
            })
        ));

        let invalid = raw_archive(vec![row(2, 1, 2), row(1, 1, 1)]);
        let invalid_commit = CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            data(&invalid),
            empty_metadata_handle(),
        );
        assert_eq!(
            validate_commit(&descriptor, &invalid_commit, &invalid),
            Err(SimpleArchiveUnionValidationError::InvalidElement {
                role: ElementRole::CommitData,
                source: UnarchiveError::BadCanonicalizationOrdering,
            })
        );
    }

    #[test]
    fn merge_validation_is_exact_and_binds_every_endpoint() {
        let descriptor = root("first");
        let left = archive([row(1, 1, 1), row(3, 1, 3)]);
        let right = archive([row(2, 1, 2), row(3, 1, 3)]);
        let result = join(&left, &right).unwrap();
        let claim = CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            data(&left),
            data(&right),
            data(&result),
        );
        let (low, high) = ordered_inputs(&left, &right);
        validate_merge(&descriptor, &claim, low, high, &result).unwrap();

        let wrong_collection = CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&root("ninth")),
            data(low),
            data(high),
            data(&result),
        );
        assert!(matches!(
            validate_merge(&descriptor, &wrong_collection, low, high, &result),
            Err(SimpleArchiveUnionValidationError::WrongCollection { .. })
        ));

        assert!(matches!(
            validate_merge(&descriptor, &claim, high, low, &result),
            Err(SimpleArchiveUnionValidationError::EndpointMismatch {
                role: ElementRole::MergeLow,
                ..
            })
        ));

        let other_result = archive([row(4, 1, 4)]);
        assert!(matches!(
            validate_merge(&descriptor, &claim, low, high, &other_result),
            Err(SimpleArchiveUnionValidationError::EndpointMismatch {
                role: ElementRole::MergeResult,
                ..
            })
        ));

        let wrong_result = archive([row(1, 1, 1), row(2, 1, 2)]);
        let wrong_claim = CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            data(low),
            data(high),
            data(&wrong_result),
        );
        assert_eq!(
            validate_merge(&descriptor, &wrong_claim, low, high, &wrong_result),
            Err(SimpleArchiveUnionValidationError::WrongMergeResult)
        );

        let invalid_result = raw_archive(vec![row(2, 1, 2), row(1, 1, 1)]);
        let invalid_claim = CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            data(low),
            data(high),
            data(&invalid_result),
        );
        assert_eq!(
            validate_merge(&descriptor, &invalid_claim, low, high, &invalid_result),
            Err(SimpleArchiveUnionValidationError::InvalidElement {
                role: ElementRole::MergeResult,
                source: UnarchiveError::BadCanonicalizationOrdering,
            })
        );
    }

    #[cfg(feature = "proptest")]
    mod property_tests {
        use super::*;

        use proptest::collection::vec;
        use proptest::prelude::*;

        fn arb_trible() -> impl Strategy<Value = Trible> {
            (
                prop::array::uniform16(1_u8..=255),
                prop::array::uniform16(1_u8..=255),
                prop::array::uniform32(any::<u8>()),
            )
                .prop_map(|(entity, attribute, value)| {
                    let mut raw = [0; TRIBLE_LEN];
                    raw[..16].copy_from_slice(&entity);
                    raw[16..32].copy_from_slice(&attribute);
                    raw[32..].copy_from_slice(&value);
                    Trible::force_raw(raw).unwrap()
                })
        }

        fn arb_set(max: usize) -> impl Strategy<Value = TribleSet> {
            vec(arb_trible(), 0..max).prop_map(|tribles| {
                let mut set = TribleSet::new();
                for trible in &tribles {
                    set.insert(trible);
                }
                set
            })
        }

        proptest! {
            #[test]
            fn direct_union_matches_the_patch_oracle(
                left in arb_set(64),
                right in arb_set(64),
            ) {
                let expected: Blob<SimpleArchive> = (left.clone() + right.clone()).to_blob();
                let left: Blob<SimpleArchive> = left.to_blob();
                let right: Blob<SimpleArchive> = right.to_blob();
                let actual = join(&left, &right).unwrap();

                prop_assert_eq!(&actual, &expected);
                let collection = root("first");
                let claim = CollectionMerge::sign(&ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    identity_for_tests(&collection),
                    data(&left),
                    data(&right),
                    data(&actual),
                );
                let (low, high) = ordered_inputs(&left, &right);
                prop_assert!(validate_merge(&collection, &claim, low, high, &actual).is_ok());
                prop_assert_eq!(actual, join(&right, &left).unwrap());
            }

            #[test]
            fn direct_union_obeys_identity_and_aci(
                a in arb_set(32),
                b in arb_set(32),
                c in arb_set(32),
            ) {
                let empty: Blob<SimpleArchive> = TribleSet::new().to_blob();
                let a: Blob<SimpleArchive> = a.to_blob();
                let b: Blob<SimpleArchive> = b.to_blob();
                let c: Blob<SimpleArchive> = c.to_blob();

                prop_assert_eq!(join(&empty, &a).unwrap(), a.clone());
                prop_assert_eq!(join(&a, &empty).unwrap(), a.clone());
                prop_assert_eq!(join(&a, &a).unwrap(), a.clone());
                prop_assert_eq!(join(&a, &b).unwrap(), join(&b, &a).unwrap());

                let left_associated = join(&join(&a, &b).unwrap(), &c).unwrap();
                let right_associated = join(&a, &join(&b, &c).unwrap()).unwrap();
                prop_assert_eq!(left_associated, right_associated);
            }
        }
    }
}

impl From<RecordDecodeError> for SimpleArchiveUnionValidationError {
    fn from(error: RecordDecodeError) -> Self {
        Self::Malformed(error)
    }
}
