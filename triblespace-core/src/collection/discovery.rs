//! Discovery over native collection-record storage.
//!
//! A [`CollectionRead`](super::CollectionRead) snapshot is responsible for
//! decoding its physical representation into structurally canonical typed
//! records.
//! Discovery therefore performs no blob-store scan and has no malformed-record
//! recovery path: a structural storage failure is fatal. Signature verification
//! belongs to untrusted ingress, not repeated snapshot reads. Discovery selects
//! and classifies the local store's records; admission remains a separate
//! snapshot-dependent decision.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::UnknownBlob;
use crate::inline::encodings::ed25519::ED25519PublicKey;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::repo::{BlobStoreList, StoreRead};

use super::{
    CollectionCommit, CollectionDerive, CollectionEncoding, CollectionHandle, CollectionMerge,
    CollectionRead, CollectionRecord, CollectionRecordSelector, Cover,
};

/// Structurally canonical records from one trusted store enumeration.
///
/// Every collection is sorted by its exact canonical record value. The
/// result therefore does not expose backend enumeration or append order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveredCollectionRecords {
    commits: Vec<CollectionCommit>,
    merges: Vec<CollectionMerge>,
    derives: Vec<CollectionDerive>,
}

impl DiscoveredCollectionRecords {
    pub(crate) fn from_records(records: impl IntoIterator<Item = CollectionRecord>) -> Self {
        let mut discovered = Self::default();
        for record in records {
            match record {
                CollectionRecord::Commit(record) => discovered.commits.push(record),
                CollectionRecord::Merge(record) => discovered.merges.push(record),
                CollectionRecord::Derive(record) => discovered.derives.push(record),
            }
        }
        discovered.canonicalize();
        discovered
    }

    /// Locally trusted signed commits, ordered canonically.
    ///
    /// Signature validity does not authorize the signing key. Callers apply
    /// local authorization policy before treating a commit as a membership
    /// root.
    pub fn commits(&self) -> &[CollectionCommit] {
        &self.commits
    }

    /// Locally trusted signed merge claims, ordered canonically.
    pub fn merges(&self) -> &[CollectionMerge] {
        &self.merges
    }

    /// Locally trusted signed derive claims, ordered canonically.
    pub fn derives(&self) -> &[CollectionDerive] {
        &self.derives
    }

    fn canonicalize(&mut self) {
        self.commits.sort_unstable();
        self.commits.dedup();
        self.merges.sort_unstable();
        self.merges.dedup();
        self.derives.sort_unstable();
        self.derives.dedup();
    }
}

/// A native-store failure that prevents one complete record enumeration.
#[derive(Debug)]
pub enum CollectionDiscoveryError<RecordsError> {
    /// The store could not start or complete record enumeration.
    Records(RecordsError),
    /// The snapshot could not supply this collection's WRITE policy/evidence.
    Admission {
        /// Exact descriptor whose equation producers were being admitted.
        collection: CollectionHandle,
        /// Descriptor or proof-store observation failure.
        source: Box<dyn Error + Send + Sync + 'static>,
    },
    /// The frozen blob index could not answer direct-reference residency.
    Residency {
        /// Exact direct reference whose residency was being inspected.
        reference: Inline<Handle<UnknownBlob>>,
        /// Backend observation failure.
        source: Box<dyn Error + Send + Sync + 'static>,
    },
}

impl<RecordsError> fmt::Display for CollectionDiscoveryError<RecordsError>
where
    RecordsError: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Records(error) => write!(f, "failed to enumerate collection records: {error}"),
            Self::Admission { collection, source } => write!(
                f,
                "failed to observe equation admission for {}: {source}",
                hex::encode_upper(collection.raw),
            ),
            Self::Residency { reference, source } => write!(
                f,
                "failed to inspect resident collection-record reference {}: {source}",
                hex::encode_upper(reference.raw),
            ),
        }
    }
}

impl<RecordsError> Error for CollectionDiscoveryError<RecordsError>
where
    RecordsError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Records(error) => Some(error),
            Self::Admission { source, .. } => Some(source.as_ref()),
            Self::Residency { source, .. } => Some(source.as_ref()),
        }
    }
}

/// Discover native records without repeating ingress signature verification.
///
/// The store owns physical decoding and returns only structurally canonical
/// [`CollectionRecord`] values. Any failure to begin or continue enumeration
/// aborts discovery rather than turning storage corruption into a partial
/// semantic view. The local store is trusted to contain signatures checked at
/// ingress or produced locally. Callers still choose which signing keys may
/// introduce membership roots and equations. An explicit audit can recheck
/// each record with [`CollectionRecord::verify_strict`].
pub fn discover_collection_records<S>(
    snapshot: &S,
) -> Result<DiscoveredCollectionRecords, CollectionDiscoveryError<S::RecordsError>>
where
    S: CollectionRead,
{
    let mut discovered = DiscoveredCollectionRecords::default();
    let records = snapshot
        .records()
        .map_err(CollectionDiscoveryError::Records)?;

    for record in records {
        let record = record.map_err(CollectionDiscoveryError::Records)?;
        match record {
            CollectionRecord::Commit(record) => discovered.commits.push(record),
            CollectionRecord::Merge(record) => discovered.merges.push(record),
            CollectionRecord::Derive(record) => discovered.derives.push(record),
        }
    }

    discovered.canonicalize();
    Ok(discovered)
}

/// Discover same-lattice equations that may physically realize one cover.
///
/// Caller-supplied hashes are payload coordinates, not provenance claims.
/// Current WRITE producers supply trusted mathematical MERGE equations;
/// their exact same-collection MERGE witnesses inherit that endorsement.
/// COMMIT/DERIVE ancestry is deliberately unnecessary for this raw algebra.
pub(crate) fn discover_collection_equations_for_cover<S, L>(
    snapshot: &S,
    cover: &Cover<L>,
) -> Result<DiscoveredCollectionRecords, CollectionDiscoveryError<S::RecordsError>>
where
    S: StoreRead,
    L: CollectionEncoding,
{
    let collection = cover.collection().handle();
    let descriptor =
        super::api::load_collection_descriptor(snapshot, collection).map_err(|source| {
            CollectionDiscoveryError::Admission {
                collection,
                source: Box::new(source),
            }
        })?;
    let evidence = super::api::discover_admission_evidence(
        snapshot,
        super::descriptor::admission_policies(
            snapshot,
            descriptor.fragment.facts(),
            super::ACTION_WRITE,
            Some(L::id()),
        ),
        super::ACTION_WRITE,
        collection,
    )
    .map_err(|source| CollectionDiscoveryError::Admission {
        collection,
        source: Box::new(source),
    })?;
    let selectors = BTreeSet::from([CollectionRecordSelector::MergeCollection(collection)]);
    let mut discovered =
        discover_collection_records_for_cover_selectors(snapshot, cover, &selectors)?;
    let mut admitted = std::collections::BTreeMap::new();
    discovered.merges.retain(|record| {
        *admitted.entry(record.public_key().raw).or_insert_with(|| {
            ed25519_dalek::VerifyingKey::from_bytes(&record.public_key().raw)
                .ok()
                .is_some_and(|subject| evidence.authorizes(snapshot, subject))
        })
    });

    let mut pending = discovered.merges.clone();
    let mut seen: BTreeSet<_> = pending.iter().map(CollectionMerge::fingerprint).collect();
    // A merge names its input PAYLOADS, so its predecessors are whatever
    // produces them here. The cited form looked a fingerprint up and then
    // checked the record was in this collection and produced this input --
    // which is what `ProducedMember` is keyed on, so ask it directly. Every
    // producer enters rather than only the one cited; admission was never
    // re-checked on predecessors either way.
    while let Some(merge) = pending.pop() {
        let (low, high) = merge.inputs();
        for input in [low, high] {
            let producers = snapshot
                .select_records(&BTreeSet::from([CollectionRecordSelector::ProducedMember(
                    collection, input,
                )]))
                .map_err(CollectionDiscoveryError::Records)?;
            for record in producers {
                let CollectionRecord::Merge(predecessor) = record else {
                    continue;
                };
                if seen.insert(predecessor.fingerprint()) {
                    discovered.merges.push(predecessor);
                    pending.push(predecessor);
                }
            }
        }
    }
    discovered.canonicalize();
    Ok(discovered)
}

/// Discover every strictly signed provenance claim currently known for one
/// exact payload cover.
pub(crate) fn discover_collection_claims_for_cover<S, L>(
    snapshot: &S,
    cover: &Cover<L>,
) -> Result<DiscoveredCollectionRecords, CollectionDiscoveryError<S::RecordsError>>
where
    S: BlobStoreList + CollectionRead,
    L: CollectionEncoding,
{
    let selectors: BTreeSet<_> = cover
        .data_members()
        .map(|member| CollectionRecordSelector::CommitMember(cover.collection().handle(), member))
        .collect();
    discover_collection_records_for_cover_selectors(snapshot, cover, &selectors)
}

fn discover_collection_records_for_cover_selectors<S, L>(
    snapshot: &S,
    cover: &Cover<L>,
    selectors: &BTreeSet<CollectionRecordSelector>,
) -> Result<DiscoveredCollectionRecords, CollectionDiscoveryError<S::RecordsError>>
where
    S: BlobStoreList + CollectionRead,
    L: CollectionEncoding,
{
    let mut discovered = DiscoveredCollectionRecords::default();
    let mut matching_commits = Vec::new();
    let records = snapshot
        .select_records(selectors)
        .map_err(CollectionDiscoveryError::Records)?;

    for record in records {
        match record {
            CollectionRecord::Commit(record)
                if record.collection() == cover.collection().handle()
                    && cover.contains_data(record.data()) =>
            {
                matching_commits.push(record);
            }
            CollectionRecord::Commit(_) => {}
            CollectionRecord::Merge(record) => discovered.merges.push(record),
            CollectionRecord::Derive(record) => discovered.derives.push(record),
        }
    }

    discovered.commits = matching_commits;
    discovered.canonicalize();
    Ok(discovered)
}

/// Discover records for one exact collection and one exact supplied signer.
///
/// The local store has already established signature validity. This scope
/// selects provenance, not authorization, and performs no cryptographic work.
///
/// `MERGE` and `DERIVE` records are retained in full. Their relevance can span
/// collection boundaries; the resolver's policy decides which equations are
/// admitted, independently of this provenance scope.
/// Physical decoding remains the store's responsibility: a malformed record
/// or iteration failure is fatal even when it appears outside the requested
/// commit scope.
pub fn discover_collection_records_scoped<S>(
    snapshot: &S,
    collection: CollectionHandle,
    signer: Inline<ED25519PublicKey>,
) -> Result<DiscoveredCollectionRecords, CollectionDiscoveryError<S::RecordsError>>
where
    S: CollectionRead,
{
    let mut discovered = DiscoveredCollectionRecords::default();
    let mut matching_commits = Vec::new();
    let records = snapshot
        .records()
        .map_err(CollectionDiscoveryError::Records)?;

    for record in records {
        let record = record.map_err(CollectionDiscoveryError::Records)?;
        match record {
            CollectionRecord::Commit(record)
                if record.collection() == collection && record.public_key() == signer =>
            {
                matching_commits.push(record)
            }
            CollectionRecord::Commit(_) => {}
            CollectionRecord::Merge(record) => discovered.merges.push(record),
            CollectionRecord::Derive(record) => discovered.derives.push(record),
        }
    }

    discovered.commits = matching_commits;

    discovered.canonicalize();
    Ok(discovered)
}

/// Discover records for one exact collection across every caller-admitted signer.
///
/// This is the multi-author counterpart of
/// [`discover_collection_records_scoped`]. That function fixes one
/// caller-supplied signer; this one asks `is_member` for each claimed signer.
/// The predicate supplies current WRITE admission for every kind of signed
/// record in this collection. Signature validity was established at ingress;
/// a record can be stored before its proof arrives and become admitted in a
/// later snapshot. Records outside this collection are not authorized by this
/// callback and are excluded.
pub(crate) fn discover_collection_records_authorized<S, F>(
    snapshot: &S,
    collection: CollectionHandle,
    mut is_member: F,
) -> Result<DiscoveredCollectionRecords, CollectionDiscoveryError<S::RecordsError>>
where
    S: BlobStoreList + CollectionRead,
    F: FnMut(&Inline<ED25519PublicKey>) -> bool,
{
    let mut discovered = DiscoveredCollectionRecords::default();
    let mut matching_commits = Vec::new();
    let selectors = BTreeSet::from([CollectionRecordSelector::Collection(collection)]);
    let records = snapshot
        .select_records(&selectors)
        .map_err(CollectionDiscoveryError::Records)?;

    for record in records {
        if record.collection() != collection || !is_member(&record.public_key()) {
            continue;
        }
        match record {
            CollectionRecord::Commit(record) => matching_commits.push(record),
            CollectionRecord::Merge(record) => discovered.merges.push(record),
            CollectionRecord::Derive(record) => discovered.derives.push(record),
        }
    }

    discovered.commits = matching_commits;

    discovered.canonicalize();
    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    use anybytes::Bytes;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::encodings::UnknownBlob;
    use crate::blob::{BlobEncoding, IntoBlob};
    use crate::collection::{
        empty_metadata_handle, AdmissionPolicy, Collection, CollectionData, CollectionPolicy,
        CollectionSnapshotExt, CollectionStore, CollectionStoreExt, Support,
    };
    use crate::inline::encodings::hash::Handle;
    use crate::inline::{Inline, InlineEncoding};
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::pile::{Pile, PileSnapshot};
    use crate::repo::{BlobInfo, BlobStorePut, SnapshotSource};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProbeRecordsError(&'static str);

    impl fmt::Display for ProbeRecordsError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for ProbeRecordsError {}

    #[derive(Default)]
    struct ProbeStore {
        start_error: Option<ProbeRecordsError>,
        records: Vec<Result<CollectionRecord, ProbeRecordsError>>,
    }

    impl CollectionRead for ProbeStore {
        type RecordsError = ProbeRecordsError;
        type RecordIter<'a> = std::vec::IntoIter<Result<CollectionRecord, Self::RecordsError>>;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            if let Some(error) = self.start_error {
                return Err(error);
            }
            Ok(self.records.clone().into_iter())
        }
    }

    struct IndexedSelectionProbe {
        snapshot: PileSnapshot,
        collection: CollectionHandle,
        enumerations: Cell<usize>,
        selections: Cell<usize>,
        selected_records: Cell<usize>,
    }

    impl CollectionRead for IndexedSelectionProbe {
        type RecordsError = <PileSnapshot as CollectionRead>::RecordsError;
        type RecordIter<'a> = <PileSnapshot as CollectionRead>::RecordIter<'a>;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            self.enumerations.set(self.enumerations.get() + 1);
            self.snapshot.records()
        }

        fn select_records(
            &self,
            selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
            assert_eq!(
                selectors,
                &BTreeSet::from([CollectionRecordSelector::Collection(self.collection)]),
            );
            self.selections.set(self.selections.get() + 1);
            let records = self.snapshot.select_records(selectors)?;
            self.selected_records
                .set(self.selected_records.get() + records.len());
            Ok(records)
        }
    }

    impl BlobStoreList for IndexedSelectionProbe {
        type Iter<'a> = <PileSnapshot as BlobStoreList>::Iter<'a>;
        type Err = <PileSnapshot as BlobStoreList>::Err;

        fn blobs<'a>(&'a self) -> Self::Iter<'a> {
            self.snapshot.blobs()
        }

        fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
        where
            S: BlobEncoding + 'static,
            Handle<S>: InlineEncoding,
        {
            self.snapshot.contains_blob(handle)
        }

        fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
        where
            S: BlobEncoding + 'static,
            Handle<S>: InlineEncoding,
        {
            self.snapshot.blob_info(handle)
        }
    }

    fn data(byte: u8) -> CollectionData {
        Inline::new([byte; 32])
    }

    // Discovery indexes stored records; it does not interpret witness closure.
    fn witnessed_input(
        collection: CollectionHandle,
        data: CollectionData,
    ) -> (
        CollectionData,
        crate::collection::CollectionRecordFingerprint,
    ) {
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            collection,
            data,
            empty_metadata_handle(),
        ));
        (data, record.fingerprint())
    }

    fn member(byte: u8) -> Inline<Handle<SimpleArchive>> {
        Inline::new([byte; 32])
    }

    fn collection(byte: u8) -> Collection<SimpleArchive> {
        Collection::from_handle(Inline::new([byte; 32]))
    }

    fn signer(key: &SigningKey) -> Inline<ED25519PublicKey> {
        Inline::new(key.verifying_key().to_bytes())
    }

    fn invalid_signature(commit: CollectionCommit) -> CollectionCommit {
        let (r, mut s) = commit.signature();
        s.raw[0] ^= 1;
        CollectionCommit::from_parts(
            commit.collection(),
            commit.data(),
            commit.metadata(),
            commit.public_key(),
            r,
            s,
        )
    }

    #[test]
    fn cover_additions_are_payload_set_difference() {
        let target = collection(1);
        let previous = Support::from_members(target, [member(2), member(1), member(1)]);
        let current = Support::from_members(target, [member(3), member(1), member(2), member(3)]);

        let additions = current.additions_since(&previous).unwrap();
        assert_eq!(additions.members().collect::<Vec<_>>(), vec![member(3)]);
        assert!(current.additions_since(&current).unwrap().is_empty());
    }

    #[test]
    fn cover_additions_reject_shrink_and_cross_collection() {
        let first = Support::from_members(collection(1), [member(1)]);
        let empty = Support::from_members(collection(1), []);
        assert_eq!(
            empty.additions_since(&first),
            Err(crate::collection::CoverAdvanceError::ResetRequired { missing: data(1) })
        );

        let foreign = Support::from_members(collection(2), [member(1)]);
        assert_eq!(
            foreign.additions_since(&first),
            Err(crate::collection::CoverAdvanceError::DifferentCollection {
                previous: collection(1).handle(),
                current: collection(2).handle(),
            })
        );
    }

    #[test]
    fn cover_algebra_is_checked_and_patch_backed() {
        let target = collection(1);
        let left = Support::from_members(target, [member(1), member(2)]);
        let right = Support::from_members(target, [member(2), member(3)]);

        assert_eq!(
            left.union(&right).unwrap().members().collect::<Vec<_>>(),
            vec![member(1), member(2), member(3)],
        );
        assert_eq!(
            left.intersection(&right)
                .unwrap()
                .members()
                .collect::<Vec<_>>(),
            vec![member(2)],
        );
        assert_eq!(
            left.difference(&right)
                .unwrap()
                .members()
                .collect::<Vec<_>>(),
            vec![member(1)],
        );
        assert!(left.intersection(&right).unwrap().is_subset(&left).unwrap());
        assert!(!left.is_subset(&right).unwrap());

        let foreign = Support::from_members(collection(2), [member(1)]);
        assert_eq!(
            left.union(&foreign),
            Err(crate::collection::CoverAlgebraError::DifferentCollection {
                left: collection(1).handle(),
                right: collection(2).handle(),
            }),
        );
        assert!(left.intersection(&foreign).is_err());
        assert!(left.difference(&foreign).is_err());
        assert!(left.is_subset(&foreign).is_err());
    }

    #[test]
    fn endorsed_output_arrival_changes_only_later_snapshots() {
        use crate::blob::encodings::succinctarchive::{
            OrderedUniverse, SuccinctArchiveBlob, UnionArchive,
        };
        let mut store = MemoryRepo::default();
        let source = store
            .collection(
                "dangling-equations",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let target = store
            .derive::<SuccinctArchiveBlob>(
                source,
                (),
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let a = crate::prelude::entity! { crate::metadata::name: "a" };
        let b = crate::prelude::entity! { crate::metadata::name: "b" };
        let joined = crate::collection::simplearchive_union::join(
            &a.facts().clone().to_blob(),
            &b.facts().clone().to_blob(),
        )
        .unwrap();
        let output = crate::collection::succinctarchive_union::derive_element(&joined).unwrap();
        let ca = store.commit(source, &key, a).unwrap();
        let cb = store.commit(source, &key, b).unwrap();
        let merge = CollectionRecord::Merge(CollectionMerge::sign(
            &key,
            source.handle(),
            (ca.data(), CollectionRecord::Commit(ca).fingerprint()),
            (cb.data(), CollectionRecord::Commit(cb).fingerprint()),
            Handle::<SimpleArchive>::to_hash(joined.get_handle()),
        ));
        let derive = CollectionRecord::Derive(CollectionDerive::sign(
            &key,
            target.handle(),
            (
                Handle::<SimpleArchive>::to_hash(joined.get_handle()),
                merge.fingerprint(),
            ),
            Handle::<SuccinctArchiveBlob>::to_hash(output.get_handle()),
        ));
        store.insert(merge).unwrap();
        store.insert(derive).unwrap();

        let before = store.snapshot().unwrap();
        let raw = discover_collection_records(&before).unwrap();
        assert_eq!(raw.merges().len(), 1);
        assert_eq!(raw.derives().len(), 1);
        assert!(before.collection(target).unwrap().cover().is_empty());

        // Only the selected output arrives. Its source MERGE payload need
        // not become resident to read the exact endorsed witness route.
        store.put::<SuccinctArchiveBlob, _>(output).unwrap();
        let after = store.snapshot().unwrap();
        let attached = after.collection(target).unwrap();
        assert_eq!(attached.cover().len(), 1);
        assert_eq!(attached.support().unwrap().len(), 2);
        assert_eq!(
            attached
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .count(),
            2
        );
        assert!(!after.contains_blob(joined.get_handle()).unwrap());
        assert!(before.collection(target).unwrap().cover().is_empty());
    }


    /// Support names the foundation commits underneath a derived image.
    ///
    /// Two commits joined and then projected into a derived collection — the
    /// shape every derived lattice is made of. This once compared `support()`
    /// against a fold to show the index could replace the witness walk; that
    /// comparison went circular the moment `support()` started reading the
    /// index, so it asserts the expected members directly instead. The
    /// evidence that the swap preserved behaviour is the unchanged suite
    /// across it, not this test.
    #[test]
    fn support_names_the_commits_under_a_derived_image() {
        use crate::blob::encodings::succinctarchive::SuccinctArchiveBlob;
        use crate::collection::coverage::coverage_of;

        let mut store = MemoryRepo::default();
        let source = store
            .collection(
                "coverage-equivalence",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let target = store
            .derive::<SuccinctArchiveBlob>(
                source,
                (),
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let a = crate::prelude::entity! { crate::metadata::name: "a" };
        let b = crate::prelude::entity! { crate::metadata::name: "b" };
        let joined = crate::collection::simplearchive_union::join(
            &a.facts().clone().to_blob(),
            &b.facts().clone().to_blob(),
        )
        .unwrap();
        let output = crate::collection::succinctarchive_union::derive_element(&joined).unwrap();
        let ca = store.commit(source, &key, a).unwrap();
        let cb = store.commit(source, &key, b).unwrap();
        let merged = Handle::<SimpleArchive>::to_hash(joined.get_handle());
        let derived = Handle::<SuccinctArchiveBlob>::to_hash(output.get_handle());
        let merge = CollectionRecord::Merge(CollectionMerge::sign(
            &key,
            source.handle(),
            (ca.data(), CollectionRecord::Commit(ca).fingerprint()),
            (cb.data(), CollectionRecord::Commit(cb).fingerprint()),
            merged,
        ));
        let derive = CollectionRecord::Derive(CollectionDerive::sign(
            &key,
            target.handle(),
            (merged, merge.fingerprint()),
            derived,
        ));
        store.insert(merge).unwrap();
        store.insert(derive).unwrap();
        store.put::<SuccinctArchiveBlob, _>(output).unwrap();

        let snapshot = store.snapshot().unwrap();
        let attached = snapshot.collection(target).unwrap();
        let support: Vec<_> = attached
            .support()
            .unwrap()
            .data_members()
            .map(|member| member.raw)
            .collect();
        let expected = {
            let mut both = vec![ca.data().raw, cb.data().raw];
            both.sort();
            both
        };
        assert_eq!(support, expected);

        // Cover members are nodes in the target; the merge they come from is
        // a node in the source. Each is asked in its own collection, and the
        // merge result covers the same two commits without a walk.
        let index = coverage_of(&snapshot).unwrap();
        let (folded, unattested) = index
            .published()
            .union_over(target.handle(), attached.cover().data_members());
        assert!(unattested.is_empty(), "every cover member has a row");
        assert_eq!(folded.iter_ordered().copied().collect::<Vec<_>>(), expected);
        assert_eq!(
            index.coverage(source.handle(), merged).map(|row| row.len()),
            Some(2)
        );
    }

    fn fixture_records() -> (Vec<CollectionRecord>, CollectionCommit) {
        let commit = CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            collection(1).handle(),
            data(4),
            empty_metadata_handle(),
        );
        let merge = CollectionMerge::sign(
            &SigningKey::from_bytes(&[7; 32]),
            collection(1).handle(),
            (data(4), CollectionRecord::Commit(commit).fingerprint()),
            witnessed_input(collection(1).handle(), data(5)),
            data(6),
        );
        let derive = CollectionDerive::sign(
            &SigningKey::from_bytes(&[7; 32]),
            collection(7).handle(),
            (data(4), CollectionRecord::Commit(commit).fingerprint()),
            data(8),
        );

        let invalid_commit = invalid_signature(commit);

        (
            vec![
                CollectionRecord::Commit(commit),
                CollectionRecord::Merge(merge),
                CollectionRecord::Derive(derive),
                CollectionRecord::Commit(invalid_commit),
            ],
            invalid_commit,
        )
    }

    #[test]
    fn authorized_discovery_uses_the_collection_index_without_enumerating_other_records() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut store = Pile::open(file.path()).unwrap();
        let target = store
            .collection(
                "authorized-selection",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let other = store
            .collection(
                "unrelated-selection",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let authorized_key = SigningKey::from_bytes(&[7; 32]);
        let foreign_key = SigningKey::from_bytes(&[8; 32]);
        let metadata = store
            .put::<SimpleArchive, _>(crate::trible::TribleSet::new())
            .unwrap();
        let low = Handle::<UnknownBlob>::to_hash(
            store
                .put::<UnknownBlob, _>(Bytes::from_source(b"low".to_vec()))
                .unwrap(),
        );
        let high = Handle::<UnknownBlob>::to_hash(
            store
                .put::<UnknownBlob, _>(Bytes::from_source(b"high".to_vec()))
                .unwrap(),
        );
        let output = Handle::<UnknownBlob>::to_hash(
            store
                .put::<UnknownBlob, _>(Bytes::from_source(b"output".to_vec()))
                .unwrap(),
        );
        let commit = CollectionCommit::sign(&authorized_key, target.handle(), low, metadata);
        // Trusted native discovery must not add a signature audit to its
        // author checks; payload residency is a separate physical projection.
        let trusted_invalid = invalid_signature(commit);
        let merge = CollectionMerge::sign(
            &authorized_key,
            target.handle(),
            (low, CollectionRecord::Commit(commit).fingerprint()),
            witnessed_input(target.handle(), high),
            output,
        );
        let derive = CollectionDerive::sign(
            &authorized_key,
            target.handle(),
            (low, CollectionRecord::Commit(commit).fingerprint()),
            output,
        );
        let unauthorized = CollectionCommit::sign(&foreign_key, target.handle(), high, metadata);
        let dangling = CollectionCommit::sign(&authorized_key, target.handle(), data(99), metadata);
        for record in [
            CollectionRecord::Commit(commit),
            CollectionRecord::Commit(trusted_invalid),
            CollectionRecord::Merge(merge),
            CollectionRecord::Derive(derive),
            CollectionRecord::Commit(unauthorized),
            CollectionRecord::Commit(dangling),
        ] {
            store.insert(record).unwrap();
        }
        for byte in 0..64 {
            store
                .insert(CollectionRecord::Commit(CollectionCommit::sign(
                    &foreign_key,
                    other.handle(),
                    data(byte),
                    metadata,
                )))
                .unwrap();
        }
        let probe = IndexedSelectionProbe {
            snapshot: store.snapshot().unwrap(),
            collection: target.handle(),
            enumerations: Cell::new(0),
            selections: Cell::new(0),
            selected_records: Cell::new(0),
        };
        let mut authorization_checks = 0;
        let discovered =
            discover_collection_records_authorized(&probe, target.handle(), |public_key| {
                authorization_checks += 1;
                *public_key == signer(&authorized_key)
            })
            .unwrap();

        let mut expected_commits = vec![commit, trusted_invalid, dangling];
        expected_commits.sort_unstable();
        assert_eq!(discovered.commits(), expected_commits);
        assert_eq!(discovered.merges(), &[merge]);
        assert_eq!(discovered.derives(), &[derive]);
        assert_eq!(probe.enumerations.get(), 0);
        assert_eq!(probe.selections.get(), 1);
        assert_eq!(probe.selected_records.get(), 6);
        assert_eq!(authorization_checks, 6);
    }

    #[test]
    fn trusted_native_records_are_classified_without_repeating_signature_checks() {
        let (records, invalid_commit) = fixture_records();
        let forward = ProbeStore {
            records: records.iter().copied().map(Ok).collect(),
            ..ProbeStore::default()
        };
        let reverse = ProbeStore {
            records: records.iter().rev().copied().map(Ok).collect(),
            ..ProbeStore::default()
        };

        let forward_records = discover_collection_records(&forward).unwrap();
        let reverse_records = discover_collection_records(&reverse).unwrap();

        assert_eq!(forward_records, reverse_records);
        assert_eq!(forward_records.commits().len(), 2);
        assert_eq!(forward_records.merges().len(), 1);
        assert_eq!(forward_records.derives().len(), 1);
        // A trusted backend bypasses foreign ingress here on purpose. This
        // distinguishes ordinary discovery from an explicit signature audit.
        assert!(forward_records.commits().contains(&invalid_commit));
        assert!(invalid_commit.verify_strict().is_err());
    }

    #[test]
    fn scoped_discovery_selects_provenance_without_reauditing_local_records() {
        let target = collection(1);
        let other = collection(2);
        let authorized_key = SigningKey::from_bytes(&[7; 32]);
        let foreign_key = SigningKey::from_bytes(&[8; 32]);
        let valid = CollectionCommit::sign(
            &authorized_key,
            target.handle(),
            data(1),
            empty_metadata_handle(),
        );
        let relevant_invalid = invalid_signature(CollectionCommit::sign(
            &authorized_key,
            target.handle(),
            data(2),
            empty_metadata_handle(),
        ));
        let wrong_collection = invalid_signature(CollectionCommit::sign(
            &authorized_key,
            other.handle(),
            data(3),
            empty_metadata_handle(),
        ));
        let wrong_signer = invalid_signature(CollectionCommit::sign(
            &foreign_key,
            target.handle(),
            data(4),
            empty_metadata_handle(),
        ));
        let target_merge = CollectionMerge::sign(
            &SigningKey::from_bytes(&[7; 32]),
            target.handle(),
            (data(1), CollectionRecord::Commit(valid).fingerprint()),
            (
                data(2),
                CollectionRecord::Commit(relevant_invalid).fingerprint(),
            ),
            data(5),
        );
        let other_merge = CollectionMerge::sign(
            &SigningKey::from_bytes(&[7; 32]),
            other.handle(),
            witnessed_input(other.handle(), data(3)),
            witnessed_input(other.handle(), data(4)),
            data(6),
        );
        let crossing_derive = CollectionDerive::sign(
            &SigningKey::from_bytes(&[7; 32]),
            other.handle(),
            (data(5), CollectionRecord::Merge(target_merge).fingerprint()),
            data(6),
        );

        let store = ProbeStore {
            records: [
                CollectionRecord::Commit(wrong_signer),
                CollectionRecord::Merge(other_merge),
                CollectionRecord::Commit(relevant_invalid),
                CollectionRecord::Derive(crossing_derive),
                CollectionRecord::Commit(valid),
                CollectionRecord::Commit(wrong_collection),
                CollectionRecord::Merge(target_merge),
            ]
            .into_iter()
            .map(Ok)
            .collect(),
            ..ProbeStore::default()
        };

        let discovered =
            discover_collection_records_scoped(&store, target.handle(), signer(&authorized_key))
                .unwrap();

        assert_eq!(discovered.commits().len(), 2);
        assert!(discovered.commits().contains(&valid));
        assert!(discovered.commits().contains(&relevant_invalid));
        assert_eq!(discovered.merges().len(), 2);
        assert!(discovered.merges().contains(&target_merge));
        assert!(discovered.merges().contains(&other_merge));
        assert_eq!(discovered.derives(), &[crossing_derive]);
    }

    #[test]
    fn scoped_discovery_is_an_opaque_key_selection_not_admission() {
        let target = collection(1);
        let mut invalid_signer_bytes = [0; 32];
        invalid_signer_bytes[0] = 2;
        let invalid_signer = Inline::new(invalid_signer_bytes);
        assert!(VerifyingKey::from_bytes(&invalid_signer.raw).is_err());

        let template = CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            target.handle(),
            data(1),
            empty_metadata_handle(),
        );
        let (r, s) = template.signature();
        let invalid_key_commit = CollectionCommit::from_parts(
            target.handle(),
            template.data(),
            template.metadata(),
            invalid_signer,
            r,
            s,
        );
        let store = ProbeStore {
            records: vec![Ok(CollectionRecord::Commit(invalid_key_commit))],
            ..ProbeStore::default()
        };

        let discovered =
            discover_collection_records_scoped(&store, target.handle(), invalid_signer).unwrap();
        assert_eq!(discovered.commits(), &[invalid_key_commit]);
        assert!(invalid_key_commit.verify_strict().is_err());
    }

    #[test]
    fn scoped_discovery_equals_full_discovery_projected_to_valid_matching_commits() {
        let target = collection(1);
        let other = collection(2);
        let authorized_key = SigningKey::from_bytes(&[7; 32]);
        let foreign_key = SigningKey::from_bytes(&[8; 32]);
        let matching = [
            CollectionCommit::sign(
                &authorized_key,
                target.handle(),
                data(1),
                empty_metadata_handle(),
            ),
            CollectionCommit::sign(
                &authorized_key,
                target.handle(),
                data(2),
                empty_metadata_handle(),
            ),
        ];
        let records = vec![
            CollectionRecord::Commit(CollectionCommit::sign(
                &foreign_key,
                target.handle(),
                data(3),
                empty_metadata_handle(),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &SigningKey::from_bytes(&[7; 32]),
                other.handle(),
                witnessed_input(other.handle(), data(3)),
                witnessed_input(other.handle(), data(4)),
                data(5),
            )),
            CollectionRecord::Commit(matching[1]),
            CollectionRecord::Derive(CollectionDerive::sign(
                &SigningKey::from_bytes(&[7; 32]),
                target.handle(),
                witnessed_input(other.handle(), data(5)),
                data(2),
            )),
            CollectionRecord::Commit(CollectionCommit::sign(
                &authorized_key,
                other.handle(),
                data(4),
                empty_metadata_handle(),
            )),
            CollectionRecord::Commit(matching[0]),
            CollectionRecord::Merge(CollectionMerge::sign(
                &SigningKey::from_bytes(&[7; 32]),
                target.handle(),
                (data(1), CollectionRecord::Commit(matching[0]).fingerprint()),
                (data(2), CollectionRecord::Commit(matching[1]).fingerprint()),
                data(6),
            )),
        ];
        let full_store = ProbeStore {
            records: records.iter().copied().map(Ok).collect(),
            ..ProbeStore::default()
        };
        let scoped_store = ProbeStore {
            records: records.into_iter().map(Ok).collect(),
            ..ProbeStore::default()
        };

        let full = discover_collection_records(&full_store).unwrap();
        let scoped = discover_collection_records_scoped(
            &scoped_store,
            target.handle(),
            signer(&authorized_key),
        )
        .unwrap();
        let expected_commits: Vec<_> = full
            .commits()
            .iter()
            .copied()
            .filter(|commit| {
                commit.collection() == target.handle()
                    && commit.public_key() == signer(&authorized_key)
            })
            .collect();

        assert_eq!(scoped.commits(), expected_commits);
        assert_eq!(scoped.merges(), full.merges());
        assert_eq!(scoped.derives(), full.derives());
        assert_eq!(expected_commits.len(), matching.len());
    }

    #[test]
    fn trusted_discovery_is_canonical_and_idempotent() {
        let target = collection(1);
        let authorized_key = SigningKey::from_bytes(&[7; 32]);
        let mut records: Vec<_> = (0..64)
            .map(|byte| {
                let commit = CollectionCommit::sign(
                    &authorized_key,
                    target.handle(),
                    data(byte),
                    empty_metadata_handle(),
                );
                CollectionRecord::Commit(if byte % 3 == 0 {
                    invalid_signature(commit)
                } else {
                    commit
                })
            })
            .collect();
        records.reverse();
        // Duplicate physical evidence is canonicalized by exact record.
        records.push(records[7]);

        let store = ProbeStore {
            records: records.iter().copied().map(Ok).collect(),
            ..ProbeStore::default()
        };
        let discovered =
            discover_collection_records_scoped(&store, target.handle(), signer(&authorized_key))
                .unwrap();
        assert_eq!(discovered.commits().len(), 64);
        assert!(discovered
            .commits()
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn start_and_iteration_failures_are_fatal() {
        let start_failure = ProbeStore {
            start_error: Some(ProbeRecordsError("start")),
            ..ProbeStore::default()
        };
        assert!(matches!(
            discover_collection_records(&start_failure),
            Err(CollectionDiscoveryError::Records(ProbeRecordsError(
                "start"
            )))
        ));

        let (records, _) = fixture_records();
        let iteration_failure = ProbeStore {
            records: vec![Ok(records[0]), Err(ProbeRecordsError("iteration"))],
            ..ProbeStore::default()
        };
        assert!(matches!(
            discover_collection_records(&iteration_failure),
            Err(CollectionDiscoveryError::Records(ProbeRecordsError(
                "iteration"
            )))
        ));

        let scoped_failure = ProbeStore {
            records: vec![Ok(records[0]), Err(ProbeRecordsError("scoped iteration"))],
            ..ProbeStore::default()
        };
        assert!(matches!(
            discover_collection_records_scoped(
                &scoped_failure,
                collection(99).handle(),
                signer(&SigningKey::from_bytes(&[9; 32])),
            ),
            Err(CollectionDiscoveryError::Records(ProbeRecordsError(
                "scoped iteration"
            )))
        ));
    }
}
