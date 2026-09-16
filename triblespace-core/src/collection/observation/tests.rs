use std::collections::BTreeSet;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use crate::blob::{Blob, BlobEncoding, IntoBlob, TryFromBlob};
use crate::capability::{CapabilityProof, CapabilityProofId};
use crate::collection::{
    descriptor, read_capability, succinctarchive_union, write_capability, AdmissionPolicy,
    Collection, CollectionCommit, CollectionData, CollectionDerivation, CollectionDerive,
    CollectionMerge, CollectionPolicy, CollectionRead, CollectionRealizationError,
    CollectionRecord, CollectionRecordFingerprint, CollectionRecordSelector, CollectionSnapshotExt,
    CollectionStore, CollectionStoreExt,
};
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use crate::repo::pile::Pile;
use crate::repo::{
    BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList, BlobStoreMeta, BlobStorePut,
    CapabilityProofRead, SnapshotSource, StoreChanges, StoreSnapshot, WantRead,
};
use crate::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

fn policy(signer: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(signer.verifying_key()),
    )
}

fn facts(entity: u8, value: u8) -> TribleSet {
    let mut bytes = [value; TRIBLE_LEN];
    bytes[..16].fill(entity);
    bytes[16..32].fill(9);
    let mut facts = TribleSet::new();
    facts.insert(&Trible::force_raw(bytes).unwrap());
    facts
}

fn data<E: BlobEncoding>(blob: &Blob<E>) -> CollectionData
where
    Handle<E>: InlineEncoding,
{
    Handle::<E>::to_hash(blob.get_handle())
}

/// The target descriptor and output are resident; its actual source descriptor,
/// COMMIT, payload and metadata have deliberately not been inserted.
struct OneHop {
    store: MemoryRepo,
    source_descriptor: Fragment,
    source: Collection<SimpleArchive>,
    target: Collection<SuccinctArchiveBlob>,
    source_blob: Blob<SimpleArchive>,
    metadata: Blob<SimpleArchive>,
    commit: CollectionCommit,
    output: Blob<SuccinctArchiveBlob>,
    equation: CollectionRecord,
    producer: SigningKey,
}

fn one_hop() -> OneHop {
    let source_owner = SigningKey::from_bytes(&[11; 32]);
    let producer = SigningKey::from_bytes(&[12; 32]);
    let source_descriptor =
        descriptor::naming::<SimpleArchive>("passive-observation-source", policy(&source_owner));
    let source = Collection::from_handle(source_descriptor.facts().clone().to_blob().get_handle());
    let mut store = MemoryRepo::default();
    let target = store
        .derive::<SuccinctArchiveBlob>(source, (), policy(&producer))
        .unwrap();
    let source_blob = facts(1, 21).to_blob();
    let metadata = facts(2, 22).to_blob();
    let commit = CollectionCommit::sign(
        &source_owner,
        source.handle(),
        data(&source_blob),
        metadata.get_handle(),
    );
    let output = succinctarchive_union::derive_element(&source_blob).unwrap();
    store.put::<SuccinctArchiveBlob, _>(output.clone()).unwrap();
    let equation = CollectionRecord::Derive(CollectionDerive::sign(
        &producer,
        target.handle(),
        (commit.data(), commit.fingerprint()),
        data(&output),
    ));
    OneHop {
        store,
        source_descriptor,
        source,
        target,
        source_blob,
        metadata,
        commit,
        output,
        equation,
        producer,
    }
}

#[derive(Default)]
struct ReadCounts {
    gets: Mutex<Vec<CollectionData>>,
    metadata: Mutex<Vec<CollectionData>>,
    point_records: Mutex<Vec<CollectionRecordFingerprint>>,
    selections: Mutex<Vec<BTreeSet<CollectionRecordSelector>>>,
    record_enumerations: AtomicUsize,
    proof_queries: AtomicUsize,
}

#[derive(Clone)]
struct CountingSnapshot {
    inner: MemoryRepoSnapshot,
    counts: Arc<ReadCounts>,
}

impl CountingSnapshot {
    fn new(inner: MemoryRepoSnapshot) -> Self {
        Self {
            inner,
            counts: Arc::default(),
        }
    }

    fn assert_no_ancestor_record_reads(&self) {
        assert!(self.counts.point_records.lock().unwrap().is_empty());
        assert_eq!(self.counts.record_enumerations.load(Ordering::SeqCst), 0);
        assert!(self
            .counts
            .selections
            .lock()
            .unwrap()
            .iter()
            .all(|selectors| {
                selectors
                    .iter()
                    .all(|selector| !matches!(selector, CollectionRecordSelector::Fingerprint(_)))
            }));
    }

    fn assert_not_loaded(&self, handle: CollectionData) {
        assert!(!self.counts.gets.lock().unwrap().contains(&handle));
        assert!(!self.counts.metadata.lock().unwrap().contains(&handle));
    }
}

impl StoreSnapshot for CountingSnapshot {
    fn instant(&self) -> hifitime::Epoch {
        self.inner.instant()
    }
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }
}

impl BlobStoreGet for CountingSnapshot {
    type GetError<E: Error + Send + Sync + 'static> =
        <MemoryRepoSnapshot as BlobStoreGet>::GetError<E>;

    fn get<T, E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<E>>::Error>>
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.counts
            .gets
            .lock()
            .unwrap()
            .push(CollectionData::new(handle.raw));
        self.inner.get(handle)
    }
}

impl BlobStoreMeta for CountingSnapshot {
    type MetaError = <MemoryRepoSnapshot as BlobStoreMeta>::MetaError;
    fn metadata<E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.counts
            .metadata
            .lock()
            .unwrap()
            .push(CollectionData::new(handle.raw));
        self.inner.metadata(handle)
    }
}

impl BlobStoreList for CountingSnapshot {
    type Err = <MemoryRepoSnapshot as BlobStoreList>::Err;
    type Iter<'a>
        = <MemoryRepoSnapshot as BlobStoreList>::Iter<'a>
    where
        Self: 'a;
    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.inner.blobs()
    }
    fn contains_blob<E>(&self, handle: Inline<Handle<E>>) -> Result<bool, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.inner.contains_blob(handle)
    }
    fn blob_info<E>(&self, handle: Inline<Handle<E>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.inner.blob_info(handle)
    }
    fn blobs_diff<'a>(&'a self, previous: &Self) -> Self::Iter<'a> {
        self.inner.blobs_diff(&previous.inner)
    }
}

impl CollectionRead for CountingSnapshot {
    type RecordsError = <MemoryRepoSnapshot as CollectionRead>::RecordsError;
    type RecordIter<'a>
        = <MemoryRepoSnapshot as CollectionRead>::RecordIter<'a>
    where
        Self: 'a;
    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.counts
            .record_enumerations
            .fetch_add(1, Ordering::SeqCst);
        self.inner.records()
    }
    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        self.counts.point_records.lock().unwrap().push(fingerprint);
        self.inner.record(fingerprint)
    }
    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.counts
            .selections
            .lock()
            .unwrap()
            .push(selectors.clone());
        self.inner.select_records(selectors)
    }
}

impl CapabilityProofRead for CountingSnapshot {
    type ProofsError = <MemoryRepoSnapshot as CapabilityProofRead>::ProofsError;
    type ProofIter<'a>
        = <MemoryRepoSnapshot as CapabilityProofRead>::ProofIter<'a>
    where
        Self: 'a;
    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.counts.proof_queries.fetch_add(1, Ordering::SeqCst);
        self.inner.proofs()
    }
    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.counts.proof_queries.fetch_add(1, Ordering::SeqCst);
        self.inner.proof(id)
    }
}

impl WantRead for CountingSnapshot {
    type WantsError = <MemoryRepoSnapshot as WantRead>::WantsError;
    type WantIter<'a>
        = <MemoryRepoSnapshot as WantRead>::WantIter<'a>
    where
        Self: 'a;
    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.inner.wants()
    }
}

#[test]
fn resident_target_reads_before_ancestry_and_support_requires_a_fresh_closed_snapshot() {
    let mut fixture = one_hop();
    fixture.store.insert(fixture.equation).unwrap();
    let before = CountingSnapshot::new(fixture.store.snapshot().unwrap());
    assert!(!before.inner.contains_blob(fixture.source.handle()).unwrap());
    assert_eq!(
        before.inner.record(fixture.commit.fingerprint()).unwrap(),
        None
    );
    let observed = before.collection(fixture.target).unwrap();
    assert_eq!(
        observed.cover().members().collect::<Vec<_>>(),
        [fixture.output.get_handle()]
    );
    let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
    assert_eq!(view.iter().collect::<TribleSet>(), facts(1, 21));
    before.assert_no_ancestor_record_reads();
    before.assert_not_loaded(data(&fixture.source_blob));
    before.assert_not_loaded(data(&fixture.metadata));
    before.assert_not_loaded(Handle::<SimpleArchive>::to_hash(fixture.source.handle()));
    // Selected output residency is legitimate work; do not confuse it with
    // recursively loading source payloads or ancestry.
    assert!(before
        .counts
        .metadata
        .lock()
        .unwrap()
        .contains(&data(&fixture.output)));
    assert!(matches!(observed.support(),
        Err(CollectionRealizationError::MissingDependency { member })
            if member == Handle::<SimpleArchive>::to_hash(fixture.source.handle())
    ));

    descriptor::put_closure(&mut fixture.store, &fixture.source_descriptor).unwrap();
    let without_commit = fixture
        .store
        .snapshot()
        .unwrap()
        .collection(fixture.target)
        .unwrap();
    assert!(matches!(without_commit.support(),
        Err(CollectionRealizationError::IncompleteSupport { records })
            if records == vec![fixture.equation.fingerprint()]
    ));
    fixture
        .store
        .insert(CollectionRecord::Commit(fixture.commit))
        .unwrap();
    let after = CountingSnapshot::new(fixture.store.snapshot().unwrap());
    let complete = after.collection(fixture.target).unwrap();
    let support = complete.support().unwrap();
    assert_eq!(support.collection(), fixture.source);
    assert_eq!(support.len(), 1);
    assert!(support.contains(fixture.source_blob.get_handle()));
    assert!(!after
        .inner
        .contains_blob(fixture.source_blob.get_handle())
        .unwrap());
    after.assert_not_loaded(data(&fixture.source_blob));
    after.assert_not_loaded(data(&fixture.metadata));
    assert!(matches!(
        observed.support(),
        Err(CollectionRealizationError::MissingDependency { .. })
    ));
    assert!(matches!(
        without_commit.support(),
        Err(CollectionRealizationError::IncompleteSupport { .. })
    ));
    assert_eq!(
        observed
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        facts(1, 21)
    );
}

#[test]
fn unauthorized_target_producers_neither_admit_outputs_nor_hide_authorized_inputs() {
    let mut fixture = one_hop();
    fixture.store.insert(fixture.equation).unwrap();
    let outsider = SigningKey::from_bytes(&[31; 32]);
    let other_source: Blob<SimpleArchive> = facts(3, 23).to_blob();
    let other_commit = CollectionCommit::sign(
        &outsider,
        fixture.source.handle(),
        data(&other_source),
        fixture.metadata.get_handle(),
    );
    let wrong = succinctarchive_union::derive_element(&other_source).unwrap();
    fixture
        .store
        .put::<SuccinctArchiveBlob, _>(wrong.clone())
        .unwrap();
    fixture
        .store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &outsider,
            fixture.target.handle(),
            (other_commit.data(), other_commit.fingerprint()),
            data(&wrong),
        )))
        .unwrap();
    fixture
        .store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &outsider,
            fixture.target.handle(),
            (data(&fixture.output), fixture.equation.fingerprint()),
            (data(&fixture.output), fixture.equation.fingerprint()),
            data(&wrong),
        )))
        .unwrap();
    let snapshot = fixture.store.snapshot().unwrap();
    let observed = snapshot.collection(fixture.target).unwrap();
    assert_eq!(
        observed.cover().members().collect::<Vec<_>>(),
        [fixture.output.get_handle()]
    );
    assert_eq!(
        observed
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        facts(1, 21)
    );
    assert_eq!(snapshot.proofs().unwrap().count(), 0);
}

#[test]
fn unavailable_target_parent_falls_back_to_its_resident_exact_inputs() {
    let mut fixture = one_hop();
    fixture.store.insert(fixture.equation).unwrap();
    let other_source: Blob<SimpleArchive> = facts(3, 23).to_blob();
    let other_commit = CollectionCommit::sign(
        &fixture.producer,
        fixture.source.handle(),
        data(&other_source),
        fixture.metadata.get_handle(),
    );
    let other_output = succinctarchive_union::derive_element(&other_source).unwrap();
    fixture
        .store
        .put::<SuccinctArchiveBlob, _>(other_output.clone())
        .unwrap();
    let other_equation = CollectionRecord::Derive(CollectionDerive::sign(
        &fixture.producer,
        fixture.target.handle(),
        (other_commit.data(), other_commit.fingerprint()),
        data(&other_output),
    ));
    fixture.store.insert(other_equation).unwrap();
    let mut union = facts(1, 21);
    union.union(facts(3, 23));
    let union_blob = succinctarchive_union::derive_element(&union.clone().to_blob()).unwrap();
    let parent = CollectionRecord::Merge(CollectionMerge::sign(
        &fixture.producer,
        fixture.target.handle(),
        (data(&fixture.output), fixture.equation.fingerprint()),
        (data(&other_output), other_equation.fingerprint()),
        data(&union_blob),
    ));
    fixture.store.insert(parent).unwrap();
    let before = fixture
        .store
        .snapshot()
        .unwrap()
        .collection(fixture.target)
        .unwrap();
    assert_eq!(before.cover().len(), 2);
    assert!(before.cover().contains(fixture.output.get_handle()));
    assert!(before.cover().contains(other_output.get_handle()));
    assert_eq!(
        before
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        union
    );

    fixture
        .store
        .put::<SuccinctArchiveBlob, _>(union_blob.clone())
        .unwrap();
    let after = fixture
        .store
        .snapshot()
        .unwrap()
        .collection(fixture.target)
        .unwrap();
    assert_eq!(
        after.cover().members().collect::<Vec<_>>(),
        [union_blob.get_handle()]
    );
    assert_eq!(
        after
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        union
    );
    assert_eq!(before.cover().len(), 2);
    assert_eq!(
        before
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        union
    );
}

#[test]
fn direct_commit_in_a_derived_target_does_not_become_foundational_membership() {
    let mut fixture = one_hop();
    fixture
        .store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &fixture.producer,
            fixture.target.handle(),
            data(&fixture.output),
            fixture.metadata.get_handle(),
        )))
        .unwrap();
    let before = fixture
        .store
        .snapshot()
        .unwrap()
        .collection(fixture.target)
        .unwrap();
    assert!(before.cover().is_empty());
    assert!(before
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap()
        .iter()
        .next()
        .is_none());
    fixture.store.insert(fixture.equation).unwrap();
    let after = fixture
        .store
        .snapshot()
        .unwrap()
        .collection(fixture.target)
        .unwrap();
    assert_eq!(
        after.cover().members().collect::<Vec<_>>(),
        [fixture.output.get_handle()]
    );
    assert!(before.cover().is_empty());
}

#[test]
fn multihop_support_uses_exact_endorsed_records_without_ancestor_authority_or_payload_rechecks() {
    let mut fixture = one_hop();
    descriptor::put_closure(&mut fixture.store, &fixture.source_descriptor).unwrap();
    // The historical source/intermediate grants are absent here. The final
    // accepted producer endorses these exact signed inputs, rather than making
    // this reader repeat their former admission decisions.
    let historical = SigningKey::from_bytes(&[41; 32]);
    let commit = CollectionCommit::sign(
        &historical,
        fixture.source.handle(),
        data(&fixture.source_blob),
        fixture.metadata.get_handle(),
    );
    let raw_record = CollectionRecord::Derive(CollectionDerive::sign(
        &historical,
        fixture.target.handle(),
        (commit.data(), commit.fingerprint()),
        data(&fixture.output),
    ));
    fixture
        .store
        .insert(CollectionRecord::Commit(commit))
        .unwrap();
    fixture.store.insert(raw_record).unwrap();
    let final_owner = SigningKey::from_bytes(&[42; 32]);
    let final_target = fixture
        .store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(fixture.target, (), policy(&final_owner))
        .unwrap();
    let accelerated = Rank9AcceleratedSuccinctArchiveBlob::map(
        &(),
        &fixture.output,
        &fixture.store.snapshot().unwrap(),
    )
    .unwrap();
    fixture
        .store
        .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(accelerated.clone())
        .unwrap();
    fixture
        .store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &final_owner,
            final_target.handle(),
            (data(&fixture.output), raw_record.fingerprint()),
            data(&accelerated),
        )))
        .unwrap();
    let inner = fixture.store.snapshot().unwrap();
    assert!(inner.collection(fixture.source).unwrap().cover().is_empty());
    assert!(inner.collection(fixture.target).unwrap().cover().is_empty());
    assert_eq!(inner.proofs().unwrap().count(), 0);
    let snapshot = CountingSnapshot::new(inner);
    let observed = snapshot.collection(final_target).unwrap();
    assert_eq!(
        observed.cover().members().collect::<Vec<_>>(),
        [accelerated.get_handle()]
    );
    let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
    assert_eq!(view.iter().collect::<TribleSet>(), facts(1, 21));
    snapshot.assert_no_ancestor_record_reads();
    snapshot.assert_not_loaded(data(&fixture.source_blob));
    snapshot.assert_not_loaded(data(&fixture.metadata));
    let proof_queries = snapshot.counts.proof_queries.load(Ordering::SeqCst);
    let support = observed.support().unwrap();
    assert_eq!(support.collection(), fixture.source);
    assert!(support.contains(fixture.source_blob.get_handle()));
    assert_eq!(support.len(), 1);
    assert!(snapshot
        .counts
        .point_records
        .lock()
        .unwrap()
        .contains(&raw_record.fingerprint()));
    assert!(snapshot
        .counts
        .point_records
        .lock()
        .unwrap()
        .contains(&commit.fingerprint()));
    assert_eq!(
        snapshot.counts.proof_queries.load(Ordering::SeqCst),
        proof_queries
    );
    snapshot.assert_not_loaded(data(&fixture.source_blob));
    snapshot.assert_not_loaded(data(&fixture.metadata));
    let point_reads = snapshot.counts.point_records.lock().unwrap().len();
    let blob_reads = snapshot.counts.gets.lock().unwrap().len();
    let cloned = observed.clone();
    assert_eq!(cloned.support().unwrap(), support);
    assert_eq!(
        snapshot.counts.point_records.lock().unwrap().len(),
        point_reads
    );
    assert_eq!(snapshot.counts.gets.lock().unwrap().len(), blob_reads);
}

fn empty_pile(dir: &tempfile::TempDir) -> Pile {
    let path = dir.path().join("observation.pile");
    std::fs::File::create(&path).unwrap();
    Pile::open(&path).unwrap()
}

#[test]
fn pile_observation_tracks_only_consulted_ancestry_and_target_changes() {
    let fixture = one_hop();
    let dir = tempfile::tempdir().unwrap();
    let mut pile = empty_pile(&dir);
    assert_eq!(
        pile.derive::<SuccinctArchiveBlob>(fixture.source, (), policy(&fixture.producer))
            .unwrap(),
        fixture.target
    );
    pile.put::<SuccinctArchiveBlob, _>(fixture.output.clone())
        .unwrap();
    pile.insert(fixture.equation).unwrap();
    let before = pile.snapshot().unwrap();
    let basic = before.collection(fixture.target).unwrap();
    assert_eq!(
        basic
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        facts(1, 21)
    );
    assert!(basic.is_current(&before));

    // A separate attachment keeps the basic read's dependencies independent
    // of this explicit provenance request. Clones intentionally share them.
    let missing_descriptor = before.collection(fixture.target).unwrap();
    assert!(matches!(missing_descriptor.support(),
        Err(CollectionRealizationError::MissingDependency { member })
            if member == Handle::<SimpleArchive>::to_hash(fixture.source.handle())
    ));
    let unrelated_descriptor = descriptor::naming::<SimpleArchive>(
        "unrelated-observation-source",
        policy(&fixture.producer),
    );
    let unrelated = descriptor::put_closure(&mut pile, &unrelated_descriptor).unwrap();
    let unrelated_blob: Blob<SimpleArchive> = facts(7, 27).to_blob();
    pile.put::<SimpleArchive, _>(unrelated_blob.clone())
        .unwrap();
    pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
        &fixture.producer,
        unrelated,
        data(&unrelated_blob),
        fixture.metadata.get_handle(),
    )))
    .unwrap();
    let after_unrelated = pile.snapshot().unwrap();
    assert!(basic.is_current(&after_unrelated));
    assert!(missing_descriptor.is_current(&after_unrelated));

    descriptor::put_closure(&mut pile, &fixture.source_descriptor).unwrap();
    let after_descriptor = pile.snapshot().unwrap();
    assert!(basic.is_current(&after_descriptor));
    assert!(!missing_descriptor.is_current(&after_descriptor));
    assert!(matches!(
        missing_descriptor.support(),
        Err(CollectionRealizationError::MissingDependency { .. })
    ));
    let missing_witness = after_descriptor.collection(fixture.target).unwrap();
    assert!(matches!(missing_witness.support(),
        Err(CollectionRealizationError::IncompleteSupport { records })
            if records == vec![fixture.equation.fingerprint()]
    ));
    assert!(missing_witness.is_current(&after_descriptor));

    pile.insert(CollectionRecord::Commit(fixture.commit))
        .unwrap();
    let after_witness = pile.snapshot().unwrap();
    assert!(basic.is_current(&after_witness));
    assert!(!missing_witness.is_current(&after_witness));
    assert!(matches!(
        missing_witness.support(),
        Err(CollectionRealizationError::IncompleteSupport { .. })
    ));
    let complete = after_witness.collection(fixture.target).unwrap();
    let support = complete.support().unwrap();
    assert_eq!(support.collection(), fixture.source);
    assert_eq!(support.len(), 1);
    assert!(support.contains(fixture.source_blob.get_handle()));
    assert!(!after_witness
        .contains_blob(fixture.source_blob.get_handle())
        .unwrap());

    // Even a new target equation with the same visible bytes invalidates the
    // old observation: target membership, not only output hashes, was read.
    pile.insert(CollectionRecord::Merge(CollectionMerge::sign(
        &fixture.producer,
        fixture.target.handle(),
        (data(&fixture.output), fixture.equation.fingerprint()),
        (data(&fixture.output), fixture.equation.fingerprint()),
        data(&fixture.output),
    )))
    .unwrap();
    let after_target = pile.snapshot().unwrap();
    assert!(!basic.is_current(&after_target));
    assert!(!complete.is_current(&after_target));
    assert!(basic.is_current(&after_witness));
    assert_eq!(
        after_target
            .collection(fixture.target)
            .unwrap()
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        facts(1, 21)
    );
}

#[test]
fn pile_observation_tracks_a_missing_selected_output_occurrence() {
    let fixture = one_hop();
    let dir = tempfile::tempdir().unwrap();
    let mut pile = empty_pile(&dir);
    assert_eq!(
        pile.derive::<SuccinctArchiveBlob>(fixture.source, (), policy(&fixture.producer))
            .unwrap(),
        fixture.target
    );
    pile.insert(fixture.equation).unwrap();
    let before = pile.snapshot().unwrap();
    let observed = before.collection(fixture.target).unwrap();
    assert!(observed.cover().is_empty());
    assert!(observed
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap()
        .iter()
        .next()
        .is_none());
    assert!(observed.is_current(&before));

    pile.put::<SimpleArchive, _>(facts(8, 28).to_blob())
        .unwrap();
    let unrelated = pile.snapshot().unwrap();
    assert!(observed.is_current(&unrelated));
    pile.put::<SuccinctArchiveBlob, _>(fixture.output.clone())
        .unwrap();
    let after = pile.snapshot().unwrap();
    assert!(!observed.is_current(&after));
    assert!(observed.is_current(&before));
    assert!(observed.cover().is_empty());
    assert!(!before.contains_blob(fixture.output.get_handle()).unwrap());
    assert_eq!(
        before
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        after
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    );
    let recovered = after.collection(fixture.target).unwrap();
    assert!(recovered.cover().contains(fixture.output.get_handle()));
    assert_eq!(
        recovered
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        facts(1, 21)
    );
}

#[test]
fn pile_observation_tracks_missing_target_write_definition_without_new_records() {
    let mut fixture = one_hop();
    let dir = tempfile::tempdir().unwrap();
    let mut pile = empty_pile(&dir);
    let fixture_snapshot = fixture.store.snapshot().unwrap();
    let target_descriptor: Blob<SimpleArchive> =
        fixture_snapshot.get(fixture.target.handle()).unwrap();
    let read_definition: Blob<SimpleArchive> = fixture_snapshot.get(read_capability()).unwrap();
    let write_definition: Blob<SimpleArchive> = fixture_snapshot.get(write_capability()).unwrap();
    // Copy exact descriptor bytes, not their closure, to isolate one missing
    // policy definition. The signed target and its payload are already here.
    pile.put::<SimpleArchive, _>(target_descriptor).unwrap();
    pile.put::<SimpleArchive, _>(read_definition).unwrap();
    pile.put::<SuccinctArchiveBlob, _>(fixture.output.clone())
        .unwrap();
    pile.insert(fixture.equation).unwrap();
    let before = pile.snapshot().unwrap();
    assert!(!before.contains_blob(write_capability()).unwrap());
    let observed = before.collection(fixture.target).unwrap();
    assert!(observed.cover().is_empty());
    assert!(observed.is_current(&before));
    pile.put::<SimpleArchive, _>(facts(9, 29).to_blob())
        .unwrap();
    let unrelated = pile.snapshot().unwrap();
    assert!(observed.is_current(&unrelated));

    pile.put::<SimpleArchive, _>(write_definition).unwrap();
    let after = pile.snapshot().unwrap();
    assert!(!observed.is_current(&after));
    assert!(observed.is_current(&before));
    assert!(observed.cover().is_empty());
    assert!(!before.contains_blob(write_capability()).unwrap());
    assert_eq!(
        before
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        after
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    );
    assert_eq!(after.proofs().unwrap().count(), 0);
    let recovered = after.collection(fixture.target).unwrap();
    assert!(recovered.cover().contains(fixture.output.get_handle()));
    assert_eq!(
        recovered
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        facts(1, 21)
    );
}

/// Live-pile probe for one derived collection's target-first frontier: why
/// attachment selects what it selects. Ignored unless `TRIBLESPACE_PROBE_PILE`
/// names a pile; `TRIBLESPACE_PROBE_SUCCINCT` and `TRIBLESPACE_PROBE_RANK9`
/// name the two collection handles in hex. Reads only; nothing is published.
fn probe_frontier<E>(snapshot: &crate::repo::pile::PileSnapshot, label: &str, handle_hex: &str)
where
    E: crate::collection::CollectionEncoding,
    Handle<E>: InlineEncoding,
{
    use crate::collection::encoding::CollectionMemberAvailability;
    let mut raw = [0u8; 32];
    hex::decode_to_slice(handle_hex, &mut raw).unwrap();
    let target = Collection::<E>::from_handle(Inline::new(raw));
    let loaded = crate::collection::api::load_collection_descriptor(snapshot, target.handle()).unwrap();
    let evidence = crate::collection::api::discover_admission_evidence(
        snapshot,
        descriptor::admission_policies(
            snapshot,
            loaded.fragment.facts(),
            crate::collection::ACTION_WRITE,
            Some(E::id()),
        ),
        crate::collection::ACTION_WRITE,
        target.handle(),
    )
    .unwrap();
    let candidates = snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
            target.handle(),
        )]))
        .unwrap();
    let mut admitted = std::collections::BTreeMap::new();
    let mut by_kind = [0usize; 3];
    let mut unadmitted = 0usize;
    let mut records = std::collections::BTreeMap::new();
    for record in candidates {
        let kind = match record {
            CollectionRecord::Commit(_) => 0,
            CollectionRecord::Merge(_) => 1,
            CollectionRecord::Derive(_) => 2,
        };
        by_kind[kind] += 1;
        let ok = *admitted
            .entry(record.public_key().raw)
            .or_insert_with(|| {
                ed25519_dalek::VerifyingKey::from_bytes(&record.public_key().raw)
                    .ok()
                    .is_some_and(|key| evidence.authorizes(snapshot, key))
            });
        if ok {
            records.insert(record.fingerprint(), record);
        } else {
            unadmitted += 1;
        }
    }
    let mut availability = [0usize; 4];
    let mut consumed_by_complete = BTreeSet::new();
    let mut consumed_by_any = BTreeSet::new();
    let mut examples = Vec::new();
    for record in records.values() {
        let CollectionRecord::Merge(merge) = record else {
            continue;
        };
        let (low_witness, high_witness) = merge.input_witnesses();
        consumed_by_any.insert(low_witness);
        consumed_by_any.insert(high_witness);
        let availability_kind = match crate::collection::encoding::collection_member_availability::<
            E,
            _,
        >(merge.result(), snapshot)
        .unwrap()
        {
            CollectionMemberAvailability::Absent => 0,
            CollectionMemberAvailability::Incomplete => 1,
            CollectionMemberAvailability::Unusable => 2,
            CollectionMemberAvailability::Complete => 3,
        };
        availability[availability_kind] += 1;
        if availability_kind == 3 {
            consumed_by_complete.insert(low_witness);
            consumed_by_complete.insert(high_witness);
        } else if examples.len() < 3 {
            let missing = E::missing_representation_dependencies(merge.result(), snapshot)
                .map(|missing| missing.len())
                .unwrap_or(usize::MAX);
            examples.push((
                hex::encode_upper(&record.fingerprint().raw()[..6]),
                hex::encode_upper(&merge.result().raw[..6]),
                availability_kind,
                missing,
            ));
        }
    }
    let attached = crate::collection::observation::attach::<_, E>(snapshot, target).unwrap();
    let mut selected_kinds = [0usize; 3];
    let mut selected_consumed_complete = 0usize;
    let mut selected_consumed_any = 0usize;
    for witness in attached.witnesses() {
        let kind = match witness {
            CollectionRecord::Commit(_) => 0,
            CollectionRecord::Merge(_) => 1,
            CollectionRecord::Derive(_) => 2,
        };
        selected_kinds[kind] += 1;
        if consumed_by_complete.contains(&witness.fingerprint()) {
            selected_consumed_complete += 1;
        }
        if consumed_by_any.contains(&witness.fingerprint()) {
            selected_consumed_any += 1;
        }
    }
    eprintln!(
        "probe {label} {}: records commit {} merge {} derive {}, unadmitted {}; merge outputs absent {} incomplete {} unusable {} complete {}; selected {} (commit {}, merge {}, derive {}); selected witnesses consumed by an admitted merge: {} (by one with a complete output: {}); incomplete examples (record, result, kind, missing deps): {:?}",
        &handle_hex[..8],
        by_kind[0],
        by_kind[1],
        by_kind[2],
        unadmitted,
        availability[0],
        availability[1],
        availability[2],
        availability[3],
        attached.witnesses().len(),
        selected_kinds[0],
        selected_kinds[1],
        selected_kinds[2],
        selected_consumed_any,
        selected_consumed_complete,
        examples
    );
}

#[test]
#[ignore]
fn probe_live_frontier() {
    let Some(path) = std::env::var_os("TRIBLESPACE_PROBE_PILE") else {
        return;
    };
    let mut pile = Pile::open(std::path::Path::new(&path)).unwrap();
    pile.refresh().unwrap();
    let snapshot = pile.snapshot().unwrap();
    if let Ok(handle) = std::env::var("TRIBLESPACE_PROBE_SUCCINCT") {
        probe_frontier::<SuccinctArchiveBlob>(&snapshot, "succinct", &handle);
    }
    if let Ok(handle) = std::env::var("TRIBLESPACE_PROBE_RANK9") {
        probe_frontier::<Rank9AcceleratedSuccinctArchiveBlob>(&snapshot, "rank9", &handle);
    }
}
