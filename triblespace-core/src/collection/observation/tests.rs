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
    CollectionRecord, CollectionRecordSelector, CollectionSnapshotExt, CollectionStore,
    CollectionStoreExt,
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
    source_owner: SigningKey,
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
        crate::collection::SourceLocator::of(commit.data().raw),
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
        source_owner,
        producer,
    }
}

/// Make the fixture's lineage whole: the source descriptor and the admitted
/// COMMIT the target's one image stands on.
fn admit_source(fixture: &mut OneHop) {
    descriptor::put_closure(&mut fixture.store, &fixture.source_descriptor).unwrap();
    fixture
        .store
        .insert(CollectionRecord::Commit(fixture.commit))
        .unwrap();
}

#[derive(Default)]
struct ReadCounts {
    gets: Mutex<Vec<CollectionData>>,
    metadata: Mutex<Vec<CollectionData>>,
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

    fn assert_no_record_enumeration(&self) {
        // The index answers every read; the only way left to reach an
        // ancestor's rows would be a whole enumeration, and there is none.
        assert_eq!(self.counts.record_enumerations.load(Ordering::SeqCst), 0);
    }

    fn assert_not_loaded(&self, handle: CollectionData) {
        assert!(!self.counts.gets.lock().unwrap().contains(&handle));
        assert!(!self.counts.metadata.lock().unwrap().contains(&handle));
    }
}

impl StoreSnapshot for CountingSnapshot {
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

impl crate::collection::CoverageRead for CountingSnapshot {
    fn index(
        &self,
        lineage: &BTreeSet<crate::collection::CollectionHandle>,
    ) -> Result<crate::collection::coverage::CoverageIndex, Self::RecordsError> {
        self.inner.index(lineage)
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
    fn collections(&self) -> Result<Vec<crate::collection::CollectionHandle>, Self::RecordsError> {
        self.inner.collections()
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
fn target_stands_for_nothing_until_its_input_is_admitted_then_reads_from_the_index() {
    let mut fixture = one_hop();
    fixture.store.insert(fixture.equation).unwrap();
    // Without the source descriptor the lineage beneath the target is not
    // known, so a read cannot say which foundation the target stands on.
    let before = fixture.store.snapshot().unwrap();
    assert!(!before.contains_blob(fixture.source.handle()).unwrap());
    assert!(matches!(
        before.collection(fixture.target),
        Err(CollectionRealizationError::MissingDependency { member })
            if member == Handle::<SimpleArchive>::to_hash(fixture.source.handle())
    ));

    descriptor::put_closure(&mut fixture.store, &fixture.source_descriptor).unwrap();
    let without_commit = CountingSnapshot::new(fixture.store.snapshot().unwrap());
    assert!(without_commit
        .inner
        .select_records(&BTreeSet::from([CollectionRecordSelector::ProducedMember(
            fixture.source.handle(),
            fixture.commit.data(),
        )]))
        .unwrap()
        .is_empty());
    // The producer's image names an input no admitted record stands behind.
    // The fold has no row for it, so the target stands for nothing: an empty
    // cover and an empty support, and no record walked to certify more from
    // what the producer named.
    let observed = without_commit.collection(fixture.target).unwrap();
    assert!(observed.cover().is_empty());
    assert!(observed.support().unwrap().is_empty());
    assert!(observed
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap()
        .iter()
        .next()
        .is_none());
    without_commit.assert_no_record_enumeration();
    without_commit.assert_not_loaded(data(&fixture.source_blob));
    without_commit.assert_not_loaded(data(&fixture.metadata));

    fixture
        .store
        .insert(CollectionRecord::Commit(fixture.commit))
        .unwrap();
    let after = CountingSnapshot::new(fixture.store.snapshot().unwrap());
    let complete = after.collection(fixture.target).unwrap();
    assert_eq!(
        complete.cover().members().collect::<Vec<_>>(),
        [fixture.output.get_handle()]
    );
    let view: UnionArchive<OrderedUniverse> = complete.view().unwrap();
    assert_eq!(view.iter().collect::<TribleSet>(), facts(1, 21));
    let support = complete.support().unwrap();
    assert_eq!(support.collection(), fixture.source);
    assert_eq!(support.len(), 1);
    assert!(support.contains(fixture.source_blob.get_handle()));
    // The source payload and metadata are neither resident nor asked for:
    // support is a lookup in the index, and reading the target loads only
    // its own output.
    assert!(!after
        .inner
        .contains_blob(fixture.source_blob.get_handle())
        .unwrap());
    after.assert_no_record_enumeration();
    after.assert_not_loaded(data(&fixture.source_blob));
    after.assert_not_loaded(data(&fixture.metadata));
    // The earlier observation keeps standing for nothing.
    assert!(observed.cover().is_empty());
    assert!(observed.support().unwrap().is_empty());
}

#[test]
fn unauthorized_target_producers_neither_admit_outputs_nor_hide_authorized_inputs() {
    let mut fixture = one_hop();
    admit_source(&mut fixture);
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
            crate::collection::SourceLocator::of(other_commit.data().raw),
            data(&wrong),
        )))
        .unwrap();
    fixture
        .store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &outsider,
                fixture.target.handle(),
                // An unauthorized absorption of the authorized output.
                [data(&fixture.output), data(&wrong)],
                data(&wrong),
            )
            .unwrap(),
        ))
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
fn absent_target_parent_is_read_through_its_resident_merge_inputs() {
    let mut fixture = one_hop();
    admit_source(&mut fixture);
    fixture.store.insert(fixture.equation).unwrap();
    let other_source: Blob<SimpleArchive> = facts(3, 23).to_blob();
    let other_commit = CollectionCommit::sign(
        &fixture.source_owner,
        fixture.source.handle(),
        data(&other_source),
        fixture.metadata.get_handle(),
    );
    fixture
        .store
        .insert(CollectionRecord::Commit(other_commit))
        .unwrap();
    let other_output = succinctarchive_union::derive_element(&other_source).unwrap();
    fixture
        .store
        .put::<SuccinctArchiveBlob, _>(other_output.clone())
        .unwrap();
    let other_equation = CollectionRecord::Derive(CollectionDerive::sign(
        &fixture.producer,
        fixture.target.handle(),
        crate::collection::SourceLocator::of(other_commit.data().raw),
        data(&other_output),
    ));
    fixture.store.insert(other_equation).unwrap();
    let mut union = facts(1, 21);
    union.union(facts(3, 23));
    let union_blob = succinctarchive_union::derive_element(&union.clone().to_blob()).unwrap();
    // The parent's record is here; its bytes are not. The frontier is the
    // parent alone, and the read descends through the MERGE that produced
    // it to the two resident images beneath.
    let parent = CollectionRecord::Merge(
        CollectionMerge::sign(
            &fixture.producer,
            fixture.target.handle(),
            [data(&fixture.output), data(&other_output)],
            data(&union_blob),
        )
        .unwrap(),
    );
    fixture.store.insert(parent).unwrap();
    let both = fixture
        .source
        .cover([fixture.source_blob.get_handle(), other_source.get_handle()]);
    let before = fixture
        .store
        .snapshot()
        .unwrap()
        .collection(fixture.target)
        .unwrap();
    assert_eq!(before.cover().len(), 2);
    assert!(before.cover().contains(fixture.output.get_handle()));
    assert!(before.cover().contains(other_output.get_handle()));
    assert_eq!(before.support().unwrap(), &both);
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
    assert_eq!(after.support().unwrap(), &both);
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
    admit_source(&mut fixture);
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
    assert!(before.support().unwrap().is_empty());
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

/// A second hop on top of the fixture: the Rank9 image of the target's one
/// output, produced by `final_owner`.
fn second_hop(
    fixture: &mut OneHop,
    final_owner: &SigningKey,
) -> (
    Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    Blob<Rank9AcceleratedSuccinctArchiveBlob>,
) {
    let final_target = fixture
        .store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(fixture.target, (), policy(final_owner))
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
            final_owner,
            final_target.handle(),
            crate::collection::SourceLocator::of(data(&fixture.output).raw),
            data(&accelerated),
        )))
        .unwrap();
    (final_target, accelerated)
}

#[test]
fn multihop_read_takes_cover_and_support_from_the_index_without_payload_reads() {
    let mut fixture = one_hop();
    admit_source(&mut fixture);
    fixture.store.insert(fixture.equation).unwrap();
    let final_owner = SigningKey::from_bytes(&[42; 32]);
    let (final_target, accelerated) = second_hop(&mut fixture, &final_owner);
    let inner = fixture.store.snapshot().unwrap();
    // The source's one commit payload is not resident, so the source itself
    // has no resident cover; the images above it are read all the same.
    assert!(inner.collection(fixture.source).unwrap().cover().is_empty());
    assert_eq!(
        inner
            .collection(fixture.target)
            .unwrap()
            .cover()
            .members()
            .collect::<Vec<_>>(),
        [fixture.output.get_handle()]
    );
    assert_eq!(inner.proofs().unwrap().count(), 0);
    let snapshot = CountingSnapshot::new(inner);
    let observed = snapshot.collection(final_target).unwrap();
    assert_eq!(
        observed.cover().members().collect::<Vec<_>>(),
        [accelerated.get_handle()]
    );
    let view: UnionArchive<OrderedUniverse> = observed.view().unwrap();
    assert_eq!(view.iter().collect::<TribleSet>(), facts(1, 21));
    snapshot.assert_no_record_enumeration();
    snapshot.assert_not_loaded(data(&fixture.source_blob));
    snapshot.assert_not_loaded(data(&fixture.metadata));
    let support = observed.support().unwrap();
    assert_eq!(support.collection(), fixture.source);
    assert!(support.contains(fixture.source_blob.get_handle()));
    assert_eq!(support.len(), 1);
    // Support is the row the index already holds. Asking for it charges the
    // lineage to the observation and reads nothing else: no record is
    // selected, no payload loaded, no proof asked for.
    snapshot.assert_no_record_enumeration();
    snapshot.assert_not_loaded(data(&fixture.source_blob));
    snapshot.assert_not_loaded(data(&fixture.metadata));
    let selections = snapshot.counts.selections.lock().unwrap().len();
    let blob_reads = snapshot.counts.gets.lock().unwrap().len();
    let proof_queries = snapshot.counts.proof_queries.load(Ordering::SeqCst);
    let cloned = observed.clone();
    assert_eq!(cloned.support().unwrap(), support);
    assert_eq!(snapshot.counts.selections.lock().unwrap().len(), selections);
    assert_eq!(snapshot.counts.gets.lock().unwrap().len(), blob_reads);
    assert_eq!(
        snapshot.counts.proof_queries.load(Ordering::SeqCst),
        proof_queries
    );
}

#[test]
fn multihop_read_stands_for_nothing_beneath_an_unadmitted_ancestor() {
    let mut fixture = one_hop();
    descriptor::put_closure(&mut fixture.store, &fixture.source_descriptor).unwrap();
    // The historical source commit and the target's image of it are signed
    // by a key nothing here admits. The final producer is admitted, and its
    // record is believed, but the image it names has no row to stand on.
    let historical = SigningKey::from_bytes(&[41; 32]);
    fixture
        .store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &historical,
            fixture.source.handle(),
            data(&fixture.source_blob),
            fixture.metadata.get_handle(),
        )))
        .unwrap();
    fixture
        .store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &historical,
            fixture.target.handle(),
            crate::collection::SourceLocator::of(fixture.commit.data().raw),
            data(&fixture.output),
        )))
        .unwrap();
    let final_owner = SigningKey::from_bytes(&[42; 32]);
    let (final_target, accelerated) = second_hop(&mut fixture, &final_owner);
    let snapshot = CountingSnapshot::new(fixture.store.snapshot().unwrap());
    let observed = snapshot.collection(final_target).unwrap();
    assert!(observed.cover().is_empty());
    assert!(observed.support().unwrap().is_empty());
    assert!(observed
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap()
        .iter()
        .next()
        .is_none());
    // Nothing walked the chain to certify the final image from what its
    // producer named: no enumeration, no ancestor payload.
    snapshot.assert_no_record_enumeration();
    snapshot.assert_not_loaded(data(&fixture.source_blob));
    snapshot.assert_not_loaded(data(&fixture.output));

    // Admitted records for the same payloads make the chain stand.
    fixture
        .store
        .insert(CollectionRecord::Commit(fixture.commit))
        .unwrap();
    fixture.store.insert(fixture.equation).unwrap();
    let admitted = fixture
        .store
        .snapshot()
        .unwrap()
        .collection(final_target)
        .unwrap();
    assert_eq!(
        admitted.cover().members().collect::<Vec<_>>(),
        [accelerated.get_handle()]
    );
    assert_eq!(
        admitted.support().unwrap(),
        &fixture.source.cover([fixture.source_blob.get_handle()])
    );
    assert!(observed.cover().is_empty());
}

fn empty_pile(dir: &tempfile::TempDir) -> Pile {
    let path = dir.path().join("observation.pile");
    std::fs::File::create(&path).unwrap();
    Pile::open(&path).unwrap()
}

#[test]
fn pile_observation_tracks_only_consulted_lineage_and_target_changes() {
    let fixture = one_hop();
    let dir = tempfile::tempdir().unwrap();
    let mut pile = empty_pile(&dir);
    assert_eq!(
        pile.derive::<SuccinctArchiveBlob>(fixture.source, (), policy(&fixture.producer))
            .unwrap(),
        fixture.target
    );
    descriptor::put_closure(&mut pile, &fixture.source_descriptor).unwrap();
    pile.put::<SuccinctArchiveBlob, _>(fixture.output.clone())
        .unwrap();
    pile.insert(fixture.equation).unwrap();
    let before = pile.snapshot().unwrap();
    // The image is ahead of its input: the target holds a blocked record,
    // so a record landing anywhere in the lineage can move its frontier and
    // the whole lineage is what this read depends on.
    let blocked = before.collection(fixture.target).unwrap();
    assert!(blocked.cover().is_empty());
    assert!(blocked.is_current(&before));

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
    assert!(blocked.is_current(&after_unrelated));

    pile.insert(CollectionRecord::Commit(fixture.commit))
        .unwrap();
    let after_commit = pile.snapshot().unwrap();
    assert!(!blocked.is_current(&after_commit));
    assert!(blocked.is_current(&before));
    assert!(blocked.cover().is_empty());
    let complete = after_commit.collection(fixture.target).unwrap();
    assert_eq!(
        complete.cover().members().collect::<Vec<_>>(),
        [fixture.output.get_handle()]
    );
    assert!(complete.is_current(&after_commit));

    // With nothing blocked, the cover depends on the target's own records
    // only. A second source commit leaves it current until its support is
    // asked for, which is what charges the lineage.
    let second_blob: Blob<SimpleArchive> = facts(8, 28).to_blob();
    pile.insert(CollectionRecord::Commit(CollectionCommit::sign(
        &fixture.source_owner,
        fixture.source.handle(),
        data(&second_blob),
        fixture.metadata.get_handle(),
    )))
    .unwrap();
    let after_second = pile.snapshot().unwrap();
    assert!(complete.is_current(&after_second));
    let support = complete.support().unwrap();
    assert_eq!(support.collection(), fixture.source);
    assert_eq!(support.len(), 1);
    assert!(support.contains(fixture.source_blob.get_handle()));
    assert!(!after_second
        .contains_blob(fixture.source_blob.get_handle())
        .unwrap());
    assert!(!complete.is_current(&after_second));
    assert!(complete.is_current(&after_commit));

    // A new target equation with the same visible bytes invalidates the
    // observation too: target membership, not only output hashes, was read.
    let fresh = after_second.collection(fixture.target).unwrap();
    pile.insert(CollectionRecord::Merge(
        CollectionMerge::sign(
            &fixture.producer,
            fixture.target.handle(),
            // An absorbing merge whose other input is not here: it adds no
            // row, yet it is a new target record the observation read past.
            [
                data(&fixture.output),
                crate::collection::CollectionData::new([0xAB; 32]),
            ],
            data(&fixture.output),
        )
        .unwrap(),
    ))
    .unwrap();
    let after_target = pile.snapshot().unwrap();
    assert!(!fresh.is_current(&after_target));
    assert!(fresh.is_current(&after_second));
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
    descriptor::put_closure(&mut pile, &fixture.source_descriptor).unwrap();
    pile.insert(CollectionRecord::Commit(fixture.commit))
        .unwrap();
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
    // policy definition. The signed records and the target payload are
    // already here.
    pile.put::<SimpleArchive, _>(target_descriptor).unwrap();
    pile.put::<SimpleArchive, _>(fixture.source_descriptor.facts().clone())
        .unwrap();
    pile.put::<SimpleArchive, _>(read_definition).unwrap();
    pile.put::<SuccinctArchiveBlob, _>(fixture.output.clone())
        .unwrap();
    pile.insert(CollectionRecord::Commit(fixture.commit))
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
