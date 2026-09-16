//! Counted diagnostics for the existing whole-pass maintenance gate.
//!
//! These tests call the real pass and dependency predicate, not the sleeping
//! watch loop. Counts describe storage access and publication attempts, not
//! signature checks, mapping invocations, CPU time, or physical disk writes.
//! Poll snapshots/tail replay and the predicate's own prefix lookups are outside
//! these per-pass counters; zero active work does not mean zero polling cost.
//! Nested backend acquisition and metadata reads are also below the counter
//! boundary. Two selections per chain can come from the CLI's census alone;
//! proof enumeration under a direct-owner policy does not imply verification.
//! The logical chains initially share payload bytes. Record-set comparisons
//! establish snapshot-visible publication, not persistence after a crash.
//! All counters belong to one test observation; no production/global state.

use super::*;
use std::any::TypeId;
use std::sync::{Arc, Mutex};
use triblespace_core::blob::encodings::entity_id_set::EntityIdSet;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::BlobEncoding;
use triblespace_core::capability::{CapabilityProof, CapabilityProofId};
use triblespace_core::collection::{
    CollectionRecordFingerprint, CollectionSnapshotExt, CollectionStore,
};
use triblespace_core::inline::InlineEncoding;
use triblespace_core::macros::entity;
use triblespace_core::repo::{
    BlobInfo, BlobMetadata, BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore,
    StoreChanges, WantRead, WantRequest, WantStore,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Counts {
    snapshots: usize,
    blob_gets: usize,
    record_enumerations: usize,
    record_lookups: usize,
    selected_calls: BTreeMap<CollectionHandle, usize>,
    selected_rows: BTreeMap<CollectionHandle, usize>,
    proof_enumerations: usize,
    proof_rows: usize,
    proof_lookups: usize,
    blob_puts: usize,
    id_set_puts: usize,
    // COMMIT, MERGE, DERIVE attempts, independently of whether already stored.
    insertions: BTreeMap<CollectionHandle, [usize; 3]>,
}

#[derive(Clone)]
struct Counted<R> {
    inner: R,
    counts: Arc<Mutex<Counts>>,
}

impl<R> Counted<R> {
    fn count(&self, update: impl FnOnce(&mut Counts)) {
        update(&mut self.counts.lock().unwrap());
    }
}

impl<S: SnapshotSource> SnapshotSource for Counted<S> {
    type Snapshot = Counted<S::Snapshot>;
    type SnapshotError = S::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.count(|counts| counts.snapshots += 1);
        Ok(Counted {
            inner: self.inner.snapshot()?,
            counts: Arc::clone(&self.counts),
        })
    }
}

impl<R: StoreSnapshot> StoreSnapshot for Counted<R> {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }

    fn changes_for(&self, previous: &Self, interests: &StoreDependencies) -> StoreChanges {
        self.inner.changes_for(&previous.inner, interests)
    }
}

impl<S: BlobStorePut> BlobStorePut for Counted<S> {
    type PutError = S::PutError;

    fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
    where
        E: BlobEncoding + 'static,
        T: IntoBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.count(|counts| {
            counts.blob_puts += 1;
            counts.id_set_puts += usize::from(TypeId::of::<E>() == TypeId::of::<EntityIdSetBlob>());
        });
        self.inner.put(item)
    }
}

impl<S: CollectionStore> CollectionStore for Counted<S> {
    type InsertError = S::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.count(|counts| {
            let kind = match record {
                CollectionRecord::Commit(_) => 0,
                CollectionRecord::Merge(_) => 1,
                CollectionRecord::Derive(_) => 2,
            };
            counts.insertions.entry(record.collection()).or_default()[kind] += 1;
        });
        self.inner.insert(record)
    }
}

impl<S: CapabilityProofStore> CapabilityProofStore for Counted<S> {
    type InsertError = S::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.inner.insert_proof(proof)
    }
}

impl<S: AsyncBlobStoreAcquire> AsyncBlobStoreAcquire for Counted<S> {
    type AcquireError = S::AcquireError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl std::future::Future<Output = Result<Option<anybytes::Bytes>, Self::AcquireError>> + Send
    {
        self.inner.acquire(handle)
    }
}

impl<R: BlobStoreGet> BlobStoreGet for Counted<R> {
    type GetError<E: std::error::Error + Send + Sync + 'static> = R::GetError<E>;

    fn get<T, E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<E>>::Error>>
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.count(|counts| counts.blob_gets += 1);
        self.inner.get(handle)
    }
}

impl<R: BlobStoreList> BlobStoreList for Counted<R> {
    type Iter<'a>
        = R::Iter<'a>
    where
        Self: 'a;
    type Err = R::Err;

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

impl<R: BlobStoreMeta> BlobStoreMeta for Counted<R> {
    type MetaError = R::MetaError;

    fn metadata<E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.inner.metadata(handle)
    }
}

impl<R: CollectionRead> CollectionRead for Counted<R> {
    type RecordsError = R::RecordsError;
    type RecordIter<'a>
        = R::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.count(|counts| counts.record_enumerations += 1);
        self.inner.records()
    }

    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        self.count(|counts| counts.record_lookups += 1);
        self.inner.record(fingerprint)
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.count(|counts| {
            for selector in selectors {
                if let CollectionRecordSelector::Collection(collection) = selector {
                    *counts.selected_calls.entry(*collection).or_default() += 1;
                }
            }
        });
        let records = self.inner.select_records(selectors)?;
        self.count(|counts| {
            for record in &records {
                *counts.selected_rows.entry(record.collection()).or_default() += 1;
            }
        });
        Ok(records)
    }
}

impl<R: CapabilityProofRead> CapabilityProofRead for Counted<R> {
    type ProofsError = R::ProofsError;
    type ProofIter<'a>
        = Box<dyn Iterator<Item = Result<CapabilityProof, R::ProofsError>> + 'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.count(|counts| counts.proof_enumerations += 1);
        Ok(Box::new(self.inner.proofs()?.inspect(move |_| {
            self.count(|counts| counts.proof_rows += 1);
        })))
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.count(|counts| counts.proof_lookups += 1);
        self.inner.proof(id)
    }
}

impl<R: WantRead> WantRead for Counted<R> {
    type WantsError = R::WantsError;
    type WantIter<'a>
        = R::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.inner.wants()
    }
}

fn counted_pass(
    pile: &mut Pile,
    selected: &[CollectionHandle],
    signer: &SigningKey,
) -> (StoreDependencies, Counts) {
    let counts = Arc::new(Mutex::new(Counts::default()));
    let mut observed = ObservedStore::new(Counted {
        inner: pile,
        counts: Arc::clone(&counts),
    });
    let references = selected
        .iter()
        .map(|handle| handle_hex(*handle))
        .collect::<Vec<_>>();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(
        runtime
            .block_on(maintenance_pass(
                &mut observed,
                &references,
                signer,
                true,
                SuccinctBackend::Cpu,
            ))
            .unwrap(),
        0
    );
    let interests = observed.dependencies();
    let recorded = counts.lock().unwrap().clone();
    (interests, recorded)
}

fn selected_records(
    snapshot: &PileSnapshot,
    collection: CollectionHandle,
) -> Vec<CollectionRecord> {
    snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
            collection,
        )]))
        .unwrap()
}

fn output_handles(snapshot: &PileSnapshot, collection: CollectionHandle) -> BTreeSet<[u8; 32]> {
    selected_records(snapshot, collection)
        .into_iter()
        .map(|record| match record {
            CollectionRecord::Commit(commit) => commit.data().raw,
            CollectionRecord::Merge(merge) => merge.result().raw,
            CollectionRecord::Derive(derive) => derive.output().raw,
        })
        .collect()
}

fn receipt(value: Id, annotation: &str) -> Fragment {
    entity! {
        metadata::supersedes: value,
        metadata::description: annotation.to_owned(),
    }
}

struct Fixture {
    pile: Pile,
    writer: Pile,
    signer: SigningKey,
    sources: [Collection<SimpleArchive>; 2],
    targets: [Collection<EntityIdSetBlob>; 2],
    other: Collection<SimpleArchive>,
    first_value: Id,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("counted-maintenance.pile");
        std::fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let writer = Pile::open(&path).unwrap();
        let signer = SigningKey::from_bytes(&[71; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(signer.verifying_key()),
            AdmissionPolicy::direct(signer.verifying_key()),
        );
        let sources = ["hot receipt source", "quiet receipt source"]
            .map(|name| pile.collection(name, policy.clone()).unwrap());
        let targets = sources.map(|source| {
            pile.derive::<EntityIdSetBlob>(source, metadata::supersedes.id(), policy.clone())
                .unwrap()
        });
        let other = pile.collection("unselected source", policy).unwrap();
        let first_value = Id::new([1; 16]).unwrap();
        for source in sources {
            pile.commit(source, &signer, receipt(first_value, "initial receipt"))
                .unwrap();
        }
        // Exercise a nonempty proof inventory without changing owner admission.
        grant_collection_read(
            &mut pile,
            sources[0].handle(),
            &signer,
            SigningKey::from_bytes(&[72; 32]).verifying_key(),
        )
        .unwrap();
        Self {
            pile,
            writer,
            signer,
            sources,
            targets,
            other,
            first_value,
            _directory: directory,
        }
    }

    fn pass(&mut self) -> (StoreDependencies, Counts) {
        counted_pass(
            &mut self.pile,
            &self.targets.map(|target| target.handle()),
            &self.signer,
        )
    }

    fn warm(&mut self) -> (PileSnapshot, StoreDependencies) {
        let (first_interests, first) = self.pass();
        assert!(first.id_set_puts > 0);
        let published = self.pile.snapshot().unwrap();
        let (interests, quiet) = self.pass();
        let settled = self.pile.snapshot().unwrap();
        assert!(!maintenance_changed(&published, &settled, &first_interests));
        assert!(!maintenance_changed(&published, &settled, &interests));
        assert_eq!(quiet.blob_puts, 0, "warm pass attempts no blob put");
        assert!(quiet.insertions.is_empty());
        assert!(quiet.proof_enumerations > 0 && quiet.proof_rows > 0);
        (settled, interests)
    }

    fn assert_value_and_support(&mut self, values: &[Id], expected_members: usize) {
        let snapshot = self.pile.snapshot().unwrap();
        let observed = snapshot.collection(self.targets[0]).unwrap();
        assert_eq!(
            observed
                .view::<EntityIdSet>()
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            values
        );
        let expected = self.sources[0].admitted(&snapshot).unwrap();
        assert_eq!(expected.len(), expected_members);
        assert_eq!(observed.support().unwrap(), &expected);
        assert!(selected_records(&snapshot, self.sources[0].handle())
            .iter()
            .all(|record| matches!(record, CollectionRecord::Commit(_))));
    }

    fn close(self) {
        self.writer.close().unwrap();
        self.pile.close().unwrap();
    }
}

fn assert_quiet_chain_revisited(counts: &Counts, fixture: &Fixture) {
    for collection in [fixture.sources[1].handle(), fixture.targets[1].handle()] {
        assert!(
            counts.selected_calls.get(&collection).copied().unwrap_or(0) >= 2,
            "unchanged chain is visited, including its before/after census"
        );
        assert!(counts.selected_rows.get(&collection).copied().unwrap_or(0) > 0);
        assert_eq!(
            counts
                .insertions
                .get(&collection)
                .copied()
                .unwrap_or_default(),
            [0; 3]
        );
    }
    assert!(counts.proof_enumerations > 0 && counts.proof_rows > 0);
    assert_eq!(
        counts.record_enumerations, 0,
        "exact targets use indexed selection"
    );
}

#[test]
fn maintenance_gate_counts_idle_unrelated_and_changed_chain_work() {
    let mut fixture = Fixture::new();
    let (settled, interests) = fixture.warm();
    let mut passes = 0;
    let mut idle_counts = Counts::default();
    for _ in 0..3 {
        let sampled = fixture.pile.snapshot().unwrap();
        if maintenance_changed(&settled, &sampled, &interests) {
            passes += 1;
            idle_counts = fixture.pass().1;
        }
    }
    fixture
        .writer
        .put::<UTF8String, _>("unrelated blob")
        .unwrap();
    let wanted: Blob<UTF8String> = "unrelated want".to_blob();
    fixture
        .writer
        .want(WantRequest::blob(wanted.get_handle()))
        .unwrap();
    fixture
        .writer
        .commit(
            fixture.other,
            &fixture.signer,
            receipt(fixture.first_value, "unrelated record"),
        )
        .unwrap();
    let unrelated = fixture.pile.snapshot().unwrap();
    assert!(!unrelated.changes_since(&settled).is_empty());
    if maintenance_changed(&settled, &unrelated, &interests) {
        passes += 1;
        idle_counts = fixture.pass().1;
    }
    assert_eq!(passes, 0);
    assert_eq!(
        idle_counts,
        Counts::default(),
        "no active pass for idle/unrelated polls"
    );

    let quiet_before = selected_records(&unrelated, fixture.targets[1].handle());
    fixture
        .writer
        .commit(
            fixture.sources[0],
            &fixture.signer,
            receipt(Id::new([2; 16]).unwrap(), "new event"),
        )
        .unwrap();
    let changed = fixture.pile.snapshot().unwrap();
    assert!(maintenance_changed(&unrelated, &changed, &interests));
    let (next_interests, counts) = fixture.pass();
    assert_quiet_chain_revisited(&counts, &fixture);
    assert!(counts.id_set_puts > 0);
    assert!(counts.insertions[&fixture.targets[0].handle()][2] > 0);
    let completed = fixture.pile.snapshot().unwrap();
    assert_eq!(
        selected_records(&completed, fixture.targets[1].handle()),
        quiet_before
    );
    assert!(maintenance_changed(&changed, &completed, &next_interests));
    let (caught_up_interests, caught_up) = fixture.pass();
    assert_eq!(caught_up.blob_puts, 0);
    assert!(caught_up.insertions.is_empty());
    assert!(!maintenance_changed(
        &completed,
        &fixture.pile.snapshot().unwrap(),
        &caught_up_interests
    ));
    eprintln!("changed selected source: {counts:?}; no-op catch-up: {caught_up:?}");
    fixture.assert_value_and_support(&[fixture.first_value, Id::new([2; 16]).unwrap()], 2);
    fixture.close();
}

#[test]
fn proof_only_arrival_revisits_warm_chains_without_publication() {
    let mut fixture = Fixture::new();
    let (settled, interests) = fixture.warm();
    assert!(interests.capability_proofs);
    let before = fixture
        .targets
        .map(|target| selected_records(&settled, target.handle()));
    grant_collection_read(
        &mut fixture.writer,
        fixture.other.handle(),
        &fixture.signer,
        SigningKey::from_bytes(&[73; 32]).verifying_key(),
    )
    .unwrap();
    let arrived = fixture.pile.snapshot().unwrap();
    assert!(arrived
        .changes_since(&settled)
        .contains(StoreChanges::CAPABILITY_PROOFS));
    assert!(maintenance_changed(&settled, &arrived, &interests));
    let (next_interests, counts) = fixture.pass();
    assert_quiet_chain_revisited(&counts, &fixture);
    for target in fixture.targets {
        assert!(counts.selected_calls[&target.handle()] >= 2);
    }
    assert_eq!(counts.blob_puts, 0);
    assert!(counts.insertions.is_empty());
    let completed = fixture.pile.snapshot().unwrap();
    assert_eq!(
        fixture
            .targets
            .map(|target| selected_records(&completed, target.handle())),
        before
    );
    assert!(!maintenance_changed(&arrived, &completed, &next_interests));
    eprintln!("unrelated proof/component-wide retry: {counts:?}");
    fixture.close();
}

#[test]
fn repeated_projected_value_adds_support_without_a_new_output_handle() {
    let mut fixture = Fixture::new();
    let (settled, interests) = fixture.warm();
    let target = fixture.targets[0].handle();
    let outputs = output_handles(&settled, target);
    let original_records = selected_records(&settled, target);
    let quiet_records = selected_records(&settled, fixture.targets[1].handle());
    let old_observation = settled.collection(fixture.targets[0]).unwrap();

    // Same projected value, genuinely different ordinary source payload. A new
    // annotation is not permission to erase its independent COMMIT support.
    fixture
        .writer
        .commit(
            fixture.sources[0],
            &fixture.signer,
            receipt(fixture.first_value, "a later annotated receipt"),
        )
        .unwrap();
    let repeated = fixture.pile.snapshot().unwrap();
    assert!(maintenance_changed(&settled, &repeated, &interests));
    let (repeat_interests, repeated_counts) = fixture.pass();
    assert_quiet_chain_revisited(&repeated_counts, &fixture);
    let certified = fixture.pile.snapshot().unwrap();
    assert!(selected_records(&certified, target).len() > original_records.len());
    assert_eq!(output_handles(&certified, target), outputs);
    assert_eq!(
        selected_records(&certified, fixture.targets[1].handle()),
        quiet_records
    );
    assert!(repeated_counts.insertions[&target][2] > 0);
    fixture.assert_value_and_support(&[fixture.first_value], 2);
    assert_eq!(old_observation.support().unwrap().len(), 1);
    assert_eq!(
        old_observation
            .view::<EntityIdSet>()
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        [fixture.first_value]
    );

    let (settled_interests, quiet) = fixture.pass();
    assert_eq!(quiet.blob_puts, 0);
    assert!(quiet.insertions.is_empty());
    let before_new_value = fixture.pile.snapshot().unwrap();
    assert!(!maintenance_changed(
        &certified,
        &before_new_value,
        &repeat_interests
    ));
    let new_value = Id::new([2; 16]).unwrap();
    fixture
        .writer
        .commit(
            fixture.sources[0],
            &fixture.signer,
            receipt(new_value, "a different event"),
        )
        .unwrap();
    assert!(maintenance_changed(
        &before_new_value,
        &fixture.pile.snapshot().unwrap(),
        &settled_interests
    ));
    let (_, new_counts) = fixture.pass();
    assert_quiet_chain_revisited(&new_counts, &fixture);
    assert!(new_counts.id_set_puts > 0);
    assert!(new_counts.insertions[&target][2] > 0);
    let with_new_value = fixture.pile.snapshot().unwrap();
    assert_ne!(output_handles(&with_new_value, target), outputs);
    fixture.assert_value_and_support(&[fixture.first_value, new_value], 3);
    eprintln!("same value/new support: {repeated_counts:?}; new value: {new_counts:?}");
    fixture.close();
}
