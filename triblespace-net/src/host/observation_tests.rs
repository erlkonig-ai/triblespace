//! Component reuse at the immutable host observation boundary.
//!
//! Counts are per snapshot family, not global instrumentation. Comparing the
//! retained leaf addresses additionally distinguishes reuse from rebuilding an
//! equal record PATCH and merely obtaining the same Merkle summary.

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, BlobEncoding, IntoBlob, TryFromBlob};
use triblespace_core::capability::policy::{resource_collection, resource_policy};
use triblespace_core::capability::{
    CapabilityProof, CapabilityProofId, CapabilityResource, capability_action,
};
use triblespace_core::collection::{
    ACTION_READ, AdmissionPolicy, Collection, CollectionCommit, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionRecordFingerprint, CollectionRecordSelector,
    CollectionStore, CollectionStoreExt, KIND_COLLECTION_DESCRIPTOR, read_capability,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{Inline, InlineEncoding};
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::{
    BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList, BlobStoreMeta, BlobStorePut,
    CapabilityProofRead, CapabilityProofStore, SnapshotSource, StoreChanges, StoreDependencies,
    StoreSnapshot as CoreStoreSnapshot, WantRead,
};

use super::{ActiveCollections, CollectionSnapshot, PatchEntry, StoreSnapshot};

#[derive(Clone)]
struct CountedSnapshot<R = MemoryRepoSnapshot> {
    inner: R,
    enumerations: Arc<AtomicUsize>,
    proof_enumerations: Arc<AtomicUsize>,
    blob_reads: Arc<AtomicUsize>,
}

impl<R> CountedSnapshot<R> {
    fn new(inner: R, enumerations: &Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            enumerations: enumerations.clone(),
            proof_enumerations: Arc::default(),
            blob_reads: Arc::default(),
        }
    }
}

impl<R: CoreStoreSnapshot> CoreStoreSnapshot for CountedSnapshot<R> {
    fn instant(&self) -> hifitime::Epoch {
        self.inner.instant()
    }

    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }

    fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
        self.inner.changes_for(&previous.inner, dependencies)
    }
}

impl<R: BlobStoreGet> BlobStoreGet for CountedSnapshot<R> {
    type GetError<E: Error + Send + Sync + 'static> = R::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.blob_reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get(handle)
    }
}

impl<R: BlobStoreList> BlobStoreList for CountedSnapshot<R> {
    type Iter<'a>
        = R::Iter<'a>
    where
        Self: 'a;
    type Err = R::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.inner.blobs()
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.contains_blob(handle)
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.blob_info(handle)
    }

    fn blobs_diff<'a>(&'a self, previous: &Self) -> Self::Iter<'a> {
        self.inner.blobs_diff(&previous.inner)
    }
}

impl<R: BlobStoreMeta> BlobStoreMeta for CountedSnapshot<R> {
    type MetaError = R::MetaError;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.metadata(handle)
    }
}

impl<R: CapabilityProofRead> CapabilityProofRead for CountedSnapshot<R> {
    type ProofsError = R::ProofsError;
    type ProofIter<'a>
        = R::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        // One enumeration per canonical evidence construction. Bootstrap must
        // consume that constructed evidence, not construct a second copy.
        self.proof_enumerations.fetch_add(1, Ordering::Relaxed);
        self.inner.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.inner.proof(id)
    }
}

impl<R: CollectionRead> CollectionRead for CountedSnapshot<R> {
    type RecordsError = R::RecordsError;
    type RecordIter<'a>
        = R::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.enumerations.fetch_add(1, Ordering::Relaxed);
        self.inner.records()
    }

    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        self.inner.record(fingerprint)
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.enumerations.fetch_add(1, Ordering::Relaxed);
        self.inner.select_records(selectors)
    }
}

impl<R: WantRead> WantRead for CountedSnapshot<R> {
    type WantsError = R::WantsError;
    type WantIter<'a>
        = R::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.inner.wants()
    }
}

struct Fixture {
    store: MemoryRepo,
    root: SigningKey,
    collection: Collection<SimpleArchive>,
    records: [CollectionRecord; 2],
    pending: CollectionRecord,
    enumerations: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let root = SigningKey::from_bytes(&[101; 32]);
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "host-observation-component-reuse",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::direct(root.verifying_key()),
                ),
            )
            .unwrap();
        let first = store
            .commit(collection, &root, entity! { metadata::name: "first" })
            .unwrap();
        let second = store
            .commit(collection, &root, entity! { metadata::name: "second" })
            .unwrap();
        // Stage the next payload before freezing so its later COMMIT alone
        // changes the record component, independently of blob residency.
        let next = store
            .put::<SimpleArchive, _>(entity! { metadata::name: "third" }.facts().clone())
            .unwrap();
        let pending = CollectionRecord::Commit(CollectionCommit::sign(
            &root,
            collection.handle(),
            Handle::<SimpleArchive>::to_hash(next),
            first.metadata(),
        ));
        Self {
            store,
            root,
            collection,
            records: [
                CollectionRecord::Commit(first),
                CollectionRecord::Commit(second),
            ],
            pending,
            enumerations: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn snapshot(&mut self) -> CountedSnapshot {
        CountedSnapshot::new(self.store.snapshot().unwrap(), &self.enumerations)
    }
}

fn active(collection: CollectionHandle) -> ActiveCollections {
    let mut active = ActiveCollections::new();
    active.insert(&PatchEntry::new(&collection.raw));
    active
}

fn assert_same_record_leaves(
    before: &CollectionSnapshot,
    after: &CollectionSnapshot,
    records: &[CollectionRecord],
) {
    assert_eq!(
        before.repair.records().summary(),
        after.repair.records().summary()
    );
    for record in records {
        let key = record.fingerprint().raw();
        assert!(
            std::ptr::eq(
                before.repair.records().patch().get(&key).unwrap(),
                after.repair.records().patch().get(&key).unwrap(),
            ),
            "unchanged record leaves must be retained, not reconstructed"
        );
    }
}

#[test]
fn unrelated_blob_arrivals_reuse_records_without_enumeration() {
    let mut fixture = Fixture::new();
    let active = active(fixture.collection.handle());
    let local = fixture.root.verifying_key();
    let mut before = fixture.snapshot();
    let mut serving_before = StoreSnapshot::from_store_changes(
        before.clone(),
        &active,
        local,
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    assert_eq!(fixture.enumerations.swap(0, Ordering::Relaxed), 1);

    for value in ["unrelated-one", "unrelated-two", "unrelated-three"] {
        fixture
            .store
            .put::<SimpleArchive, _>(entity! { metadata::name: value }.facts().clone())
            .unwrap();
        let after = fixture.snapshot();
        let changes = after.changes_since(&before);
        assert_eq!(changes, StoreChanges::BLOBS);
        let serving_after = StoreSnapshot::from_store_changes(
            after.clone(),
            &active,
            local,
            Some(&before),
            Some(&serving_before),
            changes,
        )
        .unwrap();
        assert_eq!(fixture.enumerations.load(Ordering::Relaxed), 0);
        let old = serving_before
            .collection(fixture.collection.handle())
            .unwrap();
        let new = serving_after
            .collection(fixture.collection.handle())
            .unwrap();
        assert_same_record_leaves(&old, &new, &fixture.records);
        assert_eq!(old.wake_root(), new.wake_root());
        before = after;
        serving_before = serving_after;
    }
}

#[test]
fn proof_arrival_refreshes_read_bootstrap_without_record_enumeration() {
    let mut fixture = Fixture::new();
    let reader = SigningKey::from_bytes(&[102; 32]).verifying_key();
    let active = active(fixture.collection.handle());
    let before = fixture.snapshot();
    let serving_before = StoreSnapshot::from_store_changes(
        before.clone(),
        &active,
        reader,
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let old = serving_before
        .collection(fixture.collection.handle())
        .unwrap();
    assert!(old.read_bootstrap.is_empty());
    assert_eq!(fixture.enumerations.swap(0, Ordering::Relaxed), 1);

    let proof = CapabilityProof::new(
        CapabilityResource::from(fixture.collection.handle()),
        &fixture.root,
        read_capability(),
        reader,
    );
    fixture.store.insert_proof(proof.clone()).unwrap();
    let after = fixture.snapshot();
    let changes = after.changes_since(&before);
    assert_eq!(changes, StoreChanges::CAPABILITY_PROOFS);
    let serving_after = StoreSnapshot::from_store_changes(
        after,
        &active,
        reader,
        Some(&before),
        Some(&serving_before),
        changes,
    )
    .unwrap();
    let new = serving_after
        .collection(fixture.collection.handle())
        .unwrap();
    assert_eq!(fixture.enumerations.load(Ordering::Relaxed), 0);
    assert_same_record_leaves(&old, &new, &fixture.records);
    assert_ne!(old.wake_root(), new.wake_root());
    assert_eq!(new.read_bootstrap.as_ref(), &[proof.clone()]);
    assert!(
        new.repair
            .authorization_evidence()
            .reader_is_admitted_by(reader, &[proof])
    );
}

#[test]
fn new_commit_enumerates_and_updates_the_record_summary() {
    let mut fixture = Fixture::new();
    let active = active(fixture.collection.handle());
    let local = fixture.root.verifying_key();
    let before = fixture.snapshot();
    let serving_before = StoreSnapshot::from_store_changes(
        before.clone(),
        &active,
        local,
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let old = serving_before
        .collection(fixture.collection.handle())
        .unwrap();
    assert_eq!(old.repair.records().summary().leaf_count(), 2);
    assert_eq!(fixture.enumerations.swap(0, Ordering::Relaxed), 1);

    fixture.store.insert(fixture.pending).unwrap();
    let after = fixture.snapshot();
    let changes = after.changes_since(&before);
    assert_eq!(changes, StoreChanges::COLLECTION_RECORDS);
    let serving_after = StoreSnapshot::from_store_changes(
        after,
        &active,
        local,
        Some(&before),
        Some(&serving_before),
        changes,
    )
    .unwrap();
    let new = serving_after
        .collection(fixture.collection.handle())
        .unwrap();
    assert_eq!(fixture.enumerations.load(Ordering::Relaxed), 1);
    assert_eq!(new.repair.records().summary().leaf_count(), 3);
    assert_ne!(
        old.repair.records().summary(),
        new.repair.records().summary()
    );
    assert_eq!(
        new.repair.records().get(fixture.pending.fingerprint()),
        Some(fixture.pending)
    );
    assert_ne!(old.wake_root(), new.wake_root());
}

#[test]
fn cold_collection_activation_enumerates_even_with_a_blob_only_change_mask() {
    let mut fixture = Fixture::new();
    let second = fixture
        .store
        .collection(
            "newly-active-existing-records",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
        )
        .unwrap();
    let record = CollectionRecord::Commit(
        fixture
            .store
            .commit(
                second,
                &fixture.root,
                entity! { metadata::name: "cold activation" },
            )
            .unwrap(),
    );
    let mut active = active(fixture.collection.handle());
    let local = fixture.root.verifying_key();
    let before = fixture.snapshot();
    let serving_before = StoreSnapshot::from_store_changes(
        before.clone(),
        &active,
        local,
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    assert!(serving_before.collection(second.handle()).is_none());
    assert_eq!(fixture.enumerations.swap(0, Ordering::Relaxed), 1);

    // The new interest has records already in both snapshots. The unrelated
    // blob is the only persistent component change and cannot authorize
    // reusing some other collection's record component for this cold target.
    active.insert(&PatchEntry::new(&second.handle().raw));
    fixture
        .store
        .put::<SimpleArchive, _>(
            entity! { metadata::name: "new unrelated blob" }
                .facts()
                .clone(),
        )
        .unwrap();
    let after = fixture.snapshot();
    let changes = after.changes_since(&before);
    assert_eq!(changes, StoreChanges::BLOBS);
    let serving_after = StoreSnapshot::from_store_changes(
        after,
        &active,
        local,
        Some(&before),
        Some(&serving_before),
        changes,
    )
    .unwrap();
    assert_eq!(fixture.enumerations.load(Ordering::Relaxed), 1);
    let cold = serving_after.collection(second.handle()).unwrap();
    assert_eq!(cold.repair.records().summary().leaf_count(), 1);
    assert_eq!(
        cold.repair.records().get(record.fingerprint()),
        Some(record)
    );
    assert_same_record_leaves(
        &serving_before
            .collection(fixture.collection.handle())
            .unwrap(),
        &serving_after
            .collection(fixture.collection.handle())
            .unwrap(),
        &fixture.records,
    );
}

#[test]
fn arriving_read_definition_refreshes_admission_with_same_wake_root_and_record_leaves() {
    let root = SigningKey::from_bytes(&[103; 32]);
    let reader = SigningKey::from_bytes(&[104; 32]).verifying_key();
    let mut store = MemoryRepo::default();
    // Keep the policy binding and its proof, but not the READ definition blob.
    // Repair retains structurally relevant evidence before that definition.
    let descriptor = entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(read_capability()),
    };
    let collection = store
        .put::<SimpleArchive, _>(descriptor.facts().clone())
        .unwrap();
    let data = store
        .put::<SimpleArchive, _>(
            entity! { metadata::name: "record before definition" }
                .facts()
                .clone(),
        )
        .unwrap();
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        &root,
        collection,
        Handle::<SimpleArchive>::to_hash(data),
        data,
    ));
    store.insert(record).unwrap();
    let proof = CapabilityProof::new(
        CapabilityResource::from(collection),
        &root,
        read_capability(),
        reader,
    );
    store.insert_proof(proof.clone()).unwrap();
    let enumerations = Arc::new(AtomicUsize::new(0));
    let active = active(collection);
    let before = CountedSnapshot::new(store.snapshot().unwrap(), &enumerations);
    assert!(!before.contains_blob(read_capability()).unwrap());
    let serving_before = StoreSnapshot::from_store_changes(
        before.clone(),
        &active,
        reader,
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let old = serving_before.collection(collection).unwrap();
    assert!(old.read_bootstrap.is_empty());
    assert!(
        !old.repair
            .authorization_evidence()
            .reader_is_admitted_by(reader, &[proof.clone()])
    );
    assert_eq!(enumerations.swap(0, Ordering::Relaxed), 1);

    let definition = store
        .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
        .unwrap();
    assert_eq!(definition, read_capability());
    let after = CountedSnapshot::new(store.snapshot().unwrap(), &enumerations);
    let changes = after.changes_since(&before);
    assert_eq!(changes, StoreChanges::BLOBS);
    let serving_after = StoreSnapshot::from_store_changes(
        after,
        &active,
        reader,
        Some(&before),
        Some(&serving_before),
        changes,
    )
    .unwrap();
    let new = serving_after.collection(collection).unwrap();
    assert_eq!(enumerations.load(Ordering::Relaxed), 0);
    assert_same_record_leaves(&old, &new, &[record]);
    assert_eq!(old.wake_root(), new.wake_root());
    assert!(!Arc::ptr_eq(&old.repair, &new.repair));
    assert_eq!(new.read_bootstrap.as_ref(), &[proof.clone()]);
    assert!(
        new.repair
            .authorization_evidence()
            .reader_is_admitted_by(reader, &[proof.clone()])
    );
    assert!(
        !old.repair
            .authorization_evidence()
            .reader_is_admitted_by(reader, &[proof])
    );
}

// Use the production Pile comparison here. MemoryRepo intentionally has only
// conservative component-level invalidation, so it cannot establish scoped
// no-work assertions for unrelated blob arrivals.
struct ScopedFixture {
    store: Pile,
    root: SigningKey,
    local: VerifyingKey,
    collections: [Collection<SimpleArchive>; 2],
    records: [CollectionRecord; 2],
    proofs: [CapabilityProof; 2],
    enumerations: Arc<AtomicUsize>,
    proof_enumerations: Arc<AtomicUsize>,
    blob_reads: Arc<AtomicUsize>,
    _directory: tempfile::TempDir,
}

impl ScopedFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scoped-host-observation.pile");
        std::fs::File::create(&path).unwrap();
        let mut store = Pile::open(&path).unwrap();
        let root = SigningKey::from_bytes(&[111; 32]);
        let local = SigningKey::from_bytes(&[112; 32]).verifying_key();
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(root.verifying_key()),
            AdmissionPolicy::direct(root.verifying_key()),
        );
        let collections = [
            store.collection("scoped first", policy.clone()).unwrap(),
            store.collection("scoped second", policy).unwrap(),
        ];
        let records = collections.map(|collection| {
            CollectionRecord::Commit(
                store
                    .commit(collection, &root, entity! { metadata::name: "resident" })
                    .unwrap(),
            )
        });
        let proofs = collections.map(|collection| {
            let proof = CapabilityProof::new(
                CapabilityResource::from(collection.handle()),
                &root,
                read_capability(),
                local,
            );
            store.insert_proof(proof.clone()).unwrap();
            proof
        });
        Self {
            store,
            root,
            local,
            collections,
            records,
            proofs,
            enumerations: Arc::default(),
            proof_enumerations: Arc::default(),
            blob_reads: Arc::default(),
            _directory: directory,
        }
    }

    fn active(&self) -> ActiveCollections {
        let mut selected = active(self.collections[0].handle());
        selected.insert(&PatchEntry::new(&self.collections[1].handle().raw));
        selected
    }

    fn observe(
        &mut self,
        selected: &ActiveCollections,
        previous: Option<&(CountedSnapshot<PileSnapshot>, StoreSnapshot)>,
    ) -> (CountedSnapshot<PileSnapshot>, StoreSnapshot) {
        let snapshot = CountedSnapshot {
            inner: self.store.snapshot().unwrap(),
            enumerations: self.enumerations.clone(),
            proof_enumerations: self.proof_enumerations.clone(),
            blob_reads: self.blob_reads.clone(),
        };
        let changes = previous.map_or(StoreChanges::ALL, |previous| {
            snapshot.changes_since(&previous.0)
        });
        let serving = StoreSnapshot::from_store_changes(
            snapshot.clone(),
            selected,
            self.local,
            previous.map(|previous| &previous.0),
            previous.map(|previous| &previous.1),
            changes,
        )
        .unwrap();
        (snapshot, serving)
    }

    fn take_counts(&self) -> (usize, usize, usize) {
        (
            self.enumerations.swap(0, Ordering::Relaxed),
            self.proof_enumerations.swap(0, Ordering::Relaxed),
            self.blob_reads.swap(0, Ordering::Relaxed),
        )
    }
}

#[test]
fn scoped_unrelated_blobs_reuse_proofs_bootstrap_and_records_without_point_reads() {
    let mut fixture = ScopedFixture::new();
    let selected = fixture.active();
    let mut before = fixture.observe(&selected, None);
    let (records, proofs, _) = fixture.take_counts();
    assert_eq!(
        (records, proofs),
        (2, 2),
        "one evidence build per C, not two"
    );
    for name in ["unrelated one", "unrelated two", "unrelated three"] {
        let arrived = fixture
            .store
            .put::<SimpleArchive, _>(entity! { metadata::name: name }.facts().clone())
            .unwrap();
        let after = fixture.observe(&selected, Some(&before));
        assert_eq!(after.0.changes_since(&before.0), StoreChanges::BLOBS);
        assert_eq!(fixture.take_counts(), (0, 0, 0));
        for index in 0..2 {
            let collection = fixture.collections[index].handle();
            let old = before.1.collection(collection).unwrap();
            let new = after.1.collection(collection).unwrap();
            assert_same_record_leaves(&old, &new, &[fixture.records[index]]);
            assert!(Arc::ptr_eq(&old.read_bootstrap, &new.read_bootstrap));
            let id = fixture.proofs[index].id();
            assert!(std::ptr::eq(
                old.repair.authorization_evidence().get(id).unwrap(),
                new.repair.authorization_evidence().get(id).unwrap(),
            ));
        }
        assert!(before.1.get_blob(&arrived.raw).is_none());
        assert!(after.1.get_blob(&arrived.raw).is_some());
        fixture.take_counts();
        before = after;
    }
}

#[test]
fn scoped_record_changes_rebuild_only_the_selected_c_and_keep_authorization() {
    let mut fixture = ScopedFixture::new();
    let selected = fixture.active();
    let mut before = fixture.observe(&selected, None);
    fixture.take_counts();
    for name in ["next first-C record", "another first-C record"] {
        let record = fixture
            .store
            .commit(
                fixture.collections[0],
                &fixture.root,
                entity! { metadata::name: name },
            )
            .unwrap();
        let after = fixture.observe(&selected, Some(&before));
        assert_eq!(fixture.take_counts(), (1, 0, 0));
        let old = before
            .1
            .collection(fixture.collections[0].handle())
            .unwrap();
        let new = after.1.collection(fixture.collections[0].handle()).unwrap();
        assert_ne!(old.wake_root(), new.wake_root());
        assert!(new.repair.records().get(record.fingerprint()).is_some());
        assert!(Arc::ptr_eq(&old.read_bootstrap, &new.read_bootstrap));
        let old_other = before
            .1
            .collection(fixture.collections[1].handle())
            .unwrap();
        let new_other = after.1.collection(fixture.collections[1].handle()).unwrap();
        assert_same_record_leaves(&old_other, &new_other, &[fixture.records[1]]);
        assert!(Arc::ptr_eq(
            &old_other.read_bootstrap,
            &new_other.read_bootstrap
        ));
        before = after;
    }
}

#[test]
fn scoped_proof_change_refreshes_authorization_without_losing_record_interests() {
    let mut fixture = ScopedFixture::new();
    let selected = fixture.active();
    let before = fixture.observe(&selected, None);
    fixture.take_counts();
    let proof = CapabilityProof::new(
        CapabilityResource::from(fixture.collections[0].handle()),
        &fixture.root,
        read_capability(),
        SigningKey::from_bytes(&[113; 32]).verifying_key(),
    );
    fixture.store.insert_proof(proof.clone()).unwrap();
    let after = fixture.observe(&selected, Some(&before));
    let (records, proofs, _) = fixture.take_counts();
    // CapabilityProofRead currently enumerates the whole component. Its raw
    // dependency must remain conservative even for a proof naming just one C.
    assert_eq!((records, proofs), (0, 2));
    let new = after.1.collection(fixture.collections[0].handle()).unwrap();
    assert_eq!(
        new.repair.authorization_evidence().get(proof.id()),
        Some(&proof)
    );

    let record = fixture
        .store
        .commit(
            fixture.collections[0],
            &fixture.root,
            entity! { metadata::name: "after proof" },
        )
        .unwrap();
    let final_observation = fixture.observe(&selected, Some(&after));
    assert_eq!(fixture.take_counts(), (1, 0, 0));
    let new = final_observation
        .1
        .collection(fixture.collections[0].handle())
        .unwrap();
    assert!(new.repair.records().get(record.fingerprint()).is_some());
}

#[test]
fn scoped_missing_descriptor_stays_pending_until_its_exact_blob_arrives() {
    let mut fixture = ScopedFixture::new();
    let mut descriptor_store = MemoryRepo::default();
    let cold = descriptor_store
        .collection(
            "not yet resident",
            CollectionPolicy::new(
                AdmissionPolicy::direct(fixture.root.verifying_key()),
                AdmissionPolicy::Open,
            ),
        )
        .unwrap();
    let descriptor: Blob<SimpleArchive> = descriptor_store
        .snapshot()
        .unwrap()
        .get(cold.handle())
        .unwrap();
    let selected = active(cold.handle());
    let before = fixture.observe(&selected, None);
    assert!(before.1.collection(cold.handle()).is_none());
    assert!(before.1.notices().is_empty());
    assert_eq!(fixture.take_counts(), (0, 0, 1));

    fixture
        .store
        .put::<SimpleArchive, _>(
            entity! { metadata::name: "not the descriptor" }
                .facts()
                .clone(),
        )
        .unwrap();
    let unrelated = fixture.observe(&selected, Some(&before));
    assert!(unrelated.1.collection(cold.handle()).is_none());
    assert!(unrelated.1.notices().is_empty());
    assert_eq!(fixture.take_counts(), (0, 0, 0));

    assert_eq!(
        fixture.store.put::<SimpleArchive, _>(descriptor).unwrap(),
        cold.handle()
    );
    let arrived = fixture.observe(&selected, Some(&unrelated));
    assert!(arrived.1.collection(cold.handle()).is_some());
    assert_eq!(arrived.1.notices().len(), 1);
    let (records, proofs, reads) = fixture.take_counts();
    assert_eq!((records, proofs), (1, 1));
    assert!(reads > 0);
}

#[test]
fn scoped_missing_definition_landing_changes_bootstrap_without_rebuilding_records() {
    let mut fixture = ScopedFixture::new();
    let definition: Blob<SimpleArchive> = entity! {
        capability_action: ACTION_READ,
        metadata::name: "delayed READ definition",
    }
    .facts()
    .clone()
    .to_blob();
    let capability = definition.get_handle();
    let collection = fixture.store.put::<SimpleArchive, _>(entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        resource_policy*: AdmissionPolicy::direct(fixture.root.verifying_key()).binding(capability),
    }.facts().clone()).unwrap();
    let proof = CapabilityProof::new(
        CapabilityResource::from(collection),
        &fixture.root,
        capability,
        fixture.local,
    );
    fixture.store.insert_proof(proof.clone()).unwrap();
    let selected = active(collection);
    let before = fixture.observe(&selected, None);
    let old = before.1.collection(collection).unwrap();
    assert!(old.read_bootstrap.is_empty());
    assert!(
        !old.repair
            .authorization_evidence()
            .reader_is_admitted_by(fixture.local, &[proof.clone()])
    );
    fixture.take_counts();

    fixture
        .store
        .put::<SimpleArchive, _>(
            entity! { metadata::name: "not the definition" }
                .facts()
                .clone(),
        )
        .unwrap();
    let unrelated = fixture.observe(&selected, Some(&before));
    assert_eq!(fixture.take_counts(), (0, 0, 0));
    assert!(
        unrelated
            .1
            .collection(collection)
            .unwrap()
            .read_bootstrap
            .is_empty()
    );

    fixture.store.put::<SimpleArchive, _>(definition).unwrap();
    let arrived = fixture.observe(&selected, Some(&unrelated));
    let (records, proofs, reads) = fixture.take_counts();
    assert_eq!((records, proofs), (0, 1));
    assert!(reads > 0);
    let new = arrived.1.collection(collection).unwrap();
    assert_eq!(old.wake_root(), new.wake_root());
    assert_eq!(new.read_bootstrap.as_ref(), &[proof.clone()]);
    assert!(
        new.repair
            .authorization_evidence()
            .reader_is_admitted_by(fixture.local, &[proof.clone()])
    );
    assert!(
        !old.repair
            .authorization_evidence()
            .reader_is_admitted_by(fixture.local, &[proof])
    );
}

#[test]
fn scoped_reuse_rebinds_novel_request_resource_and_definition_reads() {
    use crate::collection_activation::CollectionAuthorizationEvidenceError;

    let mut fixture = ScopedFixture::new();
    let collection = fixture.collections[0].handle();
    let selected = active(collection);
    let resource_root = SigningKey::from_bytes(&[114; 32]);
    let recipient = SigningKey::from_bytes(&[115; 32]).verifying_key();
    let resource: Blob<SimpleArchive> = entity! {
        resource_collection: collection,
        resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key()).binding(read_capability()),
    }.facts().clone().to_blob();
    let incoming_resource = CapabilityProof::new(
        CapabilityResource::from(resource.get_handle()),
        &resource_root,
        read_capability(),
        recipient,
    );
    let definition: Blob<SimpleArchive> = entity! {
        capability_action: ACTION_READ,
        metadata::name: "first referenced by a future request",
    }
    .facts()
    .clone()
    .to_blob();
    let incoming_read = CapabilityProof::new(
        CapabilityResource::from(collection),
        &fixture.root,
        definition.get_handle(),
        recipient,
    );
    let before = fixture.observe(&selected, None);
    fixture.take_counts();
    // Neither proof exists in the local proof set at construction time, so
    // these two handles are not construction dependencies of the fixed result.
    fixture.store.put::<SimpleArchive, _>(resource).unwrap();
    fixture.store.put::<SimpleArchive, _>(definition).unwrap();
    let after = fixture.observe(&selected, Some(&before));
    assert_eq!(fixture.take_counts(), (0, 0, 0));
    let old = before.1.collection(collection).unwrap();
    let new = after.1.collection(collection).unwrap();
    assert!(Arc::ptr_eq(&old.read_bootstrap, &new.read_bootstrap));
    assert_eq!(old.wake_root(), new.wake_root());
    assert!(matches!(
        old.repair
            .authorization_evidence()
            .validate_proof(&incoming_resource),
        Err(CollectionAuthorizationEvidenceError::ResourceDescriptorUnavailable(_))
    ));
    new.repair
        .authorization_evidence()
        .validate_proof(&incoming_resource)
        .unwrap();
    assert!(
        !old.repair
            .authorization_evidence()
            .reader_is_admitted_by(recipient, &[incoming_read.clone()])
    );
    assert!(
        new.repair
            .authorization_evidence()
            .reader_is_admitted_by(recipient, &[incoming_read])
    );
    // Reader freshness does not silently publish either newly received proof.
    assert!(
        new.repair
            .authorization_evidence()
            .get(incoming_resource.id())
            .is_none()
    );
}

#[test]
fn scoped_bootstrap_is_bound_to_the_local_subject_as_well_as_store_inputs() {
    let mut fixture = ScopedFixture::new();
    let selected = active(fixture.collections[0].handle());
    let before = fixture.observe(&selected, None);
    assert!(
        !before
            .1
            .collection(fixture.collections[0].handle())
            .unwrap()
            .read_bootstrap
            .is_empty()
    );
    fixture.take_counts();
    fixture.local = SigningKey::from_bytes(&[116; 32]).verifying_key();
    let after = fixture.observe(&selected, Some(&before));
    assert_eq!(after.0.changes_since(&before.0), StoreChanges::NONE);
    assert!(
        after
            .1
            .collection(fixture.collections[0].handle())
            .unwrap()
            .read_bootstrap
            .is_empty()
    );
    let (records, proofs, _) = fixture.take_counts();
    assert_eq!((records, proofs), (1, 1));
}
