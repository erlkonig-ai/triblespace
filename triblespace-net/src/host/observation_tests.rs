//! Component reuse at the immutable host observation boundary.
//!
//! Counts are per snapshot family, not global instrumentation. Comparing the
//! retained leaf addresses additionally distinguishes reuse from rebuilding an
//! equal record PATCH and merely obtaining the same Merkle summary.

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{BlobEncoding, TryFromBlob};
use triblespace_core::capability::policy::resource_policy;
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
use triblespace_core::repo::{
    BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList, BlobStoreMeta, BlobStorePut,
    CapabilityProofRead, CapabilityProofStore, SnapshotSource, StoreChanges,
    StoreSnapshot as CoreStoreSnapshot, WantRead,
};

use super::{ActiveCollections, CollectionSnapshot, PatchEntry, StoreSnapshot};

#[derive(Clone)]
struct CountedSnapshot {
    inner: MemoryRepoSnapshot,
    enumerations: Arc<AtomicUsize>,
}

impl CountedSnapshot {
    fn new(inner: MemoryRepoSnapshot, enumerations: &Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            enumerations: enumerations.clone(),
        }
    }
}

impl CoreStoreSnapshot for CountedSnapshot {
    fn instant(&self) -> hifitime::Epoch {
        self.inner.instant()
    }

    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }
}

impl BlobStoreGet for CountedSnapshot {
    type GetError<E: Error + Send + Sync + 'static> =
        <MemoryRepoSnapshot as BlobStoreGet>::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.inner.get(handle)
    }
}

impl BlobStoreList for CountedSnapshot {
    type Iter<'a> = <MemoryRepoSnapshot as BlobStoreList>::Iter<'a>;
    type Err = <MemoryRepoSnapshot as BlobStoreList>::Err;

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

impl BlobStoreMeta for CountedSnapshot {
    type MetaError = <MemoryRepoSnapshot as BlobStoreMeta>::MetaError;

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

impl CapabilityProofRead for CountedSnapshot {
    type ProofsError = <MemoryRepoSnapshot as CapabilityProofRead>::ProofsError;
    type ProofIter<'a> = <MemoryRepoSnapshot as CapabilityProofRead>::ProofIter<'a>;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.inner.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.inner.proof(id)
    }
}

impl CollectionRead for CountedSnapshot {
    type RecordsError = <MemoryRepoSnapshot as CollectionRead>::RecordsError;
    type RecordIter<'a> = <MemoryRepoSnapshot as CollectionRead>::RecordIter<'a>;

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

impl WantRead for CountedSnapshot {
    type WantsError = <MemoryRepoSnapshot as WantRead>::WantsError;
    type WantIter<'a> = <MemoryRepoSnapshot as WantRead>::WantIter<'a>;

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
