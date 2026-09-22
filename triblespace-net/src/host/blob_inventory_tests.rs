//! Positive resident closure at the real immutable store/host boundary.

use anybytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionHandle, CollectionPolicy, CollectionRecord,
    CollectionStore, CollectionStoreExt,
};
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::{
    BlobStoreGet, BlobStoreList, BlobStorePut, SnapshotSource, StoreChanges,
    StoreSnapshot as CoreStoreSnapshot,
};
use triblespace_core::trible::TribleSet;

use super::{ActiveCollections, PatchEntry, StoreSnapshot};

struct Fixture {
    store: MemoryRepo,
    local: VerifyingKey,
    collection: CollectionHandle,
}

impl Fixture {
    fn new(body: Bytes) -> Self {
        let signing = SigningKey::from_bytes(&[109; 32]);
        let local = signing.verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "host-positive-resident-inventory",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(local),
                    AdmissionPolicy::direct(local),
                ),
            )
            .unwrap()
            .handle();
        let data = store.put::<UnknownBlob, _>(body).unwrap();
        let metadata = store.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        // Synchronization retains structurally valid signed records and their
        // exact direct blob references independently of payload decoding or
        // semantic WRITE admission. The bytes intentionally expose a simple
        // reference chain rather than imposing a SimpleArchive reader here.
        store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &signing,
                collection,
                Handle::<UnknownBlob>::to_hash(data),
                metadata,
            )))
            .unwrap();
        Self {
            store,
            local,
            collection,
        }
    }

    fn active(&self) -> ActiveCollections {
        let mut active = ActiveCollections::new();
        active.insert(&PatchEntry::new(&self.collection.raw));
        active
    }
}

fn observe(
    snapshot: &MemoryRepoSnapshot,
    active: &ActiveCollections,
    local: VerifyingKey,
    prior: Option<(&MemoryRepoSnapshot, &StoreSnapshot)>,
) -> StoreSnapshot {
    StoreSnapshot::from_store_changes(
        snapshot.clone(),
        active,
        local,
        prior.map(|(store, _)| store),
        prior.map(|(_, host)| host),
        prior.map_or(StoreChanges::ALL, |(before, _)| {
            snapshot.changes_since(before)
        }),
    )
    .unwrap()
}

fn settle(
    snapshot: &MemoryRepoSnapshot,
    active: &ActiveCollections,
    local: VerifyingKey,
    mut serving: StoreSnapshot,
) -> StoreSnapshot {
    for _ in 0..128 {
        if serving
            .collections()
            .all(|collection| !collection.blob_scan.has_pending_work())
        {
            return serving;
        }
        serving = observe(snapshot, active, local, Some((snapshot, &serving)));
    }
    panic!("unchanged finite store did not finish its resident closure");
}

#[test]
fn blob_only_child_arrival_changes_inventory_not_record_or_authority_roots() {
    let child =
        Blob::<UnknownBlob>::new(Bytes::from_source(b"nested child arrives later".to_vec()));
    let child_handle = child.get_handle();
    let mut fixture = Fixture::new(Bytes::from_source(child_handle.raw.to_vec()));
    let active = fixture.active();
    let before = fixture.store.snapshot().unwrap();
    let old = settle(
        &before,
        &active,
        fixture.local,
        observe(&before, &active, fixture.local, None),
    );
    let old_collection = old.collection(fixture.collection).unwrap();
    assert!(
        !old_collection
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );

    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let after = fixture.store.snapshot().unwrap();
    assert_eq!(after.changes_since(&before), StoreChanges::BLOBS);
    let new = settle(
        &after,
        &active,
        fixture.local,
        observe(&after, &active, fixture.local, Some((&before, &old))),
    );
    let new_collection = new.collection(fixture.collection).unwrap();
    let old_manifest = crate::collection_session::manifest(&old_collection.repair);
    let new_manifest = crate::collection_session::manifest(&new_collection.repair);
    assert_eq!(old_manifest.records, new_manifest.records);
    assert_eq!(
        old_manifest.authorization_evidence,
        new_manifest.authorization_evidence
    );
    assert_ne!(old_manifest.resident_blobs, new_manifest.resident_blobs);
    assert_ne!(old_manifest.wake_root, new_manifest.wake_root);
    assert!(
        new_collection
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
    // The retained immutable observation does not learn a future arrival.
    assert!(
        !old_collection
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
}

#[test]
fn unchanged_store_refresh_advances_large_inventory_in_bounded_quanta() {
    let child = Blob::<UnknownBlob>::new(Bytes::from_source(b"after the large body".to_vec()));
    let child_handle = child.get_handle();
    let mut body = vec![0; 4096 * 32];
    body.extend_from_slice(&child_handle.raw);
    let mut fixture = Fixture::new(Bytes::from_source(body));
    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let active = fixture.active();
    let snapshot = fixture.store.snapshot().unwrap();
    let mut serving = observe(&snapshot, &active, fixture.local, None);
    let initial = serving.collection(fixture.collection).unwrap();
    let records = initial.repair.records().summary();
    let authorization = initial.repair.authorization_evidence().summary();
    // Each observation scans at most 1024 words for this collection. Three
    // further unchanged refreshes cannot get past 4096 padding words.
    for _ in 0..3 {
        let collection = serving.collection(fixture.collection).unwrap();
        assert!(collection.blob_scan.has_pending_work());
        assert!(
            !collection
                .repair
                .blob_inventory()
                .has_prefix(&child_handle.raw)
        );
        assert_eq!(snapshot.changes_since(&snapshot), StoreChanges::NONE);
        serving = observe(
            &snapshot,
            &active,
            fixture.local,
            Some((&snapshot, &serving)),
        );
    }
    assert!(
        !serving
            .collection(fixture.collection)
            .unwrap()
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
    let serving = settle(&snapshot, &active, fixture.local, serving);
    let complete_pass = serving.collection(fixture.collection).unwrap();
    assert!(
        complete_pass
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
    assert_eq!(complete_pass.repair.records().summary(), records);
    assert_eq!(
        complete_pass.repair.authorization_evidence().summary(),
        authorization
    );
}

#[test]
fn deselection_discards_inventory_and_reactivation_observes_current_residency() {
    let child = Blob::<UnknownBlob>::new(Bytes::from_source(b"selected child".to_vec()));
    let child_handle = child.get_handle();
    let mut fixture = Fixture::new(Bytes::from_source(child_handle.raw.to_vec()));
    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let active = fixture.active();
    let snapshot = fixture.store.snapshot().unwrap();
    let old = settle(
        &snapshot,
        &active,
        fixture.local,
        observe(&snapshot, &active, fixture.local, None),
    );
    assert!(
        old.collection(fixture.collection)
            .unwrap()
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
    let off = observe(
        &snapshot,
        &ActiveCollections::new(),
        fixture.local,
        Some((&snapshot, &old)),
    );
    assert!(off.collection(fixture.collection).is_none());
    assert_eq!(off.collections().count(), 0);
    let reactivated = settle(
        &snapshot,
        &active,
        fixture.local,
        observe(&snapshot, &active, fixture.local, Some((&snapshot, &off))),
    );
    assert!(
        reactivated
            .collection(fixture.collection)
            .unwrap()
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
}

#[test]
fn removed_parent_with_resident_child_invalidates_disconnected_inventory() {
    let child = Blob::<UnknownBlob>::new(Bytes::from_source(
        b"resident but disconnected child".to_vec(),
    ));
    let child_handle = child.get_handle();
    let parent = Blob::<UnknownBlob>::new(Bytes::from_source(child_handle.raw.to_vec()));
    let parent_handle = parent.get_handle();
    let mut fixture = Fixture::new(Bytes::from_source(parent_handle.raw.to_vec()));
    fixture.store.put::<UnknownBlob, _>(parent).unwrap();
    fixture.store.put::<UnknownBlob, _>(child).unwrap();
    let active = fixture.active();
    let before = fixture.store.snapshot().unwrap();
    let old = settle(
        &before,
        &active,
        fixture.local,
        observe(&before, &active, fixture.local, None),
    );
    assert!(
        old.collection(fixture.collection)
            .unwrap()
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
    // Deliberately bypass root-preserving repository GC to model a backing
    // store removal. All other bytes, including the disconnected child, stay.
    let kept: Vec<Inline<Handle<UnknownBlob>>> = before
        .blobs()
        .map(|entry| entry.unwrap().handle)
        .filter(|handle| *handle != parent_handle)
        .collect();
    fixture.store.blobs.keep(kept);
    let after = fixture.store.snapshot().unwrap();
    assert!(after.get::<Bytes, UnknownBlob>(child_handle).is_ok());
    assert!(after.get::<Bytes, UnknownBlob>(parent_handle).is_err());
    let new = settle(
        &after,
        &active,
        fixture.local,
        observe(&after, &active, fixture.local, Some((&before, &old))),
    );
    let collection = new.collection(fixture.collection).unwrap();
    assert!(
        !collection
            .repair
            .blob_inventory()
            .has_prefix(&parent_handle.raw)
    );
    assert!(
        !collection
            .repair
            .blob_inventory()
            .has_prefix(&child_handle.raw)
    );
    assert_eq!(
        collection.repair.records().summary(),
        old.collection(fixture.collection)
            .unwrap()
            .repair
            .records()
            .summary()
    );
}
