//! Signed equation producers are admitted by the target's frozen WRITE policy.

use ed25519_dalek::SigningKey;
use hifitime::Epoch;

use super::*;
use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use crate::blob::{Blob, IntoBlob};
use crate::capability::{
    Capability, CapabilityMode, CapabilityProof, CapabilityResource, CapabilityValidity,
};
use crate::inline::encodings::hash::Handle;
use crate::repo::memoryrepo::MemoryRepo;
use crate::repo::{BlobStorePut, CapabilityProofStore, SnapshotSource};
use crate::trible::{Trible, TribleSet, TRIBLE_LEN};

fn archive(seed: u8) -> Blob<SimpleArchive> {
    let mut row = [seed; TRIBLE_LEN];
    row[16..32].fill(1);
    let mut facts = TribleSet::new();
    facts.insert(&Trible::force_raw(row).unwrap());
    facts.to_blob()
}

fn publish(
    store: &mut MemoryRepo,
    collection: Collection<SimpleArchive>,
    signer: &SigningKey,
    blob: Blob<SimpleArchive>,
) {
    let data = store.put::<SimpleArchive, _>(blob).unwrap();
    let metadata = store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            signer,
            collection.handle(),
            Handle::<SimpleArchive>::to_hash(data),
            metadata,
        )))
        .unwrap();
}

#[test]
fn read_rights_do_not_admit_merges_or_inject_conflicts() {
    let root = SigningKey::from_bytes(&[11; 32]);
    let reader = SigningKey::from_bytes(&[12; 32]);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "signed-merge-admission",
            CollectionPolicy::new(
                AdmissionPolicy::delegable(root.verifying_key()),
                AdmissionPolicy::delegable(root.verifying_key()),
            ),
        )
        .unwrap();
    let a = archive(2);
    let b = archive(3);
    let c = simplearchive_union::join(&a, &b).unwrap();
    publish(&mut store, collection, &root, a.clone());
    publish(&mut store, collection, &root, b.clone());
    let c_handle = store.put::<SimpleArchive, _>(c).unwrap();
    let wrong = store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    grant_collection_read(
        &mut store,
        collection.handle(),
        &root,
        reader.verifying_key(),
    )
    .unwrap();

    let low = Handle::<SimpleArchive>::to_hash(a.get_handle());
    let high = Handle::<SimpleArchive>::to_hash(b.get_handle());
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &root,
            collection.handle(),
            low,
            high,
            Handle::<SimpleArchive>::to_hash(c_handle),
        )))
        .unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &reader,
            collection.handle(),
            low,
            high,
            Handle::<SimpleArchive>::to_hash(wrong),
        )))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    assert!(collection
        .reader_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
    assert!(!collection
        .writer_is_admitted(&snapshot, reader.verifying_key())
        .unwrap());
    let attached = snapshot.collection(collection).unwrap();
    assert_eq!(
        attached.cover().members().collect::<Vec<_>>(),
        vec![c_handle]
    );
    assert_eq!(attached.view::<TribleSet>().unwrap().len(), 2);
    // The lower-level constructed-cover path must apply the same producer
    // policy even though the caller selected its membership coordinates.
    let cover = collection.cover([a.get_handle(), b.get_handle()]);
    assert_eq!(
        cover.materialize::<TribleSet, _>(&snapshot).unwrap().len(),
        2
    );
}

#[test]
fn derive_before_write_proof_is_inert_then_admitted_without_reinsertion() {
    let source_owner = SigningKey::from_bytes(&[21; 32]);
    let target_owner = SigningKey::from_bytes(&[22; 32]);
    let producer = SigningKey::from_bytes(&[23; 32]);
    let mut store = MemoryRepo::default();
    let source = store
        .collection(
            "signed-derive-source",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(source_owner.verifying_key()),
            ),
        )
        .unwrap();
    let target = store
        .derive::<SuccinctArchiveBlob>(
            source,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::delegable(target_owner.verifying_key()),
            ),
        )
        .unwrap();
    let a = archive(4);
    publish(&mut store, source, &source_owner, a.clone());
    let output = store
        .put::<SuccinctArchiveBlob, _>(succinctarchive_union::derive_element(&a).unwrap())
        .unwrap();
    let equation = CollectionRecord::Derive(CollectionDerive::sign(
        &producer,
        target.handle(),
        Handle::<SimpleArchive>::to_hash(a.get_handle()),
        Handle::<SuccinctArchiveBlob>::to_hash(output),
    ));
    store.insert(equation).unwrap();
    let before = store.snapshot().unwrap();
    assert!(before.collection(target).unwrap().cover().is_empty());

    // Source WRITE and target READ are insufficient: this is a statement
    // about the target's mapping, not a new exogenous source membership.
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &source_owner,
            target.handle(),
            Handle::<SimpleArchive>::to_hash(a.get_handle()),
            Handle::<SuccinctArchiveBlob>::to_hash(output),
        )))
        .unwrap();
    assert!(store
        .snapshot()
        .unwrap()
        .collection(target)
        .unwrap()
        .cover()
        .is_empty());
    grant_collection_write(
        &mut store,
        target.handle(),
        &target_owner,
        producer.verifying_key(),
    )
    .unwrap();
    let after = store.snapshot().unwrap();
    assert_eq!(
        after
            .collection(target)
            .unwrap()
            .cover()
            .members()
            .collect::<Vec<_>>(),
        vec![output]
    );
    assert_eq!(
        after
            .collection(target)
            .unwrap()
            .support()
            .members()
            .collect::<Vec<_>>(),
        vec![a.get_handle()]
    );
    assert!(before.collection(target).unwrap().cover().is_empty());
    assert_eq!(
        after
            .records()
            .unwrap()
            .filter_map(Result::ok)
            .filter(|record| *record == equation)
            .count(),
        1
    );
}

#[test]
fn equation_authority_uses_snapshot_time_and_expires_without_removing_records() {
    let root = SigningKey::from_bytes(&[31; 32]);
    let producer = SigningKey::from_bytes(&[32; 32]);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "expiring-equation-authority",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::delegable(root.verifying_key()),
            ),
        )
        .unwrap();
    let a = archive(5);
    let b = archive(6);
    publish(&mut store, collection, &root, a.clone());
    publish(&mut store, collection, &root, b.clone());
    let joined = store
        .put::<SimpleArchive, _>(simplearchive_union::join(&a, &b).unwrap())
        .unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &producer,
            collection.handle(),
            Handle::<SimpleArchive>::to_hash(a.get_handle()),
            Handle::<SimpleArchive>::to_hash(b.get_handle()),
            Handle::<SimpleArchive>::to_hash(joined),
        )))
        .unwrap();
    store
        .insert_proof(CapabilityProof::issue_root(
            &root,
            CapabilityResource::from(collection.handle()),
            Capability::new(write_capability(), CapabilityMode::Invoke),
            Some(
                CapabilityValidity::new(
                    Epoch::from_tai_seconds(10.0),
                    Epoch::from_tai_seconds(20.0),
                )
                .unwrap(),
            ),
            producer.verifying_key(),
        ))
        .unwrap();
    let before = store.snapshot_at(Epoch::from_tai_seconds(9.0)).unwrap();
    let admitted = store.snapshot_at(Epoch::from_tai_seconds(15.0)).unwrap();
    let expired = store.snapshot_at(Epoch::from_tai_seconds(21.0)).unwrap();
    assert_eq!(before.collection(collection).unwrap().cover().len(), 2);
    assert_eq!(
        admitted
            .collection(collection)
            .unwrap()
            .cover()
            .members()
            .collect::<Vec<_>>(),
        vec![joined]
    );
    assert_eq!(expired.collection(collection).unwrap().cover().len(), 2);
    assert_eq!(admitted.collection(collection).unwrap().cover().len(), 1);
    assert_eq!(
        expired.records().unwrap().count(),
        before.records().unwrap().count()
    );
}
