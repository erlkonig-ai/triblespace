//! Raw Covers select payloads; signed equations can realize them without
//! inventing collection membership or requiring complete COMMIT provenance.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::collection::{
    empty_metadata_handle, simplearchive_union, AdmissionPolicy, Collection, CollectionCommit,
    CollectionData, CollectionMaterializationError, CollectionMerge, CollectionPolicy,
    CollectionRecord, CollectionSnapshotExt, CollectionStore, CollectionStoreExt,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource, StoreSnapshot};
use triblespace_core::trible::{Trible, TribleSet, TRIBLE_LEN};

fn archive(seeds: &[u8]) -> Blob<SimpleArchive> {
    let mut facts = TribleSet::new();
    for seed in seeds {
        let mut raw = [*seed; TRIBLE_LEN];
        raw[16..32].fill(1);
        facts.insert(&Trible::force_raw(raw).unwrap());
    }
    facts.to_blob()
}

fn data(blob: &Blob<SimpleArchive>) -> CollectionData {
    Handle::<SimpleArchive>::to_hash(blob.get_handle())
}

fn collection(store: &mut MemoryRepo, name: &str, owner: &SigningKey) -> Collection<SimpleArchive> {
    store
        .collection(
            name,
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(owner.verifying_key()),
            ),
        )
        .unwrap()
}

fn leaf(
    collection: Collection<SimpleArchive>,
    signer: &SigningKey,
    blob: &Blob<SimpleArchive>,
) -> CollectionCommit {
    // These actual records are deliberately not inserted. Raw cover reads
    // need mathematical equations, not a claim that these are admitted leaves.
    CollectionCommit::sign(
        signer,
        collection.handle(),
        data(blob),
        empty_metadata_handle(),
    )
}

#[test]
fn raw_cover_reuses_an_endorsed_merge_without_ancestor_write_authority() {
    let owner = SigningKey::from_bytes(&[11; 32]);
    let other = SigningKey::from_bytes(&[12; 32]);
    let mut store = MemoryRepo::default();
    let target = collection(&mut store, "raw-cover-endorsement", &owner);
    let a = archive(&[1]);
    let b = archive(&[2]);
    let c = archive(&[3]);
    let x = simplearchive_union::join(&a, &b).unwrap();
    let z = simplearchive_union::join(&x, &c).unwrap();
    let predecessor = CollectionMerge::sign(
        &other,
        target.handle(),
        (data(&a), leaf(target, &owner, &a).fingerprint()),
        (data(&b), leaf(target, &owner, &b).fingerprint()),
        data(&x),
    );
    let upper = CollectionMerge::sign(
        &owner,
        target.handle(),
        (data(&x), predecessor.fingerprint()),
        (data(&c), leaf(target, &owner, &c).fingerprint()),
        data(&z),
    );
    store.insert(CollectionRecord::Merge(predecessor)).unwrap();
    store.insert(CollectionRecord::Merge(upper)).unwrap();
    store.put::<SimpleArchive, _>(z.clone()).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(!target
        .writer_is_admitted(&snapshot, other.verifying_key())
        .unwrap());
    let cover = target.cover([a.get_handle(), b.get_handle(), c.get_handle()]);

    assert_eq!(cover.available(&snapshot).unwrap(), cover);
    let expected: TribleSet = z.try_from_blob().unwrap();
    assert_eq!(
        cover.materialize::<TribleSet, _>(&snapshot).unwrap(),
        expected
    );
    assert!(snapshot.collection(target).unwrap().support().is_empty());
    assert!(store
        .snapshot()
        .unwrap()
        .changes_since(&snapshot)
        .is_empty());
}

#[test]
fn raw_cover_decomposes_a_nonresident_result_into_both_resident_inputs() {
    let owner = SigningKey::from_bytes(&[21; 32]);
    let mut store = MemoryRepo::default();
    let target = collection(&mut store, "raw-cover-reverse", &owner);
    let a = archive(&[1]);
    let b = archive(&[2]);
    let c = simplearchive_union::join(&a, &b).unwrap();
    let merge = CollectionMerge::sign(
        &owner,
        target.handle(),
        (data(&a), leaf(target, &owner, &a).fingerprint()),
        (data(&b), leaf(target, &owner, &b).fingerprint()),
        data(&c),
    );
    store.insert(CollectionRecord::Merge(merge)).unwrap();
    store.put::<SimpleArchive, _>(a).unwrap();
    store.put::<SimpleArchive, _>(b).unwrap();
    let snapshot = store.snapshot().unwrap();
    let cover = target.cover([c.get_handle()]);

    assert_eq!(cover.available(&snapshot).unwrap(), cover);
    let expected: TribleSet = c.try_from_blob().unwrap();
    assert_eq!(
        cover.materialize::<TribleSet, _>(&snapshot).unwrap(),
        expected
    );
    assert!(snapshot.collection(target).unwrap().support().is_empty());
    assert!(store
        .snapshot()
        .unwrap()
        .changes_since(&snapshot)
        .is_empty());
}

#[test]
fn raw_cover_does_not_accept_one_input_as_a_complete_reverse_realization() {
    let owner = SigningKey::from_bytes(&[31; 32]);
    let mut store = MemoryRepo::default();
    let target = collection(&mut store, "raw-cover-partial-reverse", &owner);
    let a = archive(&[1]);
    let b = archive(&[2]);
    let c = simplearchive_union::join(&a, &b).unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            target.handle(),
            (data(&a), leaf(target, &owner, &a).fingerprint()),
            (data(&b), leaf(target, &owner, &b).fingerprint()),
            data(&c),
        )))
        .unwrap();
    store.put::<SimpleArchive, _>(a).unwrap();
    let snapshot = store.snapshot().unwrap();
    let cover = target.cover([c.get_handle()]);

    assert!(cover.available(&snapshot).unwrap().is_empty());
    match cover.materialize::<TribleSet, _>(&snapshot) {
        Err(CollectionMaterializationError::Missing { obligations, .. }) => {
            assert_eq!(obligations, BTreeSet::from([data(&c)]));
        }
        other => panic!("one child cannot realize the whole result: {other:?}"),
    }
}

#[test]
fn raw_cover_never_infers_an_unknown_sibling_from_a_single_input() {
    let owner = SigningKey::from_bytes(&[41; 32]);
    let mut store = MemoryRepo::default();
    let target = collection(&mut store, "raw-cover-no-sibling", &owner);
    let a = archive(&[1]);
    let b = archive(&[2]);
    let c = simplearchive_union::join(&a, &b).unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            target.handle(),
            (data(&a), leaf(target, &owner, &a).fingerprint()),
            (data(&b), leaf(target, &owner, &b).fingerprint()),
            data(&c),
        )))
        .unwrap();
    store.put::<SimpleArchive, _>(c).unwrap();
    let snapshot = store.snapshot().unwrap();
    let cover = target.cover([a.get_handle()]);

    assert!(cover.available(&snapshot).unwrap().is_empty());
    match cover.materialize::<TribleSet, _>(&snapshot) {
        Err(CollectionMaterializationError::Missing { obligations, .. }) => {
            assert_eq!(obligations, BTreeSet::from([data(&a)]));
        }
        other => panic!("the upper contains an unrequested sibling: {other:?}"),
    }
}

#[test]
fn raw_cover_ignores_unauthorized_equations_without_an_exact_endorsement() {
    let owner = SigningKey::from_bytes(&[51; 32]);
    let other = SigningKey::from_bytes(&[52; 32]);
    let mut store = MemoryRepo::default();
    let target = collection(&mut store, "raw-cover-unendorsed", &owner);
    let a = archive(&[1]);
    let b = archive(&[2]);
    let c = simplearchive_union::join(&a, &b).unwrap();
    let wrong = archive(&[9]);
    for (signer, output) in [(&owner, &c), (&other, &wrong)] {
        store
            .insert(CollectionRecord::Merge(CollectionMerge::sign(
                signer,
                target.handle(),
                (data(&a), leaf(target, &owner, &a).fingerprint()),
                (data(&b), leaf(target, &owner, &b).fingerprint()),
                data(output),
            )))
            .unwrap();
    }
    store.put::<SimpleArchive, _>(c.clone()).unwrap();
    store.put::<SimpleArchive, _>(wrong).unwrap();
    let snapshot = store.snapshot().unwrap();
    let cover = target.cover([a.get_handle(), b.get_handle()]);

    assert_eq!(cover.available(&snapshot).unwrap(), cover);
    let expected: TribleSet = c.try_from_blob().unwrap();
    assert_eq!(
        cover.materialize::<TribleSet, _>(&snapshot).unwrap(),
        expected
    );
}

#[test]
fn raw_cover_does_not_import_wrong_collection_or_output_witnesses() {
    for wrong_collection in [true, false] {
        let owner = SigningKey::from_bytes(&[61; 32]);
        let other = SigningKey::from_bytes(&[62; 32]);
        let mut store = MemoryRepo::default();
        let target = collection(&mut store, "raw-cover-wrong-witness", &owner);
        let foreign = collection(&mut store, "raw-cover-other-collection", &owner);
        let a = archive(&[1]);
        let b = archive(&[2]);
        let c = archive(&[3]);
        let x = simplearchive_union::join(&a, &b).unwrap();
        let expected_input = if wrong_collection {
            x.clone()
        } else {
            archive(&[4, 5])
        };
        let z = simplearchive_union::join(&expected_input, &c).unwrap();
        let predecessor_owner = if wrong_collection { foreign } else { target };
        let predecessor = CollectionMerge::sign(
            &other,
            predecessor_owner.handle(),
            (data(&a), leaf(predecessor_owner, &owner, &a).fingerprint()),
            (data(&b), leaf(predecessor_owner, &owner, &b).fingerprint()),
            data(&x),
        );
        let upper = CollectionMerge::sign(
            &owner,
            target.handle(),
            (data(&expected_input), predecessor.fingerprint()),
            (data(&c), leaf(target, &owner, &c).fingerprint()),
            data(&z),
        );
        store.insert(CollectionRecord::Merge(predecessor)).unwrap();
        store.insert(CollectionRecord::Merge(upper)).unwrap();
        store.put::<SimpleArchive, _>(x).unwrap();
        let snapshot = store.snapshot().unwrap();
        let cover = target.cover([a.get_handle(), b.get_handle()]);

        assert!(cover.available(&snapshot).unwrap().is_empty());
        assert!(matches!(
            cover.materialize::<TribleSet, _>(&snapshot),
            Err(CollectionMaterializationError::Missing { .. })
        ));
    }
}
