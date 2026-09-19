//! An endorsed result's support is what the believed equations beneath it
//! say, and only those: an unauthorized alternative cannot change it, while an
//! authorized one is one more attestation and is believed like any other.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use triblespace_core::blob::IntoBlob;
use triblespace_core::collection::{
    simplearchive_union, succinctarchive_union, AdmissionPolicy, CollectionDerive, CollectionMerge,
    CollectionPolicy, CollectionRecord, CollectionSnapshotExt, CollectionStore, CollectionStoreExt,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};

#[test]
fn only_believed_alternative_equations_change_an_endorsed_results_support() {
    let owner = SigningKey::from_bytes(&[73; 32]);
    let unrelated = SigningKey::from_bytes(&[74; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(owner.verifying_key()),
        AdmissionPolicy::direct(owner.verifying_key()),
    );
    let mut store = MemoryRepo::default();
    let source = store.collection("support-audit", policy.clone()).unwrap();
    let target = store
        .derive::<SuccinctArchiveBlob>(source, (), policy)
        .unwrap();
    let a = entity! { metadata::name: "a" };
    let b = entity! { metadata::name: "b" };
    let z = entity! { metadata::name: "unrelated-z" };
    let c = simplearchive_union::join(&a.facts().clone().to_blob(), &b.facts().clone().to_blob())
        .unwrap();
    let raw = succinctarchive_union::derive_element(&c).unwrap();
    let ca = store.commit(source, &owner, a).unwrap();
    let cb = store.commit(source, &owner, b).unwrap();
    let cz = store.commit(source, &owner, z).unwrap();
    let c = Handle::<SimpleArchive>::to_hash(store.put::<SimpleArchive, _>(c).unwrap());
    let t =
        Handle::<SuccinctArchiveBlob>::to_hash(store.put::<SuccinctArchiveBlob, _>(raw).unwrap());
    let merged = CollectionRecord::Merge(CollectionMerge::sign(
        &owner,
        source.handle(),
        ca.data(),
        cb.data(),
        c,
    ));
    store.insert(merged).unwrap();
    let selected = CollectionDerive::sign(&owner, target.handle(), c, t);
    store.insert(CollectionRecord::Derive(selected)).unwrap();

    let observe = |store: &mut MemoryRepo| {
        let snapshot = store.snapshot().unwrap();
        let attached = snapshot.collection(target).unwrap();
        assert_eq!(
            attached
                .cover()
                .members()
                .map(Handle::<SuccinctArchiveBlob>::to_hash)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([t]),
        );
        attached
            .support()
            .unwrap()
            .members()
            .map(Handle::<SimpleArchive>::to_hash)
            .collect::<BTreeSet<_>>()
    };

    let original = BTreeSet::from([ca.data(), cb.data()]);
    assert_eq!(observe(&mut store), original);

    // Different operation inputs mean no functional-output conflict. This
    // absorption claims `c` already contains `z`. Signed by a key with no
    // source WRITE it is not believed, so nothing downstream moves.
    let absorb = |signer: &SigningKey| {
        CollectionRecord::Merge(CollectionMerge::sign(
            signer,
            source.handle(),
            c,
            cz.data(),
            c,
        ))
    };
    store.insert(absorb(&unrelated)).unwrap();
    assert_eq!(observe(&mut store), original);

    // Signed by the owner it is one more believed attestation about `c`, and
    // coverage is the monotone union of everything believed: `c` now stands
    // for `z` as well, and the derived image inherits that through its
    // unchanged DERIVE. A writer who lies about their own collection owns
    // that lie; the index does not second-guess an admitted equation.
    store.insert(absorb(&owner)).unwrap();
    let mut extended = original.clone();
    extended.insert(cz.data());
    assert_eq!(observe(&mut store), extended);
}
