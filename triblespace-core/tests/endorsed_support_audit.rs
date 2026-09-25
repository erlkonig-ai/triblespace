//! A result's support is what the believed equations beneath it say, and only
//! those: an unauthorized alternative cannot change it, while an authorized one
//! is one more attestation and is believed like any other.
//!
//! Support is collection-local, so the audit reads the result's own row in the
//! collection that holds it. A derived collection's image never inherits a
//! source node's support through its DERIVE: its leaves stand for one source
//! foundation each, named by locator.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::IntoBlob;
use triblespace_core::collection::{
    simplearchive_union, AdmissionPolicy, CollectionData, CollectionMerge, CollectionPolicy,
    CollectionRecord, CollectionSnapshotExt, CollectionStore, CollectionStoreExt, CoverageRead,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};

#[test]
fn only_believed_alternative_equations_change_a_results_support() {
    let owner = SigningKey::from_bytes(&[73; 32]);
    let unrelated = SigningKey::from_bytes(&[74; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(owner.verifying_key()),
        AdmissionPolicy::direct(owner.verifying_key()),
    );
    let mut store = MemoryRepo::default();
    let source = store.collection("support-audit", policy).unwrap();
    let a = entity! { metadata::name: "a" };
    let b = entity! { metadata::name: "b" };
    let z = entity! { metadata::name: "unrelated-z" };
    let c = simplearchive_union::join(&a.facts().clone().to_blob(), &b.facts().clone().to_blob())
        .unwrap();
    let ca = store.commit(source, &owner, a).unwrap();
    let cb = store.commit(source, &owner, b).unwrap();
    let cz = store.commit(source, &owner, z).unwrap();
    let c = Handle::<SimpleArchive>::to_hash(store.put::<SimpleArchive, _>(c).unwrap());
    let merged = CollectionRecord::Merge(
        CollectionMerge::sign(&owner, source.handle(), [ca.data(), cb.data()], c).unwrap(),
    );
    store.insert(merged).unwrap();

    // What `c` stands for, read from its row, and what a reader of the
    // collection selects.
    let observe = |store: &mut MemoryRepo| {
        let snapshot = store.snapshot().unwrap();
        let coverage =
            CoverageRead::coverage(&snapshot, &BTreeSet::from([source.handle()])).unwrap();
        let row: BTreeSet<CollectionData> = coverage
            .of(source.handle(), c)
            .expect("c has a row")
            .iter_ordered()
            .map(|raw| Inline::new(*raw))
            .collect();
        let cover: BTreeSet<CollectionData> = snapshot
            .collection(source)
            .unwrap()
            .cover()
            .members()
            .map(Handle::<SimpleArchive>::to_hash)
            .collect();
        (row, cover)
    };

    let original = BTreeSet::from([ca.data(), cb.data()]);
    assert_eq!(
        observe(&mut store),
        (original.clone(), BTreeSet::from([c, cz.data()]))
    );

    // Different operation inputs mean no functional-output conflict. This
    // absorption claims `c` already contains `z`. Signed by a key with no
    // WRITE it is not believed, so nothing moves.
    let absorb = |signer: &SigningKey| {
        CollectionRecord::Merge(
            CollectionMerge::sign(signer, source.handle(), [c, cz.data()], c).unwrap(),
        )
    };
    store.insert(absorb(&unrelated)).unwrap();
    assert_eq!(
        observe(&mut store),
        (original.clone(), BTreeSet::from([c, cz.data()]))
    );

    // Signed by the owner it is one more believed attestation about `c`, and
    // coverage is the monotone union of everything believed: `c` now stands
    // for `z` as well, and a reader stands on `c` alone. A writer who lies
    // about their own collection owns that lie; the index does not
    // second-guess an admitted equation.
    store.insert(absorb(&owner)).unwrap();
    let mut extended = original;
    extended.insert(cz.data());
    assert_eq!(observe(&mut store), (extended, BTreeSet::from([c])));
}
