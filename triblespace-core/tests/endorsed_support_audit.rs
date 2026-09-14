//! Design probe only: payload identities do not bind a particular support path.
//! This exercises the public stateless resolver, not a changed attach policy.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use triblespace_core::blob::IntoBlob;
use triblespace_core::collection::{
    discover_collection_records, resolve_collection_semantics, simplearchive_union,
    succinctarchive_union, AdmissionPolicy, CollectionClaimValidation, CollectionData,
    CollectionDerive, CollectionMerge, CollectionPolicy, CollectionRecord, CollectionStore,
    CollectionStoreExt, CollectionValidationRequest,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};

#[test]
fn skipping_ancestor_admission_changes_support_without_changing_the_selected_derive() {
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
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            source.handle(),
            ca.data(),
            cb.data(),
            c,
        )))
        .unwrap();
    let selected = CollectionDerive::sign(&owner, target.handle(), c, t);
    store.insert(CollectionRecord::Derive(selected)).unwrap();
    let roots = BTreeSet::from([ca, cb, cz]);
    let lineage = BTreeMap::from([(target.handle(), source.handle())]);

    let observe = |store: &mut MemoryRepo, skip_ancestor_admission: bool| {
        let snapshot = store.snapshot().unwrap();
        let records = discover_collection_records(&snapshot).unwrap();
        let resolved = resolve_collection_semantics(&records, &lineage, &roots, |request| {
            let verdict = match request {
                CollectionValidationRequest::Merge { claim }
                    if !skip_ancestor_admission
                        && claim.public_key().raw != owner.verifying_key().to_bytes() =>
                {
                    CollectionClaimValidation::Pending
                }
                _ => CollectionClaimValidation::Accepted,
            };
            Ok::<CollectionClaimValidation<()>, Infallible>(verdict)
        })
        .unwrap();
        assert!(resolved
            .admitted_claims()
            .contains(&CollectionRecord::Derive(selected)));
        assert_eq!(
            resolved.semantics().frontier(target.handle()),
            Some(&BTreeSet::from([t])),
        );
        resolved.semantics().supporting_data(target.handle(), t)
    };

    let original: BTreeSet<CollectionData> = BTreeSet::from([ca.data(), cb.data()]);
    assert_eq!(observe(&mut store, false), original);
    assert_eq!(observe(&mut store, true), original);

    // Different operation inputs mean no functional-output conflict. This
    // false absorption is signed, but its producer has no source WRITE.
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &unrelated,
            source.handle(),
            c,
            cz.data(),
            c,
        )))
        .unwrap();

    assert_eq!(observe(&mut store, false), original);
    assert_eq!(
        observe(&mut store, true),
        BTreeSet::from([ca.data(), cb.data(), cz.data()]),
    );
}
