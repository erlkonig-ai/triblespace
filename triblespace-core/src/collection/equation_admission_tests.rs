//! Signed equation producers are admitted by the target's frozen WRITE policy.

use ed25519_dalek::SigningKey;
use hifitime::Epoch;

use super::*;
use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use crate::blob::{Blob, IntoBlob};
use crate::capability::{CapabilityProof, CapabilityResource};
use crate::inline::encodings::hash::Handle;
use crate::repo::memoryrepo::MemoryRepo;
use crate::repo::{BlobStoreList, BlobStorePut, CapabilityProofStore, SnapshotSource};
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
) -> CollectionCommit {
    let data = store.put::<SimpleArchive, _>(blob).unwrap();
    let metadata = store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    let commit = CollectionCommit::sign(
        signer,
        collection.handle(),
        Handle::<SimpleArchive>::to_hash(data),
        metadata,
    );
    store.insert(CollectionRecord::Commit(commit)).unwrap();
    commit
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
    let ca = publish(&mut store, collection, &root, a.clone());
    let cb = publish(&mut store, collection, &root, b.clone());
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
            (low, CollectionRecord::Commit(ca).fingerprint()),
            (high, CollectionRecord::Commit(cb).fingerprint()),
            Handle::<SimpleArchive>::to_hash(c_handle),
        )))
        .unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &reader,
            collection.handle(),
            (low, CollectionRecord::Commit(ca).fingerprint()),
            (high, CollectionRecord::Commit(cb).fingerprint()),
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
    let ca = publish(&mut store, source, &source_owner, a.clone());
    let output = store
        .put::<SuccinctArchiveBlob, _>(succinctarchive_union::derive_element(&a).unwrap())
        .unwrap();
    let equation = CollectionRecord::Derive(CollectionDerive::sign(
        &producer,
        target.handle(),
        (ca.data(), CollectionRecord::Commit(ca).fingerprint()),
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
            (ca.data(), CollectionRecord::Commit(ca).fingerprint()),
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
            .unwrap()
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
fn equation_authority_is_timeless_across_snapshot_clocks() {
    let root = SigningKey::from_bytes(&[31; 32]);
    let producer = SigningKey::from_bytes(&[32; 32]);
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(
            "timeless-equation-authority",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::delegable(root.verifying_key()),
            ),
        )
        .unwrap();
    let a = archive(5);
    let b = archive(6);
    let ca = publish(&mut store, collection, &root, a.clone());
    let cb = publish(&mut store, collection, &root, b.clone());
    let joined = store
        .put::<SimpleArchive, _>(simplearchive_union::join(&a, &b).unwrap())
        .unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &producer,
            collection.handle(),
            (ca.data(), CollectionRecord::Commit(ca).fingerprint()),
            (cb.data(), CollectionRecord::Commit(cb).fingerprint()),
            Handle::<SimpleArchive>::to_hash(joined),
        )))
        .unwrap();
    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &root,
            write_capability(),
            producer.verifying_key(),
        ))
        .unwrap();
    let before = store.snapshot_at(Epoch::from_tai_seconds(9.0)).unwrap();
    let admitted = store.snapshot_at(Epoch::from_tai_seconds(15.0)).unwrap();
    let later = store.snapshot_at(Epoch::from_tai_seconds(21.0)).unwrap();
    assert_eq!(before.collection(collection).unwrap().cover().len(), 1);
    assert_eq!(
        admitted
            .collection(collection)
            .unwrap()
            .cover()
            .members()
            .collect::<Vec<_>>(),
        vec![joined]
    );
    assert_eq!(later.collection(collection).unwrap().cover().len(), 1);
    assert_eq!(admitted.collection(collection).unwrap().cover().len(), 1);
    assert_eq!(
        later.records().unwrap().count(),
        before.records().unwrap().count()
    );
}

#[test]
fn selected_endorsement_reads_without_ancestry_but_support_needs_exact_records() {
    let source_owner = SigningKey::from_bytes(&[41; 32]);
    let source_writer = SigningKey::from_bytes(&[42; 32]);
    let target_owner = SigningKey::from_bytes(&[43; 32]);
    let mut store = MemoryRepo::default();
    let source = store
        .collection(
            "endorsed-source-without-bytes",
            CollectionPolicy::new(
                AdmissionPolicy::direct(source_owner.verifying_key()),
                AdmissionPolicy::delegable(source_owner.verifying_key()),
            ),
        )
        .unwrap();
    let target = store
        .derive::<SuccinctArchiveBlob>(
            source,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(target_owner.verifying_key()),
            ),
        )
        .unwrap();
    let input = archive(7);
    let input_data = Handle::<SimpleArchive>::to_hash(input.get_handle());
    let output = store
        .put::<SuccinctArchiveBlob, _>(succinctarchive_union::derive_element(&input).unwrap())
        .unwrap();
    // The producing node validated this input. This receiving store has the
    // signed record but neither its payload nor the source writer's grant.
    let ancestor = CollectionRecord::Commit(CollectionCommit::sign(
        &source_writer,
        source.handle(),
        input_data,
        empty_metadata_handle(),
    ));
    let selected = CollectionRecord::Derive(CollectionDerive::sign(
        &target_owner,
        target.handle(),
        (input_data, ancestor.fingerprint()),
        Handle::<SuccinctArchiveBlob>::to_hash(output),
    ));
    store.insert(selected).unwrap();
    let missing = store.snapshot().unwrap().collection(target).unwrap();
    assert_eq!(missing.cover().members().collect::<Vec<_>>(), vec![output]);
    assert!(matches!(
        missing.support(),
        Err(CollectionRealizationError::IncompleteSupport { .. })
    ));

    // An existing record in the wrong collection cannot satisfy a witness.
    let wrong_collection = CollectionRecord::Commit(CollectionCommit::sign(
        &source_writer,
        target.handle(),
        input_data,
        empty_metadata_handle(),
    ));
    store.insert(wrong_collection).unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &target_owner,
            target.handle(),
            (input_data, wrong_collection.fingerprint()),
            Handle::<SuccinctArchiveBlob>::to_hash(output),
        )))
        .unwrap();
    let mismatched = store.snapshot().unwrap().collection(target).unwrap();
    assert_eq!(
        mismatched.cover().members().collect::<Vec<_>>(),
        vec![output]
    );
    assert!(matches!(
        mismatched.support(),
        Err(CollectionRealizationError::IncompleteSupport { .. })
    ));

    // A source record with a different output is not evidence for this input.
    let other_data = Handle::<SimpleArchive>::to_hash(archive(8).get_handle());
    let wrong_payload = CollectionRecord::Commit(CollectionCommit::sign(
        &source_writer,
        source.handle(),
        other_data,
        empty_metadata_handle(),
    ));
    store.insert(wrong_payload).unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &target_owner,
            target.handle(),
            (input_data, wrong_payload.fingerprint()),
            Handle::<SuccinctArchiveBlob>::to_hash(output),
        )))
        .unwrap();
    let mismatched = store.snapshot().unwrap().collection(target).unwrap();
    assert_eq!(
        mismatched.cover().members().collect::<Vec<_>>(),
        vec![output]
    );
    assert!(matches!(
        mismatched.support(),
        Err(CollectionRealizationError::IncompleteSupport { .. })
    ));

    store.insert(ancestor).unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(!snapshot.contains_blob(input.get_handle()).unwrap());
    assert!(!source
        .writer_is_admitted(&snapshot, source_writer.verifying_key())
        .unwrap());
    assert!(!source
        .reader_is_admitted(&snapshot, target_owner.verifying_key())
        .unwrap());
    assert!(source.admitted(&snapshot).unwrap().is_empty());
    let attached = snapshot.collection(target).unwrap();
    assert_eq!(attached.cover().members().collect::<Vec<_>>(), vec![output]);
    // Ordinary attachment retained every independent target endorsement.
    // A good route does not fill in the other malformed routes' provenance.
    assert!(matches!(
        attached.support(),
        Err(CollectionRealizationError::IncompleteSupport { .. })
    ));
    // An explicit support request can choose the now-complete exact route.
    let requested = source.cover([input.get_handle()]);
    let exact = snapshot.collection_exact(target, &requested).unwrap();
    assert_eq!(exact.support().unwrap(), &requested);
    assert_eq!(
        attached
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .count(),
        1
    );
}

#[test]
fn residual_selection_names_resident_source_members_without_demanding_absent_outputs() {
    // Record before blob at the Rank9 step: Succinct member B is resident and
    // admitted, its Rank9 equation B -> R is signed and admitted, but R's
    // payload has not landed. A reader must still be offered B, the resident
    // input it can query directly; the residual is a read, not an
    // acquisition, and never demands R.
    let owner = SigningKey::from_bytes(&[41; 32]);
    let mut store = MemoryRepo::default();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(owner.verifying_key()),
    );
    let source = store.collection("residual-source", policy.clone()).unwrap();
    let succinct = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .unwrap();
    let rank9 = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
        .unwrap();
    let a = archive(4);
    let ca = publish(&mut store, source, &owner, a.clone());
    let b = store
        .put::<SuccinctArchiveBlob, _>(succinctarchive_union::derive_element(&a).unwrap())
        .unwrap();
    let b_data = Handle::<SuccinctArchiveBlob>::to_hash(b);
    let b_record = CollectionRecord::Derive(CollectionDerive::sign(
        &owner,
        succinct.handle(),
        (ca.data(), CollectionRecord::Commit(ca).fingerprint()),
        b_data,
    ));
    store.insert(b_record).unwrap();
    // R: a signed output whose bytes never arrive.
    let r_data = Handle::<Rank9AcceleratedSuccinctArchiveBlob>::to_hash(
        Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(anybytes::Bytes::from(vec![7u8; 64]))
            .get_handle(),
    );
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &owner,
            rank9.handle(),
            (b_data, b_record.fingerprint()),
            r_data,
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let records_before = snapshot.records().unwrap().count();
    // Succinct is exact for the resident source: nothing residual there.
    assert!(snapshot
        .uncovered_source_members(succinct)
        .unwrap()
        .is_empty());
    // Rank9 has nothing resident to read...
    assert!(snapshot.collection(rank9).unwrap().cover().is_empty());
    // ...and the residual names B, resident and readable, instead of failing
    // on the absent R.
    let residual = snapshot.uncovered_source_members(rank9).unwrap();
    assert_eq!(
        residual
            .iter()
            .map(|(member, _, _)| *member)
            .collect::<Vec<_>>(),
        vec![b_data]
    );
    assert!(residual[0].2.contains(&b_record.fingerprint()));
    // Asking published nothing.
    assert_eq!(
        store.snapshot().unwrap().records().unwrap().count(),
        records_before
    );
}
