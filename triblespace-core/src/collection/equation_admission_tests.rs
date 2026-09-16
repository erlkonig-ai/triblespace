//! Signed equation producers are admitted by the target's frozen WRITE policy.

use ed25519_dalek::SigningKey;
use hifitime::Epoch;

use super::*;
use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive, SuccinctArchiveBlob,
    UnionArchive,
};
use crate::blob::{Blob, IntoBlob, TryFromBlob};
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

/// A Message-shaped chain with open admission: raw facts, their Succinct
/// elements, and Rank9 acceleration. Every helper below publishes exactly the
/// records it names and nothing else.
fn edit_chain() -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    Collection<SuccinctArchiveBlob>,
    Collection<Rank9AcceleratedSuccinctArchiveBlob>,
) {
    let mut store = MemoryRepo::default();
    let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
    let source = store.collection("edit-source", policy.clone()).unwrap();
    let succinct = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .unwrap();
    let rank9 = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
        .unwrap();
    (store, source, succinct, rank9)
}

fn raw_data(blob: &Blob<SimpleArchive>) -> CollectionData {
    Handle::<SimpleArchive>::to_hash(blob.get_handle())
}

fn succinct_data(blob: &Blob<SuccinctArchiveBlob>) -> CollectionData {
    Handle::<SuccinctArchiveBlob>::to_hash(blob.get_handle())
}

/// A resident raw union of two published facts, with its MERGE record.
fn merge_raw(
    store: &mut MemoryRepo,
    collection: Collection<SimpleArchive>,
    signer: &SigningKey,
    low: (&Blob<SimpleArchive>, CollectionRecordFingerprint),
    high: (&Blob<SimpleArchive>, CollectionRecordFingerprint),
) -> (Blob<SimpleArchive>, CollectionRecord) {
    let union = simplearchive_union::join(low.0, high.0).unwrap();
    store.put::<SimpleArchive, _>(union.clone()).unwrap();
    let record = CollectionRecord::Merge(CollectionMerge::sign(
        signer,
        collection.handle(),
        (raw_data(low.0), low.1),
        (raw_data(high.0), high.1),
        raw_data(&union),
    ));
    store.insert(record).unwrap();
    (union, record)
}

/// A resident Succinct element derived from one raw member, with its DERIVE.
fn derive_succinct(
    store: &mut MemoryRepo,
    succinct: Collection<SuccinctArchiveBlob>,
    signer: &SigningKey,
    input: (&Blob<SimpleArchive>, CollectionRecordFingerprint),
) -> (Blob<SuccinctArchiveBlob>, CollectionRecord) {
    let element = succinctarchive_union::derive_element(input.0).unwrap();
    store
        .put::<SuccinctArchiveBlob, _>(element.clone())
        .unwrap();
    let record = CollectionRecord::Derive(CollectionDerive::sign(
        signer,
        succinct.handle(),
        (raw_data(input.0), input.1),
        succinct_data(&element),
    ));
    store.insert(record).unwrap();
    (element, record)
}

fn residual_members<E>(residual: &[(CollectionData, Blob<E>, Vec<CollectionRecordFingerprint>)]) -> Vec<CollectionData>
where
    E: crate::blob::BlobEncoding,
{
    let mut members: Vec<_> = residual.iter().map(|(member, _, _)| *member).collect();
    members.sort();
    members
}

#[test]
fn edit_residual_keeps_distinct_witnesses_apart_behind_an_equal_payload() {
    // Two admitted producers publish the same payload a; the target consumed
    // it through one of them, and the mapped value of those bytes is covered
    // whichever identity the route names. The same two producers publish b,
    // which no route reaches: b is retained and both identities are reported
    // apart, never merged into one witness.
    let first = SigningKey::from_bytes(&[51; 32]);
    let second = SigningKey::from_bytes(&[52; 32]);
    let (mut store, source, succinct, _) = edit_chain();
    let a = archive(4);
    let b = archive(5);
    let c1 = publish(&mut store, source, &first, a.clone());
    publish(&mut store, source, &second, a.clone());
    let cb1 = publish(&mut store, source, &first, b.clone());
    let cb2 = publish(&mut store, source, &second, b.clone());
    derive_succinct(
        &mut store,
        succinct,
        &first,
        (&a, CollectionRecord::Commit(c1).fingerprint()),
    );
    let snapshot = store.snapshot().unwrap();
    let residual = snapshot.edit_residual_source_members(succinct).unwrap();
    assert_eq!(residual_members(&residual), vec![raw_data(&b)]);
    let mut witnesses = residual[0].2.clone();
    witnesses.sort();
    let mut expected = vec![
        CollectionRecord::Commit(cb1).fingerprint(),
        CollectionRecord::Commit(cb2).fingerprint(),
    ];
    expected.sort();
    assert_eq!(witnesses, expected);
}

#[test]
fn edit_residual_retains_a_coarse_member_whose_finer_part_is_covered() {
    // Source cover is the resident union ab; the target carried only a. The
    // route reaches a's commit, not the union's merge, so ab stays.
    let owner = SigningKey::from_bytes(&[53; 32]);
    let (mut store, source, succinct, _) = edit_chain();
    let a = archive(4);
    let b = archive(5);
    let ca = publish(&mut store, source, &owner, a.clone());
    let cb = publish(&mut store, source, &owner, b.clone());
    let (ab, merge) = merge_raw(
        &mut store,
        source,
        &owner,
        (&a, CollectionRecord::Commit(ca).fingerprint()),
        (&b, CollectionRecord::Commit(cb).fingerprint()),
    );
    derive_succinct(
        &mut store,
        succinct,
        &owner,
        (&a, CollectionRecord::Commit(ca).fingerprint()),
    );
    let snapshot = store.snapshot().unwrap();
    let residual = snapshot.edit_residual_source_members(succinct).unwrap();
    assert_eq!(residual_members(&residual), vec![raw_data(&ab)]);
    assert_eq!(residual[0].2, vec![merge.fingerprint()]);
}

#[test]
fn edit_residual_retains_redundant_fine_members_under_a_coarser_target() {
    // The union's payload never landed, so the source cover is the fine pair
    // a and b, while the target carried the union through the merge record.
    // The route reaches the merge, not the commits: a and b stay, redundant
    // for the value and safe.
    let owner = SigningKey::from_bytes(&[54; 32]);
    let (mut store, source, succinct, _) = edit_chain();
    let a = archive(4);
    let b = archive(5);
    let ca = publish(&mut store, source, &owner, a.clone());
    let cb = publish(&mut store, source, &owner, b.clone());
    let union = simplearchive_union::join(&a, &b).unwrap();
    let merge = CollectionRecord::Merge(CollectionMerge::sign(
        &owner,
        source.handle(),
        (raw_data(&a), CollectionRecord::Commit(ca).fingerprint()),
        (raw_data(&b), CollectionRecord::Commit(cb).fingerprint()),
        raw_data(&union),
    ));
    store.insert(merge).unwrap();
    let element = succinctarchive_union::derive_element(&union).unwrap();
    store
        .put::<SuccinctArchiveBlob, _>(element.clone())
        .unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &owner,
            succinct.handle(),
            (raw_data(&union), merge.fingerprint()),
            succinct_data(&element),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let residual = snapshot.edit_residual_source_members(succinct).unwrap();
    let mut expected = vec![raw_data(&a), raw_data(&b)];
    expected.sort();
    assert_eq!(residual_members(&residual), expected);
}

#[test]
fn edit_residual_retains_an_unmatched_coarse_member_across_commuting_paths() {
    // The target holds the union's value through derive-then-merge; the
    // source cover is the raw union. No route reaches the raw merge record,
    // so the coarse member is retained: conservative, overlapping, allowed.
    let owner = SigningKey::from_bytes(&[55; 32]);
    let (mut store, source, succinct, _) = edit_chain();
    let a = archive(4);
    let b = archive(5);
    let ca = publish(&mut store, source, &owner, a.clone());
    let cb = publish(&mut store, source, &owner, b.clone());
    let (ab, _) = merge_raw(
        &mut store,
        source,
        &owner,
        (&a, CollectionRecord::Commit(ca).fingerprint()),
        (&b, CollectionRecord::Commit(cb).fingerprint()),
    );
    let (sa, da) = derive_succinct(
        &mut store,
        succinct,
        &owner,
        (&a, CollectionRecord::Commit(ca).fingerprint()),
    );
    let (sb, db) = derive_succinct(
        &mut store,
        succinct,
        &owner,
        (&b, CollectionRecord::Commit(cb).fingerprint()),
    );
    let sab = succinctarchive_union::join(&sa, &sb).unwrap();
    store.put::<SuccinctArchiveBlob, _>(sab.clone()).unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            succinct.handle(),
            (succinct_data(&sa), da.fingerprint()),
            (succinct_data(&sb), db.fingerprint()),
            succinct_data(&sab),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let residual = snapshot.edit_residual_source_members(succinct).unwrap();
    assert_eq!(residual_members(&residual), vec![raw_data(&ab)]);
}

#[test]
fn edit_residual_lets_missing_or_mismatched_route_edges_prove_nothing() {
    // Two resident target merges: one names a missing input witness beside a
    // valid one, the other names a real witness with the wrong payload. The
    // valid edge covers a; nothing covers b; nothing fails.
    let owner = SigningKey::from_bytes(&[56; 32]);
    let (mut store, source, succinct, _) = edit_chain();
    let a = archive(4);
    let b = archive(5);
    let ca = publish(&mut store, source, &owner, a.clone());
    let cb = publish(&mut store, source, &owner, b.clone());
    let (sa, da) = derive_succinct(
        &mut store,
        succinct,
        &owner,
        (&a, CollectionRecord::Commit(ca).fingerprint()),
    );
    let sb = succinctarchive_union::derive_element(&b).unwrap();
    let sab = succinctarchive_union::join(&sa, &sb).unwrap();
    store.put::<SuccinctArchiveBlob, _>(sab.clone()).unwrap();
    let missing = CollectionRecordFingerprint::from_raw([0x77; 32]);
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            succinct.handle(),
            (succinct_data(&sa), da.fingerprint()),
            (succinct_data(&sb), missing),
            succinct_data(&sab),
        )))
        .unwrap();
    let sabb = succinctarchive_union::join(&sab, &sb).unwrap();
    store.put::<SuccinctArchiveBlob, _>(sabb.clone()).unwrap();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &owner,
            succinct.handle(),
            // Names a's real derive but claims b's payload came out of it.
            (succinct_data(&sb), da.fingerprint()),
            (succinct_data(&sab), missing),
            succinct_data(&sabb),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let residual = snapshot.edit_residual_source_members(succinct).unwrap();
    assert_eq!(residual_members(&residual), vec![raw_data(&b)]);
    assert_eq!(
        residual[0].2,
        vec![CollectionRecord::Commit(cb).fingerprint()]
    );
}

#[test]
fn edit_residual_keeps_the_source_available_until_the_target_output_lands() {
    // Record before blob at the Rank9 step: the accelerated output is signed
    // but absent, so its route proves nothing and the Succinct member stays
    // available; once the bytes land the residual is empty. No raw record or
    // payload is consulted for the Rank9 arm.
    let owner = SigningKey::from_bytes(&[57; 32]);
    let (mut store, source, succinct, rank9) = edit_chain();
    let a = archive(4);
    let ca = publish(&mut store, source, &owner, a.clone());
    let (sa, da) = derive_succinct(
        &mut store,
        succinct,
        &owner,
        (&a, CollectionRecord::Commit(ca).fingerprint()),
    );
    let accelerated = SuccinctArchive::<OrderedUniverse>::build_accelerated_root(sa.clone()).unwrap();
    let r_data = Handle::<Rank9AcceleratedSuccinctArchiveBlob>::to_hash(accelerated.get_handle());
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &owner,
            rank9.handle(),
            (succinct_data(&sa), da.fingerprint()),
            r_data,
        )))
        .unwrap();
    assert!(store
        .snapshot()
        .unwrap()
        .edit_residual_source_members(succinct)
        .unwrap()
        .is_empty());
    // The Rank9 arm on its own observation: the raw collection is neither
    // enumerated nor read, and no raw payload hash is consulted.
    let observed = super::observed_store::ObservedStore::new(store.snapshot().unwrap());
    let residual = observed.edit_residual_source_members(rank9).unwrap();
    assert_eq!(residual_members(&residual), vec![succinct_data(&sa)]);
    assert_eq!(residual[0].2, vec![da.fingerprint()]);
    let dependencies = observed.dependencies();
    assert!(!dependencies.all_records && !dependencies.all_blobs);
    assert!(!dependencies.blobs.contains(&raw_data(&a)), "raw payload read");
    assert!(
        !dependencies
            .records
            .contains(&CollectionRecordSelector::Collection(source.handle())),
        "raw collection enumerated"
    );
    assert!(
        !dependencies
            .records
            .contains(&CollectionRecordSelector::Fingerprint(
                CollectionRecord::Commit(ca).fingerprint()
            )),
        "raw record read"
    );
    store
        .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(accelerated)
        .unwrap();
    assert!(store
        .snapshot()
        .unwrap()
        .edit_residual_source_members(rank9)
        .unwrap()
        .is_empty());
}

#[test]
fn edit_residual_union_answers_the_facts_of_the_whole_source() {
    // The target carried the union ab; c is resident and uncarried. The
    // target view joined with the residual answers every fact the source
    // holds, and nothing the source lacks.
    let owner = SigningKey::from_bytes(&[58; 32]);
    let (mut store, source, succinct, _) = edit_chain();
    let a = archive(4);
    let b = archive(5);
    let c = archive(6);
    let ca = publish(&mut store, source, &owner, a.clone());
    let cb = publish(&mut store, source, &owner, b.clone());
    publish(&mut store, source, &owner, c.clone());
    let (ab, merge) = merge_raw(
        &mut store,
        source,
        &owner,
        (&a, CollectionRecord::Commit(ca).fingerprint()),
        (&b, CollectionRecord::Commit(cb).fingerprint()),
    );
    derive_succinct(&mut store, succinct, &owner, (&ab, merge.fingerprint()));
    let snapshot = store.snapshot().unwrap();
    let residual = snapshot.edit_residual_source_members(succinct).unwrap();
    assert_eq!(residual_members(&residual), vec![raw_data(&c)]);
    let mut answered: std::collections::BTreeSet<Trible> = snapshot
        .collection(succinct)
        .unwrap()
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap()
        .iter()
        .collect();
    for (_, blob, _) in &residual {
        let facts = TribleSet::try_from_blob(blob.clone()).unwrap();
        answered.extend(facts.iter());
    }
    let mut expected = std::collections::BTreeSet::new();
    for blob in [&a, &b, &c] {
        expected.extend(TribleSet::try_from_blob(blob.clone()).unwrap().iter());
    }
    assert_eq!(answered, expected);
}
