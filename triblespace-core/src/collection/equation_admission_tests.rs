//! Signed equation producers are admitted by the target's frozen WRITE policy.

use ed25519_dalek::SigningKey;

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
    let _ca = publish(&mut store, collection, &root, a.clone());
    let _cb = publish(&mut store, collection, &root, b.clone());
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
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &root,
                collection.handle(),
                [low, high],
                Handle::<SimpleArchive>::to_hash(c_handle),
            )
            .unwrap(),
        ))
        .unwrap();
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &reader,
                collection.handle(),
                [low, high],
                Handle::<SimpleArchive>::to_hash(wrong),
            )
            .unwrap(),
        ))
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
        crate::collection::SourceLocator::of(ca.data().raw),
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
            crate::collection::SourceLocator::of(ca.data().raw),
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
        crate::collection::test_support::stood_for(&after.collection(target).unwrap())
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
fn equation_admission_uses_frozen_proof_evidence() {
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
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(
                &producer,
                collection.handle(),
                [ca.data(), cb.data()],
                Handle::<SimpleArchive>::to_hash(joined),
            )
            .unwrap(),
        ))
        .unwrap();
    let before = store.snapshot().unwrap();
    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &root,
            write_capability(),
            producer.verifying_key(),
        ))
        .unwrap();
    let admitted = store.snapshot().unwrap();
    let later = store.snapshot().unwrap();
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
    assert_eq!(later.collection(collection).unwrap().cover().len(), 1);
    assert_eq!(admitted.collection(collection).unwrap().cover().len(), 1);
    assert_eq!(
        later.records().unwrap().count(),
        before.records().unwrap().count()
    );
}

#[test]
fn target_stands_on_its_own_writers_whatever_its_source_admits() {
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
    // signed records but neither the input's payload nor the source writer's
    // grant.
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &source_writer,
            source.handle(),
            input_data,
            empty_metadata_handle(),
        )))
        .unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &target_owner,
            target.handle(),
            crate::collection::SourceLocator::of(input_data.raw),
            Handle::<SuccinctArchiveBlob>::to_hash(output),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(!source
        .writer_is_admitted(&snapshot, source_writer.verifying_key())
        .unwrap());
    assert!(source.admitted(&snapshot).unwrap().is_empty());
    // The deliberate lattice-v2 trust model: the leaf is admitted by the
    // target's own WRITE policy, and nothing checks its locator against the
    // source. The image stands on its admitted writer although nothing the
    // source admits stands behind the input it names, and no record is
    // walked to certify it either way.
    let unadmitted = snapshot.collection(target).unwrap();
    assert_eq!(
        unadmitted.cover().members().collect::<Vec<_>>(),
        vec![output]
    );
    assert_eq!(
        unadmitted.support().unwrap().members().collect::<Vec<_>>(),
        vec![output]
    );
    // What the view stands for in its source is read through its leaves by
    // locator: nothing yet.
    assert!(crate::collection::test_support::stood_for(&unadmitted).is_empty());

    // A commit written straight into the derived target, even by its own
    // admitted writer, names no foundation and attests nothing.
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &target_owner,
            target.handle(),
            input_data,
            empty_metadata_handle(),
        )))
        .unwrap();
    let mismatched = store.snapshot().unwrap().collection(target).unwrap();
    assert_eq!(
        mismatched.cover().members().collect::<Vec<_>>(),
        vec![output]
    );
    assert_eq!(mismatched.support().unwrap().len(), 1);

    grant_collection_write(
        &mut store,
        source.handle(),
        &source_owner,
        source_writer.verifying_key(),
    )
    .unwrap();
    let snapshot = store.snapshot().unwrap();
    assert!(!snapshot.contains_blob(input.get_handle()).unwrap());
    let requested = source.cover([input.get_handle()]);
    assert_eq!(source.admitted(&snapshot).unwrap(), requested);
    // Once the source admits the input, the leaf's locator names one of its
    // foundations: the view reads the same image and now stands for it.
    let attached = snapshot.collection(target).unwrap();
    assert_eq!(attached.cover().members().collect::<Vec<_>>(), vec![output]);
    assert_eq!(
        crate::collection::test_support::stood_for(&attached),
        requested
    );
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
fn indexed_reads_do_not_replace_absent_target_outputs_with_source_members() {
    // Record before blob at the Rank9 step: Succinct member B is resident and
    // admitted, its Rank9 equation B -> R is signed and admitted, but R's
    // payload has not landed. Reading Rank9 observes its own resident cover;
    // it neither substitutes B nor acquires or maintains an output.
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
        crate::collection::SourceLocator::of(ca.data().raw),
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
            crate::collection::SourceLocator::of(b_data.raw),
            r_data,
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let records_before = snapshot.records().unwrap().count();
    assert_eq!(
        snapshot
            .collection(succinct)
            .unwrap()
            .cover()
            .members()
            .collect::<Vec<_>>(),
        vec![b],
    );
    // The resident source does not make a missing Rank9 output readable.
    assert!(snapshot.collection(rank9).unwrap().cover().is_empty());
    // Asking published nothing.
    assert_eq!(
        store.snapshot().unwrap().records().unwrap().count(),
        records_before
    );
}
