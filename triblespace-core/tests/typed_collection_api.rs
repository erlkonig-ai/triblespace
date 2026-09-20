use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use std::collections::BTreeSet;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive, SuccinctArchiveBlob,
    UnionArchive,
};
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
use triblespace_core::collection::succinctarchive_union;
use triblespace_core::collection::{
    write_capability, AdmissionPolicy, CollectionCommit, CollectionDerive, CollectionMerge,
    CollectionPolicy, CollectionRead, CollectionRecord,
    CollectionSnapshotExt, CollectionStore, CollectionStoreExt,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreGet, BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore,
    SnapshotSource, StoreChanges, StoreSnapshot, WantRead,
};
use triblespace_core::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

fn one_fact(seed: u8) -> TribleSet {
    let mut row = [seed; TRIBLE_LEN];
    row[16..32].fill(seed.wrapping_add(1));
    row[32..].fill(seed.wrapping_add(2));
    let mut facts = TribleSet::new();
    facts.insert(&Trible::force_raw(row).unwrap());
    facts
}

#[test]
fn simplearchive_collection_round_trips_typed_views() {
    let authority = SigningKey::from_bytes(&[41; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let expected = one_fact(7);
    let expected_member = expected.clone().to_blob().get_handle();
    let mut store = MemoryRepo::default();

    let collection = store.collection("typed-api", policy).unwrap();

    let commit = store
        .commit(collection, &authority, Fragment::from(expected.clone()))
        .unwrap();
    assert_eq!(
        Handle::<SimpleArchive>::from_hash(commit.data()),
        expected_member
    );

    let snapshot = store.snapshot().unwrap();
    let cover = collection.admitted(&snapshot).unwrap();
    assert_eq!(cover.collection(), collection);
    assert_eq!(cover.members().collect::<Vec<_>>(), vec![expected_member]);

    let materialized: TribleSet = collection.read(&snapshot).unwrap();
    assert_eq!(materialized, expected);
}

#[test]
fn succinct_cover_materializes_as_a_typed_union_archive() {
    let authority = SigningKey::from_bytes(&[42; 32]);
    let expected = one_fact(11);
    let source_blob: Blob<SimpleArchive> = expected.clone().to_blob();
    let raw = succinctarchive_union::derive_element(&source_blob).unwrap();
    let raw_handle = raw.get_handle();
    let mut store = MemoryRepo::default();

    let source_policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let target_policy = source_policy.clone();
    let source = store.collection("typed-api-source", source_policy).unwrap();
    let target = store
        .derive::<SuccinctArchiveBlob>(source, (), target_policy)
        .unwrap();

    store
        .commit(source, &authority, Fragment::from(expected.clone()))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let source_cover = source.admitted(&snapshot).unwrap();
    let ensured = block_on(store.ensure(target, &authority)).unwrap();
    let collection = ensured.collection(target).unwrap();
    assert_eq!(collection.support().unwrap(), &source_cover);
    let cover = collection.cover();
    assert_eq!(cover.collection(), target);
    assert_eq!(cover.members().collect::<Vec<_>>(), vec![raw_handle]);

    let materialized = collection.view::<UnionArchive<OrderedUniverse>>().unwrap();
    assert_eq!(materialized.segment_count(), 1);
    assert_eq!(materialized.iter().collect::<TribleSet>(), expected);

    // Ensure and maintenance share the same immutable snapshot result shape,
    // and a warm target is a fixed point of both.
    block_on(store.ensure(target, &authority)).unwrap();
    let maintained = block_on(store.maintain(target, &authority)).unwrap();
    let collection = maintained.collection(target).unwrap();
    assert_eq!(collection.support().unwrap(), &source_cover);
    assert_eq!(
        collection.cover().members().collect::<Vec<_>>(),
        vec![raw_handle]
    );

    // Later source growth cannot silently change the support paired with a
    // completed target realization: the observation is immutable.
    store
        .commit(source, &authority, Fragment::from(one_fact(12)))
        .unwrap();
    assert_eq!(collection.support().unwrap(), &source_cover);
    assert_eq!(
        collection.cover().members().collect::<Vec<_>>(),
        vec![raw_handle]
    );
}

#[test]
fn derived_apis_accept_a_derived_source_encoding() {
    let authority = SigningKey::from_bytes(&[43; 32]);
    let expected = one_fact(13);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let mut store = MemoryRepo::default();

    let source = store
        .collection("typed-api-exact-source", policy.clone())
        .unwrap();
    let raw = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .unwrap();
    let accelerated = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
        .unwrap();
    store
        .commit(source, &authority, Fragment::from(expected.clone()))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let support = source.admitted(&snapshot).unwrap();
    // The accelerated target stands for what the raw frontier stands on. With
    // no raw member realized that is nothing: neither operation constructs
    // the missing raw input, and neither errors.
    for compact in [false, true] {
        let snapshot = if compact {
            block_on(store.maintain(accelerated, &authority))
        } else {
            block_on(store.ensure(accelerated, &authority))
        }
        .unwrap();
        let observed = snapshot.collection(accelerated).unwrap();
        assert!(observed.support().unwrap().is_empty());
        assert!(observed.cover().is_empty());
        assert!(snapshot.collection(raw).unwrap().cover().is_empty());
        assert!(!snapshot.records().unwrap().any(|record| matches!(
            record.unwrap(),
            CollectionRecord::Derive(derive) if derive.collection() == raw.handle()
        )));
    }
    block_on(store.ensure(raw, &authority)).unwrap();
    let ensured = block_on(store.ensure(accelerated, &authority)).unwrap();
    let observed = ensured.collection(accelerated).unwrap();
    assert_eq!(observed.support().unwrap(), &support);
    assert_eq!(observed.cover().len(), 1);

    let maintained = block_on(store.maintain(accelerated, &authority)).unwrap();
    let materialized = maintained
        .collection(accelerated)
        .unwrap()
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap();
    assert_eq!(materialized.iter().collect::<TribleSet>(), expected);
}

#[test]
fn maintenance_follows_a_resident_source_union_across_target_size_tiers() {
    let authority = SigningKey::from_bytes(&[61; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let small = one_fact(211);
    let mut large = TribleSet::new();
    for ordinal in 0u64..512 {
        let mut row = [77; TRIBLE_LEN];
        row[8..16].copy_from_slice(&ordinal.to_be_bytes());
        row[56..64].copy_from_slice(&ordinal.to_be_bytes());
        large.insert(&Trible::force_raw(row).unwrap());
    }
    let expected = small.clone() + large.clone();
    let mut store = MemoryRepo::default();
    let source = store
        .collection("source-guided-unequal-tiers", policy.clone())
        .unwrap();
    let raw = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .unwrap();
    let accelerated = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
        .unwrap();
    for facts in [small, large] {
        store
            .commit(source, &authority, Fragment::from(facts))
            .unwrap();
    }
    block_on(store.ensure(raw, &authority)).unwrap();
    let children = block_on(store.ensure(accelerated, &authority)).unwrap();
    let support = source.admitted(&children).unwrap();
    let raw_cover = children.collection(raw).unwrap();
    let inputs = raw_cover
        .cover()
        .members()
        .map(|handle| {
            children
                .get::<Blob<SuccinctArchiveBlob>, _>(handle)
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(inputs.len(), 2);
    let accelerated_children = children.collection(accelerated).unwrap();
    let tiers = accelerated_children
        .cover()
        .members()
        .map(|handle| children.blob_info(handle).unwrap().unwrap().length.ilog2())
        .collect::<Vec<_>>();
    assert_eq!(tiers.len(), 2);
    assert_ne!(
        tiers[0], tiers[1],
        "ordinary target LSM would not pair these"
    );

    // An independent producer has already compacted the immediate source.
    // Target maintenance must consume this fact, not create upstream artifacts.
    let union = SuccinctArchiveBlob::merge(&inputs).unwrap();
    let expected_root =
        SuccinctArchive::<OrderedUniverse>::build_accelerated_root(union.clone()).unwrap();
    let union_handle = store.put(union).unwrap();
    let input_records = inputs
        .iter()
        .map(|input| {
            let data = Handle::<SuccinctArchiveBlob>::to_hash(input.get_handle());
            let _record = children
                .records()
                .unwrap()
                .map(Result::unwrap)
                .find(|record| {
                    matches!(record, CollectionRecord::Derive(derive)
                if derive.collection() == raw.handle() && derive.output() == data)
                })
                .expect("ensure published each raw input's DERIVE");
            data
        })
        .collect::<Vec<_>>();
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &authority,
            raw.handle(),
            input_records[0],
            input_records[1],
            Handle::<SuccinctArchiveBlob>::to_hash(union_handle),
        )))
        .unwrap();
    let before = store.snapshot().unwrap();
    assert_eq!(before.collection(raw).unwrap().cover().len(), 1);
    // BlobStoreList::blobs_diff permits an over-eager full listing. Compare
    // resident identities here because this test requires exact additions.
    let blobs_before = before
        .blobs()
        .map(|info| info.unwrap().handle)
        .collect::<BTreeSet<_>>();

    // Coverage is already complete: ensure does not perform upkeep.
    let ensured = block_on(store.ensure(accelerated, &authority)).unwrap();
    assert_eq!(ensured.collection(accelerated).unwrap().cover().len(), 2);
    assert_eq!(
        ensured
            .blobs()
            .map(|info| info.unwrap().handle)
            .collect::<BTreeSet<_>>(),
        blobs_before
    );
    let records_before = before
        .records()
        .unwrap()
        .collect::<Result<BTreeSet<_>, _>>()
        .unwrap();
    assert_eq!(
        ensured
            .records()
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap(),
        records_before
    );

    let after = block_on(store.maintain(accelerated, &authority)).unwrap();
    let observed = after.collection(accelerated).unwrap();
    assert_eq!(observed.support().unwrap(), &support);
    assert_eq!(
        observed.cover().members().collect::<Vec<_>>(),
        vec![expected_root.get_handle()]
    );
    assert_eq!(
        observed
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        expected
    );
    let blobs_after = after
        .blobs()
        .map(|info| info.unwrap().handle)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        blobs_after.difference(&blobs_before).count(),
        1,
        "only the target root is new"
    );
    assert!(blobs_before.is_subset(&blobs_after));
    assert_eq!(after.wants().unwrap().count(), 0);
    let records_after = after
        .records()
        .unwrap()
        .collect::<Result<BTreeSet<_>, _>>()
        .unwrap();
    for record in records_after.difference(&records_before) {
        record.verify_strict().unwrap();
        assert_eq!(
            record.public_key().raw,
            authority.verifying_key().to_bytes()
        );
        let collection = match record {
            CollectionRecord::Derive(record) => record.collection(),
            CollectionRecord::Merge(record) => record.collection(),
            CollectionRecord::Commit(_) => panic!("maintenance must not author roots"),
        };
        assert_eq!(
            collection,
            accelerated.handle(),
            "upstream equation published"
        );
    }
    assert_eq!(children.collection(raw).unwrap().cover().len(), 2);
    assert_eq!(children.collection(accelerated).unwrap().cover().len(), 2);

    let again = block_on(store.maintain(accelerated, &authority)).unwrap();
    assert_eq!(
        again
            .blobs()
            .map(|info| info.unwrap().handle)
            .collect::<BTreeSet<_>>(),
        blobs_after
    );
    assert_eq!(
        again
            .records()
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap(),
        records_after
    );
}

#[test]
fn ordinary_derived_operations_use_only_resident_immediate_source_support() {
    // Exercise ensure and maintain independently, with no pre-existing Rank9
    // realization that could hide a request for unsupported foundation data.
    for compact in [false, true] {
        let authority = SigningKey::from_bytes(&[50; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(authority.verifying_key()),
            AdmissionPolicy::direct(authority.verifying_key()),
        );
        let first = one_fact(21);
        let second = one_fact(22);
        let third = one_fact(23);
        let third_blob: Blob<SimpleArchive> = third.clone().to_blob();
        let raw_third = succinctarchive_union::derive_element(&third_blob)
            .unwrap()
            .get_handle();
        let expected_initial: TribleSet = first.iter().chain(second.iter()).copied().collect();
        let expected_final: TribleSet = expected_initial
            .iter()
            .chain(third.iter())
            .copied()
            .collect();
        let mut store = MemoryRepo::default();
        let source = store
            .collection("typed-api-immediate-source", policy.clone())
            .unwrap();
        let raw = store
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        let accelerated = store
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
            .unwrap();
        for facts in [first, second] {
            store
                .commit(source, &authority, Fragment::from(facts))
                .unwrap();
        }
        let warmed = block_on(store.maintain(raw, &authority)).unwrap();
        let initial_support = source.admitted(&warmed).unwrap();
        assert_eq!(initial_support.len(), 2);
        assert_eq!(
            warmed.collection(raw).unwrap().support().unwrap(),
            &initial_support
        );

        store
            .commit(source, &authority, Fragment::from(third))
            .unwrap();
        let before = store.snapshot().unwrap();
        let full_support = source.admitted(&before).unwrap();
        assert_eq!(full_support.len(), 3);
        assert_eq!(
            before.collection(raw).unwrap().support().unwrap(),
            &initial_support
        );
        assert!(!before.contains_blob(raw_third).unwrap());
        let records_before = before
            .records()
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();

        let after = if compact {
            block_on(store.maintain(accelerated, &authority))
        } else {
            block_on(store.ensure(accelerated, &authority))
        }
        .expect("ordinary Rank9 work must stop at the resident raw-source frontier");
        let observed = after.collection(accelerated).unwrap();
        assert_eq!(observed.support().unwrap(), &initial_support);
        assert_eq!(
            observed
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .collect::<TribleSet>(),
            expected_initial
        );
        assert_eq!(
            after.collection(raw).unwrap().support().unwrap(),
            &initial_support
        );
        assert!(!after.contains_blob(raw_third).unwrap());
        assert_eq!(after.wants().unwrap().count(), 0);
        let records_after = after
            .records()
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        assert!(records_before.is_subset(&records_after));
        for record in records_after.difference(&records_before) {
            let collection = match record {
                CollectionRecord::Derive(record) => record.collection(),
                CollectionRecord::Merge(record) => record.collection(),
                CollectionRecord::Commit(_) => panic!("downstream work must not author roots"),
            };
            assert_eq!(
                collection,
                accelerated.handle(),
                "upstream equation published"
            );
        }

        let raw_after = block_on(store.maintain(raw, &authority)).unwrap();
        assert_eq!(
            raw_after.collection(raw).unwrap().support().unwrap(),
            &full_support
        );
        let caught_up = block_on(store.maintain(accelerated, &authority)).unwrap();
        let observed = caught_up.collection(accelerated).unwrap();
        assert_eq!(observed.support().unwrap(), &full_support);
        assert_eq!(
            observed
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .collect::<TribleSet>(),
            expected_final
        );
        assert_eq!(
            warmed.collection(raw).unwrap().support().unwrap(),
            &initial_support
        );
    }
}

#[test]
fn ordinary_derived_operations_ignore_pending_immediate_source_output() {
    let authority = SigningKey::from_bytes(&[51; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let first = one_fact(24);
    let later = one_fact(25);
    let later_blob: Blob<SimpleArchive> = later.clone().to_blob();
    let missing_raw = succinctarchive_union::derive_element(&later_blob)
        .unwrap()
        .get_handle();
    let mut store = MemoryRepo::default();
    let source = store
        .collection("typed-api-pending-immediate-source", policy.clone())
        .unwrap();
    let raw = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .unwrap();
    let accelerated = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
        .unwrap();
    store
        .commit(source, &authority, Fragment::from(first.clone()))
        .unwrap();
    let warmed = block_on(store.maintain(raw, &authority)).unwrap();
    let initial_support = source.admitted(&warmed).unwrap();
    let later_commit = store
        .commit(source, &authority, Fragment::from(later))
        .unwrap();
    let pending = CollectionDerive::sign(
        &authority,
        raw.handle(),
        later_commit.data(),
        Handle::<SuccinctArchiveBlob>::to_hash(missing_raw),
    );
    store.insert(CollectionRecord::Derive(pending)).unwrap();
    let before = store.snapshot().unwrap();
    assert_eq!(source.admitted(&before).unwrap().len(), 2);
    assert_eq!(
        before.collection(raw).unwrap().support().unwrap(),
        &initial_support
    );
    assert!(!before.contains_blob(missing_raw).unwrap());
    let records_before = before
        .records()
        .unwrap()
        .collect::<Result<BTreeSet<_>, _>>()
        .unwrap();
    assert!(records_before.contains(&CollectionRecord::Derive(pending)));

    for compact in [false, true] {
        let after = if compact {
            block_on(store.maintain(accelerated, &authority))
        } else {
            block_on(store.ensure(accelerated, &authority))
        }
        .expect("a dangling raw output is not a required Rank9 input");
        let observed = after.collection(accelerated).unwrap();
        assert_eq!(observed.support().unwrap(), &initial_support);
        assert_eq!(
            observed
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .collect::<TribleSet>(),
            first
        );
        assert_eq!(
            after.collection(raw).unwrap().support().unwrap(),
            &initial_support
        );
        assert!(!after.contains_blob(missing_raw).unwrap());
        let records_after = after
            .records()
            .unwrap()
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        assert!(records_before.is_subset(&records_after));
        for record in records_after.difference(&records_before) {
            let collection = match record {
                CollectionRecord::Derive(record) => record.collection(),
                CollectionRecord::Merge(record) => record.collection(),
                CollectionRecord::Commit(_) => panic!("downstream work must not author roots"),
            };
            assert_eq!(
                collection,
                accelerated.handle(),
                "pending source work was repaired"
            );
        }
        assert_eq!(after.wants().unwrap().count(), 0);
    }
}

#[test]
fn ordinary_derived_operations_exclude_unauthorized_immediate_source_equations() {
    let authority = SigningKey::from_bytes(&[52; 32]);
    let unauthorized = SigningKey::from_bytes(&[53; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let admitted = one_fact(26);
    let denied = one_fact(27);
    let denied_blob: Blob<SimpleArchive> = denied.clone().to_blob();
    let denied_raw_blob = succinctarchive_union::derive_element(&denied_blob).unwrap();
    let denied_raw = denied_raw_blob.get_handle();
    let mut store = MemoryRepo::default();
    let source = store
        .collection("typed-api-unauthorized-immediate-source", policy.clone())
        .unwrap();
    let raw = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .unwrap();
    let accelerated = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
        .unwrap();
    store
        .commit(source, &authority, Fragment::from(admitted.clone()))
        .unwrap();
    let warmed = block_on(store.maintain(raw, &authority)).unwrap();
    let admitted_support = source.admitted(&warmed).unwrap();

    // Reusable physical work does not confer WRITE on its producer. The
    // immediate source equation must itself have an authorized endorser.
    let denied_commit = store
        .commit(source, &unauthorized, Fragment::from(denied))
        .unwrap();
    store
        .put::<SuccinctArchiveBlob, _>(denied_raw_blob)
        .unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &unauthorized,
            raw.handle(),
            denied_commit.data(),
            Handle::<SuccinctArchiveBlob>::to_hash(denied_raw),
        )))
        .unwrap();
    let before = store.snapshot().unwrap();
    assert!(before.contains_blob(denied_raw).unwrap());
    assert_eq!(source.admitted(&before).unwrap(), admitted_support);
    assert_eq!(
        before.collection(raw).unwrap().support().unwrap(),
        &admitted_support
    );

    for compact in [false, true] {
        let after = if compact {
            block_on(store.maintain(accelerated, &authority))
        } else {
            block_on(store.ensure(accelerated, &authority))
        }
        .unwrap();
        let observed = after.collection(accelerated).unwrap();
        assert_eq!(observed.support().unwrap(), &admitted_support);
        assert_eq!(
            observed
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .collect::<TribleSet>(),
            admitted
        );
        assert!(!after.records().unwrap().any(|record| matches!(
            record.unwrap(),
            CollectionRecord::Derive(record)
                if record.collection() == accelerated.handle()
                    && record.input() == Handle::<SuccinctArchiveBlob>::to_hash(denied_raw)
        )));
    }
}

#[test]
fn collection_write_admission_is_frozen_with_proof_evidence() {
    let authority = SigningKey::from_bytes(&[44; 32]);
    let writer = SigningKey::from_bytes(&[45; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let expected = one_fact(14);
    let expected_member = expected.clone().to_blob().get_handle();
    let mut store = MemoryRepo::default();
    let collection = store.collection("typed-api-evidence", policy).unwrap();
    store
        .commit(collection, &writer, Fragment::from(expected))
        .unwrap();
    let before = store.snapshot().unwrap();

    store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &authority,
            write_capability(),
            writer.verifying_key(),
        ))
        .unwrap();

    assert!(before
        .collection(collection)
        .unwrap()
        .support()
        .unwrap()
        .is_empty());

    let valid = store.snapshot().unwrap();
    let frozen = valid.clone();
    let admitted = valid.collection(collection).unwrap();
    assert_eq!(
        admitted.support().unwrap().members().collect::<Vec<_>>(),
        vec![expected_member]
    );
    assert_eq!(
        admitted.cover().members().collect::<Vec<_>>(),
        vec![expected_member]
    );

    let later = store.snapshot().unwrap();
    assert_eq!(
        later.collection(collection).unwrap().support().unwrap(),
        admitted.support().unwrap()
    );
    assert_eq!(
        valid.changes_since(&before),
        StoreChanges::CAPABILITY_PROOFS
    );
    assert_eq!(later.changes_since(&valid), StoreChanges::NONE);
    assert_eq!(
        frozen.collection(collection).unwrap().support().unwrap(),
        admitted.support().unwrap()
    );
    assert_eq!(
        valid.collection(collection).unwrap().support().unwrap(),
        admitted.support().unwrap()
    );
}

#[test]
fn collection_returns_the_maximal_resident_partial_realization() {
    let authority = SigningKey::from_bytes(&[46; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let first = one_fact(15);
    let second = one_fact(16);
    let first_member = first.clone().to_blob().get_handle();
    let second_member = second.clone().to_blob().get_handle();
    let mut store = MemoryRepo::default();
    let source = store
        .collection("typed-api-partial-source", policy.clone())
        .unwrap();
    let target = store
        .derive::<SuccinctArchiveBlob>(source, (), policy)
        .unwrap();

    store
        .commit(source, &authority, Fragment::from(first.clone()))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let first_support = source.admitted(&snapshot).unwrap();
    block_on(store.ensure(target, &authority)).unwrap();
    store
        .commit(source, &authority, Fragment::from(second))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let admitted_source = source.admitted(&snapshot).unwrap();
    assert_eq!(admitted_source.len(), 2);
    assert!(admitted_source.contains(first_member));
    assert!(admitted_source.contains(second_member));

    let observed = snapshot.collection(target).unwrap();
    assert_eq!(observed.support().unwrap(), &first_support);
    assert_eq!(observed.cover().len(), 1);
    assert_eq!(
        observed
            .view::<UnionArchive<OrderedUniverse>>()
            .unwrap()
            .iter()
            .collect::<TribleSet>(),
        first
    );
}

#[test]
fn dangling_commit_is_admitted_before_its_payload_becomes_readable() {
    let authority = SigningKey::from_bytes(&[47; 32]);
    let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
    let payload = one_fact(17).to_blob();
    let payload_handle = payload.get_handle();
    let mut store = MemoryRepo::default();
    let collection = store.collection("typed-api-dangling", policy).unwrap();
    let metadata = store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    let commit = CollectionCommit::sign(
        &authority,
        collection.handle(),
        Handle::<SimpleArchive>::to_hash(payload_handle),
        metadata,
    );
    store.insert(CollectionRecord::Commit(commit)).unwrap();

    let before = store.snapshot().unwrap();
    assert_eq!(
        before
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![CollectionRecord::Commit(commit)]
    );
    let admitted = collection.admitted(&before).unwrap();
    assert_eq!(admitted.members().collect::<Vec<_>>(), vec![payload_handle]);
    assert!(before.collection(collection).unwrap().cover().is_empty());

    store.put::<SimpleArchive, _>(payload).unwrap();
    let after = store.snapshot().unwrap();
    assert_eq!(
        collection
            .admitted(&after)
            .unwrap()
            .members()
            .collect::<Vec<_>>(),
        vec![payload_handle]
    );
    assert_eq!(collection.admitted(&after).unwrap(), admitted);
    assert_eq!(after.collection(collection).unwrap().cover().len(), 1);
    assert!(before.collection(collection).unwrap().cover().is_empty());
}

#[test]
fn proof_with_resident_definition_activates_commit_without_recursive_blob_closure() {
    let root = SigningKey::from_bytes(&[48; 32]);
    let writer = SigningKey::from_bytes(&[49; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(root.verifying_key()),
    );
    let expected = one_fact(18);
    let expected_member = expected.clone().to_blob().get_handle();
    let mut store = MemoryRepo::default();
    let collection = store
        .collection("typed-api-dangling-proof", policy)
        .unwrap();
    store
        .commit(collection, &writer, Fragment::from(expected))
        .unwrap();

    let before = store.snapshot().unwrap();
    assert!(collection.admitted(&before).unwrap().is_empty());

    let proof = CapabilityProof::new(
        CapabilityResource::from(collection.handle()),
        &root,
        write_capability(),
        writer.verifying_key(),
    );
    store.insert_proof(proof.clone()).unwrap();

    let after = store.snapshot().unwrap();
    assert_eq!(
        after
            .proofs()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![proof]
    );
    assert_eq!(
        collection
            .admitted(&after)
            .unwrap()
            .members()
            .collect::<Vec<_>>(),
        vec![expected_member]
    );
    assert!(collection.admitted(&before).unwrap().is_empty());
}
