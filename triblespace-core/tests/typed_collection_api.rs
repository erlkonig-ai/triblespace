use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use hifitime::Epoch;
use std::collections::BTreeSet;

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive, SuccinctArchiveBlob,
    UnionArchive,
};
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::capability::{
    Capability, CapabilityMode, CapabilityProof, CapabilityResource, CapabilityValidity,
};
use triblespace_core::collection::succinctarchive_union;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionDerive, CollectionMerge, CollectionPolicy,
    CollectionRead, CollectionRealizationError, CollectionRecord, CollectionSnapshotExt,
    CollectionStore, CollectionStoreExt,
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

fn write_grant() -> Capability {
    Capability::new(
        triblespace_core::collection::write_capability(),
        CapabilityMode::Invoke,
    )
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

    let snapshot = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
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
    let snapshot = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
    let source_cover = source.admitted(&snapshot).unwrap();
    let ensured = block_on(store.ensure(target, &authority)).unwrap();
    let collection = ensured.collection_exact(target, &source_cover).unwrap();

    // Later source growth cannot silently change the support paired with the
    // completed target realization.
    store
        .commit(source, &authority, Fragment::from(one_fact(12)))
        .unwrap();
    assert_eq!(collection.support(), &source_cover);
    let cover = collection.cover();
    assert_eq!(cover.collection(), target);
    assert_eq!(cover.members().collect::<Vec<_>>(), vec![raw_handle]);

    let materialized = collection.view::<UnionArchive<OrderedUniverse>>().unwrap();
    assert_eq!(materialized.segment_count(), 1);
    assert_eq!(materialized.iter().collect::<TribleSet>(), expected);

    // The explicit-support ensure and admitted-support maintenance paths share
    // the same immutable snapshot result shape.
    block_on(store.ensure_exact(target, &authority, &source_cover)).unwrap();
    block_on(store.maintain(target, &authority)).unwrap();
    let maintained = block_on(store.maintain_exact(target, &authority, &source_cover)).unwrap();
    let collection = maintained.collection_exact(target, &source_cover).unwrap();
    assert_eq!(collection.support(), &source_cover);
    assert_eq!(
        collection.cover().members().collect::<Vec<_>>(),
        vec![raw_handle]
    );
}

#[test]
fn exact_apis_accept_a_derived_source_encoding() {
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

    let snapshot = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
    let support = source.admitted(&snapshot).unwrap();
    // Explicit support is a strict obligation, even when no immediate-source
    // member realizes it yet. Neither exact operation may construct raw input.
    for compact in [false, true] {
        let result = if compact {
            block_on(store.maintain_exact(accelerated, &authority, &support))
        } else {
            block_on(store.ensure_exact(accelerated, &authority, &support))
        };
        match result {
            Err(CollectionRealizationError::IncompleteCover {
                unsupported_members,
                ..
            }) => assert_eq!(
                unsupported_members,
                support
                    .members()
                    .map(Handle::<SimpleArchive>::to_hash)
                    .collect::<Vec<_>>()
            ),
            Err(error) => panic!("unexpected exact-source error: {error}"),
            Ok(_) => panic!("exact Rank9 realization must not construct its missing raw input"),
        }
    }
    block_on(store.ensure_exact(raw, &authority, &support)).unwrap();
    let ensured = block_on(store.ensure_exact(accelerated, &authority, &support)).unwrap();
    let observed = ensured.collection_exact(accelerated, &support).unwrap();
    assert_eq!(observed.support(), &support);
    assert_eq!(observed.cover().len(), 1);

    let maintained = block_on(store.maintain_exact(accelerated, &authority, &support)).unwrap();
    let materialized = maintained
        .collection_exact(accelerated, &support)
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
    store
        .insert(CollectionRecord::Merge(CollectionMerge::sign(
            &authority,
            raw.handle(),
            Handle::<SuccinctArchiveBlob>::to_hash(inputs[0].get_handle()),
            Handle::<SuccinctArchiveBlob>::to_hash(inputs[1].get_handle()),
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
    assert_eq!(observed.support(), &support);
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
        assert_eq!(warmed.collection(raw).unwrap().support(), &initial_support);

        store
            .commit(source, &authority, Fragment::from(third))
            .unwrap();
        let before = store.snapshot().unwrap();
        let full_support = source.admitted(&before).unwrap();
        assert_eq!(full_support.len(), 3);
        assert_eq!(before.collection(raw).unwrap().support(), &initial_support);
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
        assert_eq!(observed.support(), &initial_support);
        assert_eq!(
            observed
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .collect::<TribleSet>(),
            expected_initial
        );
        assert_eq!(after.collection(raw).unwrap().support(), &initial_support);
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
        assert_eq!(raw_after.collection(raw).unwrap().support(), &full_support);
        let caught_up = block_on(store.maintain(accelerated, &authority)).unwrap();
        let observed = caught_up.collection(accelerated).unwrap();
        assert_eq!(observed.support(), &full_support);
        assert_eq!(
            observed
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .collect::<TribleSet>(),
            expected_final
        );
        assert_eq!(warmed.collection(raw).unwrap().support(), &initial_support);
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
    assert_eq!(before.collection(raw).unwrap().support(), &initial_support);
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
        assert_eq!(observed.support(), &initial_support);
        assert_eq!(
            observed
                .view::<UnionArchive<OrderedUniverse>>()
                .unwrap()
                .iter()
                .collect::<TribleSet>(),
            first
        );
        assert_eq!(after.collection(raw).unwrap().support(), &initial_support);
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
fn ordinary_derived_operations_exclude_resident_but_unauthorized_source_members() {
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

    // Reusable physical work does not confer WRITE authority on its root.
    let denied_commit = store
        .commit(source, &unauthorized, Fragment::from(denied))
        .unwrap();
    store
        .put::<SuccinctArchiveBlob, _>(denied_raw_blob)
        .unwrap();
    store
        .insert(CollectionRecord::Derive(CollectionDerive::sign(
            &authority,
            raw.handle(),
            denied_commit.data(),
            Handle::<SuccinctArchiveBlob>::to_hash(denied_raw),
        )))
        .unwrap();
    let before = store.snapshot().unwrap();
    assert!(before.contains_blob(denied_raw).unwrap());
    assert_eq!(source.admitted(&before).unwrap(), admitted_support);
    assert_eq!(before.collection(raw).unwrap().support(), &admitted_support);

    for compact in [false, true] {
        let after = if compact {
            block_on(store.maintain(accelerated, &authority))
        } else {
            block_on(store.ensure(accelerated, &authority))
        }
        .unwrap();
        let observed = after.collection(accelerated).unwrap();
        assert_eq!(observed.support(), &admitted_support);
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
fn collection_uses_its_snapshots_frozen_authorization_instant() {
    let authority = SigningKey::from_bytes(&[44; 32]);
    let writer = SigningKey::from_bytes(&[45; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority.verifying_key()),
        AdmissionPolicy::direct(authority.verifying_key()),
    );
    let expected = one_fact(14);
    let expected_member = expected.clone().to_blob().get_handle();
    let mut store = MemoryRepo::default();
    let collection = store.collection("typed-api-clock", policy).unwrap();
    store
        .commit(collection, &writer, Fragment::from(expected))
        .unwrap();

    let validity =
        CapabilityValidity::new(Epoch::from_tai_seconds(10.0), Epoch::from_tai_seconds(20.0))
            .unwrap();
    store
        .insert_proof(CapabilityProof::issue_root(
            &authority,
            CapabilityResource::from(collection.handle()),
            write_grant(),
            Some(validity),
            writer.verifying_key(),
        ))
        .unwrap();

    let before = store.snapshot_at(Epoch::from_tai_seconds(9.0)).unwrap();
    assert!(before.collection(collection).unwrap().support().is_empty());

    let valid = store.snapshot_at(Epoch::from_tai_seconds(15.0)).unwrap();
    let frozen = valid.clone();
    let admitted = valid.collection(collection).unwrap();
    assert_eq!(
        admitted.support().members().collect::<Vec<_>>(),
        vec![expected_member]
    );
    assert_eq!(
        admitted.cover().members().collect::<Vec<_>>(),
        vec![expected_member]
    );

    let expired = store.snapshot_at(Epoch::from_tai_seconds(21.0)).unwrap();
    assert!(expired.collection(collection).unwrap().support().is_empty());
    assert_eq!(valid.changes_since(&before), StoreChanges::NONE);
    assert_eq!(expired.changes_since(&valid), StoreChanges::NONE);
    assert_eq!(frozen.instant(), Epoch::from_tai_seconds(15.0));
    assert_eq!(
        frozen.collection(collection).unwrap().support(),
        admitted.support()
    );
    assert_eq!(
        valid.collection(collection).unwrap().support(),
        admitted.support()
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
    let snapshot = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
    let first_support = source.admitted(&snapshot).unwrap();
    block_on(store.ensure_exact(target, &authority, &first_support)).unwrap();
    store
        .commit(source, &authority, Fragment::from(second))
        .unwrap();

    let snapshot = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
    let admitted_source = source.admitted(&snapshot).unwrap();
    assert_eq!(admitted_source.len(), 2);
    assert!(admitted_source.contains(first_member));
    assert!(admitted_source.contains(second_member));

    let observed = snapshot.collection(target).unwrap();
    assert_eq!(observed.support(), &first_support);
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
fn dangling_commit_is_raw_but_semantically_visible_only_in_a_later_snapshot() {
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

    let before = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
    assert_eq!(
        before
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![CollectionRecord::Commit(commit)]
    );
    assert!(collection.admitted(&before).unwrap().is_empty());

    store.put::<SimpleArchive, _>(payload).unwrap();
    let after = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
    assert_eq!(
        collection
            .admitted(&after)
            .unwrap()
            .members()
            .collect::<Vec<_>>(),
        vec![payload_handle]
    );
    assert!(collection.admitted(&before).unwrap().is_empty());
}

#[test]
fn self_contained_capability_proof_activates_commit_without_blob_closure() {
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

    let before = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
    assert!(collection.admitted(&before).unwrap().is_empty());

    let proof = CapabilityProof::issue_root(
        &root,
        CapabilityResource::from(collection.handle()),
        write_grant(),
        None,
        writer.verifying_key(),
    );
    store.insert_proof(proof.clone()).unwrap();

    let after = store.snapshot_at(Epoch::from_tai_seconds(0.0)).unwrap();
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
