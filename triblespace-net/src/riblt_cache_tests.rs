//! Independent regressions for the production source-bound cell cache.
//! Oracles use the pinned upstream encoder, not the cache's scatter routine.

use std::sync::{Arc, Barrier};

use ed25519_dalek::SigningKey;
use riblt::{Decoder, Encoder, RandomMapping, Symbol};
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
use triblespace_core::collection::{CollectionHandle, CollectionStore, read_capability};
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
use triblespace_core::repo::{SnapshotSource, StoreChanges, StoreSnapshot as _};

use crate::exchange::Tree;
use crate::host::StoreSnapshot;
use crate::riblt_cache::{
    CacheError, Cell, Generation, INHERITED_CELLS, INITIAL_CELLS, KeySymbol, MAX_INDEX,
};
use crate::riblt_store::CHUNK;
use crate::walk::WalkKind;
use crate::walk::tests::walking::{Node, open};

fn bytes(number: u64) -> [u8; 32] {
    // Full-width symbols, deliberately including many trailing zero bytes.
    let mut key = [0; 32];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key
}

fn references(numbers: impl IntoIterator<Item = u64>) -> Tree {
    let mut patch = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
    for number in numbers {
        patch.insert(&Entry::new(&bytes(number)));
    }
    Tree::References(patch)
}

fn same_cell(actual: &Cell, expected: &Cell, index: usize) {
    assert_eq!(actual.symbol, expected.symbol, "symbol at {index}");
    assert_eq!(actual.hash, expected.hash, "checksum at {index}");
    assert_eq!(actual.count, expected.count, "count at {index}");
}

fn upstream(generation: &Generation) -> Encoder<KeySymbol> {
    let mut encoder = Encoder::with_key(generation.key());
    generation
        .source()
        .for_each_key(|key| encoder.add_symbol(KeySymbol(key)));
    encoder
}

fn exact_prefix(generation: &Generation, length: usize) {
    let mut encoder = upstream(generation);
    for index in 0..length {
        same_cell(
            &generation.cell(index).unwrap(),
            &encoder.produce_next_coded_symbol(),
            index,
        );
    }
}

#[test]
fn riblt_cache_portable_raw32_checksum_and_mapping_vectors() {
    let symbol = KeySymbol(std::array::from_fn(|index| index as u8));
    let key = std::array::from_fn(|index| index as u8);
    // SipHash-2-4's 32-byte reference vector: no Rust slice length prefix.
    assert_eq!(symbol.keyed_hash(&key), 0x7127_512f_72f2_7cce);
    assert_eq!(symbol.keyed_mapping_seed(&key), symbol.keyed_hash(&key));
    let expected = [0, 1, 2, 5, 10, 32, 66, 84, 977, 1440, 1897, 2601, 3192];
    let mut mapping = RandomMapping::new(symbol.keyed_mapping_seed(&key));
    for index in expected {
        assert_eq!(mapping.last_index(), index);
        mapping.next_index();
    }
    let trailing_zero = KeySymbol(bytes(1));
    assert_eq!(trailing_zero.xor(&KeySymbol::default()), trailing_zero);
    assert_eq!(trailing_zero.xor(&trailing_zero), KeySymbol([0; 32]));
}

#[test]
fn riblt_cache_native_add_remove_noop_preserves_old_lease_and_tail() {
    let collection = CollectionHandle::new([17; 32]);
    let old =
        Generation::advance(collection, WalkKind::References, references(0..128), None).unwrap();
    assert_eq!(old.prepared().unwrap(), 0);
    exact_prefix(&old, 1300);
    assert_eq!(old.prepared().unwrap(), 2048);
    let first = old.cell(0).unwrap();
    let old_root = old.summary();

    let same = Generation::advance(
        collection,
        WalkKind::References,
        references((0..128).chain([0, 127])),
        Some(&old),
    )
    .unwrap();
    assert!(
        Arc::ptr_eq(&same, &old),
        "native duplicate insertion is a no-op"
    );

    let next = Generation::advance(
        collection,
        WalkKind::References,
        references(1..129),
        Some(&old),
    )
    .unwrap();
    assert!(!Arc::ptr_eq(&next, &old));
    assert_eq!(next.prepared().unwrap(), 2048);
    assert_ne!(next.summary(), old_root);
    exact_prefix(&next, 5000);
    exact_prefix(&old, 7000);
    same_cell(&old.cell(0).unwrap(), &first, 0);
    assert_eq!(old.summary(), old_root);
    assert_eq!(old.prepared().unwrap(), 8192);
    assert_eq!(next.prepared().unwrap(), 8192);
    exact_prefix(&next, 8192);
}

#[test]
fn riblt_cache_growth_and_update_order_have_identical_cells() {
    let collection = CollectionHandle::new([18; 32]);
    let make =
        || Generation::advance(collection, WalkKind::References, references(0..33), None).unwrap();
    let grown = make();
    grown.cell(4095).unwrap();
    let grown_then_updated = Generation::advance(
        collection,
        WalkKind::References,
        references(2..35),
        Some(&grown),
    )
    .unwrap();
    let small = make();
    small.cell(0).unwrap();
    let updated_then_grown = Generation::advance(
        collection,
        WalkKind::References,
        references(2..35),
        Some(&small),
    )
    .unwrap();
    assert_eq!(updated_then_grown.prepared().unwrap(), INITIAL_CELLS);
    updated_then_grown.cell(4095).unwrap();
    for index in 0..4096 {
        same_cell(
            &grown_then_updated.cell(index).unwrap(),
            &updated_then_grown.cell(index).unwrap(),
            index,
        );
    }
    exact_prefix(&grown_then_updated, 4096);
}

#[test]
fn riblt_cache_concurrent_growth_and_advance_never_mix_generations() {
    let collection = CollectionHandle::new([19; 32]);
    let old =
        Generation::advance(collection, WalkKind::References, references(0..64), None).unwrap();
    old.cell(0).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let readers: Vec<_> = [2047, 4095, 8191]
        .into_iter()
        .map(|index| {
            let old = old.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                old.cell(index).unwrap()
            })
        })
        .collect();
    barrier.wait();
    let next = Generation::advance(
        collection,
        WalkKind::References,
        references(8..72),
        Some(&old),
    )
    .unwrap();
    for reader in readers {
        reader.join().unwrap();
    }
    assert_eq!(old.prepared().unwrap(), 8192);
    assert_ne!(old.summary(), next.summary());
    exact_prefix(&old, 8192);
    exact_prefix(&next, 8192);
}

#[test]
fn riblt_cache_empty_source_and_exhaustion_do_not_publish_false_cells() {
    let generation = Generation::advance(
        CollectionHandle::new([20; 32]),
        WalkKind::References,
        references([]),
        None,
    )
    .unwrap();
    exact_prefix(&generation, INITIAL_CELLS + 1);
    let prepared = generation.prepared().unwrap();
    let first = generation.cell(0).unwrap();
    // Only the wire's u32 index domain is a ceiling.
    for index in [MAX_INDEX + 1, usize::MAX] {
        assert_eq!(generation.cell(index).unwrap_err(), CacheError::Exhausted);
        assert_eq!(generation.prepared().unwrap(), prepared);
        same_cell(&generation.cell(0).unwrap(), &first, 0);
    }
    assert_eq!(generation.summary().leaf_count(), 0);
}

#[test]
fn riblt_cache_grows_past_the_retired_cell_budget_in_file_backed_chunks() {
    // 1_048_576 cells was the retired MAX_CELLS. Growth past it maps more
    // chunks, keeps every earlier cell, and still matches upstream exactly.
    let retired = 1 << 20;
    let generation = Generation::advance(
        CollectionHandle::new([25; 32]),
        WalkKind::References,
        references(0..64),
        None,
    )
    .unwrap();
    let early: Vec<_> = (0..INITIAL_CELLS)
        .map(|index| generation.cell(index).unwrap())
        .collect();
    generation.cell(retired).unwrap();
    assert_eq!(generation.prepared().unwrap(), retired * 2);
    assert_eq!(
        generation.retained_bytes().unwrap(),
        retired * 2 / CHUNK * CHUNK * std::mem::size_of::<Cell>()
    );
    for (index, cell) in early.iter().enumerate() {
        same_cell(&generation.cell(index).unwrap(), cell, index);
    }
    exact_prefix(&generation, retired + 1);
    // An edit inherits at most INHERITED_CELLS cells, keeps the old lease
    // whole, and prepares the rest again, exactly, only when asked.
    let Tree::References(mut edited) = generation.source().clone() else {
        unreachable!()
    };
    edited.insert(&Entry::new(&bytes(64)));
    let next = Generation::advance(
        CollectionHandle::new([25; 32]),
        WalkKind::References,
        Tree::References(edited),
        Some(&generation),
    )
    .unwrap();
    assert_eq!(next.prepared().unwrap(), INHERITED_CELLS);
    assert_eq!(
        next.retained_bytes().unwrap(),
        INHERITED_CELLS * std::mem::size_of::<Cell>()
    );
    assert_eq!(generation.prepared().unwrap(), retired * 2);
    exact_prefix(&next, retired + 1);
    assert_eq!(next.prepared().unwrap(), retired * 2);
    exact_prefix(&generation, 4096);
    // A small prefix is inherited whole.
    let small = Generation::advance(
        CollectionHandle::new([26; 32]),
        WalkKind::References,
        references(0..8),
        None,
    )
    .unwrap();
    small.cell(INITIAL_CELLS).unwrap();
    let small_next = Generation::advance(
        CollectionHandle::new([26; 32]),
        WalkKind::References,
        references(0..9),
        Some(&small),
    )
    .unwrap();
    assert_eq!(small_next.prepared().unwrap(), 2 * INITIAL_CELLS);
    exact_prefix(&small_next, 2 * INITIAL_CELLS + 1);
}

#[test]
fn riblt_cache_collection_and_component_profiles_do_not_reuse_each_other() {
    let collection = CollectionHandle::new([21; 32]);
    let generation =
        Generation::advance(collection, WalkKind::References, references(0..4), None).unwrap();
    generation.cell(0).unwrap();
    let other_collection = Generation::advance(
        CollectionHandle::new([22; 32]),
        WalkKind::References,
        references(0..4),
        Some(&generation),
    )
    .unwrap();
    assert!(!Arc::ptr_eq(&generation, &other_collection));
    assert_ne!(generation.key(), other_collection.key());
    assert_eq!(other_collection.prepared().unwrap(), 0);
    exact_prefix(&other_collection, 1300);

    let other_component = Generation::advance(
        collection,
        WalkKind::Commit,
        Tree::Commit(PATCH::new()),
        Some(&generation),
    )
    .unwrap();
    assert_ne!(generation.key(), other_component.key());
    assert_eq!(other_component.prepared().unwrap(), 0);
    exact_prefix(&other_component, 1300);
}

#[test]
fn riblt_cache_typed_records_match_upstream() {
    let mut node = Node::new(81);
    let collection = node.hold("riblt-independent-cache", open());
    for number in 0..16 {
        node.commit(collection, number);
    }
    node.observe();
    let records = Tree::pinned(WalkKind::Commit, node.pinned(collection).repair());
    let generation = Generation::advance(collection, WalkKind::Commit, records, None).unwrap();
    assert_eq!(generation.summary().leaf_count(), 16);
    exact_prefix(&generation, 2049);
}

#[test]
fn riblt_cache_snapshot_constructor_tracks_authored_and_inserted_record_deltas() {
    let mut node = Node::new(91);
    let collection = node.hold("riblt-publication-cache", open());
    node.commit(collection, 1);
    let before = node.store.snapshot().unwrap();
    let first = StoreSnapshot::from_store_changes(
        before.clone(),
        &node.active,
        node.key.verifying_key(),
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let old_pin = first.collection(collection).unwrap();
    let old = old_pin.cache(WalkKind::Commit);
    exact_prefix(&old, 2049);
    let old_root = old.summary();

    let authored = node.commit(collection, 2);
    let mut remote = Node::new(92);
    assert_eq!(remote.hold("riblt-publication-cache", open()), collection);
    let incoming = remote.commit(collection, 3);
    node.store.insert(incoming).unwrap();
    let after = node.store.snapshot().unwrap();
    let second = StoreSnapshot::from_store_changes(
        after.clone(),
        &node.active,
        node.key.verifying_key(),
        Some(&before),
        Some(&first),
        after.changes_since(&before),
    )
    .unwrap();
    let new_pin = second.collection(collection).unwrap();
    let new = new_pin.cache(WalkKind::Commit);
    assert!(!Arc::ptr_eq(&old, &new));
    assert_eq!(old.summary(), old_root);
    assert_eq!(new.summary().leaf_count(), old_root.leaf_count() + 2);
    assert_eq!(new.summary(), new_pin.repair().records().summaries()[0]);
    let Tree::Commit(old_records) = old.source() else {
        panic!("record generation owns a record source");
    };
    let Tree::Commit(new_records) = new.source() else {
        panic!("record generation owns a record source");
    };
    for record in [authored, incoming] {
        assert!(old_records.get(&record.fingerprint().raw()).is_none());
        assert_eq!(new_records.get(&record.fingerprint().raw()).map(|view| triblespace_core::collection::CollectionRecord::Commit(view.to_record().unwrap())), Some(record));
    }
    exact_prefix(&new, 4097);
    exact_prefix(&old, 4097);

    let third = StoreSnapshot::from_store_changes(
        after.clone(),
        &node.active,
        node.key.verifying_key(),
        Some(&after),
        Some(&second),
        StoreChanges::NONE,
    )
    .unwrap();
    let unchanged = third.collection(collection).unwrap();
    for kind in [WalkKind::Commit, WalkKind::Derive, WalkKind::References] {
        assert!(Arc::ptr_eq(&new_pin.cache(kind), &unchanged.cache(kind)));
    }
}

#[test]
fn riblt_sparse_summary_matches_native_union_across_compressed_shapes() {
    // Ephemeral typed oracle, with common prefixes at many depths and overlapping
    // leaves. The sparse proof must not depend on attached values or insertion order.
    let keys: [[u8; 32]; 8] = std::array::from_fn(|index| {
        let mut key = [0xA5; 32];
        if index != 0 {
            key[[0, 1, 7, 15, 23, 30, 31][index - 1]] = index as u8;
        }
        key
    });
    for left_mask in [0u16, 1, 3, 7, 15, 42, 85, 127, 128, 170, 254, 255] {
        for right_mask in [0u16, 1, 2, 15, 42, 85, 128, 170, 254, 255] {
            let mut source = PATCH::<32, IdentitySchema, u64, Blake3Merkle>::new();
            let mut additions = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
            for (index, key) in keys.iter().enumerate() {
                if left_mask & (1 << index) != 0 {
                    source.insert(&Entry::with_value(key, index as u64));
                }
                if right_mask & (1 << index) != 0 {
                    additions.insert(&Entry::new(key));
                }
            }
            let mut actual_union = source.clone();
            for key in additions.iter() {
                actual_union.insert(&Entry::with_value(key, 1000));
            }
            let expected = actual_union.merkle_node(&[]).map_or_else(
                || crate::patch_repair::PatchSummary::new(None, 0).unwrap(),
                |node| {
                    crate::patch_repair::PatchSummary::new(Some(node.digest()), node.leaf_count())
                        .unwrap()
                },
            );
            assert_eq!(
                crate::riblt_proof::union_summary(&source, &additions),
                expected,
                "left={left_mask:#x}, right={right_mask:#x}"
            );
        }
    }
}

#[test]
fn riblt_sparse_summary_matches_real_record_and_scoped_authorization_trees() {
    let mut node = Node::new(101);
    let collection = node.hold("riblt-sparse-native-proof", open());
    let mut records = PATCH::new();
    let mut complete = PATCH::new();
    let mut additions = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
    for number in 0..24 {
        let record = node.commit(collection, number);
        let key = record.fingerprint().raw();
        let view = triblespace_core::collection::CollectionRecordView::from(record).as_commit().unwrap().clone();
        complete.insert(&Entry::with_value(&key, view.clone()));
        if number % 3 != 0 {
            records.insert(&Entry::with_value(&key, view));
        }
        if number % 3 != 1 {
            additions.insert(&Entry::new(&key));
        }
    }
    assert_eq!(
        Tree::Commit(records).summary_with_keys(&additions),
        Tree::Commit(complete).summary()
    );

    let root = SigningKey::from_bytes(&[102; 32]);
    let mut proofs = PATCH::new();
    let mut complete = PATCH::new();
    let mut additions = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
    for number in 103..119 {
        let delegate = SigningKey::from_bytes(&[number; 32]);
        let proof = CapabilityProof::new(
            CapabilityResource::new(collection.raw),
            &root,
            read_capability(),
            delegate.verifying_key(),
        );
        let relative = proof.id().raw;
        let mut physical = [0; 64];
        physical[..32].copy_from_slice(&collection.raw);
        physical[32..].copy_from_slice(&relative);
        complete.insert(&Entry::with_value(&physical, proof.clone()));
        if number % 2 == 0 {
            proofs.insert(&Entry::with_value(&physical, proof));
        }
        if number % 3 != 0 || number % 2 != 0 {
            additions.insert(&Entry::new(&relative));
        }
    }
    let expected = Tree::Authorization(collection, complete).summary();
    assert_eq!(
        Tree::Authorization(collection, proofs).summary_with_keys(&additions),
        expected
    );
    assert_ne!(
        Tree::References(additions).summary(),
        expected,
        "AUTH commits physical collection||proof keys, not bare wire suffixes"
    );
}

#[test]
fn riblt_cache_bounded_cold_edit_growth_cost_receipt() {
    // One diagnostic sample, not a benchmark distribution. Source key n is
    // n.to_be_bytes() || zero24; old 0..65_536, latest 32..65_568.
    // Native COW construction of the 32-remove/32-add snapshot is not timed.
    let collection = CollectionHandle::new([151; 32]);
    let old_source = references(0..65_536);
    let mut latest_source = old_source.clone();
    let Tree::References(latest_patch) = &mut latest_source else {
        unreachable!()
    };
    for number in 0..32 {
        latest_patch.remove(&bytes(number));
        latest_patch.insert(&Entry::new(&bytes(65_536 + number)));
    }
    let started = std::time::Instant::now();
    let old = Generation::advance(collection, WalkKind::References, old_source, None).unwrap();
    old.cell(65_535).unwrap();
    let cold = started.elapsed();
    let started = std::time::Instant::now();
    let latest =
        Generation::advance(collection, WalkKind::References, latest_source, Some(&old)).unwrap();
    let update = started.elapsed();
    let old_bytes = old.retained_bytes().unwrap();
    let update_bytes = latest.retained_bytes().unwrap();
    let started = std::time::Instant::now();
    latest.cell(131_071).unwrap();
    let growth = started.elapsed();
    assert_eq!(old.prepared().unwrap(), 65_536);
    assert_eq!(latest.prepared().unwrap(), 131_072);
    assert!(old_bytes >= 65_536 * std::mem::size_of::<Cell>());
    assert!(latest.retained_bytes().unwrap() >= 131_072 * std::mem::size_of::<Cell>());
    eprintln!(
        "RIBLT_CACHE_COST sample=1 fixture_construction=excluded update_source=native_cow_32remove_32add source=raw_be_u64_zero24 old_keys=0..65536 latest_keys=32..65568 cell_bytes={} old_prepared={} latest_prepared={} leased_old_alloc={} latest_alloc_after_edit={} latest_alloc_after_growth={} cold_us={} edit_including_diff_clone_scatter_us={} growth_us={} old_root={:?} latest_root={:?}",
        std::mem::size_of::<Cell>(),
        old.prepared().unwrap(),
        latest.prepared().unwrap(),
        old_bytes,
        update_bytes,
        latest.retained_bytes().unwrap(),
        cold.as_micros(),
        update.as_micros(),
        growth.as_micros(),
        old.summary(),
        latest.summary()
    );
}

fn subtract(remote: &Cell, local: &Cell) -> Cell {
    Cell {
        symbol: remote.symbol.xor(&local.symbol),
        hash: remote.hash ^ local.hash,
        count: remote.count.checked_sub(local.count).unwrap(),
    }
}

#[test]
fn riblt_cache_opposite_matching_prefixes_decode_at_the_same_frontier() {
    let collection = CollectionHandle::new([23; 32]);
    for (left, right) in [(0..0, 0..0), (0..32, 0..32), (0..32, 0..0), (0..64, 48..80)] {
        let a = Generation::advance(
            collection,
            WalkKind::References,
            references(left.clone()),
            None,
        )
        .unwrap();
        let b = Generation::advance(
            collection,
            WalkKind::References,
            references(right.clone()),
            None,
        )
        .unwrap();
        let mut da = Decoder::with_key(a.key());
        let mut db = Decoder::with_key(b.key());
        let mut finished = false;
        for index in 0..8192 {
            let ca = a.cell(index).unwrap();
            let cb = b.cell(index).unwrap();
            let ra = subtract(&cb, &ca);
            let rb = subtract(&ca, &cb);
            assert_eq!(ra.symbol, rb.symbol);
            assert_eq!(ra.hash, rb.hash);
            assert_eq!(ra.count, -rb.count);
            da.add_coded_symbol(ra);
            db.add_coded_symbol(rb);
            da.try_decode();
            db.try_decode();
            assert_eq!(da.decoded(), db.decoded(), "frontier {}", index + 1);
            if da.decoded() {
                // Scratch vectors exist only for this finite assertion.
                let mut local: Vec<_> = da.local().iter().map(|s| s.symbol.0).collect();
                let mut remote: Vec<_> = da.remote().iter().map(|s| s.symbol.0).collect();
                let mut other_local: Vec<_> = db.local().iter().map(|s| s.symbol.0).collect();
                let mut other_remote: Vec<_> = db.remote().iter().map(|s| s.symbol.0).collect();
                local.sort_unstable();
                remote.sort_unstable();
                other_local.sort_unstable();
                other_remote.sort_unstable();
                assert_eq!(local, other_remote);
                assert_eq!(remote, other_local);
                assert_eq!(
                    local,
                    left.clone()
                        .filter(|n| !right.contains(n))
                        .map(bytes)
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    remote,
                    right
                        .clone()
                        .filter(|n| !left.contains(n))
                        .map(bytes)
                        .collect::<Vec<_>>()
                );
                finished = true;
                break;
            }
        }
        assert!(finished, "bounded honest fixture must decode");
    }
}
