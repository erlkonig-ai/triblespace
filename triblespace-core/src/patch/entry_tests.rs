use super::*;
use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};

mod permuted {
    crate::key_segmentation!(Segments, 4, [1, 1, 1, 1]);
    crate::key_schema!(Schema, Segments, 4, [2, 0, 3, 1]);
}

mod physical_order {
    crate::key_segmentation!(Segments, 224, [32, 32, 32, 32, 96]);
    crate::key_schema!(Schema, Segments, 224, [0, 1, 3, 2, 4]);
}

#[test]
fn ordered_entries_get_key_returns_physical_heap_and_archive_bytes_under_permutation() {
    #[repr(C, align(16))]
    struct Rows([[u8; 224]; 3]);
    let rows = Arc::new(Rows(std::array::from_fn(|n| {
        std::array::from_fn(|i| (i as u8).wrapping_add(n as u8))
    })));
    let owner: Arc<dyn ArchiveOwner> = rows.clone();
    let mut archive = PATCH::<224, physical_order::Schema>::new();
    let mut heap = PATCH::<224, physical_order::Schema>::new();
    for key in &rows.0 {
        archive.insert_archive(&unsafe { ArchiveEntry::new(NonNull::from(key), &owner) });
        heap.insert(&Entry::new(key));
    }
    for key in &rows.0 {
        let ordered = physical_order::Schema::tree_ordered(key);
        assert_ne!(ordered, *key);
        let found = archive.get_key(&ordered).unwrap();
        assert_eq!(found, key);
        assert_eq!(found.as_ptr(), key.as_ptr());
        assert_ne!(found.as_ptr(), ordered.as_ptr());
        let stored = heap.get_key(&ordered).unwrap();
        assert_eq!(stored, key);
        assert!(heap.iter().any(|k| std::ptr::eq(k, stored)));
        assert_ne!(stored.as_ptr(), key.as_ptr());
        for position in [0, 31, 32, 63, 64, 95, 96, 127, 128, 159, 160, 191, 192, 223] {
            let mut missing = ordered;
            missing[position] ^= 0x80;
            assert!(archive.get_key(&missing).is_none());
            assert!(heap.get_key(&missing).is_none());
        }
    }
    assert!(archive.get_key(&[255; 224]).is_none());
    let pinned = archive.clone();
    archive.remove(&physical_order::Schema::tree_ordered(&rows.0[0]));
    assert_eq!(pinned.len(), 3);
    assert_eq!(archive.len(), 2);
}

fn key(n: u8) -> [u8; 4] { [n % 5, n, n % 7, n.wrapping_mul(19)] }

fn checked_insert<H: PatchHash + std::fmt::Debug>() {
    let mut patch = PATCH::<4, permuted::Schema, Arc<u8>, H>::new();
    let mut ordinary = PATCH::<4, permuted::Schema, Arc<u8>, H>::new();
    let factories = Cell::new(0);
    let occupied = Cell::new(0);
    let mut snapshots = Vec::new();
    for n in (0..127_u16).map(|n| (n * 53 % 127) as u8) {
        // Exercise both unique paths and paths shared with older snapshots.
        if n % 13 == 0 { snapshots.push(patch.clone()); }
        let value = Arc::new(n);
        assert!(patch.try_insert_with(&key(n), || {
            factories.set(factories.get() + 1);
            value.clone()
        }, |_| -> Result<(), ()> { panic!("unexpected occupied key") }).unwrap());
        ordinary.insert(&Entry::with_value(&key(n), value));
        assert_eq!(patch, ordinary);
    }
    assert_eq!(factories.get(), 127);
    let before = patch.clone();
    for n in 0..127 {
        let tree_key = permuted::Schema::tree_ordered(&key(n));
        let original = patch.get(&tree_key).unwrap().clone();
        assert!(!patch.try_insert_with(&key(n), || panic!("duplicate factory"), |value| {
            occupied.set(occupied.get() + 1);
            assert!(Arc::ptr_eq(value, &original));
            Ok::<_, ()>(())
        }).unwrap());
        assert!(patch.shares_root(&before));
        assert!(Arc::ptr_eq(patch.get(&tree_key).unwrap(), &original));
    }
    assert_eq!(occupied.get(), 127);
    assert_eq!(patch.try_insert_with(&key(12), || panic!("collision factory"), |_| Err("collision")), Err("collision"));
    assert!(patch.shares_root(&before));
    for missing in [false, true] {
        let attempted = if missing { [255; 4] } else { key(12) };
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = patch.try_insert_with(&attempted, || panic!("vacant panic"), |_| -> Result<(), ()> {
                panic!("occupied panic")
            });
        })).is_err());
        assert!(patch.shares_root(&before));
        assert_eq!(patch, ordinary);
    }
    // Existing APIs retain their separate first-value/replacement semantics.
    patch.insert(&Entry::with_value(&key(12), Arc::new(200)));
    assert_eq!(**patch.get(&permuted::Schema::tree_ordered(&key(12))).unwrap(), 12);
    patch.replace(&Entry::with_value(&key(12), Arc::new(201)));
    assert_eq!(**patch.get(&permuted::Schema::tree_ordered(&key(12))).unwrap(), 201);
    assert_eq!(**before.get(&permuted::Schema::tree_ordered(&key(12))).unwrap(), 12);
}

#[test]
fn checked_entries_insert_matches_both_hash_policies_and_preserves_snapshots() {
    checked_insert::<XorSip128>();
    checked_insert::<Blake3Merkle>();
}

#[test]
fn checked_entries_unique_ancestors_do_not_copy_on_write() {
    let mut patch = PATCH::<4, IdentitySchema, u8>::new();
    for (key, value) in [([0, 0, 1, 0], 1), ([1, 0, 1, 0], 2)] {
        patch.try_insert_with(&key, || value, |_| Ok::<_, ()>(())).unwrap();
    }
    let root = patch.root.as_ref().unwrap().tptr;
    patch.try_insert_with(&[0, 0, 2, 0], || 3, |_| Ok::<_, ()>(())).unwrap();
    assert_eq!(patch.root.as_ref().unwrap().tptr, root);
    assert_eq!(patch.len(), 3);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = patch.try_insert_with(&[0, 0, 3, 0], || panic!("vacant panic"), |_| Ok::<_, ()>(()));
    })).is_err());
    assert_eq!(patch.root.as_ref().unwrap().tptr, root);
    assert_eq!(patch.len(), 3);
    assert_eq!(patch.get(&[0, 0, 2, 0]), Some(&3));
}

#[test]
fn checked_entries_unused_callback_drop_panics_before_mutation() {
    struct Bomb;
    impl Drop for Bomb { fn drop(&mut self) { panic!("callback capture drop"); } }
    for shared in [false, true] {
        let mut patch = PATCH::<4, IdentitySchema, u8>::new();
        for (key, value) in [([0, 0, 1, 0], 1), ([1, 0, 1, 0], 2)] {
            patch.insert(&Entry::with_value(&key, value));
        }
        let snapshot = shared.then(|| patch.clone());
        let pointer = patch.root.as_ref().unwrap().tptr;
        let bomb = Bomb;
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = patch.try_insert_with(&[0, 0, 2, 0], || 3, move |_| {
                let _keep_capture = &bomb;
                Ok::<_, ()>(())
            });
        })).is_err());
        assert_eq!(patch.root.as_ref().unwrap().tptr, pointer);
        assert_eq!(patch.len(), 2);
        assert_eq!(patch.iter_entries_ordered().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(), vec![([0, 0, 1, 0], 1), ([1, 0, 1, 0], 2)]);
        if let Some(snapshot) = snapshot { assert!(patch.shares_root(&snapshot)); }
        patch.try_insert_with(&[0, 0, 2, 0], || 3, |_| Ok::<_, ()>(())).unwrap();
        assert_eq!(patch.len(), 3);
    }
}

#[test]
fn ordered_entries_pair_keys_values_and_scoped_cursor_in_schema_order() {
    let mut patch = PATCH::<4, permuted::Schema, u8>::new();
    assert_eq!(patch.iter_entries_ordered().len(), 0);
    assert!(patch.clone().into_iter_ordered().next_with(|_, _| ()).is_none());
    for n in (0..91).rev() { patch.insert(&Entry::with_value(&key(n), n)); }
    let mut expected: Vec<_> = (0..91).map(|n| (key(n), n)).collect();
    expected.sort_unstable_by_key(|(key, _)| permuted::Schema::tree_ordered(key));
    let mut borrowed = patch.iter_entries_ordered();
    let (_, first) = borrowed.next().unwrap();
    drop(borrowed);
    assert_eq!(*first, expected[0].1); // borrow is from PATCH, not cursor storage
    for (stored, value) in patch.iter_entries_ordered() {
        assert_eq!(patch.get(&permuted::Schema::tree_ordered(stored)), Some(value));
    }
    assert_eq!(patch.iter_entries_ordered().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(), expected);
    let snapshot = patch.clone();
    let mut owned = patch.into_iter_ordered();
    assert_eq!(owned.len(), expected.len());
    assert!(catch_unwind(AssertUnwindSafe(|| owned.next_with(|_, _| panic!("visitor panic")))).is_err());
    assert_eq!(owned.len(), expected.len() - 1);
    let mut actual = Vec::new();
    while let Some(pair) = owned.next_with(|k, v| (*k, *v)) { actual.push(pair); }
    assert_eq!(actual, expected[1..]);
    assert_eq!(owned.len(), 0);
    assert_eq!(snapshot.iter_entries_ordered().count(), expected.len());
    assert!(owned.next_with(|_, _| ()).is_none());
}

#[test]
fn ordered_entries_retain_only_owned_results_after_early_drop() {
    let value = Arc::new(String::from("owned leaf"));
    let weak = Arc::downgrade(&value);
    let mut patch = PATCH::<1, IdentitySchema, Arc<String>>::new();
    for key in [[1], [2], [3]] { patch.insert(&Entry::with_value(&key, value.clone())); }
    drop(value);
    let snapshot = patch.clone();
    let mut cursor = patch.into_iter_ordered();
    let surviving = cursor.next_with(|_, value| value.clone()).unwrap();
    drop(cursor);
    drop(snapshot);
    assert_eq!(surviving.as_str(), "owned leaf");
    assert!(weak.upgrade().is_some());
    drop(surviving);
    assert!(weak.upgrade().is_none());
}

#[test]
fn ordered_entries_archive_unit_values_keep_cover_until_cursor_drop() {
    #[repr(align(16))]
    struct Rows([[u8; 16]; 2]);
    let rows = Arc::new(Rows([[2; 16], [3; 16]]));
    let weak = Arc::downgrade(&rows);
    let owner: Arc<dyn ArchiveOwner> = rows.clone();
    let mut patch = PATCH::<16, IdentitySchema>::new();
    for row in &rows.0 {
        patch.insert_archive(&unsafe { ArchiveEntry::new(NonNull::from(row), &owner) });
    }
    patch.try_insert_with(&[1; 16], || (), |_| Ok::<_, ()>(())).unwrap();
    assert!(!patch.try_insert_with(&[2; 16], || panic!("archive duplicate"), |_| Ok::<_, ()>(())).unwrap());
    assert_eq!(patch.iter_entries_ordered().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(), vec![([1; 16], ()), ([2; 16], ()), ([3; 16], ())]);
    let mut cursor = patch.into_iter_ordered();
    drop(owner);
    drop(rows);
    assert_eq!(cursor.next_with(|k, v| (*k, *v)), Some(([1; 16], ())));
    assert!(weak.upgrade().is_some());
    drop(cursor);
    assert!(weak.upgrade().is_none());
}
