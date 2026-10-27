//! A retained raw read-set is cloned whenever an observation is reused, so a
//! clone must share structure rather than copy every consulted key.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::{Duration, Instant};

use triblespace_core::collection::{CollectionData, CollectionHandle, CollectionRecordSelector};
use triblespace_core::repo::StoreDependencies;

thread_local! {
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}

/// Counts allocations made on the current thread only, so concurrently
/// running tests in this binary cannot disturb a measurement.
struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|count| count.set(count.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAllocator = CountingAllocator;

fn allocations_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCS.with(Cell::get);
    let out = f();
    (out, ALLOCS.with(Cell::get) - before)
}

const N: u32 = 100_000;

fn raw(i: u32, salt: u8) -> [u8; 32] {
    let mut raw = [salt; 32];
    raw[..4].copy_from_slice(&i.to_be_bytes());
    raw
}

fn selector(i: u32) -> CollectionRecordSelector {
    let handle = CollectionHandle::new(raw(i, 1));
    match i % 3 {
        0 => CollectionRecordSelector::Collection(handle),
        1 => CollectionRecordSelector::ProducedMember(handle, CollectionData::new(raw(i, 2))),
        _ => CollectionRecordSelector::Foundations(handle),
    }
}

fn large_dependencies() -> StoreDependencies {
    let mut dependencies = StoreDependencies::default();
    for i in 0..N {
        dependencies.records.insert(selector(i));
        dependencies.blobs.insert(CollectionData::new(raw(i, 3)));
    }
    dependencies
}

#[test]
fn cloning_a_large_read_set_shares_structure() {
    let dependencies = large_dependencies();
    assert_eq!(dependencies.records.len(), N as usize);
    assert_eq!(dependencies.blobs.len(), N as usize);

    let (clone, allocations) = allocations_during(|| dependencies.clone());
    assert!(
        allocations <= 4,
        "cloning {N} records and {N} blobs allocated {allocations} times; \
         a retained read-set clone must share structure",
    );
    assert_eq!(clone, dependencies);

    // Sharing is copy-on-write: the clone stays independent after mutation.
    let mut clone = clone;
    let extra = CollectionRecordSelector::MergeCollection(CollectionHandle::new([9; 32]));
    clone.records.insert(extra);
    clone.blobs.insert(CollectionData::new([9; 32]));
    assert!(clone.records.contains(&extra));
    assert!(!dependencies.records.contains(&extra));
    assert_eq!(dependencies.records.len(), N as usize);
    assert_eq!(dependencies.blobs.len(), N as usize);
    assert_ne!(clone, dependencies);
}

/// Mean wall time of one call, repeated for about half a second.
fn per_clone<T>(mut f: impl FnMut() -> T) -> Duration {
    let start = Instant::now();
    let mut rounds = 0u32;
    while start.elapsed() < Duration::from_millis(500) {
        drop(f());
        rounds += 1;
    }
    start.elapsed() / rounds
}

/// Per-clone wall time of one 100k-record plus 100k-blob read-set, against
/// cloning the same keys held in `BTreeSet`s. Informational only: run with
/// `--release -- --ignored --nocapture` to read the figures.
#[test]
#[ignore = "timing report, not a correctness check"]
fn report_clone_cost_against_btreeset() {
    let dependencies = large_dependencies();
    let records: BTreeSet<CollectionRecordSelector> = (0..N).map(selector).collect();
    let blobs: BTreeSet<CollectionData> = (0..N).map(|i| CollectionData::new(raw(i, 3))).collect();

    let btree = per_clone(|| black_box((black_box(&records).clone(), black_box(&blobs).clone())));
    let deps = per_clone(|| black_box(black_box(&dependencies).clone()));

    let (_, btree_allocs) = allocations_during(|| (records.clone(), blobs.clone()));
    let (_, deps_allocs) = allocations_during(|| dependencies.clone());
    println!(
        "per clone of {N} records + {N} blobs: BTreeSet pair {btree:?} ({btree_allocs} allocations), \
         StoreDependencies {deps:?} ({deps_allocs} allocations)"
    );
}
