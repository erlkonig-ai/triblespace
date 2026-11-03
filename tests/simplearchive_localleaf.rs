//! Measures heap-allocation behaviour of `SimpleArchive` ingestion to
//! verify the `LocalLeaf` path actually eliminates per-trible heap
//! `Leaf` allocations. Above the parallel archive threshold, the public path
//! also uses the bottom-up constructor, so those larger cases are end-to-end
//! decoder regressions rather than a representation-only comparison.
//!
//! Strategy: install a counting global allocator, build a TribleSet
//! through the normal `insert` path (forcing heap Leaves), encode to
//! a `SimpleArchive` blob, then decode through `try_from_blob` while
//! counting allocations performed during the decode. The Leaf-heap
//! path costs ~96 bytes per trible. The archive path avoids those persistent
//! Leaf allocations, while its transient hash/permutation buffers and Branch
//! allocation still scale with input and trie shape.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use std::time::Instant;
use triblespace::core::blob::encodings::simplearchive::{try_from_blob_heap_only, SimpleArchive};
use triblespace::core::blob::Blob;
use triblespace::core::inline::Encodes;
use triblespace::core::trible::Trible;
use triblespace::core::trible::TribleSet;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicUsize = AtomicUsize::new(0);
/// Serializes tests that use the counting allocator so concurrent
/// tests in this file don't pollute each other's counters.
static COUNTING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) != 0 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAllocator = CountingAllocator;

/// Two archive-backed TribleSets with **overlapping** keys, unioned
/// together. Decode chunks are sorted-disjoint, so the existing
/// parallel-reduce path never hits a LocalLeaf-vs-LocalLeaf merge.
/// This test triggers that path on purpose to keep the LocalLeaf-aware
/// union honest: it would have panicked at `unreachable!()` before
/// the `union` work in the wee hours of 2026-06-03.
/// Regression: union two archive-backed TribleSets with overlapping
/// keys *from different archive Arcs*. The merge path drives both
/// the parallel `par_union` (above the 4096 threshold) and the
/// serial fallback, and exercises every LocalLeaf-vs-LocalLeaf
/// collision in the trie. The sources are dropped before any
/// reads so the result must keep all LocalLeaves' backing bytes
/// alive transitively via the surviving PATCH root owner sets.
#[test]
fn union_two_overlapping_archives() {
    // Serialize with the decode-allocation test — they share the
    // process-global counting allocator and would race on its state
    // if run in parallel.
    let _guard = COUNTING_LOCK.lock().expect("counting mutex poisoned");
    // Big enough to engage the parallel par_union path on each
    // index (threshold is 4096 leaves).
    const N: usize = 8_192;

    // Build two archive-backed TribleSets whose keys overlap heavily.
    // Both are decoded from SimpleArchive blobs so they're LocalLeaf-
    // backed, *with different owner Arcs* — the two blobs are
    // independent so `try_from_blob_inner` wraps each in its own
    // `Arc<Bytes>`. After the union consumes both inputs, the
    // merged tree must keep all LocalLeaves' underlying bytes
    // alive transitively (via the Arcs held on surviving
    // Branches) — otherwise we get a use-after-free when we
    // walk the merged data.
    let mut a_src = TribleSet::new();
    let mut b_src = TribleSet::new();
    for i in 0..N as u64 {
        a_src.insert(&make_trible(i));
        b_src.insert(&make_trible(i + N as u64 / 2));
    }
    let expected_len = (0..N as u64 + N as u64 / 2).count();

    let a_blob: Blob<SimpleArchive> = SimpleArchive::encode(&a_src);
    let b_blob: Blob<SimpleArchive> = SimpleArchive::encode(&b_src);

    // Drop the source TribleSets so the union's correctness depends
    // entirely on the archive Arcs the LocalLeaves carry.
    drop(a_src);
    drop(b_src);

    let a: TribleSet = triblespace::core::blob::TryFromBlob::try_from_blob(a_blob).unwrap();
    let b: TribleSet = triblespace::core::blob::TryFromBlob::try_from_blob(b_blob).unwrap();

    let unioned = a + b;
    assert_eq!(
        unioned.len(),
        expected_len,
        "archive-vs-archive union should contain every distinct key"
    );

    // Walk every key via the eav iterator — if any LocalLeaf points
    // into freed archive bytes, this will read garbage or fault.
    let count: usize = unioned.eav().iter_ordered().count();
    assert_eq!(count, expected_len);
}

fn make_trible(i: u64) -> Trible {
    let mut data = [0u8; 64];
    data[..8].copy_from_slice(&i.to_be_bytes());
    data[8] = 1;
    data[16..24].copy_from_slice(&(i ^ 0xdead_beef_dead_beef).to_be_bytes());
    data[24] = 2;
    data[32..40].copy_from_slice(&i.to_be_bytes());
    data[40..48].copy_from_slice(&(i.wrapping_mul(31)).to_be_bytes());
    Trible::force_raw(data).expect("non-nil entity/attribute")
}

fn measure<R>(f: impl FnOnce() -> R) -> (R, usize, usize) {
    ALLOCS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(1, Ordering::Relaxed);
    let r = f();
    COUNTING.store(0, Ordering::Relaxed);
    (
        r,
        ALLOCS.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

#[test]
fn simplearchive_decode_uses_archive_owner() {
    let _guard = COUNTING_LOCK.lock().expect("counting mutex poisoned");
    // Below 4096 rows both paths use the same serial online decoder and isolate
    // heap Leaf versus archive LocalLeaf representation. At and above the
    // threshold, heap-only keeps the online worker while the public archive
    // path builds each worker chunk bottom-up; those cases deliberately guard
    // the complete decoders rather than attributing the difference to leaves.
    // Set `RAYON_NUM_THREADS=1` for less noisy local measurements:
    //
    //     RAYON_NUM_THREADS=1 cargo test --release --test simplearchive_localleaf
    //
    // Parallel runs remain valid regression checks, but are not a causal
    // representation benchmark above the threshold.
    measure_at(1_024);
    measure_at(4_095);
    measure_at(10_000);
    measure_at(100_000);
}

#[allow(non_snake_case)]
fn measure_at(n: usize) {
    let N = n;

    let mut source = TribleSet::new();
    for i in 0..N as u64 {
        source.insert(&make_trible(i));
    }
    assert_eq!(source.len(), N);

    let archive: Blob<SimpleArchive> = SimpleArchive::encode(&source);
    assert_eq!(archive.bytes.len(), N * 64);

    // Heap-Leaf baseline: same SimpleArchive ingest pipeline, but the
    // owner Arc is forced to None so every trible allocates a fresh
    // heap `Leaf`. This isolates the cost of the per-trible Leaf
    // alloc from any unrelated validation/iteration overhead.
    let (heap_set, heap_allocs, heap_bytes) =
        measure(|| -> TribleSet { try_from_blob_heap_only(archive.clone()).unwrap() });
    assert_eq!(heap_set.len(), N);

    // Public archive ingest. Below the threshold this differs only in
    // LocalLeaf representation; above it the bottom-up worker is also active.
    let (archive_set, archive_allocs, archive_bytes) =
        measure(|| -> TribleSet { archive.clone().try_from_blob().unwrap() });
    assert_eq!(archive_set.len(), N);

    // Wall-clock timing: warm up once, then take a min-of-3 to filter
    // GC/allocator noise. Min beats mean for tight ingest loops where
    // the floor is the signal and the tail is OS jitter.
    let iters = 3usize;
    let _ = try_from_blob_heap_only(archive.clone()).unwrap();
    let heap_time = (0..iters)
        .map(|_| {
            let t = Instant::now();
            let s = try_from_blob_heap_only(archive.clone()).unwrap();
            let d = t.elapsed();
            drop(s);
            d
        })
        .min()
        .unwrap();
    let _ = archive.clone().try_from_blob::<TribleSet>().unwrap();
    let archive_time = (0..iters)
        .map(|_| {
            let t = Instant::now();
            let s: TribleSet = archive.clone().try_from_blob().unwrap();
            let d = t.elapsed();
            drop(s);
            d
        })
        .min()
        .unwrap();

    let heap_per = heap_bytes as f64 / N as f64;
    let archive_per = archive_bytes as f64 / N as f64;
    let savings_pct = (1.0 - archive_per / heap_per) * 100.0;
    let speedup = heap_time.as_nanos() as f64 / archive_time.as_nanos() as f64;
    let time_savings = (1.0 - 1.0 / speedup) * 100.0;

    eprintln!("--- N={N} ---");
    eprintln!(
        "heap path:    allocs={heap_allocs}, alloc_bytes={heap_bytes}, \
         bytes/trible={heap_per:.2}, time={:?}",
        heap_time
    );
    eprintln!(
        "archive path: allocs={archive_allocs}, alloc_bytes={archive_bytes}, \
         bytes/trible={archive_per:.2}, time={:?}",
        archive_time
    );
    eprintln!(
        "memory savings: {savings_pct:.1}%, time speedup: {speedup:.2}× \
         ({time_savings:.1}% faster)"
    );

    assert!(
        archive_bytes < heap_bytes,
        "archive-ingest path should allocate fewer bytes than the \
         heap-Leaf path (heap={heap_bytes}, archive={archive_bytes})"
    );
    assert!(
        archive_allocs < heap_allocs,
        "archive-ingest path should perform fewer allocations than \
         the heap-Leaf path (heap_allocs={heap_allocs}, \
         archive_allocs={archive_allocs})"
    );
}
