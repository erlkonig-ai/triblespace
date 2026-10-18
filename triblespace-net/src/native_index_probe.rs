//! Matched synthetic Pile replay: private benchmark-only adaptation.
//! Logical fixtures/lifetimes are equal across encodings; actual peer overlay
//! and cache APIs deliberately retain each production representation.

use crate::collection_delta::{collection_record_patch, update_collection_record_patch};
use crate::exchange::Tree;
use crate::riblt_cache::Generation;
use crate::walk::WalkKind;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;
use triblespace_core::collection::{
    CollectionCommit, CollectionDerive, CollectionHandle, CollectionMap, CollectionMerge,
    CollectionRead, CollectionRecord, CollectionRecordSelector,
    CollectionStore, SourceLocator,
};
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{PileFile, PileRecords};
use triblespace_core::repo::{SnapshotSource, StoreDependencies, StoreSnapshot};

// Explicit generic-backend control: delegates existing owned APIs but does not
// override the view APIs. This measures the explicit owned-encoding fallback,
// separately from native borrowed bodies.
struct OwnedBoundary<'a>(&'a triblespace_core::repo::pile::PileFileSnapshot);
impl CollectionRead for OwnedBoundary<'_> {
    type RecordsError =
        <triblespace_core::repo::pile::PileFileSnapshot as CollectionRead>::RecordsError;
    type RecordIter<'a>
        = <triblespace_core::repo::pile::PileFileSnapshot as CollectionRead>::RecordIter<'a>
    where
        Self: 'a;
    fn records(&self) -> Result<Self::RecordIter<'_>, Self::RecordsError> {
        self.0.records()
    }
    fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
        self.0.collections()
    }
    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.0.select_records(selectors)
    }
    fn select_record_changes(
        &self,
        previous: &Self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<(Vec<CollectionRecord>, Vec<CollectionRecord>), Self::RecordsError> {
        self.0.select_record_changes(previous.0, selectors)
    }
}

fn mapping_receipt(path: &std::path::Path, stage: &str) {
    let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let (mut matching, mut count, mut size, mut rss) = (false, 0, 0_u64, 0_u64);
    for line in smaps.lines() {
        if line
            .split_whitespace()
            .next()
            .is_some_and(|v| v.contains('-'))
        {
            matching = line.ends_with(path.to_str().unwrap());
            count += usize::from(matching);
        } else if matching && (line.starts_with("Size:") || line.starts_with("Rss:")) {
            let value: u64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
            if line.starts_with("Size:") {
                size += value;
            } else {
                rss += value;
            }
        }
    }
    println!(
        "index-probe mapping_stage={stage} maps={count} virtual_kib={size} summed_rss_kib={rss}"
    );
}

struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static BLOCKS: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn allocated(size: usize) {
    let current = LIVE.fetch_add(size, Relaxed) + size;
    BLOCKS.fetch_add(1, Relaxed);
    PEAK.fetch_max(current, Relaxed);
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        BLOCKS.fetch_sub(1, Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, size) };
        if !new.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
            let current = LIVE.fetch_add(size, Relaxed) + size;
            PEAK.fetch_max(current, Relaxed);
        }
        new
    }
}
#[cfg(feature = "matched-probe-meter")]
#[global_allocator]
static ALLOCATOR: Meter = Meter;

fn measure<T>(label: &str, operation: impl FnOnce() -> T) -> T {
    let start_live = LIVE.load(Relaxed);
    let start_blocks = BLOCKS.load(Relaxed);
    PEAK.store(start_live, Relaxed);
    let started = Instant::now();
    let result = operation();
    let elapsed = started.elapsed();
    let live = LIVE.load(Relaxed);
    let peak = PEAK.load(Relaxed);
    let blocks = BLOCKS.load(Relaxed);
    println!("index-probe stage={label} us={} live_heap={live} live_blocks={blocks} added_heap={} peak_extra_heap={} added_blocks={}",
        elapsed.as_micros(), live as i64 - start_live as i64, peak.saturating_sub(start_live), blocks as i64 - start_blocks as i64);
    result
}


fn logical_row(record: &CollectionRecord) -> [u8; 32] {
    // Private fixture comparison only: excludes encoding/signature, includes
    // every semantic field and the original author. Never a production key.
    let mut hash = blake3::Hasher::new();
    hash.update(&record.collection().raw);
    hash.update(&record.public_key().raw);
    match record {
        CollectionRecord::Commit(r) => {
            hash.update(&[1]);
            hash.update(&r.data().raw);
            hash.update(&r.metadata().raw);
        }
        CollectionRecord::Derive(r) => {
            hash.update(&[2]);
            hash.update(&r.output().raw);
            hash.update(&r.input().raw());
        }
        CollectionRecord::Map(r) => {
            hash.update(&[3]);
            hash.update(&r.attachment().raw);
            hash.update(&r.node().raw);
        }
        CollectionRecord::Merge(r) => {
            hash.update(&[4]);
            hash.update(&r.result().raw);
            for input in r.inputs() { hash.update(&input.raw); }
        }
    }
    *hash.finalize().as_bytes()
}
fn logical_set(mut rows: Vec<[u8; 32]>) -> [u8; 32] {
    // Operation-local sorting scratch, dropped before measured phases.
    rows.sort_unstable();
    assert!(rows.windows(2).all(|pair| pair[0] != pair[1]));
    let mut hash = blake3::Hasher::new();
    for row in rows { hash.update(&row); }
    *hash.finalize().as_bytes()
}
fn verified_set(records: impl IntoIterator<Item = CollectionRecord>) -> [u8; 32] {
    logical_set(records.into_iter().map(|record| {
        record.verify_strict().unwrap();
        logical_row(&record)
    }).collect())
}

fn raw(n: usize) -> [u8; 32] {
    // Random-looking content handles prepared outside measured index work;
    // not an eager full-record hash or a production-derived lookup ID.
    *blake3::hash(&(n as u64).to_be_bytes()).as_bytes()
}

fn collection(n: usize) -> CollectionHandle {
    Inline::new(raw(1 + n % 4))
}
fn fixture(n: usize, hot: bool) -> CollectionRecord {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7 + (n % 2) as u8; 32]);
    let c = collection(n);
    let member = Inline::new(raw(1000 + if hot { n % 64 } else { n }));
    match n % 3 {
        0 => CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            c,
            member,
            Inline::new(raw(n + 2000)),
        )),
        1 => CollectionRecord::Derive(CollectionDerive::sign(
            &key,
            c,
            SourceLocator::of(raw(n + 2000)),
            member,
        )),
        _ => CollectionRecord::Map(CollectionMap::sign(
            &key,
            c,
            Inline::new(raw(n + 2000)),
            member,
        )),
    }
}

#[test]
#[ignore = "private singleton allocation accounting, not a third implementation"]
fn body_view_owner_allocation_probe() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("single-body.pile");
    std::fs::File::create(&path).unwrap();
    let mut pile = PileFile::open(&path).unwrap();
    let record = fixture(0, false);
    pile.insert(record).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let native = measure("single_native_overlay", || {
        collection_record_patch(&snapshot, record.collection()).unwrap()
    });
    println!(
        "index-probe singleton_value_bytes={} nodes={:?}",
        std::mem::size_of_val(native.commits().get(&record.fingerprint().raw()).unwrap()),
        native.commits().node_stats()
    );
    measure("drop_single_native_overlay", || drop(native));
    let generic = measure("single_generic_overlay", || {
        collection_record_patch(&OwnedBoundary(&snapshot), record.collection()).unwrap()
    });
    measure("drop_single_generic_overlay", || drop(generic));
}

#[test]
#[ignore = "private synthetic index replacement measurement"]
fn replacement_replay_and_network_overlay() {
    let n: usize = std::env::var("NATIVE_INDEX_PROBE_N")
        .unwrap_or_else(|_| "10000".into())
        .parse()
        .unwrap();
    assert!((1000..=100000).contains(&n));
    println!("index-probe metered={} production_arm=final", cfg!(feature = "matched-probe-meter"));
    println!("index-probe fixed_index=valued_blake96_streaming trusted_carrier_bytes={} typed_view_bytes={}",
        std::mem::size_of::<triblespace_core::collection::CollectionRecordView>(),
        std::mem::size_of::<anybytes::View<triblespace_core::collection::EncodedCommit>>());
    let hot = std::env::var("NATIVE_INDEX_PROBE_SHAPE").is_ok_and(|v| v == "hot");
    let duplicates = std::env::var("NATIVE_INDEX_PROBE_DUPLICATES").is_ok_and(|v| v == "1");
    let owned_fallback = std::env::var("NATIVE_BODY_VIEW_FORCE_OWNED").is_ok_and(|v| v == "1");
    println!("index-probe owned_fallback={owned_fallback}");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.pile");
    std::fs::File::create(&path).unwrap();
    let mut writer = PileFile::open(&path).unwrap();
    let mut logical_rows = Vec::with_capacity(n + 4);
    let mut collection_rows: [Vec<[u8; 32]>; 4] = std::array::from_fn(|_| Vec::new());
    let mut member_rows = Vec::new();
    for i in 0..n {
        let record = fixture(i, hot);
        record.verify_strict().unwrap();
        let row = logical_row(&record);
        logical_rows.push(row);
        collection_rows[i % 4].push(row);
        if i == 0 || (hot && i % 64 == 0) { member_rows.push(row); }
        writer.insert(record).unwrap();
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    for i in 0..4 {
        let record = CollectionRecord::Merge(CollectionMerge::sign(
            &key, collection(i), (0..8).map(|j| Inline::new(raw(j))),
            Inline::new(raw(9999)),
        ).unwrap());
        record.verify_strict().unwrap();
        let row = logical_row(&record);
        logical_rows.push(row);
        collection_rows[i].push(row);
        writer.insert(record).unwrap();
    }
    let expected_logical = logical_set(logical_rows);
    let expected_collections = collection_rows.map(logical_set);
    let expected_member = logical_set(member_rows);
    println!("index-probe logical_fixture_blake3={}", blake3::Hash::from_bytes(expected_logical));
    writer.close().unwrap();
    // Identical physical duplicate append in each implementation, outside all
    // measured regions. No baseline index remains beside the candidate.
    let bytes = std::fs::read(&path).unwrap();
    let fixture_hash = blake3::hash(&bytes);
    if duplicates {
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    let duplicate_frame = bytes[..256].to_vec();
    drop(bytes);
    println!("index-probe n={n} hot={hot} duplicates={duplicates} canonical_fixture_blake3={fixture_hash} physical_bytes={} enum_bytes={} cell_bytes={}",
        std::fs::metadata(&path).unwrap().len(), std::mem::size_of::<CollectionRecord>(), std::mem::size_of::<crate::riblt_cache::Cell>());
    let mut pile = measure("open", || PileFile::open(&path).unwrap());
    let before = measure("replacement_replay_snapshot", || pile.snapshot().unwrap());
    assert_eq!(
        measure("iteration", || before
            .records()
            .unwrap()
            .map(Result::unwrap)
            .count()),
        n + 4
    );
    assert_eq!(
        measure("collection_enumeration", || before.collections().unwrap()).len(),
        4
    );
    for c in 0..4 {
        let selectors = BTreeSet::from([CollectionRecordSelector::Collection(collection(c))]);
        let selected = measure("collection_selector", || {
            before.select_records(&selectors).unwrap()
        });
        assert!(selected.iter().all(|r| r.collection() == collection(c)));
        assert_eq!(logical_set(selected.iter().map(logical_row).collect()), expected_collections[c]);
        println!("index-probe collection_query={c} count={} logical_blake3={}", selected.len(), blake3::Hash::from_bytes(expected_collections[c]));
        drop(selected);
    }
    let member = BTreeSet::from([CollectionRecordSelector::ProducedMember(
        collection(0),
        Inline::new(raw(1000)),
    )]);
    let selected = measure("member_selector", || {
        before.select_records(&member).unwrap()
    });
    assert!(!selected.is_empty());
    assert_eq!(logical_set(selected.iter().map(logical_row).collect()), expected_member);
    println!("index-probe member_query_count={} logical_blake3={}", selected.len(), blake3::Hash::from_bytes(expected_member));
    drop(selected);
    let overlays = measure("actual_fingerprint_overlays", || {
        (0..4)
            .map(|c| {
                if owned_fallback {
                    collection_record_patch(&OwnedBoundary(&before), collection(c)).unwrap()
                } else {
                    collection_record_patch(&before, collection(c)).unwrap()
                }
            })
            .collect::<Vec<_>>()
    });
    let mut foundations = 0;
    for patch in &overlays {
        foundations += patch.len();
        println!(
            "index-probe overlay_records={} commit_nodes={:?} derive_nodes={:?}",
            patch.len(),
            patch.commits().node_stats(), patch.derives().node_stats()
        );
    }
    // Retain the same logical COMMIT in both encodings, not a minimum
    // fingerprint whose ordering changes when canonical bytes change.
    let survivor = fixture(0, hot).fingerprint().raw();
    let one_body = crate::walk::Value::Commit(overlays[0].commits().get(&survivor).unwrap().clone());
    measure("kind_directed_borrowed_lookup", || {
        let mut count = 0;
        for patch in &overlays {
            for id in patch.commits().iter_ordered() {
                std::hint::black_box(patch.commits().get(id).unwrap());
                count += 1;
            }
            for id in patch.derives().iter_ordered() {
                std::hint::black_box(patch.derives().get(id).unwrap());
                count += 1;
            }
        }
        assert_eq!(count, foundations);
    });
    measure("actual_eager_lookup_body_frame", || {
        for patch in &overlays {
            for id in patch.commits().iter_ordered() {
                let value = crate::walk::Value::Commit(patch.commits().get(id).unwrap().clone());
                let bytes = value.bytes(patch.collection()).unwrap();
                assert_eq!(bytes.len(), 224);
                let frame = crate::walk_stream::Frame::Value { key: *id, bytes };
                std::hint::black_box(frame.encode());
            }
            for id in patch.derives().iter_ordered() {
                let value = crate::walk::Value::Derive(patch.derives().get(id).unwrap().clone());
                let bytes = value.bytes(patch.collection()).unwrap();
                assert_eq!(bytes.len(), 224);
                let frame = crate::walk_stream::Frame::Value { key: *id, bytes };
                std::hint::black_box(frame.encode());
            }
        }
    });
    let generations = measure("actual_initial_sketch_caches", || {
        overlays
            .iter()
            .flat_map(|patch| {
                [(WalkKind::Commit, Tree::Commit(patch.commits().clone())),
                 (WalkKind::Derive, Tree::Derive(patch.derives().clone()))].map(|(kind, tree)| {
                    let generation = Generation::advance(patch.collection(), kind, tree, None).unwrap();
                    generation.cell(1023).unwrap();
                    generation
                })
            })
            .collect::<Vec<_>>()
    });
    println!(
        "index-probe cache_bytes={}",
        generations
            .iter()
            .map(|g| g.retained_bytes().unwrap())
            .sum::<usize>()
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&duplicate_frame)
        .unwrap();
    let duplicate = measure("duplicate_only_snapshot", || pile.snapshot().unwrap());
    let all =
        BTreeSet::from_iter((0..4).map(|c| CollectionRecordSelector::Collection(collection(c))));
    assert_eq!(
        measure("duplicate_semantic_delta", || duplicate
            .select_record_changes(&before, &all)
            .unwrap()),
        (vec![], vec![])
    );
    let mut append_rows = Vec::with_capacity(128);
    for i in n..n + 128 {
        let record = fixture(i, hot);
        record.verify_strict().unwrap();
        append_rows.push(logical_row(&record));
        pile.insert(record).unwrap();
    }
    let expected_append = logical_set(append_rows);
    let after = measure("append_snapshot", || pile.snapshot().unwrap());
    let delta = measure("selected_delta", || {
        after.select_record_changes(&before, &all).unwrap()
    });
    assert_eq!((delta.0.len(), delta.1.len()), (128, 0));
    assert_eq!(verified_set(delta.0.iter().copied()), expected_append);
    println!("index-probe logical_append_blake3={}", blake3::Hash::from_bytes(expected_append));
    drop(delta);
    let next = measure("actual_overlay_delta", || {
        overlays
            .iter()
            .map(|p| {
                if owned_fallback {
                    update_collection_record_patch(
                        &OwnedBoundary(&after),
                        &OwnedBoundary(&before),
                        p,
                    )
                    .unwrap()
                } else {
                    update_collection_record_patch(&after, &before, p).unwrap()
                }
            })
            .collect::<Vec<_>>()
    });
    let next_generations = measure("actual_sketch_delta", || {
        next.iter()
            .zip(generations.chunks_exact(2))
            .flat_map(|(patch, old)| {
                [(WalkKind::Commit, Tree::Commit(patch.commits().clone())),
                 (WalkKind::Derive, Tree::Derive(patch.derives().clone()))].into_iter().enumerate().map(move |(i, (kind, tree))| {
                    Generation::advance(patch.collection(), kind, tree, Some(&old[i])).unwrap()
                })
            })
            .collect::<Vec<_>>()
    });
    assert!(after
        .changes_for(
            &before,
            &StoreDependencies {
                all_records: true,
                ..Default::default()
            }
        )
        .contains(triblespace_core::repo::StoreChanges::COLLECTION_RECORDS));
    assert_eq!(before.records().unwrap().count(), n + 4);
    let raw = measure("physical_decoder_census", || {
        PileRecords::open(&path)
            .unwrap()
            .map(Result::unwrap)
            .count()
    });
    assert_eq!(raw, (1 + usize::from(duplicates)) * (n + 4) + 1 + 128);
    // Actual rewrite planning includes the candidate's operation-local raw
    // occurrence reconstruction/sort, not just a stand-in byte estimate.
    let plan = measure("actual_retained_rewrite_plan", || {
        pile.plan_retained_rewrite(
            &triblespace_core::repo::RetentionRoots::new(),
            triblespace_core::repo::pile::WantRewritePolicy::Drop,
            &[],
            &mut triblespace_core::repo::pile::CarryEveryFrame,
        )
        .unwrap()
    });
    println!(
        "index-probe rewrite_repeated_frames={}",
        plan.repeated_frames
    );
    drop(plan);
    assert_eq!(verified_set(before.records().unwrap().map(Result::unwrap)), expected_logical);
    assert_eq!(verified_set(duplicate.records().unwrap().map(Result::unwrap)), expected_logical);
    println!("index-probe logical_replay_verified=true");
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status
        .lines()
        .filter(|s| s.starts_with("VmRSS:") || s.starts_with("VmSize:") || s.starts_with("VmHWM:"))
    {
        println!("index-probe {line}");
    }
    println!(
        "index-probe final_live_heap={} final_blocks={} snapshots=3 overlay_generations=2 cache_generations=2 cache_components_per_collection=2",
        LIVE.load(Relaxed),
        BLOCKS.load(Relaxed)
    );
    drop(next_generations);
    drop(next);
    drop(generations);
    drop(overlays);
    drop(after);
    drop(duplicate);
    drop(before);
    pile.close().unwrap();
    measure("one_surviving_body", || std::hint::black_box(&one_body));
    mapping_receipt(&path, "one_surviving_body");
    assert_eq!(one_body.bytes(collection(0)).unwrap().len(), 224);
    measure("drop_last_body", || drop(one_body));
    mapping_receipt(&path, "after_last_body_drop");
}
