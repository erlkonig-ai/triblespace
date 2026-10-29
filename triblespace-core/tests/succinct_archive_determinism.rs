//! SuccinctArchive bytes are a pure function of the input facts.
//!
//! # Why this exists
//!
//! A collection MERGE names its result by content: two hosts that rebuild the
//! same merge node, or one host that rebuilds it twice, must store the same
//! blob, or content-addressed dedup fails and every rebuild appends a full
//! copy. In July 2026 three identical subset imports produced three different
//! merged-archive hashes (equal lengths, about half the bytes different), with
//! rayon-scheduled section assembly as the suspect. The portable raw format
//! that replaced the old serialization has a canonical writer, but nothing
//! pinned that its bytes stay independent of thread count and scheduling.
//!
//! This test builds every archive path several times under rayon pools of
//! different sizes and requires one handle per path:
//!
//! - raw leaf: `SuccinctArchiveBlob::build_from_simple_archive`
//!   (the `SimpleToSuccinctMappingV1` attachment map);
//! - raw union: `SuccinctArchiveBlob::merge` and the collection `join`
//!   (`SuccinctArchiveBlob` collection MERGE);
//! - native leaf: `SuccinctArchive::from(&TribleSet)` with its Rank9 root;
//! - native union: `merge_ordered_archives` + `to_accelerated_parts`
//!   (`Rank9AcceleratedSuccinctArchiveBlob` collection MERGE, whose raw
//!   handle must be resident, i.e. equal the raw union's handle);
//! - `build_accelerated_root` from the raw blob.
//!
//! The fixture is just large enough to cross the parallel thresholds in
//! triblespace-core (`PARALLEL_EAV_DECODE_THRESHOLD` = 4 Ki input rows over
//! more than one segment, and the packed wavelet freeze that splits a rotation
//! into chunks of at least 64 Ki rows whenever two or more chunks fit). A
//! one-thread pool takes the serial freeze and every larger pool the chunked
//! one, so the comparison spans both code paths and four schedulings. A run
//! with 2^19 rows and five builds per pool (four and eight chunks as well)
//! agreed too, at about four minutes a run.

use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    merge_ordered_archives, OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchive,
    SuccinctArchiveBlob,
};
use triblespace_core::blob::{Blob, BlobEncoding, IntoBlob};
use triblespace_core::collection::succinctarchive_union;
use triblespace_core::inline::RawInline;
use triblespace_core::trible::{Trible, TribleSet};

/// 2^17 rows: two 64 Ki-row freeze chunks with two or more threads, and the
/// serial path with one.
const ROWS: usize = 1 << 17;
/// Builds per pool size: each path is built `REPEATS * POOL_SIZES.len()` = 4
/// times.
const REPEATS: usize = 1;
const POOL_SIZES: [usize; 4] = [1, 2, 4, 16];

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn id_bytes(class: u64, ordinal: u64) -> [u8; 16] {
    let mut state = class.wrapping_mul(0x1000_0000_01b3) ^ ordinal;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&splitmix(&mut state).to_le_bytes());
    bytes[8..].copy_from_slice(&splitmix(&mut state).to_le_bytes());
    bytes[0] |= 0x80; // never the nil id
    bytes
}

/// A fixed fact set with shared entities and attributes, repeated values, and
/// entities in value position, so every rotation has long runs and the domain
/// is much smaller than three times the row count.
fn fixture() -> TribleSet {
    let entities = (ROWS / 8) as u64;
    let attributes = 61u64;
    let values = (ROWS / 3) as u64;
    let mut state = 0x5eed_0000_0000_0001u64;
    let mut set = TribleSet::new();
    while set.len() < ROWS {
        let e = id_bytes(1, splitmix(&mut state) % entities);
        let a = id_bytes(2, splitmix(&mut state) % attributes);
        let pick = splitmix(&mut state);
        let mut v: RawInline = [0u8; 32];
        if pick % 4 == 0 {
            // An entity reference: the id occupies the low 16 bytes.
            v[16..].copy_from_slice(&id_bytes(1, pick % entities));
        } else {
            let mut value_state = pick % values;
            for chunk in v.chunks_exact_mut(8) {
                chunk.copy_from_slice(&splitmix(&mut value_state).to_le_bytes());
            }
        }
        let mut raw = [0u8; 64];
        raw[..16].copy_from_slice(&e);
        raw[16..32].copy_from_slice(&a);
        raw[32..].copy_from_slice(&v);
        set.insert(&Trible::force_raw(raw).expect("non-nil entity and attribute"));
    }
    set
}

/// Three overlapping segments of the fixture (every seventh row is in two).
fn segments(set: &TribleSet) -> [TribleSet; 3] {
    let mut parts: [TribleSet; 3] = std::array::from_fn(|_| TribleSet::new());
    for (ordinal, trible) in set.iter_ordered().enumerate() {
        parts[ordinal % 3].insert(trible);
        if ordinal % 7 == 0 {
            parts[(ordinal + 1) % 3].insert(trible);
        }
    }
    parts
}

fn hex<S: BlobEncoding>(blob: &Blob<S>) -> String {
    blob.get_handle()
        .raw
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

/// Every observed hash per path, in build order.
#[derive(Default)]
struct Observed {
    paths: Vec<(&'static str, Vec<(usize, String)>)>,
}

impl Observed {
    fn record<S: BlobEncoding>(&mut self, path: &'static str, threads: usize, blob: &Blob<S>) {
        let hash = hex(blob);
        match self.paths.iter_mut().find(|(name, _)| *name == path) {
            Some((_, hashes)) => hashes.push((threads, hash)),
            None => self.paths.push((path, vec![(threads, hash)])),
        }
    }

    fn assert_each_path_has_one_hash(&self) {
        let mut failures = Vec::new();
        for (path, hashes) in &self.paths {
            let first = &hashes[0].1;
            let distinct: std::collections::BTreeSet<&str> =
                hashes.iter().map(|(_, hash)| hash.as_str()).collect();
            println!(
                "{path}: {} builds, {} distinct handle(s), first {first}",
                hashes.len(),
                distinct.len()
            );
            if distinct.len() != 1 {
                failures.push(format!("{path}: {hashes:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "archive bytes depend on more than the input facts:\n{}",
            failures.join("\n")
        );
    }

    fn only(&self, path: &str) -> &str {
        &self
            .paths
            .iter()
            .find(|(name, _)| *name == path)
            .expect("path recorded")
            .1[0]
            .1
    }
}

fn pool(threads: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("rayon pool")
}

#[test]
fn succinct_archive_bytes_are_independent_of_repetition_and_thread_count() {
    const RAW_PATHS: [&str; 6] = [
        "raw leaf (build_from_simple_archive)",
        "raw leaf (From<&TribleSet>)",
        "raw union (SuccinctArchiveBlob::merge)",
        "raw union (merge, reversed inputs)",
        "raw union (collection join, pairwise)",
        "raw union (merge_ordered_archives)",
    ];
    const RANK9_PATHS: [&str; 3] = [
        "rank9 root (From<&TribleSet>)",
        "rank9 root (merge_ordered_archives)",
        "rank9 root (build_accelerated_root)",
    ];
    const SEGMENT_PATHS: [&str; 3] = ["raw segment 0", "raw segment 1", "raw segment 2"];

    let set = fixture();
    let simple: Blob<SimpleArchive> = (&set).to_blob();
    let parts = segments(&set);
    let simple_parts: Vec<Blob<SimpleArchive>> = parts.iter().map(|part| part.to_blob()).collect();
    assert!(parts.iter().map(TribleSet::len).sum::<usize>() > ROWS);

    let mut observed = Observed::default();
    for threads in POOL_SIZES {
        pool(threads).install(|| {
            // Merge inputs are built once per pool (so leaf builds of the
            // segments are also compared across pools); each merge then runs
            // REPEATS times from those fixed inputs.
            let raw_parts: Vec<Blob<SuccinctArchiveBlob>> = simple_parts
                .iter()
                .map(|part| SuccinctArchiveBlob::build_from_simple_archive(part).unwrap())
                .collect();
            let native_parts: Vec<SuccinctArchive<OrderedUniverse>> =
                parts.iter().map(Into::into).collect();
            for ((path, raw), native) in SEGMENT_PATHS.iter().zip(&raw_parts).zip(&native_parts) {
                observed.record(path, threads, raw);
                let (native_raw, _) = native.to_accelerated_parts();
                observed.record(path, threads, &Blob::<SuccinctArchiveBlob>::new(native_raw.bytes));
            }
            let reversed: Vec<_> = raw_parts.iter().rev().cloned().collect();

            for _ in 0..REPEATS {
                // The SuccinctArchiveBlob collection: attachment map and MERGE.
                let raw = SuccinctArchiveBlob::build_from_simple_archive(&simple).unwrap();
                observed.record(RAW_PATHS[0], threads, &raw);
                let raw_union = SuccinctArchiveBlob::merge(&raw_parts).unwrap();
                observed.record(RAW_PATHS[2], threads, &raw_union);
                observed.record(
                    RAW_PATHS[3],
                    threads,
                    &SuccinctArchiveBlob::merge(&reversed).unwrap(),
                );
                let joined = succinctarchive_union::join(
                    &succinctarchive_union::join(&raw_parts[0], &raw_parts[1]).unwrap(),
                    &raw_parts[2],
                )
                .unwrap();
                observed.record(RAW_PATHS[4], threads, &joined);

                // Native leaf with its Rank9 root, and the root rebuilt from
                // the raw blob (the Rank9 attachment map). Handles are
                // rehashed from the bytes so a stale cached handle cannot mask
                // a difference.
                let native: SuccinctArchive<OrderedUniverse> = (&set).into();
                let (native_raw, native_rank9) = native.to_accelerated_parts();
                observed.record(
                    RAW_PATHS[1],
                    threads,
                    &Blob::<SuccinctArchiveBlob>::new(native_raw.bytes.clone()),
                );
                observed.record(
                    RANK9_PATHS[0],
                    threads,
                    &Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(native_rank9.bytes),
                );
                observed.record(
                    RANK9_PATHS[2],
                    threads,
                    &SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw.clone())
                        .unwrap(),
                );
                assert_eq!(hex(&native_raw), hex(&raw));

                // The Rank9-accelerated collection MERGE.
                let merged = merge_ordered_archives(&native_parts);
                let (merged_raw, merged_rank9) = merged.to_accelerated_parts();
                observed.record(
                    RAW_PATHS[5],
                    threads,
                    &Blob::<SuccinctArchiveBlob>::new(merged_raw.bytes.clone()),
                );
                observed.record(
                    RANK9_PATHS[1],
                    threads,
                    &Blob::<Rank9AcceleratedSuccinctArchiveBlob>::new(merged_rank9.bytes),
                );
                assert_eq!(hex(&merged_raw), hex(&raw_union));
            }
        });
    }

    observed.assert_each_path_has_one_hash();
    // The segments' union is the full set: every leaf and union path is one
    // artifact, and so is every Rank9 root built over it.
    for path in RAW_PATHS {
        assert_eq!(observed.only(path), observed.only(RAW_PATHS[0]), "{path}");
    }
    for path in RANK9_PATHS {
        assert_eq!(observed.only(path), observed.only(RANK9_PATHS[0]), "{path}");
    }
}
