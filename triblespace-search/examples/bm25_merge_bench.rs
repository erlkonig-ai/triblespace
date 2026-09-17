//! Phase-level smoke benchmark for portable BM25 segment merging.
//!
//! This intentionally uses only [`PortableBM25Index::merge`] so it measures
//! the canonical join directly, without a repository-range facade. It is not
//! a statistical benchmark; run the release binary repeatedly (and under
//! `/usr/bin/time -l` on macOS) when comparing merge implementations.
//!
//! Usage:
//! `cargo run --release -p triblespace-search --example bm25_merge_bench -- \
//!      [segments] [docs_per_segment] [terms_per_doc] [vocabulary] [overlap_percent]`

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use triblespace_core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace_core::id::{Id, RawId};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::{Inline, RawInline};
use triblespace_search::portable_bm25::{PortableBM25Blob, PortableBM25Index};
use triblespace_search::tokens::WordHash;

struct TrackingAlloc;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let next = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(next, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAlloc = TrackingAlloc;

#[derive(Clone, Copy)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn id_from_u64(n: u64) -> Id {
    let mut raw: RawId = [0; 16];
    raw[0] = 1;
    raw[8..].copy_from_slice(&n.to_be_bytes());
    Id::new(raw).expect("non-zero benchmark id")
}

fn term_from_u64(n: u64) -> Inline<WordHash> {
    let mut raw: RawInline = [0; 32];
    raw[..8].copy_from_slice(&n.to_be_bytes());
    raw[8..16].copy_from_slice(&n.rotate_left(17).to_be_bytes());
    raw[16..24].copy_from_slice(&n.rotate_left(31).to_be_bytes());
    raw[24..].copy_from_slice(&n.rotate_left(47).to_be_bytes());
    Inline::new(raw)
}

fn build_segments(
    segment_count: usize,
    docs_per_segment: usize,
    terms_per_doc: usize,
    vocabulary: usize,
    overlap_percent: usize,
) -> Vec<PortableBM25Index<GenId, WordHash>> {
    assert!(segment_count > 0);
    assert!(vocabulary > 0);
    assert!(overlap_percent <= 100);
    let shared_docs = docs_per_segment * overlap_percent / 100;

    (0..segment_count)
        .map(|segment| {
            let mut rng = Rng(0xB25_5EED ^ segment as u64);
            let mut documents = Vec::with_capacity(docs_per_segment);
            let mut counts = Vec::new();
            for local in 0..docs_per_segment {
                let ordinal = if local < shared_docs {
                    local as u64
                } else {
                    shared_docs as u64
                        + (segment * (docs_per_segment - shared_docs) + local - shared_docs) as u64
                };
                let id = id_from_u64(ordinal + 1);
                let document: Inline<GenId> = triblespace_core::inline::IntoInline::to_inline(&id);
                documents.push(document);
                let mut frequencies = HashMap::new();
                for _ in 0..terms_per_doc {
                    *frequencies
                        .entry(term_from_u64(rng.next() % vocabulary as u64))
                        .or_insert(0u32) += 1;
                }
                counts.extend(
                    frequencies
                        .into_iter()
                        .map(|(term, frequency)| (document, term, frequency)),
                );
            }
            PortableBM25Index::from_exact_counts(documents, counts)
                .expect("benchmark corpus is valid")
        })
        .collect()
}

fn parse_arg(index: usize, default: usize) -> usize {
    std::env::args()
        .nth(index)
        .map(|value| value.parse().expect("benchmark arguments are usize"))
        .unwrap_or(default)
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1 << 30 {
        format!("{:.2} GiB", bytes as f64 / (1_u64 << 30) as f64)
    } else if bytes >= 1 << 20 {
        format!("{:.2} MiB", bytes as f64 / (1_u64 << 20) as f64)
    } else {
        format!("{:.2} KiB", bytes as f64 / (1_u64 << 10) as f64)
    }
}

fn average(elapsed: Duration, iterations: u32) -> Duration {
    elapsed / iterations
}

fn main() {
    let segment_count = parse_arg(1, 8);
    let docs_per_segment = parse_arg(2, 2_000);
    let terms_per_doc = parse_arg(3, 64);
    let vocabulary = parse_arg(4, 8_192);
    let overlap_percent = parse_arg(5, 10);

    let build_started = Instant::now();
    let segments = build_segments(
        segment_count,
        docs_per_segment,
        terms_per_doc,
        vocabulary,
        overlap_percent,
    );
    let input_bytes: usize = segments.iter().map(|segment| segment.bytes().len()).sum();
    println!(
        "prepared {segment_count} segments x {docs_per_segment} docs x \
         {terms_per_doc} terms ({overlap_percent}% overlap, vocab {vocabulary}) in {:.3}s; input {}",
        build_started.elapsed().as_secs_f64(),
        fmt_bytes(input_bytes),
    );

    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let merge_started = Instant::now();
    let resident = PortableBM25Index::merge(segments.iter()).expect("canonical segments merge");
    let resident_build = merge_started.elapsed();
    let extra_heap = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    let digest = blake3::hash(resident.bytes().as_ref());

    println!(
        "resident merge {:.3}s; heap peak +{}; output {}; blake3 {}",
        resident_build.as_secs_f64(),
        fmt_bytes(extra_heap),
        fmt_bytes(resident.bytes().len()),
        digest.to_hex(),
    );

    let query = [term_from_u64(0), term_from_u64(1), term_from_u64(2)];
    let encode_started = Instant::now();
    let merged_blob: Blob<PortableBM25Blob> = (&resident).to_blob();
    let encode = encode_started.elapsed();
    let reattach_started = Instant::now();
    let reattached: PortableBM25Index<GenId, WordHash> =
        PortableBM25Index::try_from_blob(merged_blob)
            .expect("merge output is a valid portable BM25 artifact");
    let reattach = reattach_started.elapsed();
    let resident_expected = resident
        .query()
        .expect("resident scoring")
        .query_multi(&query);
    let reattached_expected = reattached
        .query()
        .expect("reattached scoring")
        .query_multi(&query);
    assert_eq!(
        resident_expected
            .iter()
            .map(|(document, score)| (document.raw, score.to_bits()))
            .collect::<Vec<_>>(),
        reattached_expected
            .iter()
            .map(|(document, score)| (document.raw, score.to_bits()))
            .collect::<Vec<_>>()
    );

    const QUERY_ITERATIONS: u32 = 2_000;
    let resident_scoring = resident.query().expect("resident scoring");
    let resident_query_started = Instant::now();
    for _ in 0..QUERY_ITERATIONS {
        black_box(resident_scoring.query_multi(black_box(&query)));
    }
    let resident_query = average(resident_query_started.elapsed(), QUERY_ITERATIONS);

    let reattached_scoring = reattached.query().expect("reattached scoring");
    let reattached_started = Instant::now();
    for _ in 0..QUERY_ITERATIONS {
        black_box(reattached_scoring.query_multi(black_box(&query)));
    }
    let reattached_query = average(reattached_started.elapsed(), QUERY_ITERATIONS);

    const ONE_SHOT_ITERATIONS: u32 = 3;
    let one_shot_started = Instant::now();
    for _ in 0..ONE_SHOT_ITERATIONS {
        let one_shot =
            PortableBM25Index::merge(black_box(&segments).iter()).expect("one-shot portable merge");
        black_box(
            one_shot
                .query()
                .expect("one-shot scoring")
                .query_multi(black_box(&query)),
        );
    }
    let one_shot_query = average(one_shot_started.elapsed(), ONE_SHOT_ITERATIONS);

    println!(
        "encode {:.3}µs; reattach {:.3}µs; 3-term query resident {:.3}µs, reattached {:.3}µs, one-shot {:.3}ms",
        encode.as_secs_f64() * 1_000_000.0,
        reattach.as_secs_f64() * 1_000_000.0,
        resident_query.as_secs_f64() * 1_000_000.0,
        reattached_query.as_secs_f64() * 1_000_000.0,
        one_shot_query.as_secs_f64() * 1_000.0,
    );
}
