//! What one `Pile::snapshot` costs on a real pile.
//!
//! Written 2026-09-17 because a per-poll constant cannot be inferred from a
//! sample window divided by a poll interval: the watch loop's sleep sits
//! *between* snapshots, so an iteration costs the snapshot plus the interval
//! and the iteration count is not recoverable from the window without already
//! knowing the snapshot cost. Measuring it directly removes the circularity.
//!
//! Usage: `snapshot_cost <pile> [iterations]`
//!
//! The pile is opened read-only in the sense that nothing here writes; give it
//! a disposable copy anyway, since another process appending underneath would
//! make every sample a different pile.

use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: snapshot_cost <pile> [iterations]");
    let iterations: usize = args
        .next()
        .map(|value| value.parse().expect("iterations must be a number"))
        .unwrap_or(200);
    assert!(iterations > 0, "iterations must be positive");

    let open = Instant::now();
    let mut pile = Pile::open(Path::new(&path)).expect("open pile");
    // `Pile::open` replays lazily, so a fresh handle counts nothing until it
    // is refreshed. The replay is the expensive one-off and is reported
    // separately rather than folded into the per-snapshot figure.
    pile.refresh().expect("refresh pile");
    let opened = open.elapsed();

    // One warm snapshot establishes whatever the first one establishes; it is
    // deliberately outside the sample.
    black_box(pile.snapshot().expect("warm snapshot"));

    let start = Instant::now();
    for _ in 0..iterations {
        black_box(pile.snapshot().expect("snapshot"));
    }
    let elapsed = start.elapsed();

    let bytes = std::fs::metadata(&path).expect("stat pile").len();
    println!(
        "pile={path} bytes={bytes} open_and_replay={:.3}s iterations={iterations} \
         total={:.3}s per_snapshot={:.3}ms",
        opened.as_secs_f64(),
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1000.0 / iterations as f64
    );
}
