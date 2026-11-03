//! Times the SimpleArchive unarchive phases on synthetic, real-shaped rows.
//! Compile this identical source against two revisions of the decoder and run
//! the binaries alternately. Input preparation is excluded from every timing.
//!
//! usage: unarchive_phase_probe <rows> <mode> [inner]
//! modes: par-hash | single-hash | serial | e2e | check-base | check-ztrible
//!        | check-ztrible-blocked:<B> | view-ztrible
//!        | file:<path>:<mode>
//! check-base is the decoders' hand-written canonical check with no per-row
//! work; check-ztrible is an anybytes view as `[ZTrible]` (zerocopy validates
//! the row invariant) followed by one strictly-increasing pass;
//! check-ztrible-blocked:<B> validates and orders each block of B rows before
//! the next; view-ztrible is the whole view alone, to split the cost.
//! Prints one line: mode, rows, threads, median ns/row and min ns/row over
//! `inner` timed iterations after one warm-up.

use std::time::Instant;

use anybytes::Bytes;
use anybytes::View;
use triblespace_core::blob::encodings::simplearchive::{phase_probe, try_from_archive_bytes};
use zerocopy::IntoBytes;

#[path = "../tests/support/ztrible.rs"]
#[allow(dead_code)]
mod ztrible;
use ztrible::{check_ztrible_blocked, ZTrible};

/// The canonical check through the prototype row type: the view proves every
/// row valid, then one pass proves the rows strictly increasing. The pass has
/// the same comparison shape and error order as the hand-written check.
#[inline(never)]
fn check_ztrible(bytes: Bytes) -> Result<View<[ZTrible]>, &'static str> {
    let rows: View<[ZTrible]> = bytes.view().map_err(|_| "BadTrible")?;
    let mut previous: Option<&[u8; 64]> = None;
    for row in rows.iter() {
        let row: &[u8; 64] = row.as_bytes().try_into().unwrap();
        if let Some(previous) = previous {
            if previous == row {
                return Err("BadCanonicalizationRedundancy");
            }
            if previous > row {
                return Err("BadCanonicalizationOrdering");
            }
        }
        previous = Some(row);
    }
    Ok(rows)
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Eight facts per random entity, attributes from a pool of 64 random ids,
/// random 32-byte values; sorted and deduplicated like a canonical archive.
fn rows(len: usize) -> Vec<[u8; 64]> {
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut attrs = [[0u8; 16]; 64];
    for a in attrs.iter_mut() {
        a[..8].copy_from_slice(&splitmix(&mut state).to_be_bytes());
        a[8..].copy_from_slice(&(splitmix(&mut state) | 1).to_be_bytes());
    }
    let mut out = Vec::with_capacity(len);
    let mut entity = [0u8; 16];
    for i in 0..len {
        if i % 8 == 0 {
            entity[..8].copy_from_slice(&splitmix(&mut state).to_be_bytes());
            entity[8..].copy_from_slice(&(splitmix(&mut state) | 1).to_be_bytes());
        }
        let mut row = [0u8; 64];
        row[..16].copy_from_slice(&entity);
        row[16..32].copy_from_slice(&attrs[(splitmix(&mut state) % 64) as usize]);
        for chunk in row[32..].chunks_exact_mut(8) {
            chunk.copy_from_slice(&splitmix(&mut state).to_be_bytes());
        }
        out.push(row);
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let len: usize = args[1].parse().expect("rows");
    let mode = args[2].clone();
    let inner: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(3);

    let (bytes, sub) = if let Some(rest) = mode.strip_prefix("file:") {
        let (path, sub) = rest.rsplit_once(':').expect("file:<path>:<mode>");
        let data = std::fs::read(path).expect("read archive");
        let rows: Vec<[u8; 64]> = data
            .chunks_exact(64)
            .map(|c| c.try_into().unwrap())
            .collect();
        (Bytes::from(rows), sub.to_string())
    } else {
        (Bytes::from(rows(len)), mode.clone())
    };
    let view: View<[[u8; 64]]> = bytes.clone().view().expect("row view");
    let slice: &[[u8; 64]] = &view;
    let n = slice.len();

    let block: Option<usize> = sub
        .strip_prefix("check-ztrible-blocked:")
        .map(|b| b.parse().expect("block rows"));

    let mut times = Vec::with_capacity(inner);
    for iter in 0..=inner {
        let start = Instant::now();
        let elapsed = match sub.as_str() {
            "par-hash" => {
                let h = phase_probe::validate_and_hash_parallel(slice).unwrap();
                let e = start.elapsed();
                std::hint::black_box(h);
                e
            }
            "single-hash" => {
                let h = phase_probe::validate_and_hash_single(slice).unwrap();
                let e = start.elapsed();
                std::hint::black_box(h);
                e
            }
            "check-base" => {
                let r = phase_probe::check_rows(std::hint::black_box(slice));
                let e = start.elapsed();
                r.unwrap();
                e
            }
            "check-ztrible" => {
                let v = check_ztrible(std::hint::black_box(bytes.clone())).unwrap();
                let e = start.elapsed();
                assert_eq!(v.len(), n);
                drop(v);
                e
            }
            _ if block.is_some() => {
                let r = check_ztrible_blocked(std::hint::black_box(slice), block.unwrap());
                let e = start.elapsed();
                r.unwrap();
                e
            }
            "view-ztrible" => {
                let v: View<[ZTrible]> = std::hint::black_box(bytes.clone()).view().unwrap();
                let e = start.elapsed();
                assert_eq!(v.len(), n);
                drop(v);
                e
            }
            "serial" => {
                let s = phase_probe::serial(bytes.clone()).unwrap();
                let e = start.elapsed();
                assert_eq!(s.len(), n);
                drop(s);
                e
            }
            "e2e" => {
                let s = try_from_archive_bytes(bytes.clone()).unwrap();
                let e = start.elapsed();
                assert_eq!(s.len(), n);
                drop(s);
                e
            }
            other => panic!("unknown mode {other}"),
        };
        if iter > 0 {
            times.push(elapsed.as_nanos() as f64 / n as f64);
        }
    }
    let threads = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .unwrap_or_else(|| std::thread::available_parallelism().unwrap().to_string());
    let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
    println!(
        "{mode}\t{n}\t{threads}\t{:.3}\t{:.3}",
        median(times.clone()),
        min
    );
}
