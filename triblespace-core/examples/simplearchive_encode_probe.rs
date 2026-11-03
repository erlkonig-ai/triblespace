//! Times `SimpleArchive` encode of a `TribleSet`, today's heap path against
//! the off-heap section path, on synthetic real-shaped rows.
//!
//! usage: simplearchive_encode_probe [sizes,comma,separated] [reps]
//!
//! Arms, all from a borrowed set and all including `Blob::new` (the BLAKE3
//! handle) and the drop of the blob:
//! - old:    the pre-change body, a `Vec<[u8; 64]>` turned into `Bytes`;
//! - new:    the crate's encode (`(&set).to_blob()`);
//! - heap16: a `Vec<[u128; 4]>` (16-aligned heap) turned into `Bytes`;
//! - anon:   `Section::<[u128; 4]>::anonymous_allocated` (zero-written file).
//!
//! Each rep runs every arm once, rotating the arm order per rep, after one
//! untimed warm-up rep. One sample is `calls` back-to-back encodes timed
//! together and divided by `calls`. Input preparation is excluded. Prints per
//! size and arm: median and min..max ns per call and ns per row.

use std::hint::black_box;
use std::time::Instant;

use anybytes::area::Section;
use anybytes::Bytes;
use triblespace_core::prelude::blobencodings::SimpleArchive;
use triblespace_core::prelude::*;
use zerocopy::IntoBytes;

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Eight facts per random entity, attributes from a pool of 64 random ids,
/// random 32-byte values (the shape of unarchive_phase_probe's rows).
fn set_of(len: usize) -> TribleSet {
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut attrs = [[0u8; 16]; 64];
    for a in attrs.iter_mut() {
        a[..8].copy_from_slice(&splitmix(&mut state).to_be_bytes());
        a[8..].copy_from_slice(&(splitmix(&mut state) | 1).to_be_bytes());
    }
    let mut set = TribleSet::new();
    let mut entity = [0u8; 16];
    let mut i = 0;
    while set.len() < len {
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
        set.insert(&Trible::force_raw(row).unwrap());
        i += 1;
    }
    set
}

/// The pre-change encode body, copied verbatim apart from the signature.
#[inline(never)]
fn encode_old(source: &TribleSet) -> Blob<SimpleArchive> {
    let mut tribles: Vec<[u8; 64]> = Vec::with_capacity(source.len());
    tribles.extend(source.eav.iter_ordered());
    let bytes: Bytes = tribles.into();
    Blob::new(bytes)
}

#[inline(never)]
fn encode_new(source: &TribleSet) -> Blob<SimpleArchive> {
    source.to_blob()
}

#[inline(never)]
fn encode_heap16(source: &TribleSet) -> Blob<SimpleArchive> {
    let mut rows: Vec<[u128; 4]> = vec![[0u128; 4]; source.len()];
    for (slot, row) in rows
        .as_mut_bytes()
        .chunks_exact_mut(64)
        .zip(source.eav.iter_ordered())
    {
        slot.copy_from_slice(row);
    }
    Blob::new(Bytes::from(rows))
}

#[inline(never)]
fn encode_anon(source: &TribleSet) -> Blob<SimpleArchive> {
    if source.is_empty() {
        return Blob::new(Bytes::empty());
    }
    let mut out = Section::<[u128; 4]>::anonymous_allocated(source.len()).unwrap();
    for (slot, row) in out
        .as_mut_slice()
        .as_mut_bytes()
        .chunks_exact_mut(64)
        .zip(source.eav.iter_ordered())
    {
        slot.copy_from_slice(row);
    }
    Blob::new(out.freeze().unwrap())
}

type Arm = (&'static str, fn(&TribleSet) -> Blob<SimpleArchive>);
const ARMS: [Arm; 4] = [
    ("old", encode_old),
    ("new", encode_new),
    ("heap16", encode_heap16),
    ("anon", encode_anon),
];

fn stats(mut v: Vec<f64>) -> (f64, f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (v[v.len() / 2], v[0], v[v.len() - 1])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let sizes: Vec<usize> = args
        .get(1)
        .map(|s| s.split(',').map(|x| x.parse().unwrap()).collect())
        .unwrap_or_else(|| vec![1, 8, 64, 1_000, 100_000]);
    let reps: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(9);
    let threads = std::thread::available_parallelism().unwrap();
    println!(
        "# reps={reps} (plus 1 warm-up), available_parallelism={threads}, single-threaded loop"
    );
    println!(
        "size\tarm\tcalls\tns_call_med\tns_call_min..max\tns_row_med\tns_row_min..max\tmisaligned"
    );

    for &len in &sizes {
        let set = set_of(len);
        assert_eq!(set.len(), len);
        let reference = encode_old(&set);
        for (name, arm) in ARMS {
            assert!(arm(&set).bytes == reference.bytes, "{name} bytes differ");
        }
        let calls = (100_000 / len).clamp(3, 5_000);
        let mut samples: Vec<Vec<f64>> = vec![Vec::new(); ARMS.len()];
        let mut misaligned = [0usize; 4];
        for rep in 0..=reps {
            for k in 0..ARMS.len() {
                let index = (rep + k) % ARMS.len();
                let arm = ARMS[index].1;
                let start = Instant::now();
                for _ in 0..calls {
                    let blob = arm(black_box(&set));
                    if blob.bytes.as_ptr() as usize % 16 != 0 {
                        misaligned[index] += 1;
                    }
                    drop(black_box(blob));
                }
                let ns = start.elapsed().as_nanos() as f64 / calls as f64;
                if rep > 0 {
                    samples[index].push(ns);
                }
            }
        }
        for (index, (name, _)) in ARMS.iter().enumerate() {
            let (med, min, max) = stats(samples[index].clone());
            let n = len as f64;
            println!(
                "{len}\t{name}\t{calls}\t{med:.1}\t{min:.1}..{max:.1}\t{:.2}\t{:.2}..{:.2}\t{} of {}",
                med / n,
                min / n,
                max / n,
                misaligned[index],
                calls * (reps + 1),
            );
        }
    }
}
