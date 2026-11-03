//! Low-level CPU versus WGPU structural SuccinctArchive merge benchmark.

use std::time::Instant;

use triblespace_core::blob::encodings::succinctarchive::{
    merge_ordered_archives, merge_ordered_archives_with_backend, OrderedUniverse, SuccinctArchive,
};
use triblespace_core::trible::{Trible, TribleSet};
use triblespace_gpu::WgpuWaveletFreeze;

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn synthetic_trible(seed: u64, ordinal: usize) -> Trible {
    let mut state = seed.wrapping_add((ordinal as u64).wrapping_mul(0xd6e8_feb8_6659_fd93));
    let mut data = [0u8; 64];
    for chunk in data.chunks_exact_mut(8) {
        chunk.copy_from_slice(&splitmix(&mut state).to_le_bytes());
    }
    data[0] |= 0x80;
    data[16] |= 0x80;
    Trible::force_raw(data).expect("non-nil entity and attribute")
}

fn make_segments(rows: usize) -> [TribleSet; 3] {
    let mut sets = std::array::from_fn(|_| TribleSet::new());
    for (segment, set) in sets.iter_mut().enumerate() {
        for ordinal in 0..rows {
            set.insert(&synthetic_trible(
                0xA11C_E000_0000_0000 ^ segment as u64,
                ordinal,
            ));
        }
    }
    for ordinal in (0..rows).step_by(19) {
        let shared = synthetic_trible(0x5EED_0000_0000_0000, ordinal);
        for set in &mut sets {
            set.insert(&shared);
        }
    }
    sets
}

fn main() {
    let rows = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(100_000usize);

    let start = Instant::now();
    let sets = make_segments(rows);
    let archives: Vec<SuccinctArchive<OrderedUniverse>> = sets.iter().map(Into::into).collect();
    let input_rows = archives
        .iter()
        .map(|archive| archive.eav_c.len())
        .sum::<usize>();
    eprintln!(
        "built {} input segments / {input_rows} summed rows in {:.3}s",
        archives.len(),
        start.elapsed().as_secs_f64()
    );

    let gpu = WgpuWaveletFreeze::new(&Default::default());
    let warm_sets = make_segments(32);
    let warm_archives: Vec<SuccinctArchive<OrderedUniverse>> =
        warm_sets.iter().map(Into::into).collect();
    merge_ordered_archives_with_backend(&warm_archives, &gpu).expect("WGPU warmup merge");

    let start = Instant::now();
    let cpu = merge_ordered_archives(&archives);
    let cpu_seconds = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let accelerated =
        merge_ordered_archives_with_backend(&archives, &gpu).expect("WGPU structural merge");
    let gpu_seconds = start.elapsed().as_secs_f64();

    assert_eq!(accelerated.bytes.as_ref(), cpu.bytes.as_ref());

    println!("base rows per input segment: {rows}");
    println!("summed input rows: {input_rows}");
    println!("deduplicated output rows: {}", cpu.eav_c.len());
    println!("CPU structural merge: {cpu_seconds:.3}s");
    println!("WGPU structural merge: {gpu_seconds:.3}s");
    println!("speedup: {:.2}x", cpu_seconds / gpu_seconds);
    println!("canonical bytes: identical ({} bytes)", cpu.bytes.len());
}
