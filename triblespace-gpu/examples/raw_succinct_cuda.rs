//! Bounded raw-builder benchmark. Run only with an exclusive GB10 reservation.
//! No pile, model, collection publication or CPU fallback participates.

use std::time::{Duration, Instant};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::trible::{Trible, TribleSet};
use triblespace_gpu::CudaWaveletFreeze;

fn source(start: u32, rows: u32) -> Blob<SimpleArchive> {
    let facts: TribleSet = (start..start + rows)
        .map(|ordinal| {
            let mut data = [0u8; 64];
            data[0] = 1;
            data[12..16].copy_from_slice(&(ordinal % 1024).to_be_bytes());
            data[16] = 2;
            data[28..32].copy_from_slice(&(ordinal % 17).to_be_bytes());
            data[32] = 3;
            data[60..].copy_from_slice(&ordinal.to_be_bytes());
            Trible { data }
        })
        .collect();
    facts.to_blob()
}

fn timed<T>(operation: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let value = operation();
    (value, start.elapsed())
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let rows = arguments
        .next()
        .map(|arg| arg.parse::<u32>().expect("rows must be an integer"))
        .unwrap_or(65_536);
    let repetitions = arguments
        .next()
        .map(|arg| {
            arg.parse::<usize>()
                .expect("repetitions must be an integer")
        })
        .unwrap_or(3);
    assert!(
        rows > 0 && rows <= 250_000,
        "rows must be in 1..=250000; this is a bounded hardware gate"
    );
    assert!(
        (1..=8).contains(&repetitions) && arguments.next().is_none(),
        "usage: raw_succinct_cuda [rows<=250000] [repetitions<=8]"
    );
    let backend = CudaWaveletFreeze::default();
    let warm = source(0, 65);
    SuccinctArchiveBlob::build_from_simple_archive_with_backend(&warm, &backend)
        .expect("CUDA warmup; no fallback");
    let sources = [source(0, rows), source(rows / 2, rows)];
    for repetition in 0..repetitions {
        // Alternate ordering to expose, rather than systematically hide, warm
        // host caches. This is an end-to-end raw construction measurement;
        // sorting, canonical input validation and content hashing are included.
        let cpu_build = || {
            sources
                .iter()
                .map(|source| SuccinctArchiveBlob::build_from_simple_archive(source).unwrap())
                .collect::<Vec<_>>()
        };
        let gpu_build = || {
            sources
                .iter()
                .map(|source| {
                    SuccinctArchiveBlob::build_from_simple_archive_with_backend(source, &backend)
                        .expect("CUDA build; no fallback")
                })
                .collect::<Vec<_>>()
        };
        let ((cpu, cpu_time), (gpu, gpu_time)) = if repetition % 2 == 0 {
            (timed(cpu_build), timed(gpu_build))
        } else {
            let gpu = timed(gpu_build);
            (timed(cpu_build), gpu)
        };
        for (cpu, gpu) in cpu.iter().zip(&gpu) {
            assert_eq!(cpu.bytes.as_ref(), gpu.bytes.as_ref());
            assert_eq!(cpu.get_handle(), gpu.get_handle());
        }
        let cpu_merge = || SuccinctArchiveBlob::merge(&cpu).unwrap();
        let gpu_merge = || {
            SuccinctArchiveBlob::merge_with_backend(&gpu, &backend)
                .expect("CUDA merge; no fallback")
        };
        let ((cpu_union, cpu_merge_time), (gpu_union, gpu_merge_time)) = if repetition % 2 == 0 {
            (timed(cpu_merge), timed(gpu_merge))
        } else {
            let gpu = timed(gpu_merge);
            (timed(cpu_merge), gpu)
        };
        assert_eq!(cpu_union.bytes.as_ref(), gpu_union.bytes.as_ref());
        assert_eq!(cpu_union.get_handle(), gpu_union.get_handle());
        println!("rep={} rows_per_input={} output_bytes={} build_cpu_s={:.6} build_cuda_s={:.6} merge_cpu_s={:.6} merge_cuda_s={:.6} parity=byte+hash", repetition + 1, rows, cpu_union.bytes.len(), cpu_time.as_secs_f64(), gpu_time.as_secs_f64(), cpu_merge_time.as_secs_f64(), gpu_merge_time.as_secs_f64());
    }
}
