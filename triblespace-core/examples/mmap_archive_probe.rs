//! Offline canonical-byte and storage-ownership probe for direct archive builders.
//! Compile this identical source against the old and new core. Operation timing
//! excludes synthetic input preparation; process footprint includes preparation.
//! `join`, `derive`, and `merge` accept row count, hold seconds, and output path.

use std::error::Error;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anybytes::Bytes;
use jerky::bit_vector::Access;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, SuccinctArchive, SuccinctArchiveBlob, SuccinctRotation,
};
use triblespace_core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace_core::collection::simplearchive_union::{join, join_all};

type ProbeResult<T> = Result<T, Box<dyn Error>>;

fn id(prefix: u8, ordinal: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0] = prefix;
    bytes[8..].copy_from_slice(&ordinal.to_be_bytes());
    bytes
}

fn source(first: usize, rows: usize) -> Blob<SimpleArchive> {
    let mut data = Vec::with_capacity(rows);
    for ordinal in first..first + rows {
        let mut row = [0; 64];
        row[..16].copy_from_slice(&id(1, (ordinal / 8) as u64));
        row[16..32].copy_from_slice(&id(2, (ordinal % 8) as u64));
        row[32] = 0x80;
        row[56..].copy_from_slice(&(ordinal as u64).to_be_bytes());
        data.push(row);
    }
    Blob::new(Bytes::from(data))
}

fn raw_segments(rows: usize) -> ProbeResult<Vec<Blob<SuccinctArchiveBlob>>> {
    let segment = (rows / 4).max(1);
    let stride = segment * 3 / 4;
    (0..4)
        .map(|index| {
            SuccinctArchiveBlob::build_from_simple_archive(&source(index * stride, segment))
                .map_err(|error| format!("raw input build: {error:?}").into())
        })
        .collect()
}

fn finish<S: BlobEncoding>(
    mode: &str,
    rows: usize,
    blob: Blob<S>,
    elapsed: Duration,
    hold: u64,
    output: Option<&Path>,
) -> ProbeResult<()> {
    // Inputs and transient builders have already been dropped. Rehash every
    // byte now: a cached handle alone would not prove surviving ownership.
    let digest = blake3::hash(&blob.bytes);
    assert_eq!(digest.as_bytes(), &blob.get_handle().raw);
    if let Some(path) = output {
        std::fs::write(path, &blob.bytes)?;
    }
    println!(
        "READY mode={mode} rows={rows} bytes={} hash={} operation_ms={:.3} pid={}",
        blob.bytes.len(),
        digest,
        elapsed.as_secs_f64() * 1000.0,
        std::process::id()
    );
    io::stdout().flush()?;
    std::thread::sleep(Duration::from_secs(hold));
    std::hint::black_box(&blob);
    Ok(())
}

fn controls(output: Option<&Path>) -> ProbeResult<()> {
    let empty = source(0, 0);
    let a = source(0, 1024);
    let b = source(512, 1024);
    let expected = source(0, 1536);
    assert_eq!(join_all(&[])?.bytes.as_ref(), empty.bytes.as_ref());
    assert_eq!(
        join_all(&[empty.clone()])?.bytes.as_ref(),
        empty.bytes.as_ref()
    );
    assert_eq!(join_all(&[a.clone()])?.bytes.as_ref(), a.bytes.as_ref());
    assert_eq!(join(&a, &empty)?.bytes.as_ref(), a.bytes.as_ref());
    assert_eq!(join(&a, &a)?.bytes.as_ref(), a.bytes.as_ref());
    let united = join_all(&[b.clone(), empty.clone(), a.clone(), b.clone()])?;
    assert_eq!(united.bytes.as_ref(), expected.bytes.as_ref());
    assert_eq!(join(&a, &b)?.bytes.as_ref(), join(&b, &a)?.bytes.as_ref());
    let mut four = (0..4)
        .map(|index| source(index * 256, 1024))
        .collect::<Vec<_>>();
    let k_way = join_all(&four)?;
    four.reverse();
    assert_eq!(k_way.bytes.as_ref(), join_all(&four)?.bytes.as_ref());
    drop(four);
    assert_eq!(k_way.bytes.as_ref(), source(0, 1792).bytes.as_ref());
    let leaves = [empty, a, b]
        .iter()
        .map(SuccinctArchiveBlob::build_from_simple_archive)
        .collect::<Result<Vec<_>, _>>()?;
    let merged = SuccinctArchiveBlob::merge(&leaves)?;
    drop(leaves);
    let rebuilt = SuccinctArchiveBlob::build_from_simple_archive(&expected)?;
    assert_eq!(merged.bytes.as_ref(), rebuilt.bytes.as_ref());
    assert_eq!(
        SuccinctArchiveBlob::merge(&[])?.bytes.as_ref(),
        SuccinctArchiveBlob::build_from_simple_archive(&source(0, 0))?
            .bytes
            .as_ref()
    );
    SuccinctArchiveBlob::validate(&merged)?;
    let runtime = SuccinctArchive::<OrderedUniverse>::try_from_blob(merged.clone())?;
    let rebuilt_runtime = SuccinctArchive::<OrderedUniverse>::try_from_blob(rebuilt)?;
    let actual: Vec<_> = runtime.iter().map(|row| row.data).collect();
    assert_eq!(actual.as_slice().as_flattened(), expected.bytes.as_ref());
    for rotation in SuccinctRotation::ALL {
        let mut fingerprint = blake3::Hasher::new();
        for position in 0..actual.len() {
            let character = runtime.ring_col(rotation).access(position).unwrap();
            assert_eq!(
                Some(character),
                rebuilt_runtime.ring_col(rotation).access(position)
            );
            let starts_pair = runtime.pair_changes(rotation).access(position).unwrap();
            assert_eq!(
                Some(starts_pair),
                rebuilt_runtime.pair_changes(rotation).access(position)
            );
            fingerprint.update(&(character as u64).to_le_bytes());
            fingerprint.update(&[u8::from(starts_pair)]);
        }
        println!("ROTATION {rotation:?} {}", fingerprint.finalize());
    }
    drop(runtime);
    drop(rebuilt_runtime);
    drop(expected);
    drop(united);
    finish("control", 1536, merged, Duration::ZERO, 0, output)
}

fn run() -> ProbeResult<()> {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("control");
    let rows = args
        .get(2)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(100_000);
    let hold = args
        .get(3)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(0);
    let output = args.get(4).map(Path::new);
    match mode {
        "control" => controls(output),
        "join" => {
            let a = source(0, rows);
            let b = source(rows / 2, rows);
            let start = Instant::now();
            let result = join_all(&[a, b]).map_err(|error| format!("join: {error:?}"))?;
            finish(mode, rows, result, start.elapsed(), hold, output)
        }
        "derive" => {
            let input = source(0, rows);
            let start = Instant::now();
            let result = SuccinctArchiveBlob::build_from_simple_archive(&input)
                .map_err(|error| format!("derive: {error:?}"))?;
            let elapsed = start.elapsed();
            drop(input);
            finish(mode, rows, result, elapsed, hold, output)
        }
        "merge" => {
            let inputs = raw_segments(rows)?;
            let start = Instant::now();
            let result =
                SuccinctArchiveBlob::merge(&inputs).map_err(|error| format!("merge: {error:?}"))?;
            let elapsed = start.elapsed();
            drop(inputs);
            finish(mode, rows, result, elapsed, hold, output)
        }
        "make-segments" => {
            let directory = output.ok_or("make-segments needs output directory")?;
            std::fs::create_dir_all(directory)?;
            for (index, blob) in raw_segments(rows)?.iter().enumerate() {
                std::fs::write(directory.join(format!("{index}.raw")), &blob.bytes)?;
            }
            Ok(())
        }
        "merge-files" => {
            let directory = output.ok_or("merge-files needs input directory")?;
            let inputs = (0..4)
                .map(|index| {
                    std::fs::read(directory.join(format!("{index}.raw")))
                        .map(|bytes| Blob::<SuccinctArchiveBlob>::new(Bytes::from(bytes)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let start = Instant::now();
            let result = SuccinctArchiveBlob::merge(&inputs)
                .map_err(|error| format!("merge-files: {error:?}"))?;
            let elapsed = start.elapsed();
            drop(inputs);
            finish(mode, rows, result, elapsed, hold, None)
        }
        _ => Err(format!("unknown mode: {mode}").into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("PROBE ERROR: {error}");
        std::process::exit(42);
    }
}
