//! Writer-wait reproduction for the pile's file lock, on a scratch pile.
//!
//! A pile writer that needs the exclusive lock (a WANT marker, a collection
//! record, a large blob) can wait behind readers that each hold the shared
//! lock across a whole replay. Linux `flock` grants a new shared lock while an
//! exclusive request is queued, so overlapping readers can keep the writer out
//! for as long as they keep arriving. This harness measures that wait.
//!
//! Every reader and the writer are SEPARATE PROCESSES: `flock` belongs to the
//! open file description, and a second process is the honest model of the
//! short-lived CLI readers that caused the original stalls.
//!
//! Subcommands (all paths are scratch paths; never point this at a live pile):
//!   gen <pile> <records>           append <records> 64-byte blobs to a fresh file
//!   replay <pile> [n]              time n fresh open+refresh replays
//!   reader <pile> <stop> <think_ms> <out>
//!   writer <pile> <stop> <out>
//!   trial <pile> <K> <think_ms> <readers_s> <tail_s> <out_dir>
//!
//! `trial` starts K readers, each in a closed loop of fresh-open replays with
//! `think_ms` of sleep between replays, and one writer that, every 50-250 ms,
//! times one WANT append (an exclusive-lock write of one 256-byte frame).
//! Readers stop ARRIVING after `readers_s` (an in-flight replay finishes); the
//! writer keeps sampling for `tail_s` more, so the trial shows both the wait
//! while readers keep coming and what happens once they stop.
//!
//! Frame of every reported number: one writer sample is the wall time of one
//! `PileFile::want` call from a process that has already replayed the pile,
//! i.e. lock wait plus a delta replay plus one 256-byte append, measured by
//! that process's monotonic clock. Times are milliseconds.

use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anybytes::Bytes;
use rand::Rng;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::repo::pile::PileFile;
use triblespace_core::repo::{BlobStorePut, WantRequest, WantStore};

type R<T> = Result<T, Box<dyn Error>>;

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos()
}

fn blob(payload: Vec<u8>) -> Blob<UnknownBlob> {
    Blob::<UnknownBlob>::new(Bytes::from_source(payload))
}

fn gen(path: &Path, records: u64) -> R<()> {
    File::create_new(path)?;
    let mut pile = PileFile::open(path)?;
    pile.refresh()?;
    let started = Instant::now();
    for i in 0..records {
        let mut payload = vec![0u8; 64];
        payload[..8].copy_from_slice(&i.to_le_bytes());
        pile.put::<UnknownBlob, _>(blob(payload))?;
    }
    pile.close()?;
    println!(
        "gen records={records} bytes={} secs={:.2}",
        std::fs::metadata(path)?.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn replay(path: &Path, n: usize) -> R<()> {
    let mut times = Vec::new();
    for _ in 0..n {
        let started = Instant::now();
        let mut pile = PileFile::open(path)?;
        pile.refresh()?;
        pile.close()?;
        times.push(started.elapsed().as_secs_f64() * 1e3);
    }
    times.sort_by(f64::total_cmp);
    println!(
        "replay n={n} min_ms={:.1} median_ms={:.1} max_ms={:.1}",
        times[0],
        times[times.len() / 2],
        times[times.len() - 1]
    );
    Ok(())
}

fn reader(path: &Path, stop: &Path, think_ms: u64, out: &Path) -> R<()> {
    let mut out = File::create(out)?;
    while !stop.exists() {
        let started = now_ns();
        let mut pile = PileFile::open(path)?;
        pile.refresh()?;
        pile.close()?;
        writeln!(out, "{started} {}", now_ns())?;
        if think_ms > 0 {
            std::thread::sleep(Duration::from_millis(think_ms));
        }
    }
    Ok(())
}

fn writer(path: &Path, stop: &Path, out: &Path) -> R<()> {
    let mut out = File::create(out)?;
    let mut pile = PileFile::open(path)?;
    pile.refresh()?;
    let mut rng = rand::thread_rng();
    while !stop.exists() {
        std::thread::sleep(Duration::from_millis(rng.gen_range(50..250)));
        let mut payload = vec![0u8; 32];
        rng.fill(&mut payload[..]);
        let handle = blob(payload).get_handle();
        let started_wall = now_ns();
        let started = Instant::now();
        pile.want(WantRequest::blob(handle))?;
        let ns = started.elapsed().as_nanos();
        writeln!(out, "{started_wall} {}", started_wall + ns)?;
    }
    pile.close()?;
    Ok(())
}

fn spawn(args: &[&str]) -> R<Child> {
    Ok(Command::new(std::env::current_exe()?).args(args).spawn()?)
}

fn read_pairs(path: &Path) -> R<Vec<(u128, u128)>> {
    let mut pairs = Vec::new();
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        let mut it = line.split_whitespace().map(|v| v.parse::<u128>());
        if let (Some(Ok(a)), Some(Ok(b))) = (it.next(), it.next()) {
            pairs.push((a, b));
        }
    }
    Ok(pairs)
}

fn quantiles(mut v: Vec<f64>) -> String {
    if v.is_empty() {
        return "n=0".into();
    }
    v.sort_by(f64::total_cmp);
    let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    format!(
        "n={} min={:.1} p10={:.1} p25={:.1} p50={:.1} p75={:.1} p90={:.1} p99={:.1} max={:.1}",
        v.len(),
        v[0],
        q(0.10),
        q(0.25),
        q(0.50),
        q(0.75),
        q(0.90),
        q(0.99),
        v[v.len() - 1]
    )
}

fn trial(path: &Path, k: usize, think_ms: u64, readers_s: f64, tail_s: f64, dir: &Path) -> R<()> {
    std::fs::create_dir_all(dir)?;
    let reader_stop = dir.join("readers.stop");
    let writer_stop = dir.join("writer.stop");
    let _ = std::fs::remove_file(&reader_stop);
    let _ = std::fs::remove_file(&writer_stop);
    let pile = path.to_str().ok_or("pile path")?;
    let rstop = reader_stop.to_str().ok_or("path")?;
    let wstop = writer_stop.to_str().ok_or("path")?;
    let think = think_ms.to_string();
    let mut readers = Vec::new();
    let mut reader_outs = Vec::new();
    let begin = now_ns();
    for i in 0..k {
        let out: PathBuf = dir.join(format!("reader-{i}.txt"));
        readers.push(spawn(&[
            "reader",
            pile,
            rstop,
            &think,
            out.to_str().ok_or("path")?,
        ])?);
        reader_outs.push(out);
    }
    // Let the readers overlap before the writer starts sampling.
    std::thread::sleep(Duration::from_millis(500));
    let wout = dir.join("writer.txt");
    let mut writer = spawn(&["writer", pile, wstop, wout.to_str().ok_or("path")?])?;
    std::thread::sleep(Duration::from_secs_f64(readers_s));
    File::create(&reader_stop)?;
    let readers_stopped = now_ns();
    for mut r in readers {
        r.wait()?;
    }
    let readers_done = now_ns();
    std::thread::sleep(Duration::from_secs_f64(tail_s));
    File::create(&writer_stop)?;
    let writer_stop_at = now_ns();
    writer.wait()?;

    let ms = |ns: u128| ns as f64 / 1e6;
    let mut during = Vec::new(); // started and finished while readers were arriving
    let mut spanning = Vec::new(); // started while arriving, finished after the stop
    let mut after = Vec::new(); // started after the last reader exited
    let mut spanning_after_stop = Vec::new();
    for (s, e) in read_pairs(&wout)? {
        let w = ms(e - s);
        if e <= readers_stopped {
            during.push(w);
        } else if s < readers_stopped {
            spanning.push(w);
            spanning_after_stop.push(ms(e - readers_stopped));
        } else if s >= readers_done {
            after.push(w);
        }
    }
    let mut replays = 0usize;
    let mut replay_ms = Vec::new();
    for out in &reader_outs {
        for (s, e) in read_pairs(out)? {
            if e <= readers_stopped {
                replays += 1;
                replay_ms.push(ms(e - s));
            }
        }
    }
    let active_s = (readers_stopped - begin) as f64 / 1e9;
    let censored_at_stop = spanning.len();
    println!("trial K={k} think_ms={think_ms} readers_s={readers_s} tail_s={tail_s}");
    println!(
        "  reader replays completed={replays} throughput={:.2}/s over {active_s:.1}s; replay_ms {}",
        replays as f64 / active_s,
        quantiles(replay_ms)
    );
    println!(
        "  writer_wait_ms while readers arrive: {}",
        quantiles(during)
    );
    println!(
        "  writer samples in flight when readers stopped arriving: {censored_at_stop}; their total wait_ms {}; of which after the stop {}",
        quantiles(spanning),
        quantiles(spanning_after_stop)
    );
    println!(
        "  writer_wait_ms after readers exited: {}",
        quantiles(after)
    );
    println!(
        "  readers drained {:.0} ms after the stop; writer stopped {:.0} ms later",
        ms(readers_done - readers_stopped),
        ms(writer_stop_at - readers_done)
    );
    Ok(())
}

fn main() -> R<()> {
    let args: Vec<String> = std::env::args().collect();
    let a = |i: usize| -> R<&str> {
        Ok(args
            .get(i)
            .ok_or("missing argument; see the module docs")?
            .as_str())
    };
    match a(1)? {
        "gen" => gen(Path::new(a(2)?), a(3)?.parse()?),
        "replay" => replay(Path::new(a(2)?), args.get(3).map_or(Ok(3), |n| n.parse())?),
        "reader" => reader(
            Path::new(a(2)?),
            Path::new(a(3)?),
            a(4)?.parse()?,
            Path::new(a(5)?),
        ),
        "writer" => writer(Path::new(a(2)?), Path::new(a(3)?), Path::new(a(4)?)),
        "trial" => trial(
            Path::new(a(2)?),
            a(3)?.parse()?,
            a(4)?.parse()?,
            a(5)?.parse()?,
            a(6)?.parse()?,
            Path::new(a(7)?),
        ),
        other => Err(format!("unknown subcommand {other}").into()),
    }
}
