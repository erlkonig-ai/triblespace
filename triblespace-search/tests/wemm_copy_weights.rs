//! Copied weights and pile-aliased weights on the real model: run once per
//! residence, each in its own process, and compare the printed hashes.
//!
//! Binds WeMM from a frozen model pile with the residence `WEMM_COPY_WEIGHTS`
//! chooses (`1` copies to device memory, unset or `0` reads in place), then
//! embeds the nondet probe's batch `WEMM_REPS` times through
//! [`WemmRuntime::probe_texts`] and prints the bind time, the device memory
//! the process holds after bind, and the BLAKE3 hash of each forward's raw BF16
//! output. With `WEMM_OUT` set, each distinct output is also written there.
//!
//! Env: `WEMM_PILE` (a model pile, opened read-only), `WEMM_MODELS` (its
//! models collection, 64 hex digits), `WEMM_ROOT`, `WEMM_ASSETS` (a directory
//! with the checkpoint's `config.json`, `tokenizer.json` and
//! `chat_template.jinja`), and optionally `WEMM_REF_FINAL` (four 16-hex
//! final-row hashes, comma-separated; a forward whose rows differ prints
//! EVENT). Needs a GB10.
#![cfg(feature = "semantic-wemm-cuda")]

use mary::models::qwen3_5::native::{Assets, NativeWemm};
use mary::nn::cuda_bf16_alias::{CudaBf16Aliases, WeightResidence};
use triblespace_core::blob::encodings::tensor::{elements::BF16, Tensor, TENSOR_HEADER_LEN};
use triblespace_core::blob::Blob;
use triblespace_core::id::Id;
use triblespace_core::inline::Inline;
use triblespace_core::repo::BlobStoreGet;
use triblespace_search::semantic_wemm::{WemmIdentity, WemmRuntime, GB10_NATIVE_BF16_PROFILE};

/// The batch the per-layer nondeterminism probe (nondet-layer lane,
/// 2026-11-09) repeated: one sentence and the first three windows of a
/// filler text, each at most 248 tokens, in this order. Built exactly as
/// that probe built it, so its `WEMM_REF_FINAL` hashes apply here.
fn batch(codec: &mary::models::qwen3_5::input_codec::InputCodec) -> Vec<String> {
    let filler: String = (0..40)
        .map(|i| format!("Entry {i}: the lighthouse keeper trimmed the lamp wick and logged each passing ship.\n"))
        .collect();
    let sentence = "A bowl of tomato soup with fresh basil and garlic bread.";
    let fits = |w: &str| codec.text(w).is_ok_and(|ids| ids.as_slice().len() <= 248);
    let fw = windows(&filler, 16, fits);
    [sentence, fw[0], fw[1], fw[2]].iter().map(|s| s.to_string()).collect()
}

/// The nondet probe's window cutter (a copy of the index's line, word,
/// character cut), kept identical so the batch is identical.
fn windows<'t>(text: &'t str, cap: u64, mut fits: impl FnMut(&str) -> bool) -> Vec<&'t str> {
    let units: [fn(&str) -> usize; 3] = [
        |s| s.find('\n').map_or(s.len(), |at| at + 1),
        |s| {
            let word = s.find(char::is_whitespace).unwrap_or(s.len());
            s.len() - s[word..].trim_start().len()
        },
        |s| s.chars().next().map_or(0, char::len_utf8),
    ];
    let mut windows = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() && (windows.len() as u64) < cap {
        let mut end = 0;
        for unit in units {
            while end < rest.len() {
                let next = end + unit(&rest[end..]);
                if !fits(&rest[..next]) {
                    break;
                }
                end = next;
            }
            if end > 0 {
                break;
            }
        }
        let end = end.max(units[2](rest));
        windows.push(rest[..end].trim_end());
        rest = rest[end..].trim_start();
    }
    windows
}

/// The nondet probe's final-row hash (std DefaultHasher over the row bytes).
fn sip(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut s = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut s);
    s.finish()
}

#[test]
#[ignore = "needs a GB10 and a frozen WeMM model pile"]
fn copied_and_aliased_weights_print_comparable_outputs() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("set {name}"));
    let residence = match std::env::var("WEMM_COPY_WEIGHTS").as_deref() {
        Ok("1") => WeightResidence::DeviceCopy,
        Ok("0") | Err(_) => WeightResidence::PileAliased,
        Ok(other) => panic!("WEMM_COPY_WEIGHTS must be 0 or 1, not {other:?}"),
    };
    let reps: usize = std::env::var("WEMM_REPS").map_or(4, |s| s.parse().unwrap());
    let path = std::path::PathBuf::from(var("WEMM_PILE"));
    let store = mary::persist::read_model_pile_snapshot_read_only(&path).unwrap();
    let handle = mary::model_collection::parse_collection_handle(&var("WEMM_MODELS")).unwrap();
    let collection = mary::model_collection::open_model_collection(&store, handle).unwrap();
    let model = mary::model_collection::snapshot_model_collection_for(&store, collection).unwrap();
    let root = Id::from_hex(&var("WEMM_ROOT")).unwrap();
    let dir = std::path::PathBuf::from(var("WEMM_ASSETS"));
    let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
    let assets = Assets::from_bytes(
        &read("config.json"),
        &read("tokenizer.json"),
        &read("chat_template.jinja"),
    )
    .unwrap();
    let codec = assets.codec().clone();
    let texts = batch(&codec);
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    let lens: Vec<usize> = texts.iter().map(|t| codec.text(t).unwrap().as_slice().len()).collect();
    eprintln!("lens {lens:?}");
    // WEMM_REF_FINAL: the nondet probe's four steady-state final-row hashes.
    let reference: Option<Vec<u64>> = std::env::var("WEMM_REF_FINAL")
        .ok()
        .map(|s| s.split(',').map(|h| u64::from_str_radix(h, 16).unwrap()).collect());

    let started = std::time::Instant::now();
    let mut aliases = CudaBf16Aliases::new(Default::default(), 759)
        .unwrap()
        .with_residence(residence);
    // SAFETY: the model pile is a frozen copy nobody writes while this runs.
    let native = unsafe {
        NativeWemm::from_frozen(model.facts(), model.store(), root, assets, &mut aliases, |_, _, _, _| Ok(()))
    }
    .unwrap();
    let identity = WemmIdentity {
        model_root: root,
        kernel_profile: GB10_NATIVE_BF16_PROFILE,
    };
    let mut runtime = WemmRuntime::from_native(native, codec).unwrap();
    assert_eq!(runtime.identity(), identity, "the bound model's own identity");
    let stats = aliases.stats();
    eprintln!(
        "residence {residence:?} bind_s {:.2} registrations {} aliased_bytes {} copied_bytes {}",
        started.elapsed().as_secs_f64(),
        stats.registrations,
        stats.aliased_bytes,
        stats.copied_bytes
    );
    match residence {
        WeightResidence::DeviceCopy => assert_eq!(stats.copied_bytes, stats.aliased_bytes),
        WeightResidence::PileAliased => assert_eq!(stats.copied_bytes, 0),
    }
    let smi = std::process::Command::new("nvidia-smi")
        .args(["--query-compute-apps=pid,used_memory", "--format=csv,noheader"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let pid = std::process::id().to_string();
    eprintln!(
        "device_after_bind {}",
        smi.lines()
            .find(|l| l.split(',').next() == Some(pid.as_str()))
            .unwrap_or("not listed")
    );

    let out = std::env::var("WEMM_OUT").ok().map(std::path::PathBuf::from);
    let mut seen = Vec::new();
    let mut events = 0usize;
    for rep in 0..reps {
        let t = std::time::Instant::now();
        let probe = runtime.probe_texts(&texts).unwrap();
        assert_eq!(probe.forward, rep as u64);
        assert_eq!(probe.raw.len(), texts.len() * 4096 * 2);
        assert_eq!(probe.ids.len(), texts.len());
        let digest = blake3::hash(&probe.raw).to_hex().to_string();
        let rows: Vec<String> = probe
            .raw
            .chunks(4096 * 2)
            .map(|row| blake3::hash(row).to_hex()[..16].to_owned())
            .collect();
        let finals: Vec<u64> = probe.raw.chunks(4096 * 2).map(sip).collect();
        let event = reference.as_ref().is_some_and(|r| r != &finals);
        events += usize::from(event);
        eprintln!(
            "forward {rep} ms {} raw_blake3 {digest} rows {} finals {} {}",
            t.elapsed().as_millis(),
            rows.join(","),
            finals.iter().map(|f| format!("{f:016x}")).collect::<Vec<_>>().join(","),
            if reference.is_none() { "noref" } else if event { "EVENT" } else { "ok" }
        );
        if !seen.contains(&digest) {
            if let Some(out) = &out {
                std::fs::create_dir_all(out).unwrap();
                std::fs::write(out.join(format!("{digest}.bin")), &probe.raw).unwrap();
            }
            seen.push(digest);
        }
    }
    assert_eq!(runtime.forwards(), reps as u64);
    eprintln!("distinct_outputs {}", seen.len());
    eprintln!("summary residence {residence:?} forwards {reps} events {events}");
}

/// Opens the frozen model pile and its assets from the environment, as
/// `copied_and_aliased_weights_print_comparable_outputs` does. A macro, so
/// the store's type never has to be named here.
macro_rules! open_model {
    ($model:ident, $root:ident, $assets:ident, $codec:ident, $residence:ident, $reps:ident) => {
        let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("set {name}"));
        let $residence = match std::env::var("WEMM_COPY_WEIGHTS").as_deref() {
            Ok("1") => WeightResidence::DeviceCopy,
            Ok("0") | Err(_) => WeightResidence::PileAliased,
            Ok(other) => panic!("WEMM_COPY_WEIGHTS must be 0 or 1, not {other:?}"),
        };
        let $reps: usize = std::env::var("WEMM_REPS").map_or(4, |s| s.parse().unwrap());
        let path = std::path::PathBuf::from(var("WEMM_PILE"));
        let store = mary::persist::read_model_pile_snapshot_read_only(&path).unwrap();
        let handle = mary::model_collection::parse_collection_handle(&var("WEMM_MODELS")).unwrap();
        let collection = mary::model_collection::open_model_collection(&store, handle).unwrap();
        let $model = mary::model_collection::snapshot_model_collection_for(&store, collection).unwrap();
        let $root = Id::from_hex(&var("WEMM_ROOT")).unwrap();
        let dir = std::path::PathBuf::from(var("WEMM_ASSETS"));
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let $assets = Assets::from_bytes(
            &read("config.json"),
            &read("tokenizer.json"),
            &read("chat_template.jinja"),
        )
        .unwrap();
        let $codec = $assets.codec().clone();
    };
}

#[repr(C)]
#[allow(dead_code)]
struct MallInfo2 {
    arena: usize,
    ordblks: usize,
    smblks: usize,
    hblks: usize,
    hblkhd: usize,
    usmblks: usize,
    fsmblks: usize,
    uordblks: usize,
    fordblks: usize,
    keepcost: usize,
}

// glibc; the test only runs on the GB10 (Linux, glibc).
unsafe extern "C" {
    fn mallinfo2() -> MallInfo2;
    fn malloc_trim(pad: usize) -> i32;
}

/// This process's pid line from nvidia-smi's compute-apps query.
fn device_line() -> String {
    let smi = std::process::Command::new("nvidia-smi")
        .args(["--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let pid = std::process::id().to_string();
    smi.lines()
        .find(|l| l.split(',').next() == Some(pid.as_str()))
        .and_then(|l| l.split(',').nth(1))
        .map_or("not_listed".into(), |m| m.trim().to_owned())
}

/// Prints one `point` line: the unit cgroup's memory.stat (bytes), this
/// process's smaps_rollup and status (kB), glibc's mallinfo2 (bytes), the
/// device memory nvidia-smi lists for this pid (MiB), and MemAvailable (kB).
fn point(label: &str, extra: &str) {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let field = |text: &str, key: &str| {
        text.lines()
            .find_map(|l| {
                let mut it = l.split_whitespace();
                (it.next() == Some(key)).then(|| it.next().unwrap_or("?").to_owned())
            })
            .unwrap_or_else(|| "?".into())
    };
    let cgroup = read("/proc/self/cgroup");
    let cgroup = cgroup.lines().next().and_then(|l| l.splitn(3, ':').nth(2)).unwrap_or("").trim().to_owned();
    let dir = format!("/sys/fs/cgroup{cgroup}");
    let stat = read(&format!("{dir}/memory.stat"));
    let cg = ["anon", "file", "shmem", "file_mapped", "unevictable", "kernel"]
        .iter()
        .map(|k| format!("cg_{k} {}", field(&stat, k)))
        .collect::<Vec<_>>()
        .join(" ");
    let current = read(&format!("{dir}/memory.current")).trim().to_owned();
    let smaps = read("/proc/self/smaps_rollup");
    let status = read("/proc/self/status");
    let meminfo = read("/proc/meminfo");
    // SAFETY: mallinfo2 takes no arguments and returns a plain struct.
    let mi = unsafe { mallinfo2() };
    eprintln!(
        "point {label} cg_current {current} {cg} smaps_rss_kb {} smaps_anon_kb {} status_rssanon_kb {} status_rssfile_kb {} malloc_arena {} malloc_hblks {} malloc_hblkhd {} malloc_uordblks {} malloc_fordblks {} gpu_mib {} memavail_kb {} {extra}",
        field(&smaps, "Rss:"),
        field(&smaps, "Anonymous:"),
        field(&status, "RssAnon:"),
        field(&status, "RssFile:"),
        mi.arena,
        mi.hblks,
        mi.hblkhd,
        mi.uordblks,
        mi.fordblks,
        device_line(),
        field(&meminfo, "MemAvailable:"),
    );
}

/// Polls a future to completion on this thread. CubeCL's CUDA `sync`
/// future waits on its fence when first polled.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

/// Who holds the memory a weight residence costs. Binds with the residence
/// `WEMM_COPY_WEIGHTS` chooses and prints a `point` line before bind, after
/// bind, and after each step of `WEMM_OWN_ORDER`: `flush-first` (the
/// default: a CubeCL sync, two client flushes, then the forwards) or
/// `forwards-first` (the forwards, then the sync and the two flushes). Both
/// end with `malloc_trim(0)`. A CubeCL flush rotates the stream's drop
/// queue: the first moves the staged host uploads behind a fence, the second
/// waits on that fence and frees them.
#[test]
#[ignore = "needs a GB10 and a frozen WeMM model pile"]
fn weight_memory_ownership_at_fixed_points() {
    open_model!(model, root, assets, codec, residence, reps);
    let texts = batch(&codec);
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    let order = std::env::var("WEMM_OWN_ORDER").unwrap_or_else(|_| "flush-first".into());
    let steps: &[&str] = match order.as_str() {
        "flush-first" => &["sync", "flush1", "flush2", "forwards"],
        "forwards-first" => &["forwards", "sync", "flush1", "flush2"],
        other => panic!("WEMM_OWN_ORDER must be flush-first or forwards-first, not {other:?}"),
    };
    eprintln!("ownership residence {residence:?} order {order} reps {reps}");
    point("p0_before_bind", "");

    let started = std::time::Instant::now();
    let mut aliases = CudaBf16Aliases::new(Default::default(), 759)
        .unwrap()
        .with_residence(residence);
    let mut rank1 = None;
    // SAFETY: the model pile is a frozen copy nobody writes while this runs.
    let native = unsafe {
        NativeWemm::from_frozen(model.facts(), model.store(), root, assets, &mut aliases, |_, raw, shape, _| {
            if shape.len() == 1 && rank1.is_none() {
                rank1 = Some(raw);
            }
            Ok(())
        })
    }
    .unwrap();
    let identity = WemmIdentity {
        model_root: root,
        kernel_profile: GB10_NATIVE_BF16_PROFILE,
    };
    let mut runtime = WemmRuntime::from_native(native, codec).unwrap();
    assert_eq!(runtime.identity(), identity, "the bound model's own identity");
    let bind_s = started.elapsed().as_secs_f64();
    // The model's client: re-binding an already registered leaf is a lookup
    // and returns a tensor on the same client; the registration count proves it.
    let before = aliases.stats();
    let blob = model.store().get::<Blob<Tensor<BF16, 1>>, Tensor<BF16, 1>>(Inline::new(rank1.unwrap())).unwrap();
    // SAFETY: as above.
    let lookup = unsafe { aliases.bind_pile_leaf(blob) }.unwrap();
    assert_eq!(aliases.stats().registrations, before.registrations);
    let client = lookup.client.clone();
    let stats = aliases.stats();
    point(
        "p1_after_bind",
        &format!(
            "bind_s {bind_s:.2} registrations {} aliased_bytes {} copied_bytes {} cubecl {:?}",
            stats.registrations,
            stats.aliased_bytes,
            stats.copied_bytes,
            client.memory_usage()
        ),
    );

    for (n, step) in steps.iter().enumerate() {
        match *step {
            "sync" => block_on(client.sync()).unwrap(),
            "flush1" | "flush2" => client.flush().unwrap(),
            "forwards" => {
                for rep in 0..reps {
                    let t = std::time::Instant::now();
                    let probe = runtime.probe_texts(&texts).unwrap();
                    eprintln!(
                        "forward {rep} ms {} raw_blake3 {}",
                        t.elapsed().as_millis(),
                        blake3::hash(&probe.raw).to_hex()
                    );
                }
            }
            _ => unreachable!(),
        }
        point(&format!("p{}_after_{step}", n + 2), &format!("cubecl {:?}", client.memory_usage()));
    }
    // SAFETY: malloc_trim takes a padding size and touches only the allocator.
    let trimmed = unsafe { malloc_trim(0) };
    point(&format!("p{}_after_malloc_trim", steps.len() + 2), &format!("returned {trimmed}"));
    drop(lookup);
    drop(runtime);
}

/// Every weight the model registered, read back from its device handle and
/// compared byte for byte with its payload in the pile. Each leaf the bind
/// selected is fetched from the store again (its bytes hashed against its
/// content handle), re-bound (a registration lookup, which returns the
/// handle the model holds; the registration count proves no new copy was
/// made), read back, and compared, one tensor at a time.
#[test]
#[ignore = "needs a GB10 and a frozen WeMM model pile"]
fn device_weights_equal_their_pile_bytes() {
    open_model!(model, root, assets, _codec, residence, _reps);
    let mut aliases = CudaBf16Aliases::new(Default::default(), 759)
        .unwrap()
        .with_residence(residence);
    let mut leaves: Vec<([u8; 32], usize)> = Vec::new();
    let mut selections = 0usize;
    // SAFETY: the model pile is a frozen copy nobody writes while this runs.
    let native = unsafe {
        NativeWemm::from_frozen(model.facts(), model.store(), root, assets, &mut aliases, |_, raw, shape, _| {
            selections += 1;
            if !leaves.iter().any(|l| l.0 == raw) {
                leaves.push((raw, shape.len()));
            }
            Ok(())
        })
    }
    .unwrap();
    let bound = aliases.stats();
    eprintln!(
        "bytecheck residence {residence:?} selections {selections} distinct_leaves {} registrations {} aliased_bytes {} copied_bytes {}",
        leaves.len(),
        bound.registrations,
        bound.aliased_bytes,
        bound.copied_bytes
    );
    let started = std::time::Instant::now();
    let (mut tensors, mut bytes, mut mismatched, mut short, mut hash_ok, mut hash_bad) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for (raw, rank) in &leaves {
        macro_rules! check {
            ($r:literal) => {{
                let blob = model.store().get::<Blob<Tensor<BF16, $r>>, Tensor<BF16, $r>>(Inline::new(*raw)).unwrap();
                let source = blob.bytes.clone();
                // SAFETY: as above.
                let tensor = unsafe { aliases.bind_pile_leaf(blob) }.unwrap();
                let back = tensor.client.read_one(tensor.handle.clone()).unwrap();
                (source, back)
            }};
        }
        let (source, back) = match rank {
            1 => check!(1),
            2 => check!(2),
            3 => check!(3),
            4 => check!(4),
            5 => check!(5),
            r => panic!("leaf of rank {r} is not covered by this check"),
        };
        if blake3::hash(&source).as_bytes() == raw {
            hash_ok += 1;
        } else {
            hash_bad += 1;
        }
        let payload = &source[TENSOR_HEADER_LEN..];
        let back: &[u8] = &back;
        tensors += 1;
        bytes += payload.len() as u64;
        if back.len() < payload.len() {
            short += 1;
            eprintln!("SHORT leaf {} payload {} readback {}", hex(raw), payload.len(), back.len());
        } else if &back[..payload.len()] != payload {
            mismatched += 1;
            let at = payload.iter().zip(back).position(|(a, b)| a != b).unwrap();
            let differing = payload.iter().zip(back).filter(|(a, b)| a != b).count();
            eprintln!("MISMATCH leaf {} payload {} first_differing_byte {at} differing_bytes {differing}", hex(raw), payload.len());
        }
    }
    let after = aliases.stats();
    eprintln!(
        "bytecheck_summary residence {residence:?} tensors {tensors} bytes {bytes} mismatched_tensors {mismatched} short_readbacks {short} source_hash_ok {hash_ok} source_hash_bad {hash_bad} registrations_before {} registrations_after {} seconds {:.2}",
        bound.registrations,
        after.registrations,
        started.elapsed().as_secs_f64()
    );
    assert_eq!(after.registrations, bound.registrations, "a re-bind made a new registration");
    assert_eq!(hash_bad, 0);
    assert_eq!((mismatched, short), (0, 0));
    drop(native);
}

fn hex(raw: &[u8; 32]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
