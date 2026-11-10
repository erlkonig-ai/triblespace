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
use triblespace_core::id::Id;
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
    let mut runtime = WemmRuntime::from_native(identity, native, codec).unwrap();
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
