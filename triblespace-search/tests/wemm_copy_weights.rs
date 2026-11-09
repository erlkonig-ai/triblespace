//! Copied weights and pile-aliased weights on the real model: run once per
//! residence, each in its own process, and compare the printed hashes.
//!
//! Binds WeMM from a frozen model pile with the residence `WEMM_COPY_WEIGHTS`
//! chooses (`1` copies to device memory, unset or `0` reads in place), then
//! embeds one fixed batch `WEMM_REPS` times through
//! [`WemmRuntime::probe_texts`] and prints the bind time, the device memory
//! the process holds after bind, and the BLAKE3 hash of each forward's raw BF16
//! output. With `WEMM_OUT` set, each distinct output is also written there.
//!
//! Env: `WEMM_PILE` (a model pile, opened read-only), `WEMM_MODELS` (its
//! models collection, 64 hex digits), `WEMM_ROOT`, `WEMM_ASSETS` (a directory
//! with the checkpoint's `config.json`, `tokenizer.json` and
//! `chat_template.jinja`). Needs a GB10.
#![cfg(feature = "semantic-wemm-cuda")]

use mary::models::qwen3_5::native::{Assets, NativeWemm};
use mary::nn::cuda_bf16_alias::{CudaBf16Aliases, WeightResidence};
use triblespace_core::id::Id;
use triblespace_search::semantic_wemm::{WemmIdentity, WemmRuntime, GB10_NATIVE_BF16_PROFILE};

/// A fixed batch of four texts of different lengths, in this order.
const BATCH: [&str; 4] = [
    "The quick brown fox jumps over the lazy dog.",
    "Tomato seedlings want full sun, deep watering and a stake once they reach knee height.",
    "fn main() {\n    let numbers = vec![3, 1, 4, 1, 5, 9, 2, 6];\n    let total: i32 = numbers.iter().sum();\n    println!(\"{total}\");\n}",
    "A lighthouse keeper kept a logbook of every ship that passed during the long winter: their names, the hour they were sighted, the direction of the wind, and whether the fog horn had to be sounded. Most entries were short, but on stormy nights the handwriting grew larger and the notes grew longer.",
];

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
    for rep in 0..reps {
        let t = std::time::Instant::now();
        let probe = runtime.probe_texts(&BATCH).unwrap();
        assert_eq!(probe.forward, rep as u64);
        assert_eq!(probe.raw.len(), BATCH.len() * 4096 * 2);
        assert_eq!(probe.ids.len(), BATCH.len());
        let digest = blake3::hash(&probe.raw).to_hex().to_string();
        let rows: Vec<String> = probe
            .raw
            .chunks(4096 * 2)
            .map(|row| blake3::hash(row).to_hex()[..16].to_owned())
            .collect();
        eprintln!(
            "forward {rep} ms {} raw_blake3 {digest} rows {}",
            t.elapsed().as_millis(),
            rows.join(",")
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
}
