//! Real process-signal tests over disposable local piles. Reopening checks the
//! completed append prefix, not power-loss durability; the normal exit and lack
//! of a Pile Drop warning exercise the command's explicit close path.
#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionRead, CollectionStoreExt,
};
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;

struct SyncProcess(Child);

impl Drop for SyncProcess {
    fn drop(&mut self) {
        // A failed assertion must not leave an endpoint or a pile writer alive.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn record_count(path: &Path) -> usize {
    let mut pile = Pile::open(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let count = snapshot.records().unwrap().map(Result::unwrap).count();
    pile.close().unwrap();
    count
}

fn sync_closes_on_signal(signal: &str) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sync.pile");
    let key_path = directory.path().join("self.key");
    let log_path = directory.path().join("sync.log");
    std::fs::File::create(&path).unwrap();
    let key = triblespace_core::signing_key_file::init(&key_path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    let collection = pile
        .collection(
            "local signal fixture",
            CollectionPolicy::new(
                AdmissionPolicy::direct(key.verifying_key()),
                AdmissionPolicy::direct(key.verifying_key()),
            ),
        )
        .unwrap();
    pile.close().unwrap();
    let before = record_count(&path);

    let log = std::fs::File::create(&log_path).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_trible"));
    // Never inherit the developer's live pile, keys, contacts or model roots.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name == "PILE"
            || name == "PERSONA"
            || name.starts_with("TRIBLESPACE_")
            || name.starts_with("NOMIC_")
        {
            command.env_remove(key);
        }
    }
    command
        .args(["pile", "net", "sync"])
        .arg(&path)
        .arg("--key")
        .arg(&key_path)
        .arg("--collection")
        .arg(format!("blake3:{}", hex::encode(collection.handle().raw)))
        // No peer is configured and provider announcements are disabled. The
        // normal transport may still use discovery/relay infrastructure.
        .args(["--provider-publication-budget", "0"])
        .arg("--health-key")
        .arg(&key_path)
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let mut process = SyncProcess(command.spawn().unwrap());
    let startup_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "sync exited before readiness: {log}"
        );
        // The initial health COMMIT precedes this message. There is an actual
        // unclosed mutation when we stop, even though no remote peer is used.
        if log.contains("live collection repair active.") {
            break;
        }
        assert!(Instant::now() < startup_deadline, "sync did not arm: {log}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(Command::new("kill")
        .args([signal, &process.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let shutdown_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "{signal} did not close sync normally: {status}\n{}",
                std::fs::read_to_string(&log_path).unwrap()
            );
            break;
        }
        assert!(
            Instant::now() < shutdown_deadline,
            "{signal} did not stop sync"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("sync stopped; closing pile"), "{log}");
    assert!(
        !log.contains("Pile dropped without calling close()"),
        "{log}"
    );
    assert!(
        record_count(&path) > before,
        "the health COMMIT must survive"
    );
}

#[test]
fn sync_closes_on_sigint() {
    sync_closes_on_signal("-INT");
}

#[test]
fn sync_closes_on_sigterm() {
    sync_closes_on_signal("-TERM");
}
