//! Real process-signal tests over disposable local piles. Reopening checks the
//! completed append prefix, not power-loss durability; the normal exit and lack
//! of a Pile Drop warning exercise the command's explicit close path.
#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionPolicy, CollectionRead, CollectionRecord, CollectionStoreExt,
};
use triblespace_core::prelude::inlineencodings::Handle;
use triblespace_core::prelude::*;
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

fn sync_closes_on_signal(signal: &str, explicit_health_collection: bool) {
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
        .args(["--provider-publication-budget", "0"]);
    if explicit_health_collection {
        // Destination alone enables reporting, with no --health or extra key.
        command.args(["--health-collection", &hex::encode(collection.handle().raw)]);
    } else {
        command.arg("--health");
    }
    command
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
    // The process's real endpoint, health author and reported observer must be
    // one identity, without any second key argument or key file.
    assert!(log.contains(&format!(
        "node: {}",
        hex::encode(key.verifying_key().to_bytes())
    )));
    let mut pile = Pile::open(&path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let mut observers = 0;
    for record in snapshot.records().unwrap().map(Result::unwrap) {
        record.verify_strict().unwrap();
        assert_eq!(record.public_key().raw, key.verifying_key().to_bytes());
        if let CollectionRecord::Commit(commit) = record {
            let handle = Inline::<Handle<blobencodings::SimpleArchive>>::new(commit.data().raw);
            let facts: TribleSet = snapshot.get(handle).unwrap();
            for endpoint in find!(endpoint: ed25519_dalek::VerifyingKey,
                pattern!(&facts, [{ triblespace_net::health_record::attrs::endpoint: ?endpoint }])
            ) {
                assert_eq!(endpoint, key.verifying_key());
                observers += 1;
            }
        }
    }
    assert!(observers > 0, "a real signed report must name its observer");
    pile.close().unwrap();
}

#[test]
fn sync_closes_on_sigint() {
    sync_closes_on_signal("-INT", false);
}

#[test]
fn sync_closes_on_sigterm() {
    sync_closes_on_signal("-TERM", true);
}

#[test]
fn health_preflight_rejects_unadmitted_and_derived_destinations_without_appending() {
    use triblespace_core::capability::policy::resource_policy;
    use triblespace_core::collection::{
        collection_mapping, collection_representation, collection_source, mapping_algorithm,
        KIND_COLLECTION_DESCRIPTOR, KIND_COLLECTION_MAPPING,
    };
    use triblespace_core::metadata::{self, MetaDescribe};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("health.pile");
    let key_path = directory.path().join("self.key");
    let key = triblespace_core::signing_key_file::init(&key_path).unwrap();
    std::fs::File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    let other = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
    let wrong: Collection<blobencodings::SimpleArchive> = pile
        .collection(
            "other author",
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(other.verifying_key()),
            ),
        )
        .unwrap();
    let algorithm = genid();
    let mapping = entity! {
        metadata::tag: KIND_COLLECTION_MAPPING, mapping_algorithm: &algorithm
    };
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(key.verifying_key()),
    );
    let derived: Collection<blobencodings::SimpleArchive> = pile
        .register_collection(entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_source: wrong.handle(),
            resource_policy*: policy.fragment(),
            collection_representation*: blobencodings::SimpleArchive::describe(),
            collection_mapping*: mapping,
        })
        .unwrap();
    pile.close().unwrap();
    let before = std::fs::read(&path).unwrap();
    for (destination, message) in [
        (wrong, "node key is not admitted by the health destination"),
        (derived, "health destination must be a source collection"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_trible"))
            .env_clear()
            .args(["pile", "net", "sync"])
            .arg(&path)
            .arg("--key")
            .arg(&key_path)
            .args(["--collection", &hex::encode(wrong.handle().raw)])
            .args([
                "--health-collection",
                &hex::encode(destination.handle().raw),
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(message), "{stderr}");
        assert!(
            !stderr.contains("live collection repair active"),
            "{stderr}"
        );
        assert!(
            !stderr.contains("Pile dropped without calling close()"),
            "{stderr}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
