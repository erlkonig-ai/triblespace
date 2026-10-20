//! Native CLI custody checks, using only empty synthetic piles and keys.
#![cfg(unix)]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};

fn fresh(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn command(
    dir: &Path,
    source: &Path,
    mode: &str,
    output: &Path,
    key: &Path,
    source_hash: &str,
) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("trible"));
    command
        .env_clear()
        .env("HOME", dir)
        .env("PATH", "/usr/bin:/bin")
        .current_dir(dir)
        .args(["pile", "migrate"])
        .arg(source)
        .arg(mode)
        .arg("--into")
        .arg(output)
        .arg("--key")
        .arg(key)
        .arg("--source-hash")
        .arg(source_hash);
    command
}

#[test]
fn canonical_and_refresh_accept_unchanged_input_with_parent_hardlink_descriptors() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("synthetic.pile");
    let alias = dir.path().join("hardlink.pile");
    let key = dir.path().join("throwaway.key");
    fresh(&source, &[]);
    fresh(&key, hex::encode([43; 32]).as_bytes());
    std::fs::hard_link(&source, &alias).unwrap();
    let before = std::fs::metadata(&source).unwrap();
    let source_hash = blake3::hash(&std::fs::read(&source).unwrap())
        .to_hex()
        .to_string();
    let author = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[43; 32])
            .verifying_key()
            .to_bytes(),
    );
    for (mode, operation) in [("canonical", "Rewrite"), ("canonical-refresh", "Refresh")] {
        for write in [false, true] {
            let output = dir.path().join(format!("{mode}-{write}-accepted.pile"));
            // The parent keeps an r or r+ hardlink descriptor open without
            // changing its bytes. An open descriptor is not itself a writer.
            let held = OpenOptions::new()
                .read(true)
                .write(write)
                .open(&alias)
                .unwrap();
            let result = command(dir.path(), &source, mode, &output, &key, &source_hash)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{mode}, write={write}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(output.is_file());
            assert!(!output.with_extension("pile.partial").exists());
            // One invocation's report is ephemeral test scratch, not retained
            // collection state. Require the complete successful report.
            let events: Vec<Value> = std::str::from_utf8(&result.stdout)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(
                events,
                vec![
                    json!({
                        "event": "begin", "operation": operation, "source": source,
                        "source_hash": source_hash, "source_bytes": 0,
                        "author": author, "retain_source": true, "refreshes": []
                    }),
                    json!({
                        "event": "verified", "operation": operation,
                        "emitted_occurrences": 0, "distinct_current_assertions": 0,
                        "retained_original_caches": 0, "retained_inert_occurrences": 0,
                        "retained_inert_bytes": 0, "source_retention_required": true,
                        "dry_run": false
                    }),
                    json!({
                        "event": "published", "operation": operation, "destination": output,
                        "full_rewrite_obligations_satisfied": mode == "canonical",
                        "retained_original_only_caches": 0, "retained_inert_occurrences": 0,
                        "retained_inert_bytes": 0, "source_evidence_fully_replaced": false,
                        "source_retention_required": true
                    }),
                ]
            );
            assert_eq!(std::fs::read(&source).unwrap(), b"");
            assert_eq!(
                blake3::hash(&std::fs::read(&source).unwrap())
                    .to_hex()
                    .as_str(),
                source_hash
            );
            for now in [
                std::fs::metadata(&source).unwrap(),
                std::fs::metadata(&alias).unwrap(),
                held.metadata().unwrap(),
            ] {
                assert_eq!((now.dev(), now.ino()), (before.dev(), before.ino()));
                assert_eq!(now.len(), before.len());
                assert_eq!(now.modified().unwrap(), before.modified().unwrap());
            }
            drop(held);
        }
    }
}
