//! Native subprocess custody checks, using only empty synthetic piles and keys.
#![cfg(target_os = "macos")]

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

fn fresh(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn command(home: &Path, source: &Path, mode: &str, output: &Path, key: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("trible"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .args(["pile", "migrate"])
        .arg(source)
        .arg(mode)
        .arg("--into")
        .arg(output)
        .arg("--key")
        .arg(key)
        .arg("--source-hash")
        .arg(
            blake3::hash(&std::fs::read(source).unwrap())
                .to_hex()
                .as_str(),
        );
    command
}

struct Holder(Child);
impl Drop for Holder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn holder(path: &Path, write: bool) -> Holder {
    let script = if write {
        "exec 9<> \"$1\"; printf 'ready\\n'; read -r line"
    } else {
        "exec 9< \"$1\"; printf 'ready\\n'; read -r line"
    };
    let mut child = Holder(
        Command::new("/bin/sh")
            .env_clear()
            .args(["-c", script, "custody-fixture"])
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut ready = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "ready\n");
    child
}

#[test]
fn canonical_and_refresh_allow_frozen_input_but_refuse_other_process_hardlink_openers() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("synthetic.pile");
    let alias = dir.path().join("hardlink.pile");
    let key = dir.path().join("throwaway.key");
    fresh(&source, &[]);
    fresh(&key, hex::encode([43; 32]).as_bytes());
    std::fs::hard_link(&source, &alias).unwrap();
    for mode in ["canonical", "canonical-refresh"] {
        for write in [false, true] {
            let output = dir.path().join(format!("{mode}-{write}-refused.pile"));
            let held = holder(&alias, write);
            let result = command(dir.path(), &source, mode, &output, &key)
                .output()
                .unwrap();
            assert!(!result.status.success());
            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(stderr.contains("open in"), "{stderr}");
            assert!(stderr.contains(&held.0.id().to_string()), "{stderr}");
            assert!(stderr.contains("observational opener guard"), "{stderr}");
            assert!(!output.exists());
            assert!(!output.with_extension("pile.partial").exists());
            drop(held);
        }
        let output = dir.path().join(format!("{mode}-accepted.pile"));
        let result = command(dir.path(), &source, mode, &output, &key)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(output.exists());
        assert!(String::from_utf8_lossy(&result.stderr).contains("Operator-frozen input custody"));
        assert_eq!(std::fs::read(&source).unwrap(), b"");
    }
}
