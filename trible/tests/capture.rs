#![cfg(unix)]

use assert_cmd::Command;
use std::fs;

#[test]
fn bare_relative_destination_is_published_under_the_resolved_private_parent() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("source.pile"), []).unwrap();
    let output = Command::cargo_bin("trible")
        .unwrap()
        .current_dir(directory.path())
        .args(["pile", "capture", "source.pile", "--into", "capture.pile"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let receipt: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let destination = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("capture.pile");
    assert_eq!(
        receipt["destination"],
        destination.to_string_lossy().as_ref()
    );
    assert_eq!(receipt["bytes"], 0);
    assert_eq!(receipt["status"], "captured");
    assert_eq!(fs::metadata(destination).unwrap().len(), 0);
    // The absolute receipt path is also the path passed to publish: even
    // this bare-name invocation takes its directory-sync branch, not None.
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}
