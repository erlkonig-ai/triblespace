//! `trible-migrate SRC upgrade --into DST`: the fixpoint driver over a real
//! released v0.46.4 pile and synthetic dead-end and /32 inputs.

use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use tempfile::tempdir;

const BRANCH: &str = "42424242424242424242424242424242";

fn migrate() -> Command {
    let mut command = Command::cargo_bin("trible-migrate").unwrap();
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name == "PILE" || name == "PERSONA" || name.starts_with("TRIBLESPACE_") {
            command.env_remove(key);
        }
    }
    command
}

fn upgrade(source: &Path, into: &Path, decisions: Option<&Path>) -> Output {
    let mut command = migrate();
    command.arg(source).arg("upgrade").arg("--into").arg(into);
    if let Some(decisions) = decisions {
        command.arg("--decisions").arg(decisions);
    }
    command.output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn envelope(kind: &str) -> Vec<u8> {
    let mut record = vec![0u8; 256];
    record[..28].copy_from_slice(
        &hex::decode("0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B")
            .expect("envelope marker"),
    );
    record[28..32].copy_from_slice(&1u32.to_le_bytes());
    record[32..64].copy_from_slice(&hex::decode(kind).expect("record kind"));
    record
}

#[test]
fn a_released_pile_reaches_its_fixpoint_and_stays_there() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("legacy.pile");
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/legacy_v0464_branch.pile"
    ))
    .unwrap();
    std::fs::write(&source, &fixture).unwrap();
    let into = dir.path().join("current.pile");

    // First run: reframe and descriptions happen, then the branch needs a choice.
    let first = upgrade(&source, &into, None);
    let text = stdout(&first);
    assert_eq!(first.status.code(), Some(2), "{text}");
    assert!(text.contains("Reframed into"), "{text}");
    assert!(text.contains("1 live legacy branch(es) need a choice"), "{text}");
    assert!(text.contains(BRANCH), "{text}");
    assert!(into.exists());

    // Second run with the choice recorded: the branch becomes a collection.
    let key = dir.path().join("migrator.key");
    std::fs::write(&key, "03".repeat(32)).unwrap();
    let decisions = dir.path().join("decisions.json");
    std::fs::write(
        &decisions,
        serde_json::json!({"branches": {BRANCH: {
            "collection": "events",
            "signing_key": key.to_str().unwrap(),
        }}})
        .to_string(),
    )
    .unwrap();
    let second = upgrade(&source, &into, Some(&decisions));
    let text = stdout(&second);
    assert_eq!(second.status.code(), Some(0), "{text}");
    assert!(text.contains("continuing"), "{text}");
    assert!(text.contains("copied into collection \"events\""), "{text}");
    assert!(text.contains("Fixpoint reached"), "{text}");
    let settled = std::fs::read(&into).unwrap();

    // Third run: the same answers, nothing appended, the pile byte-identical.
    let third = upgrade(&source, &into, Some(&decisions));
    let text = stdout(&third);
    assert_eq!(third.status.code(), Some(0), "{text}");
    assert!(text.contains("already in collection \"events\""), "{text}");
    assert_eq!(std::fs::read(&into).unwrap(), settled);

    // The source was only ever read.
    assert_eq!(std::fs::read(&source).unwrap(), fixture);
}

#[test]
fn a_skipped_branch_is_a_choice_too() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("legacy.pile");
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/legacy_v0464_branch.pile"),
        &source,
    )
    .unwrap();
    let into = dir.path().join("current.pile");
    let decisions = dir.path().join("decisions.json");
    std::fs::write(
        &decisions,
        serde_json::json!({"branches": {BRANCH: {"skip": "archived elsewhere"}}}).to_string(),
    )
    .unwrap();
    let output = upgrade(&source, &into, Some(&decisions));
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(text.contains("left as a legacy branch (archived elsewhere)"), "{text}");
}

#[test]
fn unknown_frames_have_no_path_and_nothing_is_written() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("unknown.pile");
    let bytes = envelope("A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5");
    std::fs::write(&source, &bytes).unwrap();
    let into = dir.path().join("current.pile");
    let output = upgrade(&source, &into, None);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(3), "{text}");
    assert!(text.contains("No path forward"), "{text}");
    assert!(!into.exists());
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
}

#[test]
fn a_deployed_32_pile_is_sent_to_canonical() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("deployed.pile");
    // The /32 COMMIT kind.
    let bytes = envelope("A1322BB3F5214287C314D42AFCC1A97CB264FACD9A22B4938838BE78DB31AA59");
    std::fs::write(&source, &bytes).unwrap();
    let into = dir.path().join("current.pile");
    let output = upgrade(&source, &into, None);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(2), "{text}");
    assert!(text.contains("deployed /32 pile"), "{text}");
    assert!(text.contains("canonical"), "{text}");
    assert!(!into.exists());
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
}
