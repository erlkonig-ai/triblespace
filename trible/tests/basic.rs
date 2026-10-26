use assert_cmd::Command;
use predicates::prelude::*;

fn help(args: &[&str]) -> String {
    help_of("trible", args)
}

fn help_of(binary: &str, args: &[&str]) -> String {
    let output = Command::cargo_bin(binary)
        .unwrap()
        .args(args)
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn has_command(help: &str, name: &str) -> bool {
    help.lines().any(|line| {
        line.trim_start()
            .strip_prefix(name)
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
    })
}

#[test]
fn legacy_mutation_commands_are_absent() {
    let top = help(&[]);
    assert!(!has_command(&top, "branch"));

    let pile = help(&["pile"]);
    for removed in ["branch", "pin", "merge", "squash", "extract", "reid"] {
        assert!(
            !has_command(&pile, removed),
            "removed pile command {removed:?} remains in help:\n{pile}"
        );
    }
    // Migration moved to its own binary, `trible-migrate`.
    assert!(
        !has_command(&pile, "migrate"),
        "pile migrate should live in trible-migrate:\n{pile}"
    );
    for retained in ["blob", "collection", "compact", "net"] {
        assert!(
            has_command(&pile, retained),
            "retained pile command {retained:?} is missing from help:\n{pile}"
        );
    }

    let store = help(&["store"]);
    assert!(!has_command(&store, "branch"));
    assert!(has_command(&store, "blob"));

    let migrate = help_of("trible-migrate", &["unused.pile"]);
    assert!(has_command(&migrate, "branch-to-collection"));
    assert!(has_command(&migrate, "reframe"));
    let branch_to_collection =
        help_of("trible-migrate", &["unused.pile", "branch-to-collection"]);
    assert!(branch_to_collection.contains("--collection-name"));
    assert!(branch_to_collection.contains("--authority"));
    assert!(branch_to_collection.contains("--signing-key"));
    assert!(!branch_to_collection.contains("--namespace"));
    assert!(!branch_to_collection.contains("--proof"));
    assert!(!branch_to_collection.contains("--team-root"));
    let run = help_of("trible-migrate", &["unused.pile", "run"]);
    assert!(run.contains("monotone-wants"));
    assert!(run.contains("record-kind-descriptions"));
    assert!(!run.contains("branch-metadata-name"));
    assert!(!run.contains("no-rename-duplicates"));

    Command::cargo_bin("trible-migrate")
        .unwrap()
        .args(["unused.pile", "run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("<MIGRATION>"));
}

#[test]
fn signing_key_init_is_explicit_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("data.pile");
    let key = directory.path().join("self.key");

    let first = Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "signing-key", "init"])
        .arg(&pile)
        .output()
        .unwrap();
    assert!(first.status.success());
    assert_eq!(std::fs::metadata(&key).unwrap().len(), 64);
    assert!(!pile.exists(), "key provisioning must not create the pile");

    let second = Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "signing-key", "init"])
        .arg(&pile)
        .output()
        .unwrap();
    assert!(second.status.success());
    assert_eq!(second.stdout, first.stdout);
    assert!(String::from_utf8(first.stdout)
        .unwrap()
        .contains("public-key: "));
}

#[test]
fn genid_outputs_id() {
    Command::cargo_bin("trible")
        .unwrap()
        .arg("genid")
        .assert()
        .success()
        .stdout(predicate::str::is_match("^[A-F0-9]{32}\\n$").unwrap());
}

#[test]
fn completion_generates_script() {
    Command::cargo_bin("trible")
        .unwrap()
        .args(["completion", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("_trible()"));
}

#[test]
fn version_flag_prints_crate_version() {
    // Both `--version` and `-V` flags work and print
    // `trible <semver>` (clap's default --version format).
    Command::cargo_bin("trible")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_match("^trible \\d+\\.\\d+\\.\\d+\\n$").unwrap());

    Command::cargo_bin("trible")
        .unwrap()
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::is_match("^trible \\d+\\.\\d+\\.\\d+\\n$").unwrap());
}
