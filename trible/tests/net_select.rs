//! `trible pile net select | unselect | selection` against a real pile file.
//!
//! The commands write the register the sync daemon reads, so every check here
//! reads the result back through the same library calls the daemon uses
//! (`config_facts`, `sync_selection`) rather than trusting the CLI's output.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use triblespace_core::collection::selection::{
    config_facts, sync_collection, sync_selected, sync_selection, Selection,
    CONFIG_COLLECTION_NAME,
};
use triblespace_core::collection::{
    private_policy, AdmissionPolicy, CollectionHandle, CollectionPolicy, CollectionStoreExt,
};
use triblespace_core::macros::entity;
use triblespace_core::prelude::*;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;

struct Fixture {
    dir: tempfile::TempDir,
    signer: ed25519_dalek::SigningKey,
    /// A collection whose descriptor is resident, so its name can be shown.
    named: CollectionHandle,
    /// A handle nothing here describes: a selection may precede its descriptor.
    absent: CollectionHandle,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::File::create(dir.path().join("self.pile")).unwrap();
        let signer = triblespace_core::signing_key_file::init(&dir.path().join("self.key")).unwrap();
        let mut pile = Pile::open(&dir.path().join("self.pile")).unwrap();
        let authority = signer.verifying_key();
        let named = pile
            .collection(
                "wiki",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(authority),
                    AdmissionPolicy::direct(authority),
                ),
            )
            .unwrap()
            .handle();
        pile.close().unwrap();
        let absent = CollectionHandle::new(*blake3::hash(b"no such descriptor").as_bytes());
        Fixture {
            dir,
            signer,
            named,
            absent,
        }
    }

    fn pile_path(&self) -> PathBuf {
        self.dir.path().join("self.pile")
    }

    fn cli(&self, verb: &str) -> Command {
        let mut command = Command::cargo_bin("trible").unwrap();
        command
            .args(["pile", "net", verb])
            .arg(self.pile_path())
            .arg("--key")
            .arg(self.dir.path().join("self.key"))
            .env_remove("TRIBLESPACE_KEY");
        command
    }

    /// The register value the daemon would read for `collection`.
    fn read(&self, collection: CollectionHandle) -> Selection {
        read_selection(&self.pile_path(), &self.signer, collection)
    }
}

fn read_selection(
    path: &Path,
    signer: &ed25519_dalek::SigningKey,
    collection: CollectionHandle,
) -> Selection {
    let mut pile = Pile::open(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let facts = config_facts(&snapshot, signer.verifying_key()).unwrap();
    let value = sync_selection(&facts, collection);
    drop(snapshot);
    pile.close().unwrap();
    value
}

fn hex(collection: CollectionHandle) -> String {
    hex::encode(collection.raw)
}

#[test]
fn select_writes_the_register_the_daemon_reads() {
    let fixture = Fixture::new();
    assert_eq!(fixture.read(fixture.named), Selection::Unset);

    fixture
        .cli("select")
        .arg(hex(fixture.named))
        .arg(hex(fixture.absent))
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "selected {} (wiki)",
            hex(fixture.named)
        )))
        .stdout(predicate::str::contains(format!(
            "selected {} (no descriptor resident here yet",
            hex(fixture.absent)
        )));
    assert_eq!(fixture.read(fixture.named), Selection::Selected);
    assert_eq!(fixture.read(fixture.absent), Selection::Selected);

    fixture
        .cli("unselect")
        .arg(hex(fixture.named))
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "unselected {} (wiki)",
            hex(fixture.named)
        )));
    assert_eq!(fixture.read(fixture.named), Selection::Unselected);
    assert_eq!(fixture.read(fixture.absent), Selection::Selected);

    fixture
        .cli("selection")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "{} unselected wiki",
            hex(fixture.named)
        )))
        .stdout(predicate::str::contains(format!(
            "{} selected   no descriptor resident",
            hex(fixture.absent)
        )))
        .stdout(predicate::str::contains(
            "2 collection(s) named in this pile's configuration: 1 selected, 1 unselected.",
        ));
}

#[test]
fn select_settles_a_conflict_between_concurrent_heads() {
    let fixture = Fixture::new();
    let authority = fixture.signer.verifying_key();

    // Two writers that saw nothing: one selects, one unselects, neither
    // supersedes the other.
    let mut pile = Pile::open(&fixture.pile_path()).unwrap();
    let config = pile
        .collection(CONFIG_COLLECTION_NAME, private_policy(authority))
        .unwrap();
    for selected in [true, false] {
        let state = entity! { &genid() @
            sync_collection: fixture.named,
            sync_selected: selected,
        };
        pile.commit(config, &fixture.signer, state).unwrap();
    }
    pile.close().unwrap();
    assert!(matches!(
        fixture.read(fixture.named),
        Selection::Conflicted(heads) if heads.len() == 2
    ));

    fixture
        .cli("selection")
        .assert()
        .success()
        .stdout(predicate::str::contains("conflicted between 2 heads"));

    fixture
        .cli("select")
        .arg(hex(fixture.named))
        .assert()
        .success();
    assert_eq!(fixture.read(fixture.named), Selection::Selected);
}

#[test]
fn an_empty_configuration_lists_nothing() {
    let fixture = Fixture::new();
    fixture
        .cli("selection")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "0 collection(s) named in this pile's configuration: 0 selected, 0 unselected.",
        ));
}

#[test]
fn select_requires_a_handle() {
    let fixture = Fixture::new();
    fixture.cli("select").assert().failure();
}
