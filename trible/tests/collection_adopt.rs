//! End-to-end collection adoption on a real pile file.
//!
//! The unit tests in `triblespace_core::collection::migration` prove the
//! arithmetic. These prove the thing an operator actually does: a generation is
//! re-minted under its own name, the previous generation's records go quiet,
//! and the tooling has to find them, price the carry, perform it, and prove it
//! finished — through the command line, against bytes on disk.
//!
//! Every fixture builds its own pile in a temporary directory. Nothing here
//! reads or writes a live pile, and the subprocess has the colony's ambient
//! environment stripped so it cannot be pointed at one by accident.

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};
use std::time::Duration;
use tempfile::TempDir;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::records::{CollectionCommit, CollectionHandle};
use triblespace_core::collection::{
    grant_collection_write, AdmissionPolicy, Collection, CollectionPolicy, CollectionRead,
    CollectionRecord, CollectionStore, CollectionStoreExt,
};
use triblespace_core::id::Id;
use triblespace_core::inline::Inline;
use triblespace_core::macros::entity;
use triblespace_core::metadata;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;

fn trible() -> ProcessCommand {
    let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_trible"));
    // A developer's live pile, collection or key must not turn these isolated
    // subprocesses into consumers of colony state.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name == "PILE" || name == "PERSONA" || name.starts_with("TRIBLESPACE_") {
            command.env_remove(key);
        }
    }
    command
}

fn policy(signer: &SigningKey) -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(signer.verifying_key()),
        AdmissionPolicy::direct(signer.verifying_key()),
    )
}

fn handle_text(handle: CollectionHandle) -> String {
    format!("blake3:{}", hex::encode(handle.raw))
}

/// One name, two generations: exactly the shape a policy change produces.
struct Cutover {
    _directory: TempDir,
    path: PathBuf,
    old_key_file: PathBuf,
    new_key_file: PathBuf,
    stranger_key_file: PathBuf,
    old: Collection<SimpleArchive>,
    new: Collection<SimpleArchive>,
    stranger: SigningKey,
}

impl Cutover {
    /// `retired` rows in the old generation, `carried` of them already in the
    /// new one, so the fixture can be a fresh cutover or a half-done one.
    fn new(retired: &[u8], already: &[u8]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("adopt.pile");
        std::fs::File::create(&path).unwrap();
        let old_key_file = directory.path().join("old.key");
        let new_key_file = directory.path().join("new.key");
        let stranger_key_file = directory.path().join("stranger.key");
        let old_key = triblespace_core::signing_key_file::init(&old_key_file).unwrap();
        let new_key = triblespace_core::signing_key_file::init(&new_key_file).unwrap();
        let stranger = triblespace_core::signing_key_file::init(&stranger_key_file).unwrap();

        let mut pile = Pile::open(&path).unwrap();
        let old = pile.collection("wiki", policy(&old_key)).unwrap();
        let new = pile.collection("wiki", policy(&new_key)).unwrap();
        assert_ne!(
            old.handle(),
            new.handle(),
            "a different policy is a different collection under the same name"
        );
        for tag in retired {
            pile.commit(old, &old_key, row(*tag)).unwrap();
        }
        for tag in already {
            pile.commit(new, &new_key, row(*tag)).unwrap();
        }
        pile.close().unwrap();

        Self {
            _directory: directory,
            path,
            old_key_file,
            new_key_file,
            stranger_key_file,
            old,
            new,
            stranger,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = trible();
        command.args(["pile", "collection"]).args(args);
        Command::from_std(command)
            .timeout(Duration::from_secs(60))
            .output()
            .unwrap()
    }

    fn adopt(&self, key: &Path, extra: &[&str]) -> Output {
        let into = handle_text(self.new.handle());
        let key = key.to_str().unwrap().to_owned();
        let pile = self.path.to_str().unwrap().to_owned();
        let mut args = vec![
            "adopt",
            pile.as_str(),
            "--into",
            into.as_str(),
            "--siblings",
            "--key",
            key.as_str(),
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn adopted(&self, extra: &[&str]) -> Output {
        let target = handle_text(self.new.handle());
        let pile = self.path.to_str().unwrap().to_owned();
        let mut args = vec!["adopted", pile.as_str(), target.as_str()];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn commits(&self, collection: CollectionHandle) -> usize {
        let mut pile = Pile::open(&self.path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let count = snapshot
            .records()
            .unwrap()
            .filter_map(Result::ok)
            .filter(|record| match record {
                CollectionRecord::Commit(commit) => commit.collection() == collection,
                _ => false,
            })
            .count();
        pile.close().unwrap();
        count
    }
}

fn row(tag: u8) -> triblespace_core::trible::Fragment {
    entity! { metadata::tag: Id::new([tag; 16]).unwrap() }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The whole arc, through the command line.
#[test]
fn a_dry_run_prices_the_carry_the_apply_performs_it_and_adopted_proves_it() {
    let fixture = Cutover::new(&[0x11, 0x22, 0x33, 0x44], &[]);
    let before = std::fs::metadata(&fixture.path).unwrap().len();

    // Before anything: the completeness check fails, by content, and says so.
    let check = fixture.adopted(&[]);
    assert!(!check.status.success(), "{}", text(&check));
    let rendered = text(&check);
    assert!(rendered.contains("4"), "{rendered}");
    assert!(rendered.contains("incomplete"), "{rendered}");

    // The dry run is the default: it writes nothing and prices the carry.
    let dry = fixture.adopt(&fixture.new_key_file, &[]);
    assert!(dry.status.success(), "{}", text(&dry));
    let rendered = text(&dry);
    assert!(
        rendered.contains("records this key would append (NET NEW)     : 4"),
        "{rendered}"
    );
    assert!(rendered.contains("dry run: nothing appended"), "{rendered}");
    assert_eq!(
        std::fs::metadata(&fixture.path).unwrap().len(),
        before,
        "a dry run must not touch the file"
    );
    assert_eq!(fixture.commits(fixture.new.handle()), 0);

    // The apply appends exactly what the dry run promised.
    let applied = fixture.adopt(&fixture.new_key_file, &["--apply"]);
    assert!(applied.status.success(), "{}", text(&applied));
    let rendered = text(&applied);
    assert!(rendered.contains("appended 4 record(s)"), "{rendered}");
    assert!(
        rendered.contains("0 content pair(s) still unreached"),
        "{rendered}"
    );
    assert!(
        rendered.contains("trible pile compact"),
        "the compaction discipline is stated: {rendered}"
    );
    assert_eq!(fixture.commits(fixture.new.handle()), 4);
    assert_eq!(
        fixture.commits(fixture.old.handle()),
        4,
        "the retired generation keeps its own records"
    );

    // And now the standalone proof passes.
    let check = fixture.adopted(&[]);
    assert!(check.status.success(), "{}", text(&check));
    assert!(text(&check).contains("complete"), "{}", text(&check));

    // A second run is free: re-signing is deterministic.
    let again = fixture.adopt(&fixture.new_key_file, &[]);
    assert!(again.status.success(), "{}", text(&again));
    assert!(
        text(&again).contains("records this key would append (NET NEW)     : 0"),
        "{}",
        text(&again)
    );
    let settled = std::fs::metadata(&fixture.path).unwrap().len();
    let reapplied = fixture.adopt(&fixture.new_key_file, &["--apply"]);
    assert!(reapplied.status.success(), "{}", text(&reapplied));
    assert_eq!(
        std::fs::metadata(&fixture.path).unwrap().len(),
        settled,
        "an already-applied carry appends no bytes at all"
    );
}

/// The regression test for a carry that quietly left records behind.
///
/// A previous cutover under-delivered by 428 archives and nothing said so. Here
/// the shortfall is built on purpose — the new generation holds two of four —
/// and `adopted` has to fail, name the count, and exit non-zero, standalone,
/// with no carry in flight.
#[test]
fn adopted_detects_a_deliberately_incomplete_carry() {
    let fixture = Cutover::new(&[0x11, 0x22, 0x33, 0x44], &[]);
    // Carry half of it by hand, exactly as an interrupted adoption would.
    {
        let mut pile = Pile::open(&fixture.path).unwrap();
        let new_key =
            triblespace_core::signing_key_file::load_existing(&fixture.new_key_file).unwrap();
        for tag in [0x11, 0x22] {
            pile.commit(fixture.new, &new_key, row(tag)).unwrap();
        }
        pile.close().unwrap();
    }

    let check = fixture.adopted(&["--list"]);
    assert!(
        !check.status.success(),
        "an incomplete carry must not report success: {}",
        text(&check)
    );
    let rendered = text(&check);
    assert!(
        rendered.contains("2 content pair(s) are held by a source and absent from the target"),
        "{rendered}"
    );
    assert!(
        rendered.contains("missing data blake3:"),
        "--list names what is absent: {rendered}"
    );
}

/// The key decides the size of the write, and the tool says so before writing.
#[test]
fn the_wrong_key_is_priced_and_the_inadmissible_one_is_refused() {
    let fixture = Cutover::new(&[0x11, 0x22, 0x33], &[0x11, 0x22, 0x33]);

    // The target's own writer has nothing to do: its records are already here.
    let right = fixture.adopt(&fixture.new_key_file, &[]);
    assert!(right.status.success(), "{}", text(&right));
    assert!(
        text(&right).contains("records this key would append (NET NEW)     : 0"),
        "{}",
        text(&right)
    );

    // A stranger re-signs all of it, gains nothing, and is refused outright
    // because the target does not admit it as a writer.
    let wrong = fixture.adopt(&fixture.stranger_key_file, &[]);
    assert!(
        !wrong.status.success(),
        "an inadmissible signer must be refused: {}",
        text(&wrong)
    );
    let rendered = text(&wrong);
    assert!(
        rendered.contains("records this key would append (NET NEW)     : 3"),
        "the larger figure is still reported: {rendered}"
    );
    assert!(
        rendered.contains("of those, adding no content the target lacks: 3"),
        "{rendered}"
    );
    assert!(
        rendered.contains("admitted as a writer on the target: NO"),
        "{rendered}"
    );
    assert!(rendered.contains("not an admitted writer"), "{rendered}");

    // Grant it, and the same run is allowed — still reporting the surplus.
    {
        let mut pile = Pile::open(&fixture.path).unwrap();
        let new_key =
            triblespace_core::signing_key_file::load_existing(&fixture.new_key_file).unwrap();
        grant_collection_write(
            &mut pile,
            fixture.new.handle(),
            &new_key,
            fixture.stranger.verifying_key(),
        )
        .unwrap();
        pile.close().unwrap();
    }
    let granted = fixture.adopt(&fixture.stranger_key_file, &[]);
    assert!(granted.status.success(), "{}", text(&granted));
    assert!(
        text(&granted).contains("admitted as a writer on the target: yes"),
        "{}",
        text(&granted)
    );
}

/// Content the source never admitted is not carried, and not dropped, silently.
#[test]
fn unadmitted_content_forces_an_explicit_choice() {
    let fixture = Cutover::new(&[0x11, 0x22], &[]);
    // A claim planted in the retired generation by a key it never admitted.
    // Local storage is a claim ledger, so this lands; admission filters it at
    // read time. Re-signing it under the target's key would promote it.
    {
        let mut pile = Pile::open(&fixture.path).unwrap();
        let intruder =
            triblespace_core::signing_key_file::load_existing(&fixture.stranger_key_file).unwrap();
        pile.commit(fixture.old, &intruder, row(0x99)).unwrap();
        pile.close().unwrap();
    }

    let undecided = fixture.adopt(&fixture.new_key_file, &["--apply"]);
    assert!(
        !undecided.status.success(),
        "neither promoting nor dropping may be the silent default: {}",
        text(&undecided)
    );
    assert!(
        text(&undecided).contains("--carry-unadmitted or --skip-unadmitted"),
        "{}",
        text(&undecided)
    );
    assert_eq!(fixture.commits(fixture.new.handle()), 0);

    let skipped = fixture.adopt(&fixture.new_key_file, &["--apply", "--skip-unadmitted"]);
    assert!(skipped.status.success(), "{}", text(&skipped));
    assert_eq!(
        fixture.commits(fixture.new.handle()),
        2,
        "only the admitted"
    );

    let promoted = fixture.adopt(&fixture.new_key_file, &["--apply", "--carry-unadmitted"]);
    assert!(promoted.status.success(), "{}", text(&promoted));
    assert_eq!(
        fixture.commits(fixture.new.handle()),
        3,
        "and now the claim"
    );
}

/// Carrying one collection's content into an unrelated one needs saying twice.
#[test]
fn a_cross_name_carry_is_refused_unless_it_is_meant() {
    let fixture = Cutover::new(&[0x11], &[]);
    let compass = {
        let mut pile = Pile::open(&fixture.path).unwrap();
        let new_key =
            triblespace_core::signing_key_file::load_existing(&fixture.new_key_file).unwrap();
        let compass = pile.collection("compass", policy(&new_key)).unwrap();
        pile.commit(compass, &new_key, row(0x77)).unwrap();
        pile.close().unwrap();
        compass
    };

    let pile = fixture.path.to_str().unwrap().to_owned();
    let into = handle_text(fixture.new.handle());
    let from = handle_text(compass.handle());
    let key = fixture.new_key_file.to_str().unwrap().to_owned();
    let refused = fixture.run(&[
        "adopt", &pile, "--into", &into, "--from", &from, "--key", &key,
    ]);
    assert!(!refused.status.success(), "{}", text(&refused));
    assert!(
        text(&refused).contains("do not share the target's name"),
        "{}",
        text(&refused)
    );

    let allowed = fixture.run(&[
        "adopt",
        &pile,
        "--into",
        &into,
        "--from",
        &from,
        "--key",
        &key,
        "--allow-cross-name",
    ]);
    assert!(allowed.status.success(), "{}", text(&allowed));
}

/// A plan file carries many names in one reviewed artifact.
#[test]
fn a_plan_file_adopts_several_names_at_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plan.pile");
    std::fs::File::create(&path).unwrap();
    let key_file = directory.path().join("root.key");
    let key = triblespace_core::signing_key_file::init(&key_file).unwrap();
    let other_file = directory.path().join("other.key");
    let other = triblespace_core::signing_key_file::init(&other_file).unwrap();

    let mut pile = Pile::open(&path).unwrap();
    let old_wiki = pile.collection("wiki", policy(&other)).unwrap();
    let new_wiki = pile.collection("wiki", policy(&key)).unwrap();
    let old_compass = pile.collection("compass", policy(&other)).unwrap();
    let new_compass = pile.collection("compass", policy(&key)).unwrap();
    for tag in [0x11, 0x22] {
        pile.commit(old_wiki, &other, row(tag)).unwrap();
    }
    pile.commit(old_compass, &other, row(0x33)).unwrap();
    pile.close().unwrap();

    let plan = directory.path().join("plan.txt");
    std::fs::write(
        &plan,
        format!(
            "# the retired generation of each name\n{} -> {}\n\n{} -> {} # compass\n",
            handle_text(old_wiki.handle()),
            handle_text(new_wiki.handle()),
            handle_text(old_compass.handle()),
            handle_text(new_compass.handle()),
        ),
    )
    .unwrap();

    let mut command = trible();
    command
        .args(["pile", "collection", "adopt"])
        .arg(&path)
        .arg("--plan")
        .arg(&plan)
        .arg("--key")
        .arg(&key_file)
        .arg("--apply");
    let output = Command::from_std(command)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    let rendered = text(&output);
    assert!(
        rendered.contains("plan total: 3 record(s) to append across 2 target(s)"),
        "{rendered}"
    );
    assert!(rendered.contains("appended 3 record(s)"), "{rendered}");

    // Both names are complete afterwards.
    for target in [new_wiki.handle(), new_compass.handle()] {
        let mut command = trible();
        command
            .args(["pile", "collection", "adopted"])
            .arg(&path)
            .arg(handle_text(target));
        let check = Command::from_std(command)
            .timeout(Duration::from_secs(60))
            .output()
            .unwrap();
        assert!(check.status.success(), "{}", text(&check));
    }
}

/// A plan that chains one carry into another is refused, not silently ordered.
#[test]
fn a_plan_that_uses_a_target_as_a_source_is_refused() {
    let fixture = Cutover::new(&[0x11], &[]);
    let directory = tempfile::tempdir().unwrap();
    let plan = directory.path().join("chain.txt");
    std::fs::write(
        &plan,
        format!(
            "{} -> {}\n{} -> {}\n",
            handle_text(fixture.old.handle()),
            handle_text(fixture.new.handle()),
            handle_text(fixture.new.handle()),
            handle_text(fixture.old.handle()),
        ),
    )
    .unwrap();

    let mut command = trible();
    command
        .args(["pile", "collection", "adopt"])
        .arg(&fixture.path)
        .arg("--plan")
        .arg(&plan)
        .arg("--key")
        .arg(&fixture.new_key_file);
    let output = Command::from_std(command)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("both a source and a target"),
        "{}",
        text(&output)
    );
}

/// The pile-wide sweep points at the tool that fixes what it finds.
#[test]
fn the_sweep_names_the_command_that_repairs_it() {
    // The new generation must hold the most records for the sweep to pick it as
    // the basis; see the test below for what happens when it does not.
    let fixture = Cutover::new(&[0x11, 0x22], &[0x33, 0x44, 0x55]);
    let mut command = trible();
    command
        .args(["pile", "collection", "adopted"])
        .arg(&fixture.path);
    let output = Command::from_std(command)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("collection adopt --into <current> --siblings"),
        "the advice names the tool that fixes it: {}",
        text(&output)
    );
}

/// Why naming the live generation is the form an adoption check must use.
///
/// The sweep groups by name and takes the member holding the most records as
/// the basis. Mid-drain that is always the *retired* generation, and the new
/// one's content is a subset of it, so the sweep reports nothing outstanding
/// and exits zero while most of the records are unreachable through the name.
/// The pile is held in that state between every source of a carry. Naming
/// the generation you believe is live asks the question that is actually meant.
#[test]
fn the_exact_form_sees_a_half_finished_carry_the_sweep_calls_settled() {
    let fixture = Cutover::new(&[0x11, 0x22, 0x33, 0x44], &[0x11]);

    let mut command = trible();
    command
        .args(["pile", "collection", "adopted"])
        .arg(&fixture.path);
    let sweep = Command::from_std(command)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();
    assert!(
        sweep.status.success(),
        "the sweep's basis is the largest member, which is the retired one: {}",
        text(&sweep)
    );
    assert!(
        text(&sweep).contains("nothing is unreachable"),
        "{}",
        text(&sweep)
    );

    let exact = fixture.adopted(&[]);
    assert!(
        !exact.status.success(),
        "naming the live generation must find the shortfall: {}",
        text(&exact)
    );
    assert!(
        text(&exact).contains("3 content pair(s) are held by a source and absent from the target"),
        "{}",
        text(&exact)
    );
}

/// The sweep says how many collections it could not name.
///
/// It groups by name, so a collection whose descriptor carries no readable name
/// is in no group and is never mentioned at all — and on a real pile that is
/// where the largest arrears have been found. A count is the minimum repair.
#[test]
fn the_sweep_reports_what_it_could_not_name() {
    let fixture = Cutover::new(&[0x11, 0x22], &[0x11]);
    {
        // A commit naming a collection whose descriptor is not in this pile.
        // Nothing can read its name, so no name group contains it.
        let mut pile = Pile::open(&fixture.path).unwrap();
        let key = triblespace_core::signing_key_file::load_existing(&fixture.old_key_file).unwrap();
        let nameless = CollectionCommit::sign(
            &key,
            Inline::new([0x5A; 32]),
            Inline::new([0x11; 32]),
            Inline::new([0x00; 32]),
        );
        pile.insert(CollectionRecord::Commit(nameless)).unwrap();
        pile.close().unwrap();
    }

    let mut command = trible();
    command
        .args(["pile", "collection", "adopted"])
        .arg(&fixture.path);
    let output = Command::from_std(command)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();
    assert!(
        text(&output).contains("1 collection(s) in this pile hold commits under no name"),
        "{}",
        text(&output)
    );
}
