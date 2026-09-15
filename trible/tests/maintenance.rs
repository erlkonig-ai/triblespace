//! The command schedules existing collection algebra; it does not introduce a
//! second dependency or publication model. These fixtures deliberately register
//! descriptors before publishing any equation for their targets.

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};
use std::time::Duration;
use tempfile::TempDir;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace_core::collection::records::{
    collection_representation, CollectionHandle, KIND_COLLECTION_DESCRIPTOR,
};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionRead, CollectionRecord,
    CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_core::macros::entity;
use triblespace_core::metadata;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};
use triblespace_core::trible::TribleSet;

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    key: PathBuf,
    signer: SigningKey,
    source: Collection<SimpleArchive>,
    succinct: Collection<SuccinctArchiveBlob>,
    rank9: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    unrelated: Collection<SuccinctArchiveBlob>,
    expected: TribleSet,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("maintenance.pile");
        let key = directory.path().join("writer.key");
        std::fs::File::create(&path).unwrap();
        let signer = triblespace_core::signing_key_file::init(&key).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let policy = policy(&signer);
        let source = pile.collection("facts", policy.clone()).unwrap();
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .unwrap();
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy.clone())
            .unwrap();
        let mut expected = TribleSet::new();
        for text in ["first fact", "other fact"] {
            let fragment = entity! { metadata::description: text };
            expected += fragment.facts().clone();
            pile.commit(source, &signer, fragment).unwrap();
        }

        let unrelated_source = pile.collection("not-selected", policy.clone()).unwrap();
        let unrelated = pile
            .derive::<SuccinctArchiveBlob>(unrelated_source, (), policy)
            .unwrap();
        pile.commit(
            unrelated_source,
            &signer,
            entity! { metadata::description: "unrelated fact" },
        )
        .unwrap();
        pile.close().unwrap();
        Self {
            _directory: directory,
            path,
            key,
            signer,
            source,
            succinct,
            rank9,
            unrelated,
            expected,
        }
    }

    fn command(&self, verb: &str, targets: &[CollectionHandle]) -> ProcessCommand {
        let mut command = trible();
        command
            .args(["pile", "collection", verb])
            .arg(&self.path)
            .args(targets.iter().map(|handle| handle_text(*handle)))
            .arg("--key")
            .arg(&self.key);
        command
    }

    fn run(&self, verb: &str, targets: &[CollectionHandle]) -> Output {
        Command::from_std(self.command(verb, targets))
            .timeout(Duration::from_secs(30))
            .output()
            .unwrap()
    }
}

fn trible() -> ProcessCommand {
    let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_trible"));
    // A developer's live pile, collection, key, or model selection must not
    // turn these isolated subprocesses into consumers of colony state.
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

fn records(path: &Path) -> Vec<CollectionRecord> {
    let mut pile = Pile::open(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let records = snapshot
        .records()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    drop(snapshot);
    pile.close().unwrap();
    records
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn scheduled_handles(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            match fields.next()? {
                "maintained" | "ensured" => Some(fields.next().unwrap().to_owned()),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn author_key_priorities_are_stable_across_argument_order_and_maintenance_modes() {
    let fixture = Fixture::new();
    let mut pile = Pile::open(&fixture.path).unwrap();
    let targets: Vec<_> = (0..12)
        .map(|index| {
            // Both fixed test authors operate on the exact same descriptors.
            // One resident member per root makes every call a no-op, so the
            // observed order cannot come from different publication histories.
            let root = pile
                .collection(
                    &format!("shared scheduling target {index}"),
                    CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
                )
                .unwrap();
            pile.commit(
                root,
                &fixture.signer,
                entity! { metadata::description: "one resident member" },
            )
            .unwrap();
            root.handle()
        })
        .collect();
    pile.close().unwrap();
    let before = records(&fixture.path);
    let bytes = std::fs::metadata(&fixture.path).unwrap().len();
    let expected: BTreeSet<_> = targets.iter().copied().map(handle_text).collect();
    let mut reordered = targets.iter().rev().copied().collect::<Vec<_>>();
    reordered.extend([targets[0], targets[4], targets[0]]);

    let mut author_orders = Vec::new();
    for seed in [31u8, 32] {
        let key = fixture.path.with_file_name(format!("author-{seed}.key"));
        // Fixture-only deterministic keys; never use a developer's key file.
        std::fs::write(&key, hex::encode([seed; 32])).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut author_order = None;
        for verb in ["maintain", "maintain-all"] {
            for selection in [&targets, &reordered] {
                let mut command = trible();
                command
                    .args(["pile", "collection", verb])
                    .arg(&fixture.path)
                    .args(selection.iter().copied().map(handle_text))
                    .arg("--key")
                    .arg(&key);
                let output = Command::from_std(command)
                    .timeout(Duration::from_secs(30))
                    .output()
                    .unwrap();
                assert_success(&output);
                let order = scheduled_handles(&output);
                assert_eq!(order.len(), targets.len(), "each target runs once");
                assert_eq!(order.iter().cloned().collect::<BTreeSet<_>>(), expected);
                if let Some(previous) = &author_order {
                    assert_eq!(
                        &order, previous,
                        "one author's order is stable across arguments, duplicates and modes",
                    );
                } else {
                    author_order = Some(order);
                }
            }
        }
        author_orders.push(author_order.unwrap());
    }
    assert_ne!(
        author_orders[0], author_orders[1],
        "the author public key must affect target priority",
    );
    assert_eq!(records(&fixture.path), before);
    assert_eq!(std::fs::metadata(&fixture.path).unwrap().len(), bytes);
}

#[test]
fn maintain_is_one_edge_and_accepts_descriptor_only_targets() {
    let fixture = Fixture::new();
    let before = records(&fixture.path);

    assert_success(&fixture.run("maintain", &[fixture.rank9.handle()]));
    assert_eq!(records(&fixture.path), before);

    assert_success(&fixture.run("maintain", &[fixture.succinct.handle()]));
    let raw_records = records(&fixture.path);
    assert!(raw_records.iter().any(|record| matches!(
        record,
        CollectionRecord::Derive(record) if record.collection() == fixture.succinct.handle()
    )));
    assert!(raw_records
        .iter()
        .all(|record| record.collection() != fixture.rank9.handle()));

    assert_success(&fixture.run("maintain", &[fixture.rank9.handle()]));
    let mut pile = Pile::open(&fixture.path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let observed = snapshot.collection(fixture.rank9).unwrap();
    assert_eq!(
        observed.support(),
        &fixture.source.admitted(&snapshot).unwrap()
    );
    let facts = observed.view::<UnionArchive<OrderedUniverse>>().unwrap();
    assert_eq!(facts.iter().collect::<TribleSet>(), fixture.expected);
    pile.close().unwrap();
}

#[test]
fn maintain_deduplicates_targets_without_scheduling_their_dependencies() {
    let fixture = Fixture::new();
    let before = records(&fixture.path);
    let bytes = std::fs::metadata(&fixture.path).unwrap().len();
    let output = fixture.run(
        "maintain",
        &[fixture.rank9.handle(), fixture.rank9.handle()],
    );
    assert_success(&output);
    assert_eq!(
        scheduled_handles(&output),
        vec![handle_text(fixture.rank9.handle())]
    );
    assert_eq!(records(&fixture.path), before);
    assert_eq!(std::fs::metadata(&fixture.path).unwrap().len(), bytes);
}

#[test]
fn maintain_all_follows_dependencies_without_merging_the_unselected_root() {
    let fixture = Fixture::new();
    let before = records(&fixture.path);
    assert_success(&fixture.run("maintain-all", &[fixture.rank9.handle()]));
    let after = records(&fixture.path);
    assert!(after.len() > before.len());
    for record in &after {
        record.verify_strict().unwrap();
        assert_eq!(
            record.public_key().raw,
            fixture.signer.verifying_key().to_bytes()
        );
        assert_ne!(record.collection(), fixture.unrelated.handle());
        if record.collection() == fixture.source.handle() {
            assert!(matches!(record, CollectionRecord::Commit(_)));
        }
    }
    assert!(before.iter().all(|record| after.contains(record)));

    let mut pile = Pile::open(&fixture.path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let support = fixture.source.admitted(&snapshot).unwrap();
    for len in [
        snapshot.collection(fixture.succinct).unwrap().cover().len(),
        snapshot.collection(fixture.rank9).unwrap().cover().len(),
    ] {
        assert_eq!(len, 1, "the equal-size inputs should be rolled up");
    }
    let observed = snapshot.collection(fixture.rank9).unwrap();
    assert_eq!(observed.support(), &support);
    assert_eq!(support.len(), 2);
    let facts = observed.view::<UnionArchive<OrderedUniverse>>().unwrap();
    assert_eq!(facts.iter().collect::<TribleSet>(), fixture.expected);
    pile.close().unwrap();

    let bytes = std::fs::metadata(&fixture.path).unwrap().len();
    assert_success(&fixture.run("maintain-all", &[fixture.rank9.handle()]));
    assert_eq!(
        records(&fixture.path),
        after,
        "a warm pass adds no equations"
    );
    assert_eq!(std::fs::metadata(&fixture.path).unwrap().len(), bytes);
}

#[test]
fn maintain_all_schedules_a_shared_upstream_once() {
    let fixture = Fixture::new();
    let mut pile = Pile::open(&fixture.path).unwrap();
    // A distinct READ policy gives the second target its own descriptor while
    // keeping the same writable source and the same deterministic mapping.
    let second = pile
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(
            fixture.succinct,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(fixture.signer.verifying_key()),
            ),
        )
        .unwrap();
    pile.close().unwrap();
    assert_ne!(fixture.rank9.handle(), second.handle());

    let output = fixture.run(
        "maintain-all",
        &[
            fixture.rank9.handle(),
            second.handle(),
            fixture.succinct.handle(),
            fixture.rank9.handle(),
            second.handle(),
        ],
    );
    assert_success(&output);
    let order = scheduled_handles(&output);
    assert_eq!(
        order.len(),
        4,
        "shared dependencies and explicit targets run once"
    );
    assert_eq!(order[0], handle_text(fixture.source.handle()));
    assert_eq!(order[1], handle_text(fixture.succinct.handle()));
    assert_eq!(
        order[2..].iter().cloned().collect::<BTreeSet<_>>(),
        [fixture.rank9.handle(), second.handle()]
            .into_iter()
            .map(handle_text)
            .collect(),
        "both downstream targets follow their shared source",
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let upstream = format!("maintained {} ", handle_text(fixture.succinct.handle()));
    assert_eq!(stdout.matches(&upstream).count(), 1, "{stdout}");

    let mut pile = Pile::open(&fixture.path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let support = fixture.source.admitted(&snapshot).unwrap();
    for target in [fixture.rank9, second] {
        let observed = snapshot.collection(target).unwrap();
        assert_eq!(observed.support(), &support);
        let facts = observed.view::<UnionArchive<OrderedUniverse>>().unwrap();
        assert_eq!(facts.iter().collect::<TribleSet>(), fixture.expected);
    }
    pile.close().unwrap();
}

#[test]
fn maintain_all_merges_a_root_when_it_is_explicitly_selected() {
    let fixture = Fixture::new();
    // Selecting the root after its descendant must still apply the explicit
    // choice before the traversal first visits it as an upstream dependency.
    let output = fixture.run(
        "maintain-all",
        &[fixture.rank9.handle(), fixture.source.handle()],
    );
    assert_success(&output);
    assert!(records(&fixture.path).iter().any(|record| matches!(
        record,
        CollectionRecord::Merge(record) if record.collection() == fixture.source.handle()
    )));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let root = handle_text(fixture.source.handle());
    assert_eq!(stdout.matches(&format!("maintained {root} ")).count(), 1);
    assert!(!stdout.contains(&format!("ensured {root} ")));
}

#[test]
fn one_failed_target_does_not_prevent_independent_targets_from_advancing() {
    for verb in ["maintain", "maintain-all"] {
        for unsupported in [false, true] {
            let fixture = Fixture::new();
            let mut pile = Pile::open(&fixture.path).unwrap();
            let bad_target = if unsupported {
                // A valid archive with an unknown encoding is not an executable
                // maintenance target. Its opaque descriptor is still storable.
                let representation = triblespace_core::id::ufoid();
                let descriptor = entity! {
                    metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                    collection_representation: representation,
                };
                pile.put::<SimpleArchive, _>(descriptor.facts().clone())
                    .unwrap()
            } else {
                let other = SigningKey::from_bytes(&[81; 32]);
                let source = pile.collection("foreign", policy(&other)).unwrap();
                pile.commit(
                    source,
                    &other,
                    entity! { metadata::description: "foreign fact" },
                )
                .unwrap();
                // The command's key can READ this target, but cannot sign new
                // derivations which satisfy its independent WRITE policy.
                pile.derive::<SuccinctArchiveBlob>(
                    source,
                    (),
                    CollectionPolicy::new(
                        AdmissionPolicy::direct(fixture.signer.verifying_key()),
                        AdmissionPolicy::direct(other.verifying_key()),
                    ),
                )
                .unwrap()
                .handle()
            };
            pile.close().unwrap();

            let output = fixture.run(verb, &[bad_target, fixture.succinct.handle()]);
            assert!(
                !output.status.success(),
                "failed target must remain reported"
            );
            assert!(!output.stderr.is_empty());
            let after = records(&fixture.path);
            assert!(after.iter().all(|record| record.collection() != bad_target));
            assert!(after.iter().any(|record| matches!(
                record,
                CollectionRecord::Derive(record) if record.collection() == fixture.succinct.handle()
            )));
            let mut pile = Pile::open(&fixture.path).unwrap();
            let snapshot = pile.snapshot().unwrap();
            let observed = snapshot.collection(fixture.succinct).unwrap();
            let facts = observed.view::<UnionArchive<OrderedUniverse>>().unwrap();
            assert_eq!(facts.iter().collect::<TribleSet>(), fixture.expected);
            pile.close().unwrap();
        }
    }
}

#[test]
fn failed_upstream_upkeep_does_not_suppress_available_downstream_work() {
    let fixture = Fixture::new();
    let mut pile = Pile::open(&fixture.path).unwrap();
    let other = SigningKey::from_bytes(&[82; 32]);
    let succinct = pile
        .derive::<SuccinctArchiveBlob>(
            fixture.source,
            (),
            CollectionPolicy::new(
                AdmissionPolicy::direct(fixture.signer.verifying_key()),
                AdmissionPolicy::direct(other.verifying_key()),
            ),
        )
        .unwrap();
    let rank9 = pile
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy(&fixture.signer))
        .unwrap();
    let snapshot = pile.snapshot().unwrap();
    let all = fixture.source.admitted(&snapshot).unwrap();
    assert_eq!(all.len(), 2);
    let first = fixture.source.cover([all.members().next().unwrap()]);
    let seeded = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(pile.ensure_exact(succinct, &other, &first))
        .unwrap();
    let available = seeded.collection(succinct).unwrap();
    assert_eq!(available.support(), &first);
    let expected = available
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap()
        .iter()
        .collect::<TribleSet>();
    assert!(seeded.collection(rank9).unwrap().support().is_empty());
    pile.close().unwrap();
    let upstream_before = records(&fixture.path)
        .into_iter()
        .filter(|record| record.collection() == succinct.handle())
        .collect::<Vec<_>>();

    let output = fixture.run("maintain-all", &[rank9.handle()]);
    assert!(
        !output.status.success(),
        "the denied upstream work is reported"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an admitted WRITE producer"),
        "{stderr}"
    );
    let after = records(&fixture.path);
    assert_eq!(
        after
            .iter()
            .copied()
            .filter(|record| record.collection() == succinct.handle())
            .collect::<Vec<_>>(),
        upstream_before,
        "the local signer must not publish unauthorized upstream work",
    );
    let downstream = after
        .iter()
        .filter(|record| record.collection() == rank9.handle())
        .collect::<Vec<_>>();
    assert_eq!(downstream.len(), 1);
    assert!(matches!(downstream[0], CollectionRecord::Derive(_)));
    downstream[0].verify_strict().unwrap();
    assert_eq!(
        downstream[0].public_key().raw,
        fixture.signer.verifying_key().to_bytes(),
    );

    let mut pile = Pile::open(&fixture.path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    assert_eq!(fixture.source.admitted(&snapshot).unwrap(), all);
    assert_eq!(snapshot.collection(succinct).unwrap().support(), &first);
    let available = snapshot.collection(rank9).unwrap();
    assert_eq!(available.support(), &first);
    let facts = available.view::<UnionArchive<OrderedUniverse>>().unwrap();
    assert_eq!(facts.iter().collect::<TribleSet>(), expected);
    pile.close().unwrap();
}

#[cfg(feature = "search")]
#[test]
fn search_reads_existing_bm25_support_and_snippets_after_source_growth() {
    use triblespace_search::portable_bm25::PortableBM25Blob;
    use triblespace_search::text_bm25::{Bm25Tokenizer, TextAttributeToBm25};

    let fixture = Fixture::new();
    let mut pile = Pile::open(&fixture.path).unwrap();
    let index = pile
        .derive::<PortableBM25Blob>(
            fixture.source,
            TextAttributeToBm25 {
                attribute: metadata::description.id(),
                tokenizer: Bm25Tokenizer::Word,
            },
            policy(&fixture.signer),
        )
        .unwrap();
    pile.close().unwrap();
    assert_success(&fixture.run("maintain", &[index.handle()]));

    let mut writer = Pile::open(&fixture.path).unwrap();
    writer
        .commit(
            fixture.source,
            &fixture.signer,
            entity! { metadata::description: "first unindexed document" },
        )
        .unwrap();
    let snapshot = writer.snapshot().unwrap();
    assert_eq!(fixture.source.admitted(&snapshot).unwrap().len(), 3);
    assert_eq!(snapshot.collection(index).unwrap().support().len(), 2);
    writer.close().unwrap();
    let before = records(&fixture.path);
    let bytes = std::fs::metadata(&fixture.path).unwrap().len();

    let mut command = trible();
    command
        .args(["pile", "collection", "search"])
        .arg(&fixture.path)
        .arg(handle_text(index.handle()))
        .args(["first", "--snippet"]);
    let output = Command::from_std(command)
        .timeout(Duration::from_secs(30))
        .output()
        .unwrap();
    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("1 hit(s)"), "{stdout}");
    assert!(stdout.contains("first fact"), "{stdout}");
    assert!(!stdout.contains("unindexed"), "{stdout}");
    assert_eq!(
        records(&fixture.path),
        before,
        "search is a read, not upkeep"
    );
    assert_eq!(std::fs::metadata(&fixture.path).unwrap().len(), bytes);
}

#[test]
fn zero_interval_is_rejected_before_maintenance() {
    let fixture = Fixture::new();
    let before = records(&fixture.path);
    for verb in ["maintain", "maintain-all"] {
        let mut command = fixture.command(verb, &[fixture.rank9.handle()]);
        command.args(["--watch", "--interval-ms", "0"]);
        let output = Command::from_std(command)
            .timeout(Duration::from_secs(5))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--interval-ms"));
        assert_eq!(records(&fixture.path), before);
    }
}

#[cfg(unix)]
#[test]
fn watch_follows_an_external_append_and_exits_cleanly_on_sigint() {
    use std::process::{Child, Stdio};
    use std::time::Instant;

    struct Watcher(Child);
    impl Drop for Watcher {
        fn drop(&mut self) {
            // Also run on assertion failure so a test can never orphan its
            // maintenance daemon or retain the temporary pile indefinitely.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_for_support(fixture: &Fixture, watcher: &mut Watcher, count: usize, log: &Path) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                watcher.0.try_wait().unwrap().is_none(),
                "watch exited early: {}",
                std::fs::read_to_string(log).unwrap(),
            );
            let mut pile = Pile::open(&fixture.path).unwrap();
            let snapshot = pile.snapshot().unwrap();
            let observed = snapshot.collection(fixture.rank9).unwrap();
            if observed.support().len() == count {
                let facts = observed.view::<UnionArchive<OrderedUniverse>>().unwrap();
                assert_eq!(facts.iter().collect::<TribleSet>(), fixture.expected);
                pile.close().unwrap();
                return;
            }
            pile.close().unwrap();
            assert!(
                Instant::now() < deadline,
                "watch did not realize {count} support members: {}",
                std::fs::read_to_string(log).unwrap(),
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    let mut fixture = Fixture::new();
    let log_path = fixture.path.with_extension("watch.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut command = fixture.command("maintain-all", &[fixture.rank9.handle()]);
    command
        .args(["--watch", "--interval-ms", "10"])
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let mut watcher = Watcher(command.spawn().unwrap());
    wait_for_support(&fixture, &mut watcher, 2, &log_path);

    let mut writer = Pile::open(&fixture.path).unwrap();
    let fragment = entity! { metadata::description: "external append" };
    fixture.expected += fragment.facts().clone();
    writer
        .commit(fixture.source, &fixture.signer, fragment)
        .unwrap();
    writer.close().unwrap();
    wait_for_support(&fixture, &mut watcher, 3, &log_path);

    assert!(ProcessCommand::new("kill")
        .args(["-INT", &watcher.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = watcher.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "SIGINT did not close normally: {status}\n{}",
                std::fs::read_to_string(&log_path).unwrap(),
            );
            break;
        }
        assert!(Instant::now() < deadline, "SIGINT did not stop the watcher");
        std::thread::sleep(Duration::from_millis(20));
    }
}
