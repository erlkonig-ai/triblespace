//! Generated local worker -> signed telemetry -> read-only terminal dashboard.
//! No sync endpoint, live pile, model, GPU, or remote service participates.

use ed25519_dalek::VerifyingKey;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use triblespace_core::blob::encodings::entity_id_set::{EntityIdSet, EntityIdSetBlob};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionRead, CollectionRecord,
    CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace_core::metadata;
use triblespace_core::prelude::*;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::SnapshotSource;
use triblespace_net::telemetry::{self, Metric, WorkerReport};

const WORKER: &str = "generated-maintainer";

struct Fixture {
    directory: TempDir,
    path: PathBuf,
    key: PathBuf,
    author: VerifyingKey,
    source: Collection<blobencodings::SimpleArchive>,
    target: Collection<EntityIdSetBlob>,
    reports: Collection<blobencodings::SimpleArchive>,
    expected: Id,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("colony.pile");
        let key = directory.path().join("self.key");
        std::fs::File::create(&path).unwrap();
        let signer = triblespace_core::signing_key_file::init(&key).unwrap();
        let author = signer.verifying_key();
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(author),
            AdmissionPolicy::direct(author),
        );
        let mut pile = Pile::open(&path).unwrap();
        let source = pile.collection("generated facts", policy.clone()).unwrap();
        let target = pile
            .derive::<EntityIdSetBlob>(source, metadata::supersedes.id(), policy.clone())
            .unwrap();
        let reports = pile.collection("generated telemetry", policy).unwrap();
        let expected = *genid();
        pile.commit(source, &signer, entity! { metadata::supersedes: expected })
            .unwrap();
        let snapshot = pile.snapshot().unwrap();
        for collection in [source, reports] {
            assert!(collection.writer_is_admitted(&snapshot, author).unwrap());
        }
        drop(snapshot);
        pile.close().unwrap();
        Self {
            directory,
            path,
            key,
            author,
            source,
            target,
            reports,
            expected,
        }
    }

    fn worker(&self) -> Command {
        let mut command = trible();
        command
            .current_dir(self.directory.path())
            .args(["pile", "collection", "maintain-all"])
            .arg(&self.path)
            .arg(hex::encode(self.target.handle().raw))
            .arg("--key")
            .arg(&self.key)
            .arg("--telemetry-collection")
            .arg(hex::encode(self.reports.handle().raw))
            .args(["--telemetry-worker", WORKER]);
        command
    }

    fn observe(&self) -> (Vec<WorkerReport>, bool) {
        let mut pile = Pile::open(&self.path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let facts = snapshot
            .collection(self.reports)
            .unwrap()
            .view::<TribleSet>()
            .unwrap();
        let reports = telemetry::observe(
            &facts,
            triblespace_core::clock::epoch_now()
                .to_tai_duration()
                .total_nanoseconds(),
            Duration::from_secs(300),
        );
        let projected = snapshot
            .collection(self.target)
            .unwrap()
            .view::<EntityIdSet>()
            .unwrap()
            .contains(self.expected);
        let mut commits = 0;
        let mut derives = 0;
        for record in snapshot.records().unwrap() {
            let record = record.unwrap();
            if record.collection() == self.reports.handle() {
                assert!(matches!(record, CollectionRecord::Commit(_)));
                assert!(
                    record.verify_strict().is_ok(),
                    "invalid telemetry signature"
                );
                assert!(record.public_key().raw == self.author.to_bytes());
                commits += 1;
            }
            if record.collection() == self.target.handle()
                && matches!(record, CollectionRecord::Derive(_))
            {
                assert!(record.verify_strict().is_ok(), "invalid derive signature");
                assert_eq!(record.public_key().raw, self.author.to_bytes());
                derives += 1;
            }
        }
        assert!(reports.is_empty() || commits > 0);
        assert!(
            !projected || derives > 0,
            "projection requires a real derive"
        );
        drop(snapshot);
        pile.close().unwrap();
        (reports, projected)
    }
}

fn trible() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trible"));
    // Match the isolated maintenance/signal fixtures: never inherit live pile,
    // persona, key/collection/health policy, or model configuration.
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
    command.stdin(Stdio::null());
    command
}

fn run(command: Command) -> Output {
    let output = assert_cmd::Command::from_std(command)
        .timeout(Duration::from_secs(30))
        .output()
        .unwrap();
    // Maintenance stdout contains handles; never echo it in assertion failures.
    assert!(output.status.success(), "generated-pile command failed");
    output
}

fn scope<'a>(reports: &'a [WorkerReport], stage: Option<&str>) -> &'a WorkerReport {
    reports
        .iter()
        .find(|report| match stage {
            None => report.role == "process" && report.stages.is_empty(),
            Some(stage) => {
                report.role == "maintenance"
                    && report.stages.len() == 1
                    && report.stages[0] == stage
            }
        })
        .expect("missing maintenance scope")
}

fn metric(report: &WorkerReport, metric: Metric) -> u128 {
    report
        .metrics
        .iter()
        .find(|value| value.metric == metric)
        .and_then(|value| value.value.value())
        .expect("missing numeric worker metric")
}

fn assert_finished(fixture: &Fixture, reports: &[WorkerReport]) {
    assert_eq!(reports.len(), 4);
    assert!(reports
        .iter()
        .all(|report| report.node == fixture.author.to_bytes() && report.worker == WORKER));
    for stage in [None, Some("maintenance-hop"), Some("pass")] {
        assert_eq!(metric(scope(reports, stage), Metric::Active), 0);
    }
    scope(reports, Some("no-publication-pass"));
    assert!(
        metric(
            scope(reports, Some("maintenance-hop")),
            Metric::CompletedDerives
        ) > 0
    );
}

#[test]
fn maintained_signed_telemetry_reaches_dashboard_without_reader_writes() {
    let fixture = Fixture::new();
    let (before, projected) = fixture.observe();
    assert!(before.is_empty() && !projected);
    run(fixture.worker());
    let (reports, projected) = fixture.observe();
    assert!(projected, "worker did not realize the generated projection");
    assert_finished(&fixture, &reports);
    let derive_rate = scope(&reports, Some("maintenance-hop"))
        .metrics
        .iter()
        .find(|value| value.metric == Metric::CompletedDerives)
        .and_then(|value| value.per_second)
        .expect("initial and final worker samples must expose the derive delta");
    assert!(derive_rate > 0.0);

    let before = std::fs::read(&fixture.path).unwrap();
    let mut dashboard = trible();
    dashboard
        .current_dir(fixture.directory.path())
        .args(["pile", "net", "dashboard"])
        .arg(&fixture.path)
        .arg("--key")
        .arg(&fixture.key)
        .arg("--telemetry-collection")
        .arg(hex::encode(fixture.reports.handle().raw))
        .args(["--tui", "--once", "--max-age", "300"]);
    let output = run(dashboard);
    assert!(
        std::fs::read(&fixture.path).unwrap() == before,
        "dashboard changed generated pile bytes"
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "1 observed nodes · 4 worker scopes · 1/1 telemetry sources readable",
        "generated-maintainer / process",
        "generated-maintainer / maintenance",
        "stage maintenance-hop",
        "stage pass",
        "stage no-publication-pass",
        "derive publications",
    ] {
        assert!(
            text.contains(expected),
            "dashboard omitted a generated scope or metric"
        );
    }
    // A node is named by the host its own daemons declare -- `WORKER` is
    // `generated-maintainer`, so the host is `generated` -- beside the short
    // handle, so a reader can tell two identities of one machine apart.
    assert!(text.contains(&format!(
        "NODE generated · {}",
        hex::encode(&fixture.author.to_bytes()[..6])
    )));
    assert!(text.contains(&format!("derive publications {derive_rate:.2}/s")));
    for handle in [
        fixture.source.handle(),
        fixture.target.handle(),
        fixture.reports.handle(),
    ] {
        assert!(
            !text.contains(&hex::encode(handle.raw)),
            "dashboard exposed a full capability"
        );
        assert!(
            !text.contains(&hex::encode_upper(handle.raw)),
            "dashboard exposed a full capability"
        );
    }
}

#[cfg(unix)]
#[test]
fn watched_maintenance_sigterm_publishes_inactive_final_scopes_and_closes() {
    use std::process::Child;
    use std::time::Instant;

    struct Worker(Child);
    impl Drop for Worker {
        fn drop(&mut self) {
            // Reap on every path, including failed readiness/shutdown assertions.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let fixture = Fixture::new();
    let log_path = fixture.directory.path().join("worker.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut command = fixture.worker();
    command
        .args(["--watch", "--interval-ms", "20"])
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let mut worker = Worker(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "worker exited before readiness"
        );
        let (reports, projected) = fixture.observe();
        if projected && !reports.is_empty() && metric(scope(&reports, None), Metric::Active) == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "worker did not publish and realize its target"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(Command::new("kill")
        .args(["-TERM", &worker.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = worker.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "SIGTERM did not close maintenance normally"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "SIGTERM did not stop maintenance"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("maintenance stopped; closing pile"));
    assert!(!log.contains("Pile dropped without calling close()"));
    let (reports, projected) = fixture.observe();
    assert!(projected);
    assert_finished(&fixture, &reports);
}
