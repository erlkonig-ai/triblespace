//! `trible pile compact --dropped-into DROPPED`: the compaction keeps what it
//! drops. DROPPED is exactly `trible pile subtract SOURCE --minus OUT`, so
//! `cat OUT DROPPED` holds everything SOURCE held, even after OUT replaces
//! the source and older difference files relied on frames OUT left out.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use predicates::prelude::*;
use tempfile::tempdir;
use triblespace::prelude::BlobStorePut;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{WantRequest, WantStore};

const FRAME_MAGIC: &str = "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B";
const RETIRED_PEER_EVIDENCE: &str =
    "327FFCAAA3F5A10424DC2059E3A7A3517F837E7E56A3C850979EFA9F5E3A1ED7";
const RETIRED_WANT_ASSERT: &str =
    "EC1C024C04AF08243DB3AE318C93FA500355C74395C0F553CFFC0AF0A4BA0346";

/// A retired frame default compaction recognizes and drops.
fn retired_frame(kind: &str, payload: [u8; 32]) -> Vec<u8> {
    let mut frame = vec![0u8; 256];
    frame[..28].copy_from_slice(&hex::decode(FRAME_MAGIC).unwrap());
    frame[28..32].copy_from_slice(&1u32.to_le_bytes());
    frame[32..64].copy_from_slice(&hex::decode(kind).unwrap());
    frame[64..96].copy_from_slice(&payload);
    frame
}

/// Two collections with commits, blobs, WANTs and an unrooted blob, then
/// retired frames: default compaction drops the retired frames, and
/// `--drop-collection drop-me` also drops a collection and unrooted blobs.
fn build_source(path: &Path, rounds: usize) {
    use std::io::Write as _;
    use triblespace::prelude::*;
    use triblespace_core::metadata;
    std::fs::File::create(path).unwrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(key.verifying_key()),
        AdmissionPolicy::direct(key.verifying_key()),
    );
    let mut pile = Pile::open(path).unwrap();
    let dropped = pile.collection("drop-me", policy.clone()).unwrap();
    let kept = pile.collection("keep-me", policy).unwrap();
    let mut last = None;
    for round in 0..rounds {
        let shared = pile
            .put::<UTF8String, _>(format!("shared payload {round}"))
            .unwrap();
        let private = pile
            .put::<UTF8String, _>(format!("dropped payload {round}"))
            .unwrap();
        pile.put::<UTF8String, _>(format!("unrooted payload {round}"))
            .unwrap();
        pile.want(WantRequest::blob(shared)).unwrap();
        pile.commit(kept, &key, entity! { metadata::description: shared })
            .unwrap();
        pile.commit(dropped, &key, entity! { metadata::description: private })
            .unwrap();
        last = Some(shared);
    }
    pile.close().unwrap();
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&retired_frame(RETIRED_PEER_EVIDENCE, [0x17; 32]))
        .unwrap();
    file.write_all(&retired_frame(RETIRED_WANT_ASSERT, last.unwrap().raw))
        .unwrap();
}

fn append_tail(writer: &mut Pile, round: usize) {
    let handle = writer
        .put::<UTF8String, _>(format!("appended after the prefix {round}"))
        .unwrap();
    writer.want(WantRequest::blob(handle)).unwrap();
}

fn head(path: &Path, prefix: u64, into: &Path) {
    let bytes = std::fs::read(path).unwrap();
    std::fs::write(into, &bytes[..prefix as usize]).unwrap();
}

fn trible() -> Command {
    Command::cargo_bin("trible").unwrap()
}

fn compact(source: &Path, into: &Path, dropped: &Path, prefix: Option<u64>, drop: bool) -> Command {
    let mut command = trible();
    command
        .args(["pile", "compact"])
        .arg(source)
        .arg("--into")
        .arg(into)
        .arg("--dropped-into")
        .arg(dropped);
    if let Some(prefix) = prefix {
        command.args(["--source-prefix", &prefix.to_string()]);
    }
    if drop {
        command.args(["--drop-collection", "drop-me"]);
    }
    command
}

fn subtract(source: &Path, minus: &Path, into: &Path, prefix: Option<u64>) -> Command {
    let mut command = trible();
    command
        .args(["pile", "subtract"])
        .arg(source)
        .arg("--minus")
        .arg(minus)
        .arg("--into")
        .arg(into);
    if let Some(prefix) = prefix {
        command.args(["--source-prefix", &prefix.to_string()]);
    }
    command
}

fn check(source: &Path, minus: &Path, diff: &Path, prefix: Option<u64>) -> Command {
    let mut command = trible();
    command
        .args(["pile", "subtract", "--check"])
        .arg(source)
        .arg("--minus")
        .arg(minus)
        .arg("--diff")
        .arg(diff);
    if let Some(prefix) = prefix {
        command.args(["--source-prefix", &prefix.to_string()]);
    }
    command
}

/// Frame kinds in file order, to say what a difference holds.
fn kinds(path: &Path) -> Vec<&'static str> {
    PileRecords::open(path)
        .unwrap()
        .map(|record| match record.unwrap().content {
            PileRecordContent::Blob { .. } => "blob",
            PileRecordContent::Collection { .. } => "collection",
            PileRecordContent::Want { .. } => "want",
            PileRecordContent::RetiredPeerEvidenceV1 => "retired peer evidence",
            PileRecordContent::RetiredWantAssert { .. } => "retired want",
            _ => "other",
        })
        .collect()
}

#[test]
fn dropped_into_is_exactly_a_separate_subtract_and_checks() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    build_source(&source, 12);
    let before = std::fs::read(&source).unwrap();

    for drop in [false, true] {
        let out = dir.path().join(format!("out-{drop}.pile"));
        let dropped = dir.path().join(format!("dropped-{drop}.pile"));
        compact(&source, &out, &dropped, None, drop)
            .assert()
            .success()
            .stdout(predicate::str::contains("bytes written"));
        let separate = dir.path().join(format!("separate-{drop}.pile"));
        subtract(&source, &out, &separate, None).assert().success();
        assert_eq!(
            std::fs::read(&dropped).unwrap(),
            std::fs::read(&separate).unwrap(),
            "drop-collection: {drop}"
        );
        let held = kinds(&dropped);
        assert!(held.contains(&"retired peer evidence"), "{held:?}");
        assert!(held.contains(&"retired want"), "{held:?}");
        if drop {
            assert!(held.contains(&"collection"), "{held:?}");
            assert!(held.contains(&"blob"), "{held:?}");
        }
        check(&source, &out, &dropped, None)
            .assert()
            .success()
            .stdout(predicate::str::contains("missing: 0"));
        // No hidden sibling is left behind.
        let leftovers: Vec<PathBuf> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
    assert_eq!(std::fs::read(&source).unwrap(), before);
}

#[test]
fn dropped_into_composes_with_source_prefix_on_a_growing_source() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("growing.pile");
    build_source(&source, 400);
    let prefix = std::fs::metadata(&source).unwrap().len();
    let copy = dir.path().join("copy.pile");
    head(&source, prefix, &copy);

    let stop = Arc::new(AtomicBool::new(false));
    let appended = Arc::new(AtomicUsize::new(0));
    let appender = {
        let (stop, appended, source) = (stop.clone(), appended.clone(), source.clone());
        std::thread::spawn(move || {
            let mut writer = Pile::open(&source).unwrap();
            while !stop.load(Ordering::Relaxed) {
                append_tail(&mut writer, appended.load(Ordering::Relaxed));
                appended.fetch_add(1, Ordering::Relaxed);
            }
            writer.close().unwrap();
        })
    };
    while appended.load(Ordering::Relaxed) == 0 {
        std::thread::yield_now();
    }

    let mut overlaps = Vec::new();
    for drop in [false, true] {
        let out = dir.path().join(format!("out-{drop}.pile"));
        let dropped = dir.path().join(format!("dropped-{drop}.pile"));
        let started = appended.load(Ordering::Relaxed);
        compact(&source, &out, &dropped, Some(prefix), drop)
            .assert()
            .success();
        overlaps.push(appended.load(Ordering::Relaxed) - started);
        // The check bounds the still-growing source to the same prefix.
        check(&source, &out, &dropped, Some(prefix))
            .assert()
            .success()
            .stdout(predicate::str::contains("missing: 0"));
    }
    stop.store(true, Ordering::Relaxed);
    appender.join().unwrap();
    assert!(
        overlaps.iter().all(|appends| *appends > 0),
        "appends during each compaction: {overlaps:?}"
    );
    assert!(std::fs::metadata(&source).unwrap().len() > prefix);

    for drop in [false, true] {
        let out = dir.path().join(format!("out-{drop}.pile"));
        let dropped = dir.path().join(format!("dropped-{drop}.pile"));
        // The dropped set is the prefix minus OUT: equal to subtracting OUT
        // from a separate copy of the prefix, and to a bounded subtract.
        let from_copy = dir.path().join(format!("from-copy-{drop}.pile"));
        subtract(&copy, &out, &from_copy, None).assert().success();
        let bounded = dir.path().join(format!("bounded-{drop}.pile"));
        subtract(&source, &out, &bounded, Some(prefix))
            .assert()
            .success();
        let bytes = std::fs::read(&dropped).unwrap();
        assert!(!bytes.is_empty(), "drop-collection: {drop}");
        assert_eq!(
            bytes,
            std::fs::read(&from_copy).unwrap(),
            "drop-collection: {drop}"
        );
        assert_eq!(
            bytes,
            std::fs::read(&bounded).unwrap(),
            "drop-collection: {drop}"
        );
        check(&copy, &out, &dropped, None).assert().success();
    }
}

#[test]
fn an_existing_dropped_destination_is_refused_before_any_work() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    build_source(&source, 2);
    let out = dir.path().join("out.pile");
    let dropped = dir.path().join("dropped.pile");
    std::fs::write(&dropped, b"precious").unwrap();

    compact(&source, &out, &dropped, None, false)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("already exists")
                .and(predicate::str::contains("scanning").not()),
        );
    assert!(!out.exists(), "no compaction ran");
    assert_eq!(std::fs::read(&dropped).unwrap(), b"precious");

    // OUT and DROPPED may not be one path.
    std::fs::remove_file(&dropped).unwrap();
    compact(&source, &out, &out, None, false)
        .assert()
        .failure()
        .stderr(predicate::str::contains("same path"));
    assert!(!out.exists());
}

/// OUT appears under its own name only once DROPPED is complete, so a run
/// killed at any moment leaves no OUT that looks like a finished compaction.
#[test]
fn out_is_published_only_after_its_dropped_frames() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    build_source(&source, 400);
    let out = dir.path().join("out.pile");
    let dropped = dir.path().join("dropped.pile");
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("trible"))
        .args(["pile", "compact"])
        .arg(&source)
        .arg("--into")
        .arg(&out)
        .arg("--dropped-into")
        .arg(&dropped)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let (mut looks, mut early) = (0u64, 0u64);
    let status = loop {
        // OUT checked first: once it exists, DROPPED must already.
        if out.exists() && !dropped.exists() {
            early += 1;
        }
        looks += 1;
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
    };
    assert!(status.success());
    assert_eq!(early, 0, "OUT without DROPPED in {early} of {looks} looks");
    assert!(out.exists() && dropped.exists());
}

#[test]
fn dropped_into_spelling_the_destination_differently_is_refused_before_copying() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    build_source(&source, 2);
    let out = dir.path().join("out.pile");
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    let alias = dir.path().join("sub").join("..").join("out.pile");

    compact(&source, &out, &alias, None, false)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("same file")
                .and(predicate::str::contains("copying retained state").not()),
        );
    assert!(!out.exists());
    let left: Vec<PathBuf> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(left.len(), 2, "{left:?}");
}

#[cfg(unix)]
#[test]
fn a_failed_dropped_write_leaves_no_compaction_output() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    build_source(&source, 2);
    let out = dir.path().join("out.pile");
    let yard = dir.path().join("yard");
    std::fs::create_dir(&yard).unwrap();
    std::fs::set_permissions(&yard, std::fs::Permissions::from_mode(0o555)).unwrap();
    let dropped = yard.join("dropped.pile");

    let assert = compact(&source, &out, &dropped, None, false)
        .assert()
        .failure()
        .stderr(predicate::str::contains("dropped frames"));
    std::fs::set_permissions(&yard, std::fs::Permissions::from_mode(0o755)).unwrap();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        !stdout.contains("Compacted"),
        "no success summary is printed: {stdout}"
    );
    assert!(
        !out.exists(),
        "OUT is removed when its dropped frames are not kept"
    );
    assert!(!dropped.exists());
    assert_eq!(std::fs::read_dir(&yard).unwrap().count(), 0);
}
