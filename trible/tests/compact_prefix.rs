//! `trible pile compact --source-prefix L`: compacting the first `L` bytes
//! of a pile that writers keep appending to, read-only, equals compacting a
//! separate copy of those bytes.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use predicates::prelude::*;
use tempfile::tempdir;
use triblespace::prelude::BlobStorePut;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{WantRequest, WantStore};

/// A source with two collections, commits in both, blobs, WANTs and an
/// unrooted blob, so default and `--drop-collection` compaction both have
/// something to keep and something to leave.
fn build_source(path: &Path, rounds: usize) {
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
    }
    pile.close().unwrap();
}

/// Writer-side appends after the prefix: blobs and WANTs, through the same
/// append path a live writer uses.
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

/// The compacted bytes with each blob record's insertion timestamp zeroed:
/// compaction re-stamps repacked blobs with the wall clock, so two runs
/// differ there and nowhere else.
fn masked(path: &Path) -> Vec<u8> {
    let mut bytes = std::fs::read(path).unwrap();
    let mut blobs = 0;
    for record in PileRecords::open(path).unwrap() {
        let record = record.unwrap();
        if let PileRecordContent::Blob { timestamp, .. } = record.content {
            let stamp = record.offset + 64..record.offset + 72;
            assert_eq!(bytes[stamp.clone()], timestamp.to_le_bytes());
            bytes[stamp].fill(0);
            blobs += 1;
        }
    }
    assert!(blobs > 0, "{} holds no blob records", path.display());
    bytes
}

fn compact(source: &Path, into: &Path, prefix: Option<u64>, drop: bool) -> Command {
    let mut command = Command::cargo_bin("trible").unwrap();
    command
        .args(["pile", "compact"])
        .arg(source)
        .arg("--into")
        .arg(into);
    if let Some(prefix) = prefix {
        command.args(["--source-prefix", &prefix.to_string()]);
    }
    if drop {
        command.args(["--drop-collection", "drop-me"]);
    }
    command
}

#[cfg(unix)]
fn identity(path: &Path) -> (Vec<u8>, std::time::SystemTime, i64, i64) {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path).unwrap();
    (
        std::fs::read(path).unwrap(),
        metadata.modified().unwrap(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(unix)]
#[test]
fn source_prefix_matches_a_copy_of_the_prefix_and_never_touches_the_source() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    build_source(&source, 24);
    let prefix = std::fs::metadata(&source).unwrap().len();
    let mut writer = Pile::open(&source).unwrap();
    for round in 0..16 {
        append_tail(&mut writer, round);
    }
    writer.close().unwrap();
    assert!(std::fs::metadata(&source).unwrap().len() > prefix);
    let copy = dir.path().join("copy.pile");
    head(&source, prefix, &copy);

    // A source nobody may open for writing: an append-mode open would fail.
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o444)).unwrap();
    let before = identity(&source);

    for drop in [false, true] {
        let expected: PathBuf = dir.path().join(format!("expected-{drop}.pile"));
        let actual: PathBuf = dir.path().join(format!("actual-{drop}.pile"));
        compact(&copy, &expected, None, drop).assert().success();
        compact(&source, &actual, Some(prefix), drop)
            .assert()
            .success()
            .stdout(predicate::str::contains(format!("bytes: {prefix} -> ")));
        assert_eq!(
            masked(&actual),
            masked(&expected),
            "drop-collection: {drop}"
        );
    }
    assert_eq!(identity(&source), before);
}

#[test]
fn source_prefix_compacts_a_prefix_while_a_writer_appends() {
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
        let actual = dir.path().join(format!("actual-{drop}.pile"));
        let started = appended.load(Ordering::Relaxed);
        compact(&source, &actual, Some(prefix), drop)
            .assert()
            .success();
        overlaps.push(appended.load(Ordering::Relaxed) - started);
    }
    // Witness that the appends really overlap a compaction: without the
    // prefix the same growing source is refused, by a length check or by the
    // lock-free header census reading an append still in flight.
    let unbounded = dir.path().join("unbounded.pile");
    compact(&source, &unbounded, None, false)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("source pile changed")
                .and(predicate::str::contains("amputate").not()),
        );
    stop.store(true, Ordering::Relaxed);
    appender.join().unwrap();
    assert!(
        overlaps.iter().all(|appends| *appends > 0),
        "appends during each compaction: {overlaps:?}"
    );
    assert!(std::fs::metadata(&source).unwrap().len() > prefix);
    eprintln!("appends during the two prefix compactions: {overlaps:?}");

    for drop in [false, true] {
        let expected = dir.path().join(format!("expected-{drop}.pile"));
        let actual = dir.path().join(format!("actual-{drop}.pile"));
        compact(&copy, &expected, None, drop).assert().success();
        assert_eq!(
            masked(&actual),
            masked(&expected),
            "drop-collection: {drop}"
        );
    }
}

#[test]
fn source_prefix_refuses_a_cut_inside_a_record_and_a_prefix_past_the_end() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    build_source(&source, 2);
    let length = std::fs::metadata(&source).unwrap().len();
    let first = PileRecords::open(&source)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .len as u64;
    let original = std::fs::read(&source).unwrap();
    for (prefix, message) in [
        (first + 8, "is not a record boundary"),
        (length - 1, "is not a record boundary"),
        (length + 1, "past the end"),
    ] {
        let destination = dir.path().join(format!("refused-{prefix}.pile"));
        compact(&source, &destination, Some(prefix), false)
            .assert()
            .failure()
            .stderr(predicate::str::contains(message));
        assert!(!destination.exists());
    }
    assert_eq!(std::fs::read(&source).unwrap(), original);
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap();
    file.write_all(&[0u8; 7]).unwrap();
    // A torn tail past the prefix is never read.
    let destination = dir.path().join("past-torn-tail.pile");
    compact(&source, &destination, Some(length), false)
        .assert()
        .success();
}
