//! `trible pile subtract`: a pile minus a mainline pile, written as a fresh
//! difference file, and `--check` confirming that mainline plus difference
//! still holds everything the original did.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::Path;

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use predicates::prelude::*;
use tempfile::tempdir;
use triblespace::prelude::BlobStoreGet;
use triblespace::prelude::BlobStorePut;
use triblespace::prelude::SnapshotSource;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::Blob;
use triblespace_core::collection::{CollectionCommit, CollectionRecord, CollectionStore};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{WantRequest, WantStore};

const FRAME_MAGIC: &str = "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B";

fn commit(seed: u8) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[7; 32]),
        Inline::new([0xC0; 32]),
        Inline::new([seed; 32]),
        Inline::new([0xD0; 32]),
    ))
}

/// Append blobs, commits and blob WANTs to `path` (creating it if absent),
/// returning the blob handles in order.
fn append(path: &Path, blobs: &[&str], commits: &[u8]) -> Vec<Inline<Handle<UTF8String>>> {
    if !path.exists() {
        std::fs::File::create(path).unwrap();
    }
    let mut pile = Pile::open(path).unwrap();
    let mut handles = Vec::new();
    for text in blobs {
        let handle = pile.put::<UTF8String, _>(*text).unwrap();
        pile.want(WantRequest::blob(handle)).unwrap();
        handles.push(handle);
    }
    for seed in commits {
        pile.insert(commit(*seed)).unwrap();
    }
    pile.close().unwrap();
    handles
}

/// One current-framing record of a kind no reader knows.
fn unknown_kind_frame() -> Vec<u8> {
    let mut frame = vec![0u8; 256];
    frame[..28].copy_from_slice(&hex::decode(FRAME_MAGIC).unwrap());
    frame[28..32].copy_from_slice(&1u32.to_le_bytes());
    frame[32..64].copy_from_slice(&[0x5A; 32]);
    frame[64..96].copy_from_slice(&[0x11; 32]);
    frame
}

#[derive(Debug, Default, PartialEq)]
struct Content {
    blobs: BTreeSet<[u8; 32]>,
    records: BTreeSet<Vec<u8>>,
    wants: BTreeSet<[u8; 97]>,
    opaque: usize,
    frames: usize,
}

fn content(path: &Path) -> Content {
    let mut content = Content::default();
    for record in PileRecords::open(path).unwrap() {
        let record = record.unwrap();
        content.frames += 1;
        match record.content {
            PileRecordContent::Blob { hash, .. } => {
                content.blobs.insert(hash.raw);
            }
            PileRecordContent::Collection { record } => {
                content.records.insert(record.to_bytes());
            }
            PileRecordContent::Want { request } => {
                content.wants.insert(request.to_bytes());
            }
            PileRecordContent::Opaque { .. } => content.opaque += 1,
            other => panic!("unexpected record {other:?}"),
        }
    }
    content
}

fn subtract(a: &Path, b: &Path, c: &Path) -> assert_cmd::assert::Assert {
    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "subtract"])
        .arg(a)
        .arg("--minus")
        .arg(b)
        .arg("--into")
        .arg(c)
        .assert()
}

fn check(a: &Path, b: &Path, c: &Path) -> assert_cmd::assert::Assert {
    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "subtract", "--check"])
        .arg(a)
        .arg("--minus")
        .arg(b)
        .arg("--diff")
        .arg(c)
        .assert()
}

#[test]
fn extras_beyond_the_mainline_are_exactly_the_difference() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    let shared = append(&b, &["shared one", "shared two"], &[1, 2]);
    std::fs::copy(&b, &a).unwrap();
    let extra = append(&a, &["only in a"], &[3]);
    // A concatenated history repeats frames; the difference holds each once.
    let once = std::fs::read(&a).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .unwrap()
        .write_all(&once)
        .unwrap();
    let (a_before, b_before) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());

    subtract(&a, &b, &c).success().stdout(
        predicate::str::contains("blob")
            .and(predicate::str::contains("bytes written"))
            .and(predicate::str::contains("opaque/unknown frames kept: 0")),
    );

    assert_eq!(std::fs::read(&a).unwrap(), a_before, "A is never written");
    assert_eq!(std::fs::read(&b).unwrap(), b_before, "B is never written");
    let diff = content(&c);
    assert_eq!(diff.blobs, BTreeSet::from([extra[0].raw]));
    assert_eq!(diff.records, BTreeSet::from([commit(3).to_bytes()]));
    assert_eq!(
        diff.wants,
        BTreeSet::from([WantRequest::blob(extra[0]).to_bytes()])
    );
    assert_eq!(diff.frames, 3, "each extra exactly once");

    check(&a, &b, &c)
        .success()
        .stdout(predicate::str::contains("missing: 0"));

    // Concatenation is the merge: B then C reads every blob A holds.
    let merged = dir.path().join("merged.pile");
    std::fs::write(
        &merged,
        [std::fs::read(&b).unwrap(), std::fs::read(&c).unwrap()].concat(),
    )
    .unwrap();
    let mut pile = Pile::open(&merged).unwrap();
    let snapshot = pile.snapshot().unwrap();
    for handle in shared.iter().chain(&extra) {
        let _: Blob<UTF8String> = snapshot.get(*handle).unwrap();
    }
    drop(snapshot);
    pile.close().unwrap();
}

#[test]
fn disjoint_piles_keep_all_of_a() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&a, &["alpha", "beta"], &[10, 11]);
    append(&b, &["gamma"], &[12]);

    subtract(&a, &b, &c).success();
    assert_eq!(std::fs::read(&c).unwrap(), std::fs::read(&a).unwrap());
    check(&a, &b, &c).success();
}

#[test]
fn a_subset_of_b_leaves_an_empty_difference() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&a, &["alpha"], &[20]);
    std::fs::copy(&a, &b).unwrap();
    append(&b, &["beta"], &[21]);

    subtract(&a, &b, &c).success();
    assert_eq!(std::fs::metadata(&c).unwrap().len(), 0);
    check(&a, &b, &c).success();
}

#[test]
fn an_unknown_kind_is_kept_verbatim_and_counted() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&b, &["shared"], &[30]);
    std::fs::copy(&b, &a).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .unwrap()
        .write_all(&unknown_kind_frame())
        .unwrap();

    subtract(&a, &b, &c)
        .success()
        .stdout(predicate::str::contains("opaque/unknown frames kept: 1"));
    assert_eq!(std::fs::read(&c).unwrap(), unknown_kind_frame());
    check(&a, &b, &c).success();
}

const PIN_HEAD: &str = "2BC0B9FE0EFDB0BC53654E17BB9D06E01259F36AF93EEE54AD5D557B12DF706D";
const PIN_TOMBSTONE: &str = "8D9F27E76D3620EEC29B781F841E9EF77F2607B40DC702FE3DAED007E9228CA5";

/// One legacy pin record: a head when `head` is given, else a tombstone.
fn legacy_pin(branch: [u8; 16], head: Option<[u8; 32]>) -> Vec<u8> {
    let mut frame = vec![0u8; 256];
    frame[..28].copy_from_slice(&hex::decode(FRAME_MAGIC).unwrap());
    frame[28..32].copy_from_slice(&1u32.to_le_bytes());
    let kind = if head.is_some() { PIN_HEAD } else { PIN_TOMBSTONE };
    frame[32..64].copy_from_slice(&hex::decode(kind).unwrap());
    frame[64..80].copy_from_slice(&branch);
    if let Some(head) = head {
        frame[96..128].copy_from_slice(&head);
    }
    frame
}

/// Head, tombstone, the same head again: last write wins, so the pin ends
/// pointing at the head. Dropping the repeat would end it deleted.
fn repeated_pin_log() -> Vec<u8> {
    let mut log = legacy_pin([0x31; 16], Some([0x41; 32]));
    log.extend_from_slice(&legacy_pin([0x31; 16], None));
    log.extend_from_slice(&legacy_pin([0x31; 16], Some([0x41; 32])));
    log
}

#[test]
fn a_repeated_legacy_pin_log_is_kept_in_full_and_in_order() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&b, &["shared"], &[50]);
    std::fs::copy(&b, &a).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .unwrap()
        .write_all(&repeated_pin_log())
        .unwrap();

    subtract(&a, &b, &c).success();
    assert_eq!(std::fs::read(&c).unwrap(), repeated_pin_log());
    check(&a, &b, &c).success();
}

#[test]
fn check_refuses_a_difference_whose_pin_log_lost_its_order() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&b, &["shared"], &[51]);
    std::fs::copy(&b, &a).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .unwrap()
        .write_all(&repeated_pin_log())
        .unwrap();

    // Every identity is present, but the final repeat of the head is gone.
    let mut deduplicated = legacy_pin([0x31; 16], Some([0x41; 32]));
    deduplicated.extend_from_slice(&legacy_pin([0x31; 16], None));
    std::fs::write(&c, &deduplicated).unwrap();

    check(&a, &b, &c)
        .failure()
        .stderr(predicate::str::contains("order-sensitive"));
}

#[test]
fn check_names_what_the_difference_is_missing() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&b, &["shared"], &[40]);
    std::fs::copy(&b, &a).unwrap();
    let extra = append(&a, &["needed"], &[41]);
    subtract(&a, &b, &c).success();

    // Drop the blob frame from the difference, keep the rest.
    let mut kept = Vec::new();
    let mut records = PileRecords::open(&c).unwrap();
    let mut frames = Vec::new();
    while let Some(record) = records.next() {
        frames.push(record.unwrap());
    }
    for record in frames {
        if !matches!(record.content, PileRecordContent::Blob { .. }) {
            kept.extend_from_slice(&records.bytes()[record.offset..record.offset + record.len]);
        }
    }
    drop(records);
    std::fs::remove_file(&c).unwrap();
    std::fs::write(&c, &kept).unwrap();

    check(&a, &b, &c).failure().stdout(
        predicate::str::contains("missing: 1")
            .and(predicate::str::contains(hex::encode_upper(extra[0].raw))),
    );
}

#[test]
fn refuses_an_existing_destination() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&a, &["alpha"], &[]);
    append(&b, &["beta"], &[]);
    std::fs::write(&c, b"precious").unwrap();

    subtract(&a, &b, &c)
        .failure()
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(std::fs::read(&c).unwrap(), b"precious");
}

#[test]
fn refuses_the_same_file_under_two_names() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&a, &["alpha"], &[]);
    std::fs::hard_link(&a, &b).unwrap();

    subtract(&a, &b, &c)
        .failure()
        .stderr(predicate::str::contains("same file"));
    assert!(!c.exists());
}

#[test]
fn refuses_a_torn_source_naming_the_offset() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&a, &["alpha"], &[]);
    append(&b, &["beta"], &[]);
    let valid = std::fs::metadata(&a).unwrap().len();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .unwrap()
        .write_all(&[0xFF; 8])
        .unwrap();

    subtract(&a, &b, &c)
        .failure()
        .stderr(predicate::str::contains(format!("byte {valid}")));
    assert!(!c.exists());
}

#[test]
fn a_corrupt_blob_refuses_unless_explicitly_skipped() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&a, &["damaged payload"], &[50]);
    append(&b, &["beta"], &[]);
    let (record_offset, data_offset) = PileRecords::open(&a)
        .unwrap()
        .find_map(|record| {
            let record = record.unwrap();
            match record.content {
                PileRecordContent::Blob { data_offset, .. } => Some((record.offset, data_offset)),
                _ => None,
            }
        })
        .unwrap();
    let mut bytes = std::fs::read(&a).unwrap();
    bytes[data_offset] ^= 0xFF;
    std::fs::write(&a, &bytes).unwrap();

    subtract(&a, &b, &c)
        .failure()
        .stderr(predicate::str::contains(format!("byte {record_offset}")));
    assert!(!c.exists());

    Command::cargo_bin("trible")
        .unwrap()
        .args(["pile", "subtract"])
        .arg(&a)
        .arg("--minus")
        .arg(&b)
        .arg("--into")
        .arg(&c)
        .arg("--allow-corrupt")
        .assert()
        .success()
        .stdout(predicate::str::contains("corrupt blob frames skipped: 1"));
    let diff = content(&c);
    assert!(diff.blobs.is_empty());
    assert_eq!(diff.records, BTreeSet::from([commit(50).to_bytes()]));
}

fn with_prefix(mut command: Command, prefix: u64) -> assert_cmd::assert::Assert {
    command
        .args(["--source-prefix", &prefix.to_string()])
        .assert()
}

#[test]
fn source_prefix_bounds_subtract_and_check_to_the_first_bytes() {
    let dir = tempdir().unwrap();
    let (a, b, c) = (
        dir.path().join("a.pile"),
        dir.path().join("b.pile"),
        dir.path().join("c.pile"),
    );
    append(&b, &["shared"], &[60]);
    std::fs::copy(&b, &a).unwrap();
    let extra = append(&a, &["inside the prefix"], &[61]);
    let prefix = std::fs::metadata(&a).unwrap().len();
    append(&a, &["past the prefix"], &[62]);
    // A torn tail past the prefix is never read.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&a)
        .unwrap()
        .write_all(&[0xFF; 8])
        .unwrap();
    let copy = dir.path().join("copy.pile");
    std::fs::write(&copy, &std::fs::read(&a).unwrap()[..prefix as usize]).unwrap();

    let mut bounded = Command::cargo_bin("trible").unwrap();
    bounded
        .args(["pile", "subtract"])
        .arg(&a)
        .arg("--minus")
        .arg(&b)
        .arg("--into")
        .arg(&c);
    with_prefix(bounded, prefix).success();
    let expected = dir.path().join("expected.pile");
    subtract(&copy, &b, &expected).success();
    assert_eq!(std::fs::read(&c).unwrap(), std::fs::read(&expected).unwrap());
    let diff = content(&c);
    assert_eq!(diff.blobs, BTreeSet::from([extra[0].raw]));
    assert_eq!(diff.records, BTreeSet::from([commit(61).to_bytes()]));

    let mut checked = Command::cargo_bin("trible").unwrap();
    checked
        .args(["pile", "subtract", "--check"])
        .arg(&a)
        .arg("--minus")
        .arg(&b)
        .arg("--diff")
        .arg(&c);
    with_prefix(checked, prefix)
        .success()
        .stdout(predicate::str::contains("missing: 0"));
    // Unbounded, the same check reads past the prefix and refuses.
    check(&a, &b, &c).failure();

    let cut = dir.path().join("cut.pile");
    let mut inside = Command::cargo_bin("trible").unwrap();
    inside
        .args(["pile", "subtract"])
        .arg(&a)
        .arg("--minus")
        .arg(&b)
        .arg("--into")
        .arg(&cut);
    with_prefix(inside, prefix - 8)
        .failure()
        .stderr(predicate::str::contains("not a record boundary"));
    assert!(!cut.exists());
}
