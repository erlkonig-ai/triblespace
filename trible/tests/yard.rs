//! `trible yard diff` and `trible yard pack`: an old pile kept as what it
//! adds to the live pile plus every pile of a yard folder, and a yard packed
//! into one deduplicated pile, both verified before they are published.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use predicates::prelude::*;
use tempfile::tempdir;
use triblespace::prelude::BlobStoreGet;
use triblespace::prelude::BlobStorePut;
use triblespace::prelude::SnapshotSource;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::collection::CollectionRead;
use triblespace_core::collection::{CollectionCommit, CollectionRecord, CollectionStore};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
use triblespace_core::repo::{WantRead, WantRequest, WantStore};

const FRAME_MAGIC: &str = "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B";
const PIN_HEAD: &str = "2BC0B9FE0EFDB0BC53654E17BB9D06E01259F36AF93EEE54AD5D557B12DF706D";
const PIN_TOMBSTONE: &str = "8D9F27E76D3620EEC29B781F841E9EF77F2607B40DC702FE3DAED007E9228CA5";

fn commit(seed: u8) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[7; 32]),
        Inline::new([0xC0; 32]),
        Inline::new([seed; 32]),
        Inline::new([0xD0; 32]),
    ))
}

/// Append blobs (each with its blob WANT) and commits to `path`, creating it
/// if absent, returning the blob handles in order.
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

fn append_bytes(path: &Path, bytes: &[u8]) {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn hash(text: &str) -> [u8; 32] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

/// Flip a payload byte of the blob frame naming `text`.
fn corrupt(path: &Path, text: &str) {
    let wanted = hash(text);
    let data_offset = PileRecords::open(path)
        .unwrap()
        .find_map(|record| match record.unwrap().content {
            PileRecordContent::Blob {
                hash, data_offset, ..
            } if hash.raw == wanted => Some(data_offset),
            _ => None,
        })
        .unwrap();
    let mut bytes = std::fs::read(path).unwrap();
    bytes[data_offset] ^= 0xFF;
    std::fs::write(path, &bytes).unwrap();
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

/// One legacy pin record: a head when `head` is given, else a tombstone.
fn legacy_pin(branch: [u8; 16], head: Option<[u8; 32]>) -> Vec<u8> {
    let mut frame = vec![0u8; 256];
    frame[..28].copy_from_slice(&hex::decode(FRAME_MAGIC).unwrap());
    frame[28..32].copy_from_slice(&1u32.to_le_bytes());
    let kind = if head.is_some() {
        PIN_HEAD
    } else {
        PIN_TOMBSTONE
    };
    frame[32..64].copy_from_slice(&hex::decode(kind).unwrap());
    frame[64..80].copy_from_slice(&branch);
    if let Some(head) = head {
        frame[96..128].copy_from_slice(&head);
    }
    frame
}

#[derive(Debug, Default, PartialEq)]
struct Content {
    blobs: BTreeSet<[u8; 32]>,
    blob_frames: usize,
    records: BTreeSet<Vec<u8>>,
    /// Legacy pin and opaque frames, as exact bytes in file order.
    log: Vec<Vec<u8>>,
}

fn content(path: &Path) -> Content {
    let bytes = std::fs::read(path).unwrap();
    let mut content = Content::default();
    for record in PileRecords::open(path).unwrap() {
        let record = record.unwrap();
        match record.content {
            PileRecordContent::Blob { hash, .. } => {
                content.blob_frames += 1;
                content.blobs.insert(hash.raw);
            }
            PileRecordContent::Collection { record } => {
                content.records.insert(record.to_bytes());
            }
            PileRecordContent::Want { .. } => {}
            PileRecordContent::Branch { .. }
            | PileRecordContent::BranchTombstone { .. }
            | PileRecordContent::Opaque { .. } => content
                .log
                .push(bytes[record.offset..record.offset + record.len].to_vec()),
            other => panic!("unexpected record {other:?}"),
        }
    }
    content
}

fn concatenated(dir: &Path, name: &str, parts: &[&Path]) -> PathBuf {
    let path = dir.join(name);
    for part in parts {
        append_bytes(&path, &std::fs::read(part).unwrap());
    }
    path
}

fn trible() -> Command {
    Command::cargo_bin("trible").unwrap()
}

fn diff(yard: &Path, old: &Path, live: &Path, into: &Path) -> assert_cmd::assert::Assert {
    trible()
        .args(["yard", "diff"])
        .arg(yard)
        .arg(old)
        .arg("--live")
        .arg(live)
        .arg("--into")
        .arg(into)
        .assert()
}

fn recheck(yard: &Path, old: &Path, live: &Path, out: &Path) -> assert_cmd::assert::Assert {
    trible()
        .args(["yard", "diff"])
        .arg(yard)
        .arg(old)
        .arg("--live")
        .arg(live)
        .arg("--check")
        .arg(out)
        .assert()
}

fn pack(yard: &Path, extra: &[&str], out: &Path) -> assert_cmd::assert::Assert {
    trible()
        .args(["yard", "pack"])
        .arg(yard)
        .args(extra)
        .arg("--into")
        .arg(out)
        .assert()
}

fn pack_check(yard: &Path, extra: &[&str], out: &Path) -> assert_cmd::assert::Assert {
    trible()
        .args(["yard", "pack"])
        .arg(yard)
        .args(extra)
        .arg("--check")
        .arg(out)
        .assert()
}

/// A yard of two generations, a live pile, and an old pile holding items of
/// all three plus a novel blob and commit.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    yard: PathBuf,
    live: PathBuf,
    old: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let yard = root.join("yard");
    std::fs::create_dir(&yard).unwrap();
    let live = root.join("live.pile");
    append(&live, &["in live"], &[1]);
    append(&yard.join("g1.pile"), &["in g1"], &[2]);
    append(&yard.join("g2.pile"), &["in g2", "also in g2"], &[]);
    let old = root.join("old.pile");
    append(&old, &["in g2", "in live", "novel", "in g1"], &[2, 9, 1]);
    Fixture {
        _dir: dir,
        root,
        yard,
        live,
        old,
    }
}

fn no_leftovers(dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(
            !name.to_string_lossy().ends_with(".tmp"),
            "temporary {name:?} left behind"
        );
    }
}

#[test]
fn a_difference_holds_only_what_live_and_every_generation_lack() {
    let f = fixture();
    let out = f.yard.join("old.minus-yard.pile");
    diff(&f.yard, &f.old, &f.live, &out).success().stdout(
        predicate::str::contains("missing: 0")
            .and(predicate::str::contains("extra: 0"))
            .and(predicate::str::contains("g1.pile (3 item(s))"))
            .and(predicate::str::contains("g2.pile (2 item(s))"))
            .and(predicate::str::contains("published")),
    );
    let kept = content(&out);
    assert_eq!(kept.blobs, BTreeSet::from([hash("novel")]));
    assert_eq!(kept.records, BTreeSet::from([commit(9).to_bytes()]));

    // Concatenation is the merge: LIVE, the yard and the difference hold OLD.
    let all = concatenated(
        &f.root,
        "all.pile",
        &[
            &f.live,
            &f.yard.join("g1.pile"),
            &f.yard.join("g2.pile"),
            &out,
        ],
    );
    let (all, old) = (content(&all), content(&f.old));
    assert!(old.blobs.is_subset(&all.blobs));
    assert!(old.records.is_subset(&all.records));

    // The difference is now a member, yet a recheck excludes it by name.
    recheck(&f.yard, &f.old, &f.live, &out)
        .success()
        .stdout(predicate::str::contains(
            "ignored old.minus-yard.pile (the output)",
        ));
    no_leftovers(&f.yard);
}

#[test]
fn a_recheck_fails_once_a_generation_it_depends_on_is_gone() {
    let f = fixture();
    let out = f.root.join("old.minus-yard.pile");
    append(&f.yard.join("unused.pile"), &["unrelated"], &[]);
    diff(&f.yard, &f.old, &f.live, &out).success();

    // A generation that covered nothing can go without consequence.
    std::fs::remove_file(f.yard.join("unused.pile")).unwrap();
    recheck(&f.yard, &f.old, &f.live, &out).success();

    // One that covered items cannot.
    std::fs::remove_file(f.yard.join("g1.pile")).unwrap();
    recheck(&f.yard, &f.old, &f.live, &out).failure().stdout(
        predicate::str::contains(format!("blob {}", hex::encode_upper(hash("in g1"))))
            .and(predicate::str::contains("missing: 3")),
    );
}

#[test]
fn a_corrupt_generation_copy_covers_nothing_and_a_valid_one_does() {
    let f = fixture();
    // g1's copy of "in g1" no longer validates, so OLD's valid copy is kept.
    corrupt(&f.yard.join("g1.pile"), "in g1");
    // OLD's copy of "in g2" is damaged, but g2 holds a valid one.
    corrupt(&f.old, "in g2");
    let out = f.root.join("out.pile");
    diff(&f.yard, &f.old, &f.live, &out).success();
    assert_eq!(
        content(&out).blobs,
        BTreeSet::from([hash("novel"), hash("in g1")])
    );
    recheck(&f.yard, &f.old, &f.live, &out).success();

    // A damaged blob with no valid copy anywhere refuses and leaves nothing.
    corrupt(&f.old, "novel");
    let refused = f.root.join("refused.pile");
    diff(&f.yard, &f.old, &f.live, &refused)
        .failure()
        .stderr(predicate::str::contains("fail hash validation"));
    assert!(!refused.exists());
    no_leftovers(&f.root);
}

#[test]
fn an_order_sensitive_log_and_unknown_frames_keep_every_occurrence() {
    let f = fixture();
    let mut log = legacy_pin([0x31; 16], Some([0x41; 32]));
    log.extend_from_slice(&legacy_pin([0x31; 16], None));
    log.extend_from_slice(&legacy_pin([0x31; 16], Some([0x41; 32])));
    // An unknown kind cannot be assumed idempotent: U, V, U is not U, V.
    let unknown = unknown_kind_frame();
    let mut other = unknown_kind_frame();
    other[64] = 0x22;
    log.extend_from_slice(&unknown);
    log.extend_from_slice(&other);
    log.extend_from_slice(&unknown);
    // A generation holding the same frames does not cover their occurrences.
    append_bytes(&f.yard.join("g2.pile"), &log);
    append_bytes(&f.old, &log);

    let out = f.root.join("out.pile");
    diff(&f.yard, &f.old, &f.live, &out).success();
    assert_eq!(content(&out).log.concat(), log);
    recheck(&f.yard, &f.old, &f.live, &out).success();

    // A difference that collapsed the repeated unknown frame fails.
    let collapsed = f.root.join("collapsed.pile");
    let bytes = std::fs::read(&out).unwrap();
    std::fs::write(&collapsed, &bytes[..bytes.len() - unknown.len()]).unwrap();
    recheck(&f.yard, &f.old, &f.live, &collapsed)
        .failure()
        .stderr(predicate::str::contains("order-sensitive"));
}

#[test]
fn live_may_grow_but_a_torn_old_refuses() {
    let f = fixture();
    let read = std::fs::metadata(&f.live).unwrap().len();
    let out = f.root.join("out.pile");
    diff(&f.yard, &f.old, &f.live, &out)
        .success()
        .stdout(predicate::str::contains(format!(
            "read as its first {read} bytes"
        )));
    // Ordinary appends to LIVE afterwards do not disturb the difference.
    append(&f.live, &["arrived later"], &[30]);
    recheck(&f.yard, &f.old, &f.live, &out).success();

    // An OLD whose last record is torn is not a complete source.
    let frame = {
        let probe = f.root.join("probe.pile");
        append(&probe, &["half"], &[]);
        std::fs::read(&probe).unwrap()
    };
    append_bytes(&f.old, &frame[..frame.len() / 2]);
    let refused = f.root.join("refused.pile");
    diff(&f.yard, &f.old, &f.live, &refused)
        .failure()
        .stderr(predicate::str::contains("open OLD"));
    assert!(!refused.exists());
}

#[test]
fn hidden_and_foreign_entries_are_not_generations() {
    let f = fixture();
    // An in-flight output of another run, and notes: neither covers anything.
    std::fs::copy(&f.old, f.yard.join(".other.pile.yard-diff-1.tmp")).unwrap();
    std::fs::copy(&f.old, f.yard.join("notes.txt")).unwrap();
    std::fs::create_dir(f.yard.join("nested.pile")).unwrap();
    let out = f.root.join("out.pile");
    diff(&f.yard, &f.old, &f.live, &out).success().stdout(
        predicate::str::contains("(hidden)")
            .and(predicate::str::contains("notes.txt (not named *.pile)"))
            .and(predicate::str::contains("nested.pile (not a regular file)")),
    );
    assert_eq!(content(&out).blobs, BTreeSet::from([hash("novel")]));
}

#[test]
fn aliases_are_refused_not_dropped() {
    let f = fixture();
    let out = f.root.join("out.pile");

    // OLD hard-linked into the yard would cover itself.
    std::fs::hard_link(&f.old, f.yard.join("old-link.pile")).unwrap();
    diff(&f.yard, &f.old, &f.live, &out)
        .failure()
        .stderr(predicate::str::contains("same file"));
    assert!(!out.exists());
    std::fs::remove_file(f.yard.join("old-link.pile")).unwrap();

    // LIVE as a member.
    std::fs::hard_link(&f.live, f.yard.join("live-link.pile")).unwrap();
    diff(&f.yard, &f.old, &f.live, &out)
        .failure()
        .stderr(predicate::str::contains("same file"));
    std::fs::remove_file(f.yard.join("live-link.pile")).unwrap();

    // Two names of one generation.
    std::fs::hard_link(f.yard.join("g1.pile"), f.yard.join("g1-again.pile")).unwrap();
    diff(&f.yard, &f.old, &f.live, &out)
        .failure()
        .stderr(predicate::str::contains("same file"));
    std::fs::remove_file(f.yard.join("g1-again.pile")).unwrap();

    // A checked difference hard-linked under another member name.
    diff(&f.yard, &f.old, &f.live, &out).success();
    std::fs::hard_link(&out, f.yard.join("out-link.pile")).unwrap();
    recheck(&f.yard, &f.old, &f.live, &out)
        .failure()
        .stderr(predicate::str::contains("same file"));

    // And an existing destination is never replaced.
    let before = std::fs::read(&out).unwrap();
    diff(&f.yard, &f.old, &f.live, &out)
        .failure()
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(std::fs::read(&out).unwrap(), before);
}

/// Two generations sharing a blob neither LIVE nor the other holds twice.
fn overlapping_yard() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempdir().unwrap();
    let yard = dir.path().join("yard");
    std::fs::create_dir(&yard).unwrap();
    append(&yard.join("a.pile"), &["only a", "shared"], &[3]);
    append(&yard.join("b.pile"), &["shared", "only b"], &[3, 4]);
    let live = dir.path().join("live.pile");
    append(&live, &["only live"], &[5]);
    (dir, yard, live)
}

#[test]
fn a_pack_writes_a_blob_two_differences_share_once() {
    let (dir, yard, live) = overlapping_yard();
    let out = dir.path().join("packed.pile");
    pack(&yard, &[], &out)
        .success()
        .stdout(predicate::str::contains("extra: 0").and(predicate::str::contains("missing: 0")));
    let packed = content(&out);
    assert_eq!(
        packed.blobs,
        BTreeSet::from([hash("only a"), hash("shared"), hash("only b")])
    );
    assert_eq!(packed.blob_frames, 3, "the shared blob is written once");
    assert_eq!(
        packed.records,
        BTreeSet::from([commit(3).to_bytes(), commit(4).to_bytes()])
    );
    pack_check(&yard, &[], &out).success();
    for input in ["a.pile", "b.pile"] {
        assert!(yard.join(input).exists(), "inputs are kept");
    }

    // With LIVE as an input the pack is self-contained.
    let whole = dir.path().join("whole.pile");
    let live_arg = live.to_str().unwrap();
    pack(&yard, &["--live", live_arg], &whole).success();
    assert!(content(&whole).blobs.contains(&hash("only live")));
    pack_check(&yard, &["--live", live_arg], &whole).success();
    // Without LIVE, the same pack holds items no input holds: not exact.
    pack_check(&yard, &[], &whole)
        .failure()
        .stdout(predicate::str::contains("EXTRA"));
}

#[test]
fn a_pack_check_is_exact_in_both_directions() {
    let (dir, yard, _live) = overlapping_yard();
    let out = dir.path().join("packed.pile");
    pack(&yard, &[], &out).success();

    // A new input the pack lacks.
    append(&yard.join("c.pile"), &["only c"], &[]);
    pack_check(&yard, &[], &out)
        .failure()
        .stdout(predicate::str::contains("MISSING"));
    std::fs::remove_file(yard.join("c.pile")).unwrap();

    // A removed input leaves the pack a stale superset.
    std::fs::remove_file(yard.join("b.pile")).unwrap();
    pack_check(&yard, &[], &out)
        .failure()
        .stdout(predicate::str::contains("EXTRA").and(predicate::str::contains("missing: 0")));
}

#[test]
fn a_pack_keeps_each_distinct_legacy_record_once_as_a_blob_of_its_bytes() {
    let (dir, yard, _live) = overlapping_yard();
    let head = legacy_pin([0x31; 16], Some([0x41; 32]));
    let tombstone = legacy_pin([0x31; 16], None);
    let other_head = legacy_pin([0x31; 16], Some([0x42; 32]));
    // a: head A, remove, head A. b: the opposite effect, and another head.
    append_bytes(
        &yard.join("a.pile"),
        &[head.clone(), tombstone.clone(), head.clone()].concat(),
    );
    append_bytes(
        &yard.join("b.pile"),
        &[tombstone.clone(), other_head.clone()].concat(),
    );
    let out = dir.path().join("packed.pile");
    pack(&yard, &[], &out).success();
    // Every distinct record survives once, as a blob of its exact bytes;
    // identical ones collapse; no pin frame is left to replay.
    assert!(content(&out).log.is_empty());
    let recovered = recover(&out, &[&head, &tombstone, &other_head]);
    assert_eq!(recovered, vec![1, 1, 1]);
    assert_eq!(
        oracle(&[&yard.join("a.pile"), &yard.join("b.pile")]),
        BTreeSet::from([head.clone(), tombstone.clone(), other_head.clone()])
    );
    pack_check(&yard, &[], &out).success();

    // A pack that omits one distinct record fails verification.
    let short = dir.path().join("short.pile");
    write_without(&out, &short, &other_head);
    pack_check(&yard, &[], &short)
        .failure()
        .stdout(predicate::str::contains("MISSING legacy pin head"));
}

#[test]
fn a_pack_takes_a_valid_copy_from_any_input_and_refuses_none() {
    let (dir, yard, _live) = overlapping_yard();
    corrupt(&yard.join("a.pile"), "shared");
    let out = dir.path().join("packed.pile");
    pack(&yard, &[], &out).success();
    assert!(content(&out).blobs.contains(&hash("shared")));
    pack_check(&yard, &[], &out).success();

    corrupt(&yard.join("b.pile"), "shared");
    let refused = dir.path().join("refused.pile");
    pack(&yard, &[], &refused)
        .failure()
        .stderr(predicate::str::contains("fail hash validation"));
    assert!(!refused.exists());
    no_leftovers(dir.path());
}

#[test]
fn the_help_carries_a_runnable_example() {
    for verb in ["diff", "pack"] {
        trible()
            .args(["yard", verb, "--help"])
            .assert()
            .success()
            .stdout(
                predicate::str::contains("Example:").and(predicate::str::contains(format!(
                    "trible yard {verb} ~/yard"
                ))),
            );
    }
}

const RETIRED_PEER_EVIDENCE: &str =
    "327FFCAAA3F5A10424DC2059E3A7A3517F837E7E56A3C850979EFA9F5E3A1ED7";

/// A frame of a retired kind this reader knows, carried by its exact bytes.
fn retired_peer_evidence(payload: [u8; 32]) -> Vec<u8> {
    let mut frame = vec![0u8; 256];
    frame[..28].copy_from_slice(&hex::decode(FRAME_MAGIC).unwrap());
    frame[28..32].copy_from_slice(&1u32.to_le_bytes());
    frame[32..64].copy_from_slice(&hex::decode(RETIRED_PEER_EVIDENCE).unwrap());
    frame[64..96].copy_from_slice(&payload);
    frame
}

/// Every frame's kind, in file order, with its exact bytes.
fn frames(path: &Path) -> Vec<(String, Vec<u8>)> {
    let bytes = std::fs::read(path).unwrap();
    PileRecords::open(path)
        .unwrap()
        .map(|record| {
            let record = record.unwrap();
            let kind = format!("{:?}", record.content);
            let kind = kind
                .split(|c: char| !c.is_alphanumeric())
                .next()
                .unwrap()
                .to_string();
            (
                kind,
                bytes[record.offset..record.offset + record.len].to_vec(),
            )
        })
        .collect()
}

#[test]
fn a_pack_of_mixed_formats_is_current_framed_and_recovers_every_record() {
    let (dir, yard, _live) = overlapping_yard();
    let retired = retired_peer_evidence([0x17; 32]);
    append_bytes(&yard.join("a.pile"), &retired);
    append_bytes(&yard.join("b.pile"), &retired);
    // A pile written by the released v0.46.4 writer, V1 blob and branch
    // frames at 64-byte granularity, then current records appended to the
    // same file: one input in two formats.
    let legacy =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy_v0464_branch.pile");
    let mixed = yard.join("c.pile");
    std::fs::copy(&legacy, &mixed).unwrap();
    assert_ne!(std::fs::metadata(&mixed).unwrap().len() % 256, 0);
    let current_head = legacy_pin([0x35; 16], Some([0x45; 32]));
    append_bytes(&mixed, &current_head);
    append(&mixed, &["after legacy"], &[6]);
    assert_eq!(
        frames(&mixed)
            .iter()
            .filter(|(kind, _)| kind == "Branch")
            .count()
            > 1,
        true
    );

    let out = dir.path().join("packed.pile");
    pack(&yard, &[], &out).success();
    let packed = frames(&out);
    let retired_kept = packed.iter().filter(|(_, frame)| *frame == retired).count();
    assert_eq!(
        retired_kept, 1,
        "a current-framed retired kind is a set by its exact bytes"
    );
    // Current framing throughout, checked from the raw bytes.
    current_framed_throughout(&out);
    // Every distinct historical record of every input is a blob of its
    // exact bytes in the pack, found by an oracle that shares no code with
    // the packer; every input blob is there by hash.
    let inputs = [&yard.join("a.pile"), &yard.join("b.pile"), &mixed];
    let records = oracle(&inputs);
    assert!(records.contains(&current_head));
    assert!(records.iter().any(|record| record.len() == 64));
    let wanted: Vec<&Vec<u8>> = records.iter().collect();
    let wanted: Vec<&[u8]> = wanted.iter().map(|record| record.as_slice()).collect();
    assert_eq!(recover(&out, &wanted), vec![1; wanted.len()]);
    let mut input_blobs = BTreeSet::new();
    for input in inputs {
        input_blobs.extend(content_blobs(input));
    }
    let packed_blobs = content_blobs(&out);
    assert!(input_blobs.is_subset(&packed_blobs));
    // Native data supplied in current form still reads natively.
    assert_native(&out, &[commit(3), commit(4), commit(6)]);
    pack_check(&yard, &[], &out).success();

    // A pack that kept the legacy frames as written is not normalized.
    let raw = dir.path().join("raw.pile");
    std::fs::write(
        &raw,
        [
            std::fs::read(&out).unwrap(),
            std::fs::read(&legacy).unwrap(),
        ]
        .concat(),
    )
    .unwrap();
    pack_check(&yard, &[], &raw)
        .failure()
        .stdout(predicate::str::contains("UNNORMALIZED"));

    // An unknown kind cannot be assumed idempotent: one occurrence per
    // occurrence, in input order, and a pack that collapses them fails.
    append_bytes(&yard.join("a.pile"), &unknown_kind_frame());
    append_bytes(&yard.join("b.pile"), &unknown_kind_frame());
    let again = dir.path().join("again.pile");
    pack(&yard, &[], &again).success();
    let unknown_kept = frames(&again)
        .iter()
        .filter(|(_, frame)| *frame == unknown_kind_frame())
        .count();
    assert_eq!(unknown_kept, 2);
    pack_check(&yard, &[], &again).success();
    let collapsed = dir.path().join("collapsed.pile");
    let bytes = std::fs::read(&again).unwrap();
    let unknown = unknown_kind_frame();
    let at = bytes
        .windows(unknown.len())
        .rposition(|window| window == unknown.as_slice())
        .unwrap();
    std::fs::write(
        &collapsed,
        [&bytes[..at], &bytes[at + unknown.len()..]].concat(),
    )
    .unwrap();
    pack_check(&yard, &[], &collapsed)
        .failure()
        .stderr(predicate::str::contains("order-sensitive"));
}

#[test]
fn a_pin_removal_never_costs_the_pack_a_head_or_its_payload() {
    let (dir, yard, _live) = overlapping_yard();
    let payload = dir.path().join("payload.pile");
    let handle = append(&payload, &["pinned payload"], &[])[0];
    std::fs::rename(&payload, yard.join("p.pile")).unwrap();
    let head = legacy_pin([0x33; 16], Some(handle.raw));
    let removal = legacy_pin([0x33; 16], None);
    append_bytes(
        &yard.join("a.pile"),
        &[head.clone(), removal.clone(), head.clone()].concat(),
    );
    let out = dir.path().join("packed.pile");
    pack(&yard, &[], &out).success();
    assert!(content(&out).log.is_empty());
    assert_eq!(recover(&out, &[&head, &removal]), vec![1, 1]);

    // The payload the pin names is still there, readable by its hash.
    let mut packed = Pile::open(&out).unwrap();
    let snapshot = packed.snapshot().unwrap();
    let blob: Blob<UTF8String> = snapshot.get(handle).unwrap();
    assert_eq!(&blob.bytes[..], b"pinned payload");
    drop(snapshot);
    packed.close().unwrap();
}

// An oracle for the normalized pack that shares no code with the packer:
// frame boundaries come from the library decoder, the rule for which
// records a pack keeps as blobs is restated here, and recovery is an
// ordinary blob read.

/// The exact bytes of every historical record in `inputs`: legacy pin heads
/// and tombstones and retired WANT frames in any framing, and every other
/// non-blob record whose frame is not in the current framing.
fn oracle(inputs: &[&PathBuf]) -> BTreeSet<Vec<u8>> {
    let magic = hex::decode(FRAME_MAGIC).unwrap();
    let mut records = BTreeSet::new();
    for input in inputs {
        let bytes = std::fs::read(input).unwrap();
        for record in PileRecords::open(input).unwrap() {
            let record = record.unwrap();
            let frame = &bytes[record.offset..record.offset + record.len];
            let historical = match record.content {
                PileRecordContent::Branch { .. }
                | PileRecordContent::BranchTombstone { .. }
                | PileRecordContent::RetiredWantAssert { .. }
                | PileRecordContent::RetiredWantRetract { .. } => true,
                PileRecordContent::Blob { .. }
                | PileRecordContent::Collection { .. }
                | PileRecordContent::CapabilityProof { .. }
                | PileRecordContent::Want { .. } => false,
                _ => !frame.starts_with(&magic),
            };
            if historical {
                records.insert(frame.to_vec());
            }
        }
    }
    records
}

/// For each record, how many blob frames of `packed` hold exactly its
/// bytes; asserts each one held is readable by its hash.
fn recover(packed: &Path, records: &[&[u8]]) -> Vec<usize> {
    let bytes = std::fs::read(packed).unwrap();
    let mut pile = Pile::open(packed).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let counts = records
        .iter()
        .map(|record| {
            let handle = Inline::<Handle<UnknownBlob>>::new(*blake3::hash(record).as_bytes());
            let frames = PileRecords::open(packed)
                .unwrap()
                .filter(|record_| match record_.as_ref().unwrap().content {
                    PileRecordContent::Blob {
                        data_offset,
                        data_len,
                        ..
                    } => &bytes[data_offset..data_offset + data_len] == *record,
                    _ => false,
                })
                .count();
            if frames > 0 {
                let blob: Blob<UnknownBlob> = snapshot.get(handle).unwrap();
                assert_eq!(&blob.bytes[..], *record);
            }
            frames
        })
        .collect();
    drop(snapshot);
    pile.close().unwrap();
    counts
}

/// The hashes of every blob frame of `path`, whatever else it holds.
fn content_blobs(path: &Path) -> BTreeSet<[u8; 32]> {
    PileRecords::open(path)
        .unwrap()
        .filter_map(|record| match record.unwrap().content {
            PileRecordContent::Blob { hash, .. } => Some(hash.raw),
            _ => None,
        })
        .collect()
}

/// Walk `path` from its raw bytes alone: every frame starts on a 256-byte
/// boundary with the current magic, and the spans end exactly at EOF.
fn current_framed_throughout(path: &Path) {
    let bytes = std::fs::read(path).unwrap();
    let magic = hex::decode(FRAME_MAGIC).unwrap();
    let mut at = 0usize;
    while at < bytes.len() {
        assert_eq!(at % 256, 0, "frame at byte {at} is off 256 alignment");
        assert_eq!(&bytes[at..at + 28], magic.as_slice(), "frame at {at}");
        let span = u32::from_le_bytes(bytes[at + 28..at + 32].try_into().unwrap()) as usize;
        assert!(span > 0);
        at += span * 256;
    }
    assert_eq!(at, bytes.len());
}

/// `commits` read back through the native collection and WANT readers.
fn assert_native(path: &Path, commits: &[CollectionRecord]) {
    let mut pile = Pile::open(path).unwrap();
    let snapshot = pile.snapshot().unwrap();
    let held: BTreeSet<Vec<u8>> = snapshot
        .records()
        .unwrap()
        .map(|record| record.unwrap().to_bytes())
        .collect();
    for commit in commits {
        assert!(held.contains(&commit.to_bytes()));
    }
    assert!(snapshot.wants().unwrap().count() > 0);
    drop(snapshot);
    pile.close().unwrap();
}

/// Copy `from` to `to` without the blob frames holding exactly `record`.
fn write_without(from: &Path, to: &Path, record: &[u8]) {
    let bytes = std::fs::read(from).unwrap();
    let mut kept = Vec::new();
    for frame in PileRecords::open(from).unwrap() {
        let frame = frame.unwrap();
        if let PileRecordContent::Blob {
            data_offset,
            data_len,
            ..
        } = frame.content
        {
            if &bytes[data_offset..data_offset + data_len] == record {
                continue;
            }
        }
        kept.extend_from_slice(&bytes[frame.offset..frame.offset + frame.len]);
    }
    assert!(
        kept.len() < bytes.len(),
        "the record was in {}",
        from.display()
    );
    std::fs::write(to, kept).unwrap();
}

/// The released V1 branch record: marker, pin id, head, 64 bytes.
fn v1_pin(branch: [u8; 16], head: Option<[u8; 32]>) -> Vec<u8> {
    let marker = if head.is_some() {
        "2BC991A7F5D5D2A3A468C53B0AA03504"
    } else {
        "E888CC787202D2AE4C654BFE9699C430"
    };
    let mut frame = hex::decode(marker).unwrap();
    frame.extend_from_slice(&branch);
    frame.extend_from_slice(&head.unwrap_or([0; 32]));
    frame
}

/// Sol's red on f08e7d2b: a V1 branch and a current pin frame naming the
/// same pin and head are two records, and a pack holding one of them is
/// missing the other. The same for tombstones.
#[test]
fn two_encodings_of_one_pin_are_two_records() {
    let k = [b'k'; 16];
    let h = [b'h'; 32];
    for (old, new) in [
        (v1_pin(k, Some(h)), legacy_pin(k, Some(h))),
        (v1_pin(k, None), legacy_pin(k, None)),
    ] {
        assert_eq!((old.len(), new.len()), (64, 256));
        let dir = tempdir().unwrap();
        let yard = dir.path().join("yard");
        std::fs::create_dir(&yard).unwrap();
        append_bytes(&yard.join("a.pile"), &old);
        append_bytes(&yard.join("b.pile"), &new);
        let out = dir.path().join("packed.pile");
        pack(&yard, &[], &out)
            .success()
            .stdout(predicate::str::contains("missing: 0"));
        assert_eq!(recover(&out, &[&old, &new]), vec![1, 1]);
        current_framed_throughout(&out);
        assert_eq!(
            oracle(&[&yard.join("a.pile"), &yard.join("b.pile")]),
            BTreeSet::from([old.clone(), new.clone()])
        );

        // Either encoding alone fails the check, as a blob or as written.
        for (name, without) in [("no-old.pile", &old), ("no-new.pile", &new)] {
            let short = dir.path().join(name);
            write_without(&out, &short, without);
            pack_check(&yard, &[], &short)
                .failure()
                .stdout(predicate::str::contains("missing: 1"));
        }
        let as_written = dir.path().join("as-written.pile");
        std::fs::write(&as_written, &old).unwrap();
        pack_check(&yard, &[], &as_written).failure().stdout(
            predicate::str::contains("UNNORMALIZED").and(predicate::str::contains("missing: 2")),
        );
    }
}

/// An ordinary blob holding a record's exact bytes and the record itself
/// as a legacy frame are one item: one blob in the pack, whichever input is
/// read first, and a pack of the pack is the same pack.
#[test]
fn a_record_and_a_blob_of_its_bytes_are_one_item_and_repack_unchanged() {
    let record = v1_pin([b'k'; 16], Some([b'h'; 32]));
    let mut packs = Vec::new();
    for (blob_member, frame_member) in [("a.pile", "b.pile"), ("b.pile", "a.pile")] {
        let dir = tempdir().unwrap();
        let yard = dir.path().join("yard");
        std::fs::create_dir(&yard).unwrap();
        let blob_pile = yard.join(blob_member);
        std::fs::File::create(&blob_pile).unwrap();
        let mut pile = Pile::open(&blob_pile).unwrap();
        pile.put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(
            triblespace_core::blob::Bytes::from_source(record.clone()),
        ))
        .unwrap();
        pile.close().unwrap();
        append_bytes(&yard.join(frame_member), &record);
        let out = dir.path().join("packed.pile");
        pack(&yard, &[], &out).success();
        assert_eq!(recover(&out, &[&record]), vec![1]);
        assert_eq!(content_blobs(&out).len(), 1);
        assert!(frames(&out).iter().all(|(kind, _)| kind == "Blob"));
        pack_check(&yard, &[], &out).success();

        // Repack: the wrapped record is a blob now, copied as one.
        let again_yard = dir.path().join("again");
        std::fs::create_dir(&again_yard).unwrap();
        std::fs::copy(&out, again_yard.join("packed.pile")).unwrap();
        let again = dir.path().join("again.pile");
        pack(&again_yard, &[], &again).success();
        assert_eq!(std::fs::read(&again).unwrap(), std::fs::read(&out).unwrap());
        assert_eq!(recover(&again, &[&record]), vec![1]);

        // Extraction: the blob is the record, and on its own a pile.
        let extracted = dir.path().join("record.pile");
        trible()
            .args(["pile", "blob", "get"])
            .arg(&out)
            .arg(format!(
                "blake3:{}",
                hex::encode_upper(blake3::hash(&record).as_bytes())
            ))
            .arg(&extracted)
            .assert()
            .success();
        assert_eq!(std::fs::read(&extracted).unwrap(), record);
        let decoded: Vec<_> = PileRecords::open(&extracted)
            .unwrap()
            .map(|record| record.unwrap().content)
            .collect();
        assert!(matches!(
            decoded.as_slice(),
            [PileRecordContent::Branch { .. }]
        ));
        trible()
            .args(["pile", "diagnose", "record-at"])
            .arg(&extracted)
            .arg("0")
            .assert()
            .success();
        packs.push(content_blobs(&out));
    }
    assert_eq!(
        packs[0], packs[1],
        "input order does not change the pack's items"
    );
}

/// A current capability proof supplied to a pack still reads as one.
#[test]
fn a_pack_keeps_a_current_proof_native() {
    use ed25519_dalek::SigningKey;
    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::capability::{CapabilityProof, CapabilityResource};
    use triblespace_core::repo::{CapabilityProofRead, CapabilityProofStore};

    let dir = tempdir().unwrap();
    let yard = dir.path().join("yard");
    std::fs::create_dir(&yard).unwrap();
    let member = yard.join("a.pile");
    std::fs::File::create(&member).unwrap();
    let mut pile = Pile::open(&member).unwrap();
    let capability = pile
        .put::<SimpleArchive, _>(triblespace_core::trible::TribleSet::new())
        .unwrap();
    let proof = CapabilityProof::new(
        CapabilityResource::new([0x77; 32]),
        &SigningKey::from_bytes(&[1; 32]),
        capability,
        SigningKey::from_bytes(&[2; 32]).verifying_key(),
    );
    pile.insert_proof(proof.clone()).unwrap();
    pile.close().unwrap();
    append_bytes(&member, &v1_pin([b'k'; 16], None));

    let out = dir.path().join("packed.pile");
    pack(&yard, &[], &out).success();
    current_framed_throughout(&out);
    let mut packed = Pile::open(&out).unwrap();
    let snapshot = packed.snapshot().unwrap();
    let proofs: Vec<_> = snapshot
        .proofs()
        .unwrap()
        .map(|proof| proof.unwrap())
        .collect();
    assert_eq!(proofs, vec![proof]);
    drop(snapshot);
    packed.close().unwrap();
}
