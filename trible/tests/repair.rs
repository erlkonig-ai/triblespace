//! `trible pile repair` end to end: exit status, the report on stdout, what
//! the destination holds, and that the source is never touched.

use std::path::Path;

use anybytes::Bytes;
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use triblespace::prelude::BlobStorePut;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;
use triblespace_core::repo::pile::{Pile, PileRecords};

/// Write a pile holding one blob per payload and return its frames.
fn write_pile(path: &Path, payloads: &[Vec<u8>]) -> Vec<Vec<u8>> {
    std::fs::File::create(path).unwrap();
    let mut pile: Pile = Pile::open(path).unwrap();
    for payload in payloads {
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from_source(payload.clone()));
        pile.put::<UnknownBlob, _>(blob).unwrap();
    }
    pile.close().unwrap();
    frames(path)
}

/// Every frame the ordinary reader yields; panics on any read error.
fn frames(path: &Path) -> Vec<Vec<u8>> {
    let mut records = PileRecords::open(path).unwrap();
    let mut out = Vec::new();
    while let Some(record) = records.next() {
        let record = record.unwrap();
        out.push(records.bytes()[record.offset..record.offset + record.len].to_vec());
    }
    out
}

fn repair(source: &Path, into: &Path) -> assert_cmd::assert::Assert {
    Command::cargo_bin("trible")
        .unwrap()
        .args([
            "pile",
            "repair",
            source.to_str().unwrap(),
            "--into",
            into.to_str().unwrap(),
        ])
        .assert()
}

/// Nothing but the named files, so a failed run left no hidden sibling.
fn assert_directory_holds(dir: &Path, names: &[&str]) {
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    found.sort();
    let mut expected: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn a_clean_pile_repairs_to_the_same_records_and_exits_zero() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("clean.pile");
    let into = dir.path().join("repaired.pile");
    let original = write_pile(&source, &[vec![1u8; 4], vec![2u8; 900]]);

    repair(&source, &into)
        .code(0)
        .stdout(predicate::str::contains("skipped start=").not())
        .stdout(predicate::str::contains("copied records=2 opaque=0"))
        .stdout(predicate::str::contains("total ranges=0 skipped_bytes=0"));
    assert_eq!(frames(&into), original);
}

#[test]
fn a_torn_record_is_reported_exactly_the_rest_is_kept_and_the_source_is_untouched() {
    let dir = tempdir().unwrap();
    let built = dir.path().join("built.pile");
    let f = write_pile(&built, &[vec![1u8; 4], vec![2u8; 900], vec![3u8; 600]]);
    let torn = &f[1][..500];
    let damaged = [f[0].as_slice(), torn, f[2].as_slice()].concat();
    let source = dir.path().join("damaged.pile");
    std::fs::write(&source, &damaged).unwrap();
    let into = dir.path().join("repaired.pile");

    let start = f[0].len();
    let end = start + torn.len();
    repair(&source, &into)
        .code(3)
        .stdout(predicate::str::contains(format!(
            "skipped start={start} end={end} bytes={} defect=blob-hash\n",
            torn.len()
        )))
        .stdout(predicate::str::contains("copied records=2 opaque=0"))
        .stdout(predicate::str::contains(format!(
            "total ranges=1 skipped_bytes={} source_bytes={}",
            torn.len(),
            damaged.len()
        )))
        .stderr(predicate::str::contains("fetched again by sync"));
    assert_eq!(frames(&into), vec![f[0].clone(), f[2].clone()]);
    assert_eq!(std::fs::read(&source).unwrap(), damaged);

    // The ordinary reader still refuses the source, loudly.
    assert!(PileRecords::open(&source)
        .unwrap()
        .any(|record| record.is_err()));
}

#[test]
fn an_existing_destination_is_refused_and_left_alone() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("source.pile");
    write_pile(&source, &[vec![1u8; 4]]);
    let into = dir.path().join("taken.pile");
    std::fs::write(&into, b"keep me").unwrap();

    repair(&source, &into)
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(std::fs::read(&into).unwrap(), b"keep me");
}

#[test]
fn an_empty_source_writes_nothing() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("empty.pile");
    std::fs::File::create(&source).unwrap();
    let into = dir.path().join("repaired.pile");

    repair(&source, &into)
        .code(1)
        .stderr(predicate::str::contains("is empty"));
    assert_directory_holds(dir.path(), &["empty.pile"]);
}

#[test]
fn a_source_with_no_valid_record_writes_nothing() {
    let dir = tempdir().unwrap();
    let source = dir.path().join("garbage.pile");
    std::fs::write(&source, vec![0x5Au8; 4096]).unwrap();
    let into = dir.path().join("repaired.pile");

    repair(&source, &into)
        .code(1)
        .stdout(predicate::str::contains(
            "skipped start=0 end=4096 bytes=4096 defect=unsupported-marker:",
        ))
        .stderr(predicate::str::contains("no valid record found"));
    assert_directory_holds(dir.path(), &["garbage.pile"]);
}
