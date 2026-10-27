//! A handle bounded to a fixed prefix of a pile that keeps growing: it reads,
//! replays and snapshots exactly the first `prefix` bytes, refuses a prefix
//! that is not a record boundary or lies past the end of the file, and never
//! writes.

use super::*;
use crate::blob::encodings::utf8string::UTF8String;
use crate::repo::{BlobStoreGet, BlobStoreList, BlobStorePut, SnapshotSource};
use std::collections::BTreeSet;

fn append(path: &Path, texts: &[&str]) -> Vec<Inline<Handle<UTF8String>>> {
    if !path.exists() {
        File::create(path).unwrap();
    }
    let mut pile = Pile::open(path).unwrap();
    let handles = texts
        .iter()
        .map(|text| pile.put::<UTF8String, _>(*text).unwrap())
        .collect();
    pile.close().unwrap();
    handles
}

fn file_len(path: &Path) -> usize {
    std::fs::metadata(path).unwrap().len() as usize
}

fn listed(pile: &mut Pile) -> BTreeSet<RawInline> {
    let snapshot = pile.snapshot().unwrap();
    snapshot
        .blobs()
        .map(|info| info.unwrap().handle.raw)
        .collect()
}

fn raw(handles: &[Inline<Handle<UTF8String>>]) -> BTreeSet<RawInline> {
    handles.iter().map(|handle| handle.raw).collect()
}

#[test]
fn prefix_handle_sees_exactly_the_prefix_while_the_file_grows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("growing.pile");
    let kept = append(&path, &["one", "two", "three"]);
    let prefix = file_len(&path);

    // Appended before the bounded open.
    let early = append(&path, &["four"]);
    let mut bounded = Pile::open_prefix(&path, prefix as u64).unwrap();
    // Appended while the bounded handle lives.
    let late = append(&path, &["five", "six"]);
    assert!(file_len(&path) > prefix);

    for _ in 0..2 {
        bounded.refresh().unwrap();
        assert_eq!(bounded.prefix(), Some(prefix as u64));
        assert_eq!(bounded.observed_length().unwrap(), prefix as u64);
        assert_eq!(listed(&mut bounded), raw(&kept));

        let snapshot = bounded.snapshot().unwrap();
        assert_eq!(snapshot.prefix_len(), prefix);
        for handle in &kept {
            assert!(snapshot.contains_blob(*handle).unwrap());
            let blob: Blob<UTF8String> = snapshot.get(*handle).unwrap();
            assert!(!blob.bytes.is_empty());
        }
        for handle in early.iter().chain(&late) {
            assert!(!snapshot.contains_blob(*handle).unwrap());
            assert!(snapshot
                .get::<Blob<UTF8String>, UTF8String>(*handle)
                .is_err());
        }
        let walked: Vec<_> = snapshot.raw_records().map(Result::unwrap).collect();
        assert_eq!(walked.len(), kept.len());
        assert_eq!(
            walked.iter().map(|record| record.len).sum::<usize>(),
            prefix
        );

        // Grow the file again between rounds.
        append(&path, &["seven"]);
    }

    let records: Vec<_> = PileRecords::open_prefix(&path, prefix as u64)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(records.len(), kept.len());
    assert_eq!(
        records.last().map(|record| record.offset + record.len),
        Some(prefix)
    );
    assert_eq!(
        PileRecords::open_prefix(&path, prefix as u64)
            .unwrap()
            .bytes()
            .len(),
        prefix
    );
    bounded.close().unwrap();
}

#[test]
fn prefix_handle_refuses_a_cut_inside_a_record_and_a_prefix_past_the_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cut.pile");
    append(&path, &["first record", "second record"]);
    let total = file_len(&path);
    let first = PileRecords::open(&path)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .len;
    assert!(first < total);

    for (cut, boundary) in [
        (1, 0),
        (first - 1, 0),
        (first + 8, first),
        (total - 1, first),
    ] {
        match Pile::open_prefix(&path, cut as u64) {
            Err(ReadError::PrefixNotRecordBoundary {
                prefix,
                valid_length,
            }) => {
                assert_eq!((prefix, valid_length), (cut, boundary));
            }
            other => panic!("prefix {cut} inside a record was not refused: {other:?}"),
        }
        let last = PileRecords::open_prefix(&path, cut as u64)
            .unwrap()
            .last()
            .unwrap();
        assert!(
            matches!(
                last,
                Err(ReadError::PrefixNotRecordBoundary { prefix, valid_length })
                    if (prefix, valid_length) == (cut, boundary)
            ),
            "raw walk of prefix {cut} ended with {last:?}"
        );
    }

    for beyond in [total + 1, total + 4096] {
        assert!(matches!(
            Pile::open_prefix(&path, beyond as u64),
            Err(ReadError::PrefixBeyondFile { prefix, length }) if (prefix, length) == (beyond, total)
        ));
        assert!(matches!(
            PileRecords::open_prefix(&path, beyond as u64),
            Err(ReadError::PrefixBeyondFile { prefix, length }) if (prefix, length) == (beyond, total)
        ));
    }

    for (cut, count) in [(0, 0), (first, 1), (total, 2)] {
        let mut bounded = Pile::open_prefix(&path, cut as u64).unwrap();
        assert_eq!(listed(&mut bounded).len(), count);
        bounded.close().unwrap();
        assert_eq!(
            PileRecords::open_prefix(&path, cut as u64).unwrap().count(),
            count
        );
    }
}

#[test]
fn prefix_handle_never_writes_and_holds_no_lock_between_calls() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("readonly.pile");
    append(&path, &["alpha", "beta"]);
    let prefix = file_len(&path);
    append(&path, &["gamma"]);
    let original = std::fs::read(&path).unwrap();

    let mut bounded = Pile::open_prefix(&path, prefix as u64).unwrap();
    assert!(bounded.put::<UTF8String, _>("refused").is_err());
    // Amputation needs the exclusive lock, which a bounded handle refuses.
    assert!(bounded.amputate_at(prefix).is_err());
    bounded.refresh().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);

    // Between calls the bounded handle holds no lock: another descriptor can
    // take the exclusive lock a writer of oversized records would.
    let other = File::open(&path).unwrap();
    other.try_lock().unwrap();
    other.unlock().unwrap();
    bounded.close().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
