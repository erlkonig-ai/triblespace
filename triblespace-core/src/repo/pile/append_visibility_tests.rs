//! Deterministic append-visibility fixtures. Splitting a fixture append models
//! the prefix Linux can expose during one writev; these are not syscall-atomicity
//! tests. The production append remains one writev, with no retry or truncation.

use super::*;
use crate::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
use std::cell::RefCell;
use std::sync::atomic::AtomicUsize;
use std::sync::{mpsc, Barrier};
use std::time::Duration;

type Hook = Option<Box<dyn FnOnce()>>;

thread_local! {
    pub(super) static BEFORE_EXCLUSIVE_RECHECK: RefCell<Hook> = RefCell::new(None);
    static BEFORE_BLOB_READBACK: RefCell<Hook> = RefCell::new(None);
}

pub(super) fn before_exclusive_recheck() {
    let hook = BEFORE_EXCLUSIVE_RECHECK.with_borrow_mut(Option::take);
    if let Some(hook) = hook {
        hook();
    }
}

pub(super) fn before_blob_readback() {
    let hook = BEFORE_BLOB_READBACK.with_borrow_mut(Option::take);
    if let Some(hook) = hook {
        hook();
    }
}

pub(super) fn blob_frame(payload: &[u8]) -> (Inline<Handle<UnknownBlob>>, Vec<u8>) {
    let blob = Blob::<UnknownBlob>::new(Bytes::from_source(payload.to_vec()));
    let handle = blob.get_handle();
    let blocks = envelope_blocks_for_payload(payload.len()).unwrap();
    let header = BlobRecordHeader::new(blocks, 0, payload.len() as u64, handle.into());
    let mut frame = header.as_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame.resize(blocks as usize * ENVELOPE_BLOCK_LEN, 0);
    (handle, frame)
}

#[derive(Debug)]
enum ReplayEvent {
    SharedParseFailure,
    Finished,
}

fn complete_during_shared_replay<T: Send + 'static>(
    mut pile: Pile,
    path: &Path,
    frame: &[u8],
    split: usize,
    operation: impl FnOnce(&mut Pile) -> T + Send + 'static,
) -> (Pile, T) {
    // Independent open descriptions are essential: duplicated descriptors
    // would share one flock ownership rather than act as reader and writer.
    let mut writer = OpenOptions::new().append(true).open(path).unwrap();
    writer.lock_shared().unwrap();
    writer.write_all(&frame[..split]).unwrap();

    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let failed = send.clone();
        BEFORE_EXCLUSIVE_RECHECK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move || {
                failed.send(ReplayEvent::SharedParseFailure).unwrap();
            }));
        });
        let result = operation(&mut pile);
        send.send(ReplayEvent::Finished).unwrap();
        (pile, result)
    });

    // Completion is ordered by the parse-failure event, never a sleep. The
    // timeout is only a deadlock watchdog; even failure releases the writer.
    let event = receive.recv_timeout(Duration::from_secs(10));
    writer.write_all(&frame[split..]).unwrap();
    writer.unlock().unwrap();
    let result = reader.join().unwrap();
    assert!(
        matches!(event, Ok(ReplayEvent::SharedParseFailure)),
        "the incomplete prefix must reach the completion barrier: {event:?}"
    );
    result
}

#[test]
fn shared_refresh_rechecks_inflight_append_at_fresh_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("refresh.pile");
    File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    let first = pile
        .put::<UnknownBlob, _>(Bytes::from_source(b"original".to_vec()))
        .unwrap();
    let previous = pile.snapshot().unwrap();
    let retained: Blob<UnknownBlob> = previous.get(first).unwrap();
    let (next, frame) = blob_frame(b"completed after the shared parse failure");

    let (pile, observed) =
        complete_during_shared_replay(pile, &path, &frame, ENVELOPE_HEADER_LEN + 1, |pile| {
            pile.snapshot()
        });
    let observed = observed.unwrap();
    assert_eq!(
        observed.covered_len,
        std::fs::metadata(&path).unwrap().len() as usize
    );
    assert!(observed.get::<Blob<UnknownBlob>, _>(next).is_ok());
    assert!(previous.get::<Blob<UnknownBlob>, _>(next).is_err());
    assert_eq!(previous.covered_len + frame.len(), observed.covered_len);
    pile.close().unwrap();
    assert_eq!(retained.bytes.as_ref(), b"original");
    assert_eq!(
        previous
            .get::<Blob<UnknownBlob>, _>(first)
            .unwrap()
            .bytes
            .as_ref(),
        b"original"
    );
}

#[test]
fn shared_blob_preflight_rechecks_inflight_append_without_rewriting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preflight.pile");
    File::create(&path).unwrap();
    let pile = Pile::open(&path).unwrap();
    let (first, frame) = blob_frame(b"other writer");
    let (mut pile, inserted) =
        complete_during_shared_replay(pile, &path, &frame, ENVELOPE_HEADER_LEN, |pile| {
            pile.put::<UnknownBlob, _>(Bytes::from_source(b"this writer".to_vec()))
        });
    let inserted = inserted.unwrap();
    let snapshot = pile.snapshot().unwrap();
    assert_eq!(
        snapshot
            .get::<Blob<UnknownBlob>, _>(first)
            .unwrap()
            .bytes
            .as_ref(),
        b"other writer"
    );
    assert_eq!(
        snapshot
            .get::<Blob<UnknownBlob>, _>(inserted)
            .unwrap()
            .bytes
            .as_ref(),
        b"this writer"
    );
    pile.close().unwrap();
    assert_eq!(
        PileRecords::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn stable_parse_failures_remain_errors_after_one_recheck_without_mutation() {
    let (_, frame) = blob_frame(b"body");
    let mut malformed = frame.clone();
    malformed[80] = 1; // Known BLOB reserved byte, not a new format.
                       // Test-only unrecognized legacy marker; not a published identifier.
    let unknown_marker = [0xA5; 16];
    for tail in [
        frame[..16].to_vec(),
        frame[..frame.len() - 1].to_vec(),
        malformed,
        unknown_marker.to_vec(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("persistent-error.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let first = pile
            .put::<UnknownBlob, _>(Bytes::from_source(b"stable".to_vec()))
            .unwrap();
        let previous = pile.snapshot().unwrap();
        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&tail).unwrap();
        let before = std::fs::read(&path).unwrap();
        let rechecks = Arc::new(AtomicUsize::new(0));
        let count = rechecks.clone();
        BEFORE_EXCLUSIVE_RECHECK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
            }));
        });
        match pile.refresh() {
            Err(ReadError::CorruptPile { valid_length }) => {
                assert_ne!(tail, unknown_marker);
                assert_eq!(valid_length, previous.covered_len);
            }
            Err(ReadError::UnsupportedRecord { offset, marker }) => {
                assert_eq!(tail, unknown_marker);
                assert_eq!(marker, unknown_marker);
                assert_eq!(offset, previous.covered_len);
            }
            other => panic!("persistent malformed tail was not rejected: {other:?}"),
        }
        assert_eq!(rechecks.load(Ordering::SeqCst), 1);
        assert_eq!(pile.applied_length, previous.covered_len);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            previous
                .get::<Blob<UnknownBlob>, _>(first)
                .unwrap()
                .bytes
                .as_ref(),
            b"stable"
        );
        pile.close().unwrap();
    }
}

#[test]
fn blob_readback_stops_before_a_later_incomplete_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("readback.pile");
    File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    let (later, frame) = blob_frame(b"later append");
    let writer = Arc::new(OpenOptions::new().append(true).open(&path).unwrap());
    let staged = writer.clone();
    let partial = frame[..ENVELOPE_HEADER_LEN].to_vec();
    BEFORE_BLOB_READBACK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move || {
            staged.lock_shared().unwrap();
            (&*staged).write_all(&partial).unwrap();
        }));
    });
    let own = pile
        .put::<UnknownBlob, _>(Bytes::from_source(b"completed own append".to_vec()))
        .unwrap();
    assert!(pile.blobs.has_prefix(&own.raw));
    assert!(!pile.blobs.has_prefix(&later.raw));
    assert_eq!(pile.applied_length, 2 * ENVELOPE_BLOCK_LEN);
    assert_eq!(
        writer.metadata().unwrap().len() as usize,
        pile.applied_length + ENVELOPE_HEADER_LEN
    );

    (&*writer).write_all(&frame[ENVELOPE_HEADER_LEN..]).unwrap();
    writer.unlock().unwrap();
    let snapshot = pile.snapshot().unwrap();
    assert!(snapshot.get::<Blob<UnknownBlob>, _>(own).is_ok());
    assert!(snapshot.get::<Blob<UnknownBlob>, _>(later).is_ok());
    pile.close().unwrap();
}

#[test]
fn concurrent_shared_writers_preserve_frozen_snapshot_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.pile");
    File::create(&path).unwrap();
    let mut pile = Pile::open(&path).unwrap();
    let first = pile
        .put::<UnknownBlob, _>(Bytes::from_source(b"frozen".to_vec()))
        .unwrap();
    let previous = pile.snapshot().unwrap();
    let retained: Blob<UnknownBlob> = previous.get(first).unwrap();
    let start = Arc::new(Barrier::new(5));
    let writers: Vec<_> = (0..4)
        .map(|writer| {
            let path = path.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                let mut pile = Pile::open(&path).unwrap();
                start.wait();
                let handles: Vec<_> = (0..16)
                    .map(|record| {
                        let bytes = format!("writer {writer} record {record}")
                            .repeat(256)
                            .into_bytes();
                        let handle = pile
                            .put::<UnknownBlob, _>(Bytes::from_source(bytes.clone()))
                            .unwrap();
                        (handle, bytes)
                    })
                    .collect();
                pile.close().unwrap();
                handles
            })
        })
        .collect();
    start.wait();
    for _ in 0..8 {
        let observed = pile.snapshot().unwrap();
        assert_eq!(
            observed
                .get::<Blob<UnknownBlob>, _>(first)
                .unwrap()
                .bytes
                .as_ref(),
            b"frozen"
        );
    }
    let handles: Vec<_> = writers
        .into_iter()
        .flat_map(|writer| writer.join().unwrap())
        .collect();
    let observed = pile.snapshot().unwrap();
    for (handle, bytes) in handles {
        assert_eq!(
            observed
                .get::<Blob<UnknownBlob>, _>(handle)
                .unwrap()
                .bytes
                .as_ref(),
            bytes
        );
        assert!(previous.get::<Blob<UnknownBlob>, _>(handle).is_err());
    }
    pile.close().unwrap();
    assert_eq!(retained.bytes.as_ref(), b"frozen");
    assert_eq!(
        PileRecords::open(&path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len(),
        65
    );
}
