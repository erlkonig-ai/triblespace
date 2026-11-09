//! Writer preference and yielding replay. Separate `File`s are separate open
//! file descriptions, so threads here contend exactly as processes do.

use super::*;
use crate::repo::{BlobStoreGet, BlobStoreList, BlobStorePut, SnapshotSource, WantStore};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

type Schedule = Option<Box<dyn FnMut(usize) -> bool>>;

thread_local! {
    /// When set, decides at every record boundary of a yielding replay on
    /// this thread, given the applied length, whether to release the shared
    /// lock there, in place of the stride and the clock.
    static YIELD_SCHEDULE: RefCell<Schedule> = RefCell::new(None);
    /// Runs once while a yielding replay on this thread holds no pile lock.
    static WHILE_RELEASED: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

pub(super) fn yield_due(applied_length: usize) -> Option<bool> {
    YIELD_SCHEDULE
        .with_borrow_mut(|schedule| schedule.as_mut().map(|schedule| schedule(applied_length)))
}

pub(super) fn while_released() {
    let hook = WHILE_RELEASED.with_borrow_mut(Option::take);
    if let Some(hook) = hook {
        hook();
    }
}

/// Every blob handle a snapshot lists, with the bytes it reads back for it
/// (`get` validates them against the handle).
fn blob_bytes(pile: &mut PileFile) -> BTreeMap<RawInline, Vec<u8>> {
    let snapshot = pile.snapshot().unwrap();
    snapshot
        .blobs()
        .map(|info| {
            let handle = info.unwrap().handle;
            let bytes: Bytes = snapshot.get::<Bytes, UnknownBlob>(handle).unwrap();
            (handle.raw, bytes.as_ref().to_vec())
        })
        .collect()
}

/// Asserts that two handles replayed the same records: equal key sets for
/// every index (a PATCH compares as a set of keys), equal branch heads, equal
/// frame logs, and the same bytes for every blob handle.
fn assert_same_state(a: &mut PileFile, b: &mut PileFile) {
    assert_eq!(a.applied_length, b.applied_length);
    assert!(a.blobs == b.blobs, "blob occurrences differ");
    assert!(a.branches == b.branches, "branch ids differ");
    for key in a.branches.iter() {
        assert_eq!(
            a.branches.get(key),
            b.branches.get(key),
            "branch head differs"
        );
    }
    assert_eq!(a.collection_records, b.collection_records);
    assert!(a.capability_proofs == b.capability_proofs, "proofs differ");
    assert!(
        a.legacy_collection_headers == b.legacy_collection_headers,
        "legacy collection headers differ"
    );
    assert!(
        a.retired_equations == b.retired_equations,
        "retired equations differ"
    );
    assert_eq!(a.opaque_records, b.opaque_records);
    assert_eq!(a.opaque_frames, b.opaque_frames);
    assert_eq!(a.retired_proof_frames, b.retired_proof_frames);
    assert!(
        a.exact_frame_digests == b.exact_frame_digests,
        "frame digests differ"
    );
    assert!(a.wants == b.wants, "wants differ");
    assert_eq!(blob_bytes(a), blob_bytes(b));
}

/// Asserts that a handle applied exactly the blob and WANT records on disk,
/// read with the raw record iterator instead of replay: every occurrence, at
/// its own offset, and nothing else.
fn assert_applied_every_record(pile: &PileFile, path: &Path) {
    let mut blobs = PileBlobIndex::new();
    let mut blob_records = 0usize;
    let mut wants = PATCH::<WANT_REQUEST_BYTES_LEN, IdentitySchema>::new();
    let mut end = 0;
    for record in PileRecords::open(path).unwrap() {
        let record = record.unwrap();
        end = record.offset + record.len;
        match record.content {
            PileRecordContent::Blob { hash, .. } => {
                blob_records += 1;
                let key = blob_occurrence_key(&hash.raw, IndexEntry::new(record.offset));
                blobs.insert(&Entry::with_value(&key, CachedValidation::default()));
            }
            PileRecordContent::Want { request } => {
                wants.insert(&Entry::new(&request.to_bytes()));
            }
            _ => {}
        }
    }
    assert_eq!(pile.applied_length, end);
    assert_eq!(pile.blobs.iter().count(), blob_records);
    assert!(
        pile.blobs == blobs,
        "applied blob occurrences differ from the file's"
    );
    assert!(pile.wants == wants, "applied wants differ from the file's");
}

fn filled_pile(path: &Path, records: u64) {
    File::create(path).unwrap();
    let mut pile = PileFile::open(path).unwrap();
    for i in 0..records {
        let mut payload = vec![0u8; 64];
        payload[..8].copy_from_slice(&i.to_le_bytes());
        pile.put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(payload)))
            .unwrap();
    }
    pile.close().unwrap();
}

#[cfg(target_os = "linux")]
fn shared_entry_would_block(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_RDLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_start = libc::off_t::MAX - 1;
    lock.l_len = 1;
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) };
    if rc == 0 {
        turnstile::leave(file);
        return false;
    }
    let err = std::io::Error::last_os_error();
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock, "{err}");
    true
}

/// The turnstile keys on the inode, so every name reaching the file shares
/// it, and a read-only descriptor can queue as a reader but never as a writer.
#[cfg(target_os = "linux")]
#[test]
fn turnstile_is_per_inode_and_read_only_never_enters_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.pile");
    File::create(&path).unwrap();
    let hard = dir.path().join("hard.pile");
    std::fs::hard_link(&path, &hard).unwrap();
    let soft = dir.path().join("soft.pile");
    std::os::unix::fs::symlink(&path, &soft).unwrap();

    let writer = OpenOptions::new()
        .read(true)
        .append(true)
        .open(&path)
        .unwrap();
    assert!(turnstile::supported(&writer));
    assert!(turnstile::enter(&writer, true));
    for alias in [&path, &hard, &soft] {
        let reader = File::open(alias).unwrap();
        assert!(shared_entry_would_block(&reader), "{alias:?}");
    }
    turnstile::leave(&writer);
    for alias in [&path, &hard, &soft] {
        assert!(!shared_entry_would_block(&File::open(alias).unwrap()));
    }

    let read_only = File::open(&path).unwrap();
    assert!(!turnstile::enter(&read_only, true));
    assert!(turnstile::enter(&read_only, false));
    turnstile::leave(&read_only);
    // Closing a descriptor releases what it held.
    let held = OpenOptions::new().append(true).open(&path).unwrap();
    assert!(turnstile::enter(&held, true));
    drop(held);
    assert!(!shared_entry_would_block(&read_only));
}

/// A replay that releases and retakes its shared lock reaches the same state
/// as one that never does, including over appends made while it ran.
#[test]
fn yielding_replay_matches_exclusive_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("yield.pile");
    filled_pile(&path, 60_000);
    let stop = Arc::new(AtomicBool::new(false));
    let appender = {
        let path = path.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut pile = PileFile::open(&path).unwrap();
            pile.refresh().unwrap();
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let payload = format!("concurrent {n}").into_bytes();
                pile.put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(Bytes::from_source(payload)))
                    .unwrap();
                n += 1;
            }
            pile.close().unwrap();
            n
        })
    };
    let mut yielding = PileFile::open(&path).unwrap();
    let mut slices = 0;
    for _ in 0..4 {
        let started = Instant::now();
        let mut fresh = PileFile::open(&path).unwrap();
        fresh.refresh().unwrap();
        slices += (started.elapsed().as_millis() / SHARED_REPLAY_SLICE.as_millis()) as usize;
        fresh.close().unwrap();
        yielding.refresh().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    let appended = appender.join().unwrap();
    assert!(appended > 0);
    yielding.refresh().unwrap();

    // An independent open of the same file, replayed without ever yielding.
    let mut exclusive = PileFile::open(&path).unwrap();
    exclusive.lock_exclusive().unwrap();
    exclusive.refresh_locked().unwrap();
    exclusive.file.unlock().unwrap();
    let len = std::fs::metadata(&path).unwrap().len() as usize;
    assert_eq!(yielding.applied_length, len);
    assert_same_state(&mut yielding, &mut exclusive);
    assert_applied_every_record(&yielding, &path);
    if turnstile::supported(&exclusive.file) {
        assert!(slices > 0, "the fixture must be large enough to yield");
    }
    yielding.close().unwrap();
    exclusive.close().unwrap();
}

/// Once a writer waits for the exclusive lock, a NEW shared arrival queues
/// behind it instead of overlapping the shared hold already in progress, which
/// is what used to let overlapping readers keep a writer out indefinitely.
#[cfg(target_os = "linux")]
#[test]
fn waiting_writer_holds_back_new_shared_arrivals() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("order.pile");
    filled_pile(&path, 16);
    let probe = File::open(&path).unwrap();
    assert!(turnstile::supported(&probe));

    // An in-progress shared hold, as a long replay has.
    let holder = PileFile::open(&path).unwrap();
    holder.lock_shared().unwrap();

    // Each side records its event while it holds the pile lock, so the
    // recorded order is the order the exclusive and shared locks were held.
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = {
        let path = path.clone();
        let events = events.clone();
        std::thread::spawn(move || {
            let pile = PileFile::open(&path).unwrap();
            pile.lock_exclusive().unwrap();
            events.lock().unwrap().push("writer");
            pile.file.unlock().unwrap();
            pile.close().unwrap();
        })
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !shared_entry_would_block(&probe) {
        assert!(
            Instant::now() < deadline,
            "the writer must reach the turnstile"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let arrival = {
        let path = path.clone();
        let events = events.clone();
        std::thread::spawn(move || {
            let pile = PileFile::open(&path).unwrap();
            pile.lock_shared().unwrap();
            events.lock().unwrap().push("arrival");
            pile.file.unlock().unwrap();
        })
    };
    // Give a non-queued arrival ample time to overtake the writer.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        events.lock().unwrap().is_empty(),
        "nothing may pass the waiting writer"
    );
    holder.file.unlock().unwrap();
    writer.join().unwrap();
    arrival.join().unwrap();
    assert_eq!(*events.lock().unwrap(), vec!["writer", "arrival"]);
    holder.close().unwrap();
}

/// A long shared replay lets a waiting writer in at a record boundary
/// instead of holding the shared lock to its end.
#[cfg(target_os = "linux")]
#[test]
fn long_shared_replay_lets_a_waiting_writer_in() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slice.pile");
    filled_pile(&path, 400_000);
    let mut writer = PileFile::open(&path).unwrap();
    writer.refresh().unwrap();
    let mut conclusive = false;
    for attempt in 0..5u32 {
        let reader = {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut pile = PileFile::open(&path).unwrap();
                pile.refresh().unwrap();
                let finished = Instant::now();
                pile.close().unwrap();
                finished
            })
        };
        std::thread::sleep(Duration::from_millis(10));
        let started = Instant::now();
        let handle = Blob::<UnknownBlob>::new(Bytes::from_source(attempt.to_le_bytes().to_vec()))
            .get_handle();
        writer.want(WantRequest::blob(handle)).unwrap();
        let written = Instant::now();
        let replayed = reader.join().unwrap();
        // Conclusive only if the replay was still running well after the
        // writer arrived; otherwise the fixture replayed too fast to tell.
        if replayed > started + 20 * SHARED_REPLAY_SLICE {
            assert!(
                written < replayed,
                "the writer waited {:?} for a replay that ended {:?} after it arrived",
                written - started,
                replayed - started
            );
            conclusive = true;
            break;
        }
    }
    assert!(conclusive, "the fixture must replay for longer than 100 ms");
    writer.close().unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Refill {
    /// Amputated and nothing appended: the file ends below the old bound.
    Nothing,
    /// Refilled with a first record that ends exactly at the old bound.
    ToBound,
    /// Refilled with a first record that crosses the old bound.
    AcrossBound,
}

/// The amputation gap. A shared replay of a file with a torn tail releases
/// its lock half way. While it holds none, another handle amputates the tail
/// and appends, refilling the bytes below the replay's bound. The replay then
/// resumes with its old bound, which only ever goes down. Each schedule ends
/// in the state a fresh open reaches, with every record on disk applied once.
#[cfg(target_os = "linux")]
#[test]
fn amputation_gap_during_a_yield() {
    use super::append_visibility_tests::{blob_frame, BEFORE_EXCLUSIVE_RECHECK};

    let small_payload = [0x5A; 64];
    let large_payload = [0xA5; 4096];
    let small = blob_frame(&small_payload).1.len();
    let large = blob_frame(&large_payload).1.len();
    let (_, torn_frame) = blob_frame(&[0xEE; 4096]);
    // The torn tail is as long as one small record, so a small refill ends
    // exactly at the bound and a large one crosses it.
    let torn = &torn_frame[..small];
    assert!(small < large && small < torn_frame.len());

    for refill in [Refill::Nothing, Refill::ToBound, Refill::AcrossBound] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gap.pile");
        filled_pile(&path, 4_000);
        let valid = std::fs::metadata(&path).unwrap().len() as usize;
        let mut raw = OpenOptions::new().append(true).open(&path).unwrap();
        raw.write_all(torn).unwrap();
        drop(raw);
        let bound = valid + torn.len();

        let mut reader = PileFile::open(&path).unwrap();
        assert!(reader.turnstile, "the yielding replay needs the turnstile");

        // Yield exactly once, after the 2,000th record.
        let yielded_at = Rc::new(Cell::new(None));
        let mut seen = 0u32;
        let at = yielded_at.clone();
        YIELD_SCHEDULE.set(Some(Box::new(move |applied| {
            seen += 1;
            if seen == 2_000 {
                at.set(Some(applied));
                true
            } else {
                false
            }
        })));
        let writer_path = path.clone();
        WHILE_RELEASED.set(Some(Box::new(move || {
            // Its own thread, so its replays never consult this schedule.
            std::thread::spawn(move || {
                let mut writer = PileFile::open(&writer_path).unwrap();
                writer.amputate().unwrap();
                assert_eq!(
                    std::fs::metadata(&writer_path).unwrap().len() as usize,
                    valid
                );
                let small = Blob::<UnknownBlob>::new(Bytes::from_source(small_payload.to_vec()));
                let large = Blob::<UnknownBlob>::new(Bytes::from_source(large_payload.to_vec()));
                let want = WantRequest::blob(small.get_handle());
                match refill {
                    Refill::Nothing => {}
                    Refill::ToBound => {
                        writer.put::<UnknownBlob, _>(small).unwrap();
                        writer.want(want).unwrap();
                        writer.put::<UnknownBlob, _>(large).unwrap();
                    }
                    Refill::AcrossBound => {
                        writer.put::<UnknownBlob, _>(large).unwrap();
                        writer.want(want).unwrap();
                        writer.put::<UnknownBlob, _>(small).unwrap();
                    }
                }
                writer.close().unwrap();
            })
            .join()
            .unwrap();
        })));
        // Consumed only if replay rechecks under the exclusive lock.
        BEFORE_EXCLUSIVE_RECHECK.set(Some(Box::new(|| {})));

        let replayed = reader.refresh();
        YIELD_SCHEDULE.set(None);
        let rechecked = BEFORE_EXCLUSIVE_RECHECK.with_borrow(Option::is_none);
        BEFORE_EXCLUSIVE_RECHECK.set(None);
        replayed.unwrap();
        assert!(
            WHILE_RELEASED.with_borrow(Option::is_none),
            "{refill:?}: the replay must yield"
        );
        let yielded_at = yielded_at.get().expect("the replay must yield");
        assert!(
            0 < yielded_at && yielded_at < valid,
            "{refill:?}: yields mid-file"
        );

        let refilled = std::fs::metadata(&path).unwrap().len() as usize;
        match refill {
            Refill::Nothing => {
                // The re-observed length lowered the bound to the new end.
                assert_eq!(refilled, valid);
                assert_eq!(reader.applied_length, valid);
                assert!(!rechecked, "{refill:?}");
            }
            Refill::ToBound => {
                // The old bound is a record boundary of the refill: replay
                // stops there and leaves the rest to the next refresh.
                assert!(refilled > bound);
                assert_eq!(valid + small, bound);
                assert_eq!(reader.applied_length, bound);
                assert!(!rechecked, "{refill:?}");
            }
            Refill::AcrossBound => {
                // The old bound cuts the large record. Only the exclusive
                // recheck at a fresh length gets past it, to the end.
                assert!(valid < bound && bound < valid + large);
                assert!(rechecked, "{refill:?}: the cut record must be rechecked");
                assert_eq!(reader.applied_length, refilled);
            }
        }
        reader.refresh().unwrap();
        assert_eq!(reader.applied_length, refilled);

        let mut fresh = PileFile::open(&path).unwrap();
        fresh.refresh().unwrap();
        assert_same_state(&mut reader, &mut fresh);
        assert_applied_every_record(&reader, &path);
        let expected_blobs = 4_000
            + if matches!(refill, Refill::Nothing) {
                0
            } else {
                2
            };
        assert_eq!(blob_bytes(&mut reader).len(), expected_blobs, "{refill:?}");
        reader.close().unwrap();
        fresh.close().unwrap();
    }
}
