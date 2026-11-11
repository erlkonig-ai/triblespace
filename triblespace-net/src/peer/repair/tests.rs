//! The held-set thread repairs what it reads; nothing else does.
//!
//! A test capability stands in for a neighbour holding valid bytes and counts
//! every exact GET it is asked, with the asking thread. A snapshot reads a
//! building collection's first closure itself only up to an allowance of
//! 16 MiB (held.rs, `INLINE_BYTES`); a larger blob, and everything the scan
//! reaches after it, is the held-set thread's. The fixtures use one such
//! blob to put the reads they test on that thread.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::covered::Covered;
use triblespace_core::collection::{
    CollectionCommit, CollectionHandle, CollectionRecord, CollectionStore, HeldRead,
};
use triblespace_core::inline::Inline;
use triblespace_core::repo::pile::{GetBlobError, PileFile, PileRecordContent, PileRecords};
use triblespace_core::repo::{BlobStoreGet, BlobStorePut, StorageClose};

use super::Repairing;
use crate::host::{self, NetCapability};
use crate::peer::{Peer, PeerSnapshot};
use crate::protocol::RawHash;
use crate::reconcile::ReplicationMode;

type Store = Covered<Repairing<PileFile>>;

/// More than a snapshot reads of a building collection itself.
const LARGE: usize = (16 << 20) + 4096;

/// A neighbour that holds `blobs` and counts every GET, by handle and by the
/// thread that asked.
#[derive(Default)]
struct Neighbour {
    blobs: HashMap<RawHash, Blob<UnknownBlob>>,
    gets: Mutex<BTreeMap<RawHash, usize>>,
    threads: Mutex<BTreeSet<String>>,
}

impl Neighbour {
    fn holding(blobs: impl IntoIterator<Item = Blob<UnknownBlob>>) -> Arc<Self> {
        Arc::new(Self {
            blobs: blobs
                .into_iter()
                .map(|blob| (blob.get_handle().raw, blob))
                .collect(),
            ..Self::default()
        })
    }

    fn gets(&self, handle: RawHash) -> usize {
        self.gets.lock().unwrap().get(&handle).copied().unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.gets.lock().unwrap().values().sum()
    }

    fn threads(&self) -> BTreeSet<String> {
        self.threads.lock().unwrap().clone()
    }
}

impl NetCapability for Neighbour {
    fn fetch_blob(
        &self,
        hash: RawHash,
    ) -> futures::future::BoxFuture<'static, Option<Blob<UnknownBlob>>> {
        *self.gets.lock().unwrap().entry(hash).or_default() += 1;
        self.threads.lock().unwrap().insert(
            std::thread::current()
                .name()
                .unwrap_or("unnamed")
                .to_owned(),
        );
        Box::pin(std::future::ready(self.blobs.get(&hash).cloned()))
    }
}

fn blob(bytes: impl Into<Vec<u8>>) -> Blob<UnknownBlob> {
    Blob::new(Bytes::from_source(bytes.into()))
}

/// `children`' handles, then `filler` up to `len` bytes.
fn parent(children: &[&Blob<UnknownBlob>], filler: &[u8], len: usize) -> Blob<UnknownBlob> {
    let mut bytes: Vec<u8> = children
        .iter()
        .flat_map(|child| child.get_handle().raw)
        .collect();
    while bytes.len() < len {
        bytes.extend_from_slice(filler);
    }
    bytes.truncate(len.max(32 * children.len()));
    blob(bytes)
}

fn commit(descriptor: &Blob<UnknownBlob>, data: RawHash, metadata: RawHash) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &SigningKey::from_bytes(&[7; 32]),
        Inline::new(descriptor.get_handle().raw),
        Inline::new(data),
        Inline::new(metadata),
    ))
}

fn collection(descriptor: &Blob<UnknownBlob>) -> CollectionHandle {
    Inline::new(descriptor.get_handle().raw)
}

/// A pile holding `blobs` and `records`, with every blob in `damaged`
/// changed in place after it was indexed: listed, and failing validation.
fn pile(
    blobs: &[&Blob<UnknownBlob>],
    records: Vec<CollectionRecord>,
    damaged: &[&Blob<UnknownBlob>],
) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut pile = PileFile::open(file.path()).unwrap();
    for blob in blobs {
        pile.put::<UnknownBlob, _>((*blob).clone()).unwrap();
    }
    for record in records {
        pile.insert(record).unwrap();
    }
    pile.close().unwrap();
    for blob in damaged {
        let handle = blob.get_handle().raw;
        let offset = PileRecords::open(file.path())
            .unwrap()
            .find_map(|record| match record.unwrap().content {
                PileRecordContent::Blob {
                    hash,
                    data_offset,
                    data_len,
                    ..
                } if hash.raw == handle => Some(data_offset + 40.min(data_len - 1)),
                _ => None,
            })
            .unwrap();
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .open(file.path())
            .unwrap();
        // Past the first word, so a parent's child handles stay intact.
        writer.seek(SeekFrom::Start(offset as u64)).unwrap();
        writer.write_all(&[0xa5]).unwrap();
    }
    file
}

/// Copies of `blob` in the file at `path`.
fn occurrences(path: &std::path::Path, blob: &Blob<UnknownBlob>) -> usize {
    let handle = blob.get_handle().raw;
    PileRecords::open(path)
        .unwrap()
        .filter(|record| {
            matches!(
                &record.as_ref().unwrap().content,
                PileRecordContent::Blob { hash, .. } if hash.raw == handle
            )
        })
        .count()
}

type Wiring = host::HostWiring<<Store as triblespace_core::repo::SnapshotSource>::Snapshot>;

fn peer(path: &std::path::Path, neighbour: Arc<Neighbour>) -> (Peer<Store>, Wiring) {
    let store = Covered::new(Repairing::new(PileFile::open(path).unwrap()));
    let key = SigningKey::from_bytes(&[91; 32]);
    let (sender, receiver, wiring) = host::wire(crate::identity::iroh_secret(&key).public().into());
    wiring.install_test_capability(neighbour);
    (Peer::with_wiring(store, sender, receiver), wiring)
}

/// Take snapshots until every one of `collections` has a held set.
fn built(peer: &mut Peer<Store>, collections: &[CollectionHandle]) -> PeerSnapshot<Store> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let snapshot = triblespace_core::repo::SnapshotSource::snapshot(peer).unwrap();
        if collections
            .iter()
            .all(|collection| snapshot.held(*collection).is_some())
        {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "held sets not built within a minute"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn holds(
    snapshot: &PeerSnapshot<Store>,
    collection: CollectionHandle,
    blob: &Blob<UnknownBlob>,
) -> bool {
    snapshot
        .held(collection)
        .expect("built")
        .has_prefix(&blob.get_handle().raw)
}

/// C7. In Shallow, a descendant and a seed whose bytes fail validation are
/// fetched once each by the held-set thread, land beside the corrupt copies,
/// and join the held set with every ancestor. An absent seed is never
/// fetched, and a corrupt blob a snapshot reads itself is never repaired.
#[test]
fn the_held_thread_repairs_corrupt_blobs_and_only_it() {
    // C: a seed `large` (read by the held thread, corrupt) names `middle`,
    // which names `leaf` (corrupt). `absent` is a seed no blob backs, though
    // the neighbour holds it.
    let leaf = blob(b"repair leaf, a damaged descendant".to_vec());
    let middle = parent(&[&leaf], b"middle", 96);
    let large = parent(&[&middle], b"large seed filler ", LARGE);
    let absent = blob(b"repair absent seed".to_vec());
    let descriptor = blob(b"repair descriptor C".to_vec());
    // C2: small, so the snapshot that settles it reads it whole itself.
    let inline_leaf = blob(b"repair inline leaf, damaged".to_vec());
    let inline_parent = parent(&[&inline_leaf], b"inline", 80);
    let inline_metadata = blob(b"repair inline metadata".to_vec());
    let inline_descriptor = blob(b"repair descriptor C2".to_vec());

    let file = pile(
        &[
            &descriptor,
            &large,
            &middle,
            &leaf,
            &inline_descriptor,
            &inline_parent,
            &inline_leaf,
            &inline_metadata,
        ],
        vec![
            // Roots are read last first: `large` before `absent`, so both
            // are the held thread's.
            commit(&descriptor, absent.get_handle().raw, large.get_handle().raw),
            commit(
                &inline_descriptor,
                inline_parent.get_handle().raw,
                inline_metadata.get_handle().raw,
            ),
        ],
        &[&large, &leaf, &inline_leaf],
    );
    let neighbour = Neighbour::holding([
        large.clone(),
        leaf.clone(),
        absent.clone(),
        inline_leaf.clone(),
        middle.clone(),
    ]);
    let (mut peer, _wiring) = peer(file.path(), neighbour.clone());
    let c = collection(&descriptor);
    let c2 = collection(&inline_descriptor);

    // C2 alone first: this call's snapshot reads all of it, on this thread.
    peer.set_replication(ReplicationMode::Shallow, [c2]);
    peer.set_replication(ReplicationMode::Shallow, [c2, c]);
    let snapshot = built(&mut peer, &[c, c2]);

    for blob in [&descriptor, &large, &middle, &leaf] {
        assert!(holds(&snapshot, c, blob), "the repaired closure joins");
    }
    assert!(!holds(&snapshot, c, &absent), "an absent seed stays out");
    assert!(holds(&snapshot, c2, &inline_descriptor));
    assert!(holds(&snapshot, c2, &inline_metadata));
    assert!(
        !holds(&snapshot, c2, &inline_leaf) && !holds(&snapshot, c2, &inline_parent),
        "a corrupt blob a snapshot read is not repaired, and nothing above it joins"
    );

    assert_eq!(neighbour.gets(large.get_handle().raw), 1);
    assert_eq!(neighbour.gets(leaf.get_handle().raw), 1);
    assert_eq!(
        neighbour.gets(absent.get_handle().raw),
        0,
        "absence is not fetched"
    );
    assert_eq!(neighbour.gets(inline_leaf.get_handle().raw), 0);
    assert_eq!(neighbour.total(), 2);
    assert_eq!(
        neighbour.threads(),
        BTreeSet::from(["held-sets".to_owned()]),
        "only the held-set thread fetched"
    );

    // A second copy of each repaired blob, read and validated from the pile.
    assert_eq!(occurrences(file.path(), &large), 2);
    assert_eq!(occurrences(file.path(), &leaf), 2);
    assert_eq!(occurrences(file.path(), &inline_leaf), 1);
    for blob in [&large, &leaf] {
        let read: Bytes =
            BlobStoreGet::get::<Bytes, UnknownBlob>(&*snapshot, blob.get_handle()).unwrap();
        assert_eq!(read, blob.bytes);
    }
    assert!(matches!(
        BlobStoreGet::get::<Bytes, UnknownBlob>(&*snapshot, inline_leaf.get_handle()),
        Err(GetBlobError::ValidationError(_))
    ));

    // Later passes ask for nothing more.
    for _ in 0..5 {
        drop(triblespace_core::repo::SnapshotSource::snapshot(&mut peer).unwrap());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(neighbour.total(), 2);
    drop(snapshot);
    peer.close().unwrap();
}

/// The repair is gated to the held-set thread because a snapshot reads held
/// sets with the store mutex held: a repair there would land under the
/// mutex it already holds. A snapshot that reads a corrupt blob itself
/// finishes, and fetches nothing.
#[test]
fn a_snapshot_that_reads_a_corrupt_blob_under_the_store_mutex_finishes() {
    let leaf = blob(b"gate leaf, damaged".to_vec());
    let parent_blob = parent(&[&leaf], b"gate", 80);
    let descriptor = blob(b"gate descriptor".to_vec());
    let file = pile(
        &[&descriptor, &parent_blob, &leaf],
        vec![commit(
            &descriptor,
            parent_blob.get_handle().raw,
            parent_blob.get_handle().raw,
        )],
        &[&leaf],
    );
    let neighbour = Neighbour::holding([leaf.clone()]);
    let c = collection(&descriptor);
    let (done, finished) = std::sync::mpsc::channel();
    let path = file.path().to_owned();
    let asked = neighbour.clone();
    let owner = std::thread::Builder::new()
        .name("owner".into())
        .spawn(move || {
            let (mut peer, _wiring) = peer(&path, asked);
            peer.set_replication(ReplicationMode::Shallow, [c]);
            let snapshot = triblespace_core::repo::SnapshotSource::snapshot(&mut peer).unwrap();
            let read = snapshot
                .held(c)
                .map(|held| held.has_prefix(&leaf.get_handle().raw));
            drop(snapshot);
            done.send(read).unwrap();
            peer.close().unwrap();
        })
        .unwrap();
    let read = finished
        .recv_timeout(Duration::from_secs(20))
        .expect("a snapshot under the store mutex did not finish");
    assert_eq!(read, Some(false), "built inline, without the corrupt leaf");
    owner.join().unwrap();
    assert_eq!(neighbour.total(), 0);
}

/// A blob no neighbour holds is tried once per thread, not once per closure
/// that reaches it: two collections share a seed whose child is corrupt.
#[test]
fn a_blob_no_neighbour_holds_is_tried_once() {
    let leaf = blob(b"memo leaf, damaged, held by nobody".to_vec());
    let shared = parent(&[&leaf], b"memo shared seed ", LARGE);
    let first = blob(b"memo descriptor one".to_vec());
    let second = blob(b"memo descriptor two".to_vec());
    let file = pile(
        &[&first, &second, &shared, &leaf],
        vec![
            commit(&first, shared.get_handle().raw, shared.get_handle().raw),
            commit(&second, shared.get_handle().raw, shared.get_handle().raw),
        ],
        &[&leaf],
    );
    let neighbour = Neighbour::holding([]);
    let (mut peer, _wiring) = peer(file.path(), neighbour.clone());
    let (one, two) = (collection(&first), collection(&second));
    // Settled by one snapshot, so the shared seed spends the allowance of
    // both: each collection's closure reaches the leaf on the held thread.
    peer.set_replication(ReplicationMode::Shallow, [one, two]);
    let snapshot = built(&mut peer, &[one, two]);
    assert!(holds(&snapshot, one, &first));
    assert!(holds(&snapshot, two, &second));
    for collection in [one, two] {
        assert!(!holds(&snapshot, collection, &shared));
        assert!(!holds(&snapshot, collection, &leaf));
    }
    assert_eq!(neighbour.gets(leaf.get_handle().raw), 1, "tried once");
    assert_eq!(neighbour.total(), 1);
    assert_eq!(occurrences(file.path(), &leaf), 1);
    drop(snapshot);
    peer.close().unwrap();
}
