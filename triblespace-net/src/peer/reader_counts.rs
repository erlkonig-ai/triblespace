//! Count resident-handle enumeration, not payload hashes or simulated latency.
//!
//! The adapter delegates residency and delta operations. Native Pile deltas
//! enumerate only changed handles; MemoryRepo's conservative fallback lists
//! both observations. The final control keeps this backend distinction visible.
//! Fake exact acquisition starts the ordinary lazy Peer boundary without a live
//! endpoint. Publication policy is tested separately by the existing simulated
//! `zero_announcement_budget_still_answers_resident_self_hints` test.
//! H remains a read capability, not a public inventory key: these diagnostics
//! print only counts. The private L-to-H map and provider-first proof ordering
//! are unchanged.
//!
//! Leech controls count enumeration and inspect retained serving/provider state,
//! including after fake host startup. There is no command-processing host loop
//! here, so these are not wire-advertisement or handshake measurements. Close
//! may send an empty provider withdrawal without constructing an inventory.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use triblespace_core::blob::TryFromBlob;
use triblespace_core::capability::{CapabilityProof, CapabilityProofId};
use triblespace_core::collection::{CollectionRead, CollectionRecord, CollectionRecordSelector};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::pile::Pile;
use triblespace_core::repo::{
    BlobInfo, BlobMetadata, BlobStoreList, BlobStoreMeta, CapabilityProofRead, StoreDependencies,
    WantRead, WantRequest,
};

use super::*;

#[derive(Default)]
struct Counts {
    full_calls: AtomicUsize,
    full_handles: Arc<AtomicUsize>,
    delta_calls: AtomicUsize,
    delta_handles: Arc<AtomicUsize>,
    get_calls: AtomicUsize,
    host_starts: AtomicUsize,
    requests: AtomicUsize,
}

impl Counts {
    fn inventory(&self) -> [usize; 4] {
        [
            self.full_calls.load(Ordering::Relaxed),
            self.full_handles.load(Ordering::Relaxed),
            self.delta_calls.load(Ordering::Relaxed),
            self.delta_handles.load(Ordering::Relaxed),
        ]
    }

    fn report(&self, case: &str, resident: usize) {
        println!(
            "reader-inventory case={case} initial_resident={resident} full_calls={} full_handles={} delta_calls={} delta_handles={}",
            self.inventory()[0],
            self.inventory()[1],
            self.inventory()[2],
            self.inventory()[3]
        );
    }
}

#[derive(Clone)]
struct Counted<S> {
    inner: S,
    counts: Arc<Counts>,
}

struct CountedIter<I> {
    inner: I,
    handles: Arc<AtomicUsize>,
}

impl<I, E> Iterator for CountedIter<I>
where
    I: Iterator<Item = Result<BlobInfo, E>>,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next()?;
        if item.is_ok() {
            self.handles.fetch_add(1, Ordering::Relaxed);
        }
        Some(item)
    }
}

impl<S: SnapshotSource> SnapshotSource for Counted<S> {
    type Snapshot = Counted<S::Snapshot>;
    type SnapshotError = S::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        Ok(Counted {
            inner: self.inner.snapshot()?,
            counts: self.counts.clone(),
        })
    }
}

impl<R: CoreStoreSnapshot> CoreStoreSnapshot for Counted<R> {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }

    fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
        self.inner.changes_for(&previous.inner, dependencies)
    }
}

impl<R: BlobStoreList> BlobStoreList for Counted<R> {
    type Iter<'a>
        = CountedIter<R::Iter<'a>>
    where
        Self: 'a;
    type Err = R::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.counts.full_calls.fetch_add(1, Ordering::Relaxed);
        CountedIter {
            inner: self.inner.blobs(),
            handles: self.counts.full_handles.clone(),
        }
    }

    fn blobs_diff<'a>(&'a self, previous: &Self) -> Self::Iter<'a> {
        self.counts.delta_calls.fetch_add(1, Ordering::Relaxed);
        CountedIter {
            inner: self.inner.blobs_diff(&previous.inner),
            handles: self.counts.delta_handles.clone(),
        }
    }

    fn contains_blob<E>(&self, handle: Inline<Handle<E>>) -> Result<bool, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.inner.contains_blob(handle)
    }

    fn blob_info<E>(&self, handle: Inline<Handle<E>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.inner.blob_info(handle)
    }
}

impl<R: BlobStoreGet> BlobStoreGet for Counted<R> {
    type GetError<E: Error + Send + Sync + 'static> = R::GetError<E>;

    fn get<T, E>(&self, handle: Inline<Handle<E>>) -> Result<T, Self::GetError<T::Error>>
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.counts.get_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.get(handle)
    }
}

impl<R: BlobStoreMeta> BlobStoreMeta for Counted<R> {
    type MetaError = R::MetaError;

    fn metadata<E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.inner.metadata(handle)
    }
}

impl<R: BlobChildren> BlobChildren for Counted<R> {}

impl<R: triblespace_core::collection::CoverageRead> triblespace_core::collection::CoverageRead
    for Counted<R>
{
    fn index(
        &self,
        lineage: &std::collections::BTreeSet<triblespace_core::collection::CollectionHandle>,
    ) -> Result<triblespace_core::collection::coverage::CoverageIndex, Self::RecordsError> {
        self.inner.index(lineage)
    }
}

impl<R: CollectionRead> CollectionRead for Counted<R> {
    type RecordsError = R::RecordsError;
    type RecordIter<'a>
        = R::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.inner.records()
    }

    fn collections(
        &self,
    ) -> Result<Vec<triblespace_core::collection::CollectionHandle>, Self::RecordsError> {
        self.inner.collections()
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.inner.select_records(selectors)
    }
}

impl<R: CapabilityProofRead> CapabilityProofRead for Counted<R> {
    type ProofsError = R::ProofsError;
    type ProofIter<'a>
        = R::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.inner.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.inner.proof(id)
    }
}

impl<R: WantRead> WantRead for Counted<R> {
    type WantsError = R::WantsError;
    type WantIter<'a>
        = R::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.inner.wants()
    }
}

impl<S: BlobStorePut> BlobStorePut for Counted<S> {
    type PutError = S::PutError;

    fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
    where
        E: BlobEncoding + 'static,
        T: IntoBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.inner.put(item)
    }
}

impl<S: CollectionStore> CollectionStore for Counted<S> {
    type InsertError = S::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.inner.insert(record)
    }
}

impl<S: CapabilityProofStore> CapabilityProofStore for Counted<S> {
    type InsertError = S::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.inner.insert_proof(proof)
    }
}

impl<S: WantStore> WantStore for Counted<S> {
    type WantError = S::WantError;

    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
        self.inner.want(request)
    }
}

impl<S: StorageFlush> StorageFlush for Counted<S> {
    type Error = S::Error;

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}

impl<S: StorageClose> StorageClose for Counted<S> {
    type Error = S::Error;

    fn close(self) -> Result<(), Self::Error> {
        self.inner.close()
    }
}

struct ExactBlob {
    blob: Blob<UnknownBlob>,
    counts: Arc<Counts>,
}

impl host::NetCapability for ExactBlob {
    fn fetch_blob(
        &self,
        hash: RawHash,
    ) -> futures::future::BoxFuture<'static, Option<Blob<UnknownBlob>>> {
        self.counts.requests.fetch_add(1, Ordering::Relaxed);
        Box::pin(std::future::ready(
            (self.blob.get_handle().raw == hash).then(|| self.blob.clone()),
        ))
    }
}

struct Fixture {
    peer: Peer<Counted<Pile>>,
    counts: Arc<Counts>,
    remote: Blob<UnknownBlob>,
    _file: tempfile::NamedTempFile,
}

impl Fixture {
    fn new(resident: usize, eager: bool) -> Self {
        let counts = Arc::new(Counts::default());
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut inner = Pile::open(file.path()).unwrap();
        for index in 0..resident {
            inner
                .put::<UnknownBlob, _>(Bytes::from_source((index as u64).to_le_bytes().to_vec()))
                .unwrap();
        }
        let store = Counted {
            inner,
            counts: counts.clone(),
        };
        let remote =
            Blob::<UnknownBlob>::new(Bytes::from_source(b"exact missing payload".to_vec()));
        let key = SigningKey::from_bytes(&[86; 32]);
        let (sender, receiver, wiring) =
            host::wire(crate::identity::iroh_secret(&key).public().into());
        let capability = Arc::new(ExactBlob {
            blob: remote.clone(),
            counts: counts.clone(),
        });
        let state = if eager {
            wiring.install_test_capability(capability);
            HostState::Running
        } else {
            let starts = counts.clone();
            HostState::Dormant(Box::new(move || {
                starts.host_starts.fetch_add(1, Ordering::Relaxed);
                wiring.install_test_capability(capability);
                Ok(None)
            }))
        };
        let peer = Peer::assemble(
            store,
            ReconcileQos {
                direction: ReconcileDirection::ReadOnly,
            },
            sender,
            receiver,
            None,
            state,
        );
        Self {
            peer,
            counts,
            remote,
            _file: file,
        }
    }
}

#[tokio::test]
async fn frozen_get_and_bare_reader_refresh_do_not_enumerate_inventory() {
    for resident in [0, 8, 128] {
        let Fixture {
            mut peer,
            counts,
            remote,
            _file,
        } = Fixture::new(resident, false);
        let frozen = peer.snapshot().unwrap();
        let handle = remote.get_handle();
        assert_eq!(
            frozen.get::<Bytes, UnknownBlob>(handle).await.unwrap(),
            remote.bytes
        );
        assert!(!frozen.contains_blob(handle).unwrap());
        // Same resident-reader operation used inside acquire_reader, not a new
        // public API. Do not expose its later control plane as the frozen view.
        let reader = peer.store().snapshot().unwrap();
        assert_eq!(
            BlobStoreGet::get::<Bytes, UnknownBlob>(&reader, handle).unwrap(),
            remote.bytes
        );
        assert_eq!(
            frozen.get::<Bytes, UnknownBlob>(handle).await.unwrap(),
            remote.bytes
        );
        assert_eq!(counts.host_starts.load(Ordering::Relaxed), 1);
        assert_eq!(counts.requests.load(Ordering::Relaxed), 1);
        assert_eq!(counts.inventory(), [0, 0, 0, 0]);
        assert!(peer.sender.current_snapshot().is_none());
        assert_eq!(peer.serving_snapshot_rebuilds, 0);
        assert_eq!(reader.wants().unwrap().count(), 0);
        peer.close().unwrap();
        assert_eq!(counts.inventory(), [0, 0, 0, 0]);
        counts.report("frozen-get-bare-refresh-close", resident);
    }
}

#[tokio::test]
async fn first_peer_resnapshot_enumerates_all_handles_then_only_deltas() {
    for resident in [0, 8, 128] {
        let Fixture {
            mut peer,
            counts,
            remote,
            _file,
        } = Fixture::new(resident, false);
        let frozen = peer.snapshot().unwrap();
        let handle = remote.get_handle();
        frozen.get::<Bytes, UnknownBlob>(handle).await.unwrap();
        let reads = counts.get_calls.load(Ordering::Relaxed);
        // An ordinary peer snapshot still refreshes serving after acquisition.
        let refreshed = peer.snapshot().unwrap();
        assert!(refreshed.contains_blob(handle).unwrap());
        assert_eq!(counts.inventory(), [1, resident + 1, 0, 0]);
        assert_eq!(
            counts.get_calls.load(Ordering::Relaxed),
            reads,
            "inventory construction reads no payloads"
        );
        assert_eq!(peer.serving_snapshot_rebuilds, 1);
        let serving = peer.sender.current_snapshot().unwrap();
        assert_eq!(serving.bearer_locators().len(), (resident + 1) as u64);
        assert_eq!(
            serving
                .bearer_locators()
                .get(&crate::bearer::blob_locator(handle.raw)),
            Some(&handle.raw)
        );
        for _ in 0..3 {
            peer.snapshot().unwrap();
        }
        assert_eq!(counts.inventory(), [1, resident + 1, 0, 0]);
        counts.report("first-peer-resnapshot", resident);

        peer.put::<UnknownBlob, _>(Bytes::from_source(b"later local payload".to_vec()))
            .unwrap();
        peer.snapshot().unwrap();
        assert_eq!(counts.inventory(), [1, resident + 1, 2, 1]);
        assert_eq!(counts.get_calls.load(Ordering::Relaxed), reads);
        assert_eq!(peer.serving_snapshot_rebuilds, 2);
        counts.report("later-delta-refresh", resident);
        peer.close().unwrap();
    }
}

#[tokio::test]
async fn second_peer_acquire_triggers_inventory_even_for_the_same_resident_handle() {
    for resident in [0, 8, 128] {
        let Fixture {
            mut peer,
            counts,
            remote,
            _file,
        } = Fixture::new(resident, false);
        let handle = remote.get_handle();
        assert_eq!(
            peer.acquire(handle).await.unwrap(),
            Some(remote.bytes.clone())
        );
        assert_eq!(counts.inventory(), [0, 0, 0, 0]);
        assert_eq!(peer.acquire(handle).await.unwrap(), Some(remote.bytes));
        assert_eq!(counts.requests.load(Ordering::Relaxed), 1);
        assert_eq!(counts.inventory(), [1, resident + 1, 0, 0]);
        counts.report("second-peer-acquire", resident);
        peer.close().unwrap();
    }
}

#[test]
fn eager_read_only_peer_constructs_a_serving_inventory() {
    for resident in [0, 8, 128] {
        let Fixture {
            peer,
            counts,
            _file,
            ..
        } = Fixture::new(resident, true);
        assert_eq!(peer.qos().direction, ReconcileDirection::ReadOnly);
        assert_eq!(counts.inventory(), [1, resident, 0, 0]);
        assert_eq!(counts.get_calls.load(Ordering::Relaxed), 0);
        assert_eq!(counts.requests.load(Ordering::Relaxed), 0);
        assert!(peer.sender.current_snapshot().is_some());
        assert_eq!(peer.serving_snapshot_rebuilds, 1);
        counts.report("eager-serving", resident);
        peer.close().unwrap();
    }
}

#[test]
fn memory_repo_conservative_delta_is_counted_without_claiming_native_pile_cost() {
    for resident in [0, 8, 128] {
        let counts = Arc::new(Counts::default());
        let mut store = Counted {
            inner: MemoryRepo::default(),
            counts: counts.clone(),
        };
        for index in 0..resident {
            store
                .put::<UnknownBlob, _>(Bytes::from_source((index as u64).to_le_bytes().to_vec()))
                .unwrap();
        }
        let before = store.snapshot().unwrap();
        let index = crate::bearer::locator_index(&before).unwrap();
        let handle = store
            .put::<UnknownBlob, _>(Bytes::from_source(b"one later memory blob".to_vec()))
            .unwrap();
        let after = store.snapshot().unwrap();
        let updated = crate::bearer::update_locator_index(&after, &before, &index).unwrap();
        assert_eq!(counts.inventory(), [1, resident, 2, 2 * resident + 1]);
        assert_eq!(counts.get_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            updated.get(&crate::bearer::blob_locator(handle.raw)),
            Some(&handle.raw)
        );
        counts.report("memoryrepo-conservative-diff", resident);
    }
}

fn assert_leech_has_no_serving_inventory(leech: &Leech<Counted<Pile>>, counts: &Counts) {
    assert_eq!(counts.inventory(), [0, 0, 0, 0]);
    assert!(leech.peer.last_store_snapshot.is_none());
    assert!(leech.peer.sender.current_snapshot().is_none());
    assert_eq!(leech.peer.serving_snapshot_rebuilds, 0);
    let health = leech.health();
    assert!(!health.store.serving_snapshot);
    assert!(health.store.last_snapshot_published_at.is_none());
}

#[test]
fn leech_public_lazy_resident_snapshots_and_writes_remain_dormant() {
    for resident in [0, 8, 128] {
        let counts = Arc::new(Counts::default());
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut inner = Pile::open(file.path()).unwrap();
        for index in 0..resident {
            inner
                .put::<UnknownBlob, _>(Bytes::from_source((index as u64).to_le_bytes().to_vec()))
                .unwrap();
        }
        // No zero-budget or read-only policy is needed for this boundary.
        let mut leech = Leech::lazy(
            Counted {
                inner,
                counts: counts.clone(),
            },
            SigningKey::from_bytes(&[87; 32]),
            PeerConfig {
                peers: Vec::new(),
                qos: ReconcileQos::default(),
                provider_publication_budget: Some(1),
            },
        );
        assert_eq!(
            leech.peer.qos().direction,
            ReconcileDirection::Bidirectional
        );
        assert!(matches!(
            leech.peer.host.lock().unwrap().state,
            HostState::Dormant(_)
        ));
        assert_leech_has_no_serving_inventory(&leech, &counts);

        let frozen = leech.snapshot().unwrap();
        for _ in 0..3 {
            leech.snapshot().unwrap();
        }
        let bytes = Bytes::from_source(b"local leech payload".to_vec());
        let handle = leech.put::<UnknownBlob, _>(bytes.clone()).unwrap();
        assert!(!frozen.contains_blob(handle).unwrap());
        assert_eq!(leech.try_local(handle.raw), Some(bytes.clone()));
        let reader = leech.snapshot().unwrap();
        assert!(reader.contains_blob(handle).unwrap());
        assert_eq!(
            BlobStoreGet::get::<Bytes, UnknownBlob>(&reader, handle).unwrap(),
            bytes
        );
        assert_eq!(reader.wants().unwrap().count(), 0);
        assert_leech_has_no_serving_inventory(&leech, &counts);
        assert!(matches!(
            leech.peer.host.lock().unwrap().state,
            HostState::Dormant(_)
        ));

        let sender = leech.peer.sender.clone();
        let host = Arc::downgrade(&leech.peer.host);
        leech.close().unwrap();
        assert!(host.upgrade().is_none());
        assert!(sender.current_snapshot().is_none());
        assert!(sender.health().store.last_snapshot_published_at.is_none());
        assert_eq!(counts.inventory(), [0, 0, 0, 0]);
        counts.report("leech-public-lazy-resident-write-close", resident);
    }
}

#[tokio::test]
async fn leech_first_and_repeated_exact_acquire_never_build_serving_inventory() {
    for resident in [0, 8, 128] {
        let Fixture {
            peer,
            counts,
            remote,
            _file,
        } = Fixture::new(resident, false);
        // Only the dormant fixture is wrapped; no running-Peer conversion is
        // exposed by the production API.
        let mut leech = Leech { peer };
        let frozen = leech.snapshot().unwrap();
        let handle = remote.get_handle();
        assert!(leech.try_local(handle.raw).is_none());
        assert_eq!(counts.host_starts.load(Ordering::Relaxed), 0);
        assert_eq!(counts.requests.load(Ordering::Relaxed), 0);
        assert_leech_has_no_serving_inventory(&leech, &counts);

        assert_eq!(
            leech.acquire(handle).await.unwrap(),
            Some(remote.bytes.clone())
        );
        assert_eq!(counts.host_starts.load(Ordering::Relaxed), 1);
        assert_eq!(counts.requests.load(Ordering::Relaxed), 1);
        assert!(!frozen.contains_blob(handle).unwrap());
        assert_leech_has_no_serving_inventory(&leech, &counts);

        for _ in 0..3 {
            let reader = leech.snapshot().unwrap();
            assert!(reader.contains_blob(handle).unwrap());
            assert_eq!(reader.wants().unwrap().count(), 0);
            assert_eq!(leech.try_local(handle.raw), Some(remote.bytes.clone()));
            assert_eq!(
                AsyncBlobStoreAcquire::acquire(&mut leech, handle)
                    .await
                    .unwrap(),
                Some(remote.bytes.clone())
            );
            assert_leech_has_no_serving_inventory(&leech, &counts);
        }
        assert_eq!(
            frozen.get::<Bytes, UnknownBlob>(handle).await.unwrap(),
            remote.bytes
        );
        assert!(!frozen.contains_blob(handle).unwrap());

        let local_bytes = Bytes::from_source(b"local write after leech startup".to_vec());
        let local = leech.put::<UnknownBlob, _>(local_bytes.clone()).unwrap();
        assert!(!frozen.contains_blob(local).unwrap());
        assert_eq!(leech.acquire(local).await.unwrap(), Some(local_bytes));
        assert!(leech.snapshot().unwrap().contains_blob(local).unwrap());
        assert_leech_has_no_serving_inventory(&leech, &counts);
        assert_eq!(counts.host_starts.load(Ordering::Relaxed), 1);
        assert_eq!(counts.requests.load(Ordering::Relaxed), 1);

        let sender = leech.peer.sender.clone();
        let host = Arc::downgrade(&leech.peer.host);
        leech.close().unwrap();
        assert!(host.upgrade().is_none());
        assert!(sender.current_snapshot().is_none());
        assert!(sender.health().store.last_snapshot_published_at.is_none());
        // This frozen observation never contained the acquired blob. After
        // close it cannot consult the cache or restart the acquisition host.
        assert!(frozen.get::<Bytes, UnknownBlob>(handle).await.is_err());
        assert_eq!(counts.host_starts.load(Ordering::Relaxed), 1);
        assert_eq!(counts.requests.load(Ordering::Relaxed), 1);
        assert_eq!(counts.inventory(), [0, 0, 0, 0]);
        counts.report("leech-exact-acquire-repeat-write-close", resident);
    }
}
