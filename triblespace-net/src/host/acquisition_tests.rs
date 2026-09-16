//! Exact-H acquisition through the production DHT and bearer RPC handlers.
//!
//! Connection latency and caller deadlines use a paused Tokio timeline.
//! Directory leases remain unexpired; publication retries receive explicit
//! monotonic instants and require no global virtual clock.
//! The shared unit-test guard excludes body receivers on other test runtimes,
//! whose independent clocks cannot make progress on this paused timeline.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use triblespace_core::collection::CollectionRead;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource, WantRead};

use crate::transport::sim::{SimConfig, SimNet, SimTransport};

use super::*;

struct CountedBlobReader {
    inner: Arc<dyn BlobSnapshotReader>,
    reads: Arc<AtomicUsize>,
}

impl BlobSnapshotReader for CountedBlobReader {
    fn get_blob(&self, hash: RawHash) -> Option<Bytes> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.get_blob(hash)
    }
}

struct Fixture {
    net: SimNet,
    client: ProviderClient<SimTransport>,
    sender: NetSender,
    provider: PeerId,
    provider_routes: Arc<Mutex<RoutingTable>>,
    provider_snapshot: SnapshotSlot,
    provider_directory: Arc<Mutex<ProviderDirectory>>,
    blob_reads: Arc<AtomicUsize>,
    hash: RawHash,
    bytes: Bytes,
    store: MemoryRepo,
    events: tokio::sync::mpsc::Receiver<NetEventBatch>,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    fn new(advertise: bool) -> Self {
        Self::with_bytes(
            advertise,
            Bytes::from_source(b"cold exact-H acquisition".to_vec()),
        )
    }

    fn with_bytes(advertise: bool, bytes: Bytes) -> Self {
        // SimNet charges one round trip for connection setup: four seconds,
        // beyond the background lookup cap but within the foreground budget.
        let latency = Duration::from_secs(2);
        let net = SimNet::new(
            0xC01D_D417,
            SimConfig {
                latency: latency..latency,
            },
        );
        let provider_key = SigningKey::from_bytes(&[91; 32]);
        let client_key = SigningKey::from_bytes(&[92; 32]);
        let provider = provider_key.verifying_key().to_bytes();
        let my_id = client_key.verifying_key().to_bytes();
        let mut server_harness = net.join(&provider_key);
        let client_harness = net.join(&client_key);
        let client = ProviderClient {
            transport: client_harness.transport,
            pool: new_shared_pool(),
            providers: Arc::new(Mutex::new(ProviderDirectory::new(my_id))),
            candidates: Arc::new(Mutex::new(RoutingTable::new(my_id, [provider]))),
            my_id,
        };
        let (sender, _receiver, wiring) = wire(EndpointId::from_bytes(&my_id).unwrap());
        wiring.install_test_capability(Arc::new(NetCap {
            client: client.clone(),
        }));

        let mut store = MemoryRepo::default();
        let hash = store.put::<UnknownBlob, _>(bytes.clone()).unwrap().raw;
        let mut snapshot = StoreSnapshot::from_store_changes(
            store.snapshot().unwrap(),
            &ActiveCollections::new(),
            provider_key.verifying_key(),
            None,
            None,
            StoreChanges::ALL,
        )
        .unwrap();
        let blob_reads = Arc::new(AtomicUsize::new(0));
        snapshot.blobs = Arc::new(CountedBlobReader {
            inner: snapshot.blobs,
            reads: blob_reads.clone(),
        });
        let mut providers = ProviderDirectory::new(provider);
        if advertise {
            assert!(providers.put(
                blob_locator(hash),
                provider,
                blob_provider_token(hash, provider),
                crate::clock::mono_now(),
            ));
        }
        let (events_tx, events) = tokio::sync::mpsc::channel(16);
        let provider_routes = Arc::new(Mutex::new(RoutingTable::new(provider, [])));
        let provider_snapshot = Arc::new(Mutex::new(Some(Arc::new(snapshot))));
        let provider_directory = Arc::new(Mutex::new(providers));
        let handler = SnapshotHandler {
            snapshot: provider_snapshot.clone(),
            candidates: provider_routes.clone(),
            providers: provider_directory.clone(),
            serve_collections: false,
            local_id: provider,
            events: events_tx,
            inbound_connections: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            inbound_requests: Arc::new(tokio::sync::Semaphore::new(MAX_REQUESTS_GLOBAL)),
        };
        let server = tokio::spawn(async move {
            while let Some(incoming) = server_harness.incoming.recv().await {
                assert_eq!(incoming.alpn, PILE_SYNC_ALPN);
                let permit = handler
                    .inbound_connections
                    .clone()
                    .try_acquire_owned()
                    .unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    handler.handle::<SimTransport>(incoming.conn, permit).await;
                });
            }
        });
        Self {
            net,
            client,
            sender,
            provider,
            provider_routes,
            provider_snapshot,
            provider_directory,
            blob_reads,
            hash,
            bytes,
            store,
            events,
            server,
        }
    }

    fn assert_no_control_effects(&mut self) {
        let snapshot = self.store.snapshot().unwrap();
        assert_eq!(snapshot.records().unwrap().count(), 0);
        assert_eq!(snapshot.wants().unwrap().count(), 0);
        assert!(matches!(
            self.events.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// An independent directory or restarted provider using the production RPC
/// handler. Its control events remain observable, and dropping it stops its
/// accept loop. Each restart installs fresh provider-side operational state.
struct RecoveryNode {
    peer: PeerId,
    directory: Arc<Mutex<ProviderDirectory>>,
    events: tokio::sync::mpsc::Receiver<NetEventBatch>,
    server: tokio::task::JoinHandle<()>,
}

impl RecoveryNode {
    fn new(net: &SimNet, key: &SigningKey, snapshot: Option<Arc<StoreSnapshot>>) -> Self {
        let peer = key.verifying_key().to_bytes();
        let mut harness = net.join(key);
        let directory = Arc::new(Mutex::new(ProviderDirectory::new(peer)));
        let (events_tx, events) = tokio::sync::mpsc::channel(16);
        let handler = SnapshotHandler {
            snapshot: Arc::new(Mutex::new(snapshot)),
            candidates: Arc::new(Mutex::new(RoutingTable::new(peer, []))),
            providers: directory.clone(),
            serve_collections: false,
            local_id: peer,
            events: events_tx,
            inbound_connections: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            inbound_requests: Arc::new(tokio::sync::Semaphore::new(MAX_REQUESTS_GLOBAL)),
        };
        let server = tokio::spawn(async move {
            while let Some(incoming) = harness.incoming.recv().await {
                assert_eq!(incoming.alpn, PILE_SYNC_ALPN);
                let permit = handler
                    .inbound_connections
                    .clone()
                    .try_acquire_owned()
                    .unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    handler.handle::<SimTransport>(incoming.conn, permit).await;
                });
            }
        });
        Self {
            peer,
            directory,
            events,
            server,
        }
    }

    fn advertise(&self, hash: RawHash, provider: PeerId) -> crate::clock::Mono {
        // Test setup installs exactly the soft state an authenticated provider
        // PUT would leave; no raw H is sent to this node by the reader.
        let now = crate::clock::mono_now();
        assert!(self.directory.lock().unwrap().put(
            blob_locator(hash),
            provider,
            blob_provider_token(hash, provider),
            now,
        ));
        now
    }

    fn assert_no_events(&mut self) {
        assert!(self.events.try_recv().is_err());
    }
}

impl Drop for RecoveryNode {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A directory which remains responsive to routing but delays its provider
/// reply. This isolates the post-FIND_NODE barrier from cold-dial behavior.
struct DelayedDirectory {
    peer: PeerId,
    queries: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl DelayedDirectory {
    fn new(
        net: &SimNet,
        key: &SigningKey,
        replies: Vec<(PeerId, ProviderToken)>,
        delay: Option<Duration>,
    ) -> Self {
        let peer = key.verifying_key().to_bytes();
        let mut harness = net.join(key);
        let queries = Arc::new(AtomicUsize::new(0));
        let counted = queries.clone();
        let server = tokio::spawn(async move {
            while let Some(incoming) = harness.incoming.recv().await {
                let replies = replies.clone();
                let queries = counted.clone();
                tokio::spawn(async move {
                    while let Some((mut send, mut recv)) = incoming.conn.accept_bi().await {
                        let replies = replies.clone();
                        let queries = queries.clone();
                        tokio::spawn(async move {
                            let op = recv_u8(&mut recv).await.unwrap();
                            let _key = recv_exact_key(&mut recv).await.unwrap();
                            match op {
                                OP_FIND_NODE => send_u8(&mut send, 0).await.unwrap(),
                                OP_PROVIDER_GET => {
                                    queries.fetch_add(1, Ordering::Relaxed);
                                    match delay {
                                        Some(delay) => tokio::time::sleep(delay).await,
                                        None => std::future::pending::<()>().await,
                                    }
                                    send_u8(&mut send, replies.len() as u8).await.unwrap();
                                    for (provider, token) in replies {
                                        send_hash(&mut send, &provider).await.unwrap();
                                        send_hash(&mut send, &token).await.unwrap();
                                    }
                                }
                                other => panic!("unexpected directory opcode {other:#x}"),
                            }
                            send.shutdown().await.unwrap();
                        });
                    }
                });
            }
        });
        Self {
            peer,
            queries,
            server,
        }
    }
}

impl Drop for DelayedDirectory {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn verified_provider_fetch_does_not_wait_for_a_stalled_directory_reply() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let slow = DelayedDirectory::new(
        &fixture.net,
        &SigningKey::from_bytes(&[133; 32]),
        Vec::new(),
        None,
    );
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [slow.peer, fixture.provider]);
    for peer in [slow.peer, fixture.provider] {
        fixture
            .client
            .find_node(peer, blob_locator(fixture.hash))
            .await
            .unwrap();
    }

    let budget = Duration::from_secs(2);
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture.sender.fetch_blob(fixture.hash, budget).await,
        Some(fixture.bytes.clone()),
        "a verified provider is usable before unrelated directory replies complete",
    );
    assert!(started.elapsed() < budget);
    assert_eq!(slow.queries.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn later_directory_hint_recovers_from_an_unavailable_first_provider() {
    later_directory_hint_case(false).await;
}

#[tokio::test(start_paused = true)]
async fn later_directory_hint_recovers_from_a_stalled_first_provider() {
    later_directory_hint_case(true).await;
}

async fn later_directory_hint_case(stalled: bool) {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let mut missing = RecoveryNode::new(&fixture.net, &SigningKey::from_bytes(&[134; 32]), None);
    let first = DelayedDirectory::new(
        &fixture.net,
        &SigningKey::from_bytes(&[135; 32]),
        vec![(
            missing.peer,
            blob_provider_token(fixture.hash, missing.peer),
        )],
        Some(Duration::ZERO),
    );
    let later = DelayedDirectory::new(
        &fixture.net,
        &SigningKey::from_bytes(&[136; 32]),
        vec![(
            fixture.provider,
            blob_provider_token(fixture.hash, fixture.provider),
        )],
        Some(Duration::from_secs(1)),
    );
    for peer in [first.peer, later.peer, fixture.provider] {
        pool_get(&fixture.client.transport, &fixture.client.pool, peer)
            .await
            .unwrap();
    }
    if stalled {
        fixture.net.stall_dials(missing.peer);
    } else {
        pool_get(
            &fixture.client.transport,
            &fixture.client.pool,
            missing.peer,
        )
        .await
        .unwrap();
    }
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [first.peer, later.peer]);
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, Duration::from_secs(2))
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(first.queries.load(Ordering::Relaxed), 1);
    assert_eq!(later.queries.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture.net.dial_count(fixture.client.my_id, missing.peer),
        1
    );
    if stalled {
        assert!(
            !fixture
                .client
                .pool
                .lock()
                .unwrap()
                .entries
                .contains_key(&missing.peer),
            "success cancels and releases the unrelated pending provider dial",
        );
    }
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
    missing.assert_no_events();
}

#[tokio::test(start_paused = true)]
async fn progressive_fetch_distinguishes_empty_directory_from_incomplete_lookup() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let empty = DelayedDirectory::new(
        &fixture.net,
        &SigningKey::from_bytes(&[137; 32]),
        Vec::new(),
        Some(Duration::ZERO),
    );
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [empty.peer]);
    assert!(
        fixture
            .client
            .fetch_blob(fixture.hash, None)
            .await
            .unwrap()
            .is_none()
    );
    let stalled = DelayedDirectory::new(
        &fixture.net,
        &SigningKey::from_bytes(&[138; 32]),
        Vec::new(),
        None,
    );
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [stalled.peer]);
    let error = fixture
        .client
        .fetch_blob(fixture.hash, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("DHT provider lookup incomplete"));
    assert_eq!(stalled.queries.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn progressive_fetch_preserves_unavailable_and_failed_provider_outcomes() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let mut absent = RecoveryNode::new(&fixture.net, &SigningKey::from_bytes(&[139; 32]), None);
    let directory = DelayedDirectory::new(
        &fixture.net,
        &SigningKey::from_bytes(&[140; 32]),
        vec![(absent.peer, blob_provider_token(fixture.hash, absent.peer))],
        Some(Duration::ZERO),
    );
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    assert!(
        fixture
            .client
            .fetch_blob(fixture.hash, None)
            .await
            .unwrap()
            .is_none()
    );
    fixture.net.crash(absent.peer);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    assert!(fixture.client.fetch_blob(fixture.hash, None).await.is_err());
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
    absent.assert_no_events();
}

#[tokio::test(start_paused = true)]
async fn progressive_fetch_does_not_dial_an_invalid_provider_hint() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let mut token = blob_provider_token(fixture.hash, fixture.provider);
    token[0] ^= 1;
    let directory = DelayedDirectory::new(
        &fixture.net,
        &SigningKey::from_bytes(&[141; 32]),
        vec![(fixture.provider, token)],
        Some(Duration::ZERO),
    );
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    assert!(
        fixture
            .client
            .fetch_blob(fixture.hash, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        0
    );
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn stale_provider_lease_survives_loss_alternate_fetch_and_same_endpoint_restart() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    // These deterministic endpoint seeds are test-only, not protocol IDs.
    let directory_key = SigningKey::from_bytes(&[101; 32]);
    let alternate_key = SigningKey::from_bytes(&[102; 32]);
    let mut directory = RecoveryNode::new(&fixture.net, &directory_key, None);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    directory.advertise(fixture.hash, fixture.provider);
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        1
    );

    // Losing the provider leaves its still-live directory lease untouched.
    // Its cached connection must fail without preventing the alternate fetch.
    fixture.net.crash(fixture.provider);
    fixture.server.abort();
    let serving = fixture.provider_snapshot.lock().unwrap().clone();
    let mut alternate = RecoveryNode::new(&fixture.net, &alternate_key, serving);
    let last_advertised = directory.advertise(fixture.hash, alternate.peer);
    let before = directory
        .directory
        .lock()
        .unwrap()
        .get(blob_locator(fixture.hash), crate::clock::mono_now());
    assert_eq!(before.len(), 2);
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert!(started.elapsed() < INTERACTIVE_FETCH_DEADLINE);
    assert_eq!(
        fixture.net.dial_count(fixture.client.my_id, alternate.peer),
        1
    );
    assert!(
        !fixture
            .client
            .pool
            .lock()
            .unwrap()
            .entries
            .contains_key(&fixture.provider)
    );
    let dials_before_restart = fixture
        .net
        .dial_count(fixture.client.my_id, fixture.provider);

    // Reconstruct all provider-side soft state at the same endpoint, retaining
    // only its immutable store observation. No re-announcement is made: this
    // fresh handler must be discoverable through the original directory lease.
    fixture.net.crash(alternate.peer);
    alternate.server.abort();
    let provider_key = SigningKey::from_bytes(&[91; 32]);
    let restored = StoreSnapshot::from_store_changes(
        fixture.store.snapshot().unwrap(),
        &ActiveCollections::new(),
        provider_key.verifying_key(),
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let mut restarted = RecoveryNode::new(&fixture.net, &provider_key, Some(Arc::new(restored)));
    assert_eq!(restarted.peer, fixture.provider);
    assert_eq!(
        restarted.directory.lock().unwrap().retained_counts(),
        (0, 0)
    );
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        dials_before_restart + 1
    );
    assert_eq!(
        directory
            .directory
            .lock()
            .unwrap()
            .get(blob_locator(fixture.hash), crate::clock::mono_now()),
        before,
        "recovery leaves both retained provider hints intact"
    );
    assert!(
        directory
            .directory
            .lock()
            .unwrap()
            .get(
                blob_locator(fixture.hash),
                last_advertised + crate::provider::PROVIDER_LEASE_LIFETIME,
            )
            .is_empty(),
        "discovery and recovery must not renew either original lease"
    );
    let snapshot = fixture.store.snapshot().unwrap();
    assert_eq!(snapshot.records().unwrap().count(), 0);
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    assert!(fixture.events.try_recv().is_err());
    directory.assert_no_events();
    alternate.assert_no_events();
    restarted.assert_no_events();
}

#[tokio::test(start_paused = true)]
async fn cancelled_discovered_provider_dial_leaves_a_same_client_retry_usable() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let directory_key = SigningKey::from_bytes(&[103; 32]);
    let mut directory = RecoveryNode::new(&fixture.net, &directory_key, None);
    directory.advertise(fixture.hash, fixture.provider);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    // Warm only the directory, so cancellation lands in the discovered
    // provider's dial rather than the bootstrap lookup.
    fixture
        .client
        .find_node(directory.peer, blob_locator(fixture.hash))
        .await
        .unwrap();
    fixture.net.stall_dials(fixture.provider);
    let started = tokio::time::Instant::now();
    assert!(
        fixture
            .sender
            .fetch_blob(fixture.hash, Duration::from_secs(1))
            .await
            .is_none()
    );
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        1
    );
    {
        let pool = fixture.client.pool.lock().unwrap();
        assert!(!pool.entries.contains_key(&fixture.provider));
        assert!(pool.entries.contains_key(&directory.peer));
        assert_eq!(pool.entries.len(), 1);
    }
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.net.unstall_dials(fixture.provider);
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        2
    );
    assert_eq!(
        fixture.net.dial_count(fixture.client.my_id, directory.peer),
        1
    );
    fixture.assert_no_control_effects();
    directory.assert_no_events();
}

#[tokio::test(start_paused = true)]
async fn alternate_provider_success_cancels_a_stalled_discovered_dial() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let directory_key = SigningKey::from_bytes(&[104; 32]);
    let stalled_key = SigningKey::from_bytes(&[105; 32]);
    let mut directory = RecoveryNode::new(&fixture.net, &directory_key, None);
    let stalled = stalled_key.verifying_key().to_bytes();
    let _stalled_harness = fixture.net.join(&stalled_key);
    fixture.net.stall_dials(stalled);
    directory.advertise(fixture.hash, stalled);
    directory.advertise(fixture.hash, fixture.provider);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    fixture
        .client
        .find_node(directory.peer, blob_locator(fixture.hash))
        .await
        .unwrap();

    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::from_secs(4));
    assert_eq!(fixture.net.dial_count(fixture.client.my_id, stalled), 1);
    let pool = fixture.client.pool.lock().unwrap();
    assert!(!pool.entries.contains_key(&stalled));
    assert_eq!(pool.entries.len(), 2);
    drop(pool);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
    directory.assert_no_events();
}

struct SignallingBlobReader {
    inner: Arc<dyn BlobSnapshotReader>,
    started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl BlobSnapshotReader for SignallingBlobReader {
    fn get_blob(&self, hash: RawHash) -> Option<Bytes> {
        let bytes = self.inner.get_blob(hash);
        if let Some(started) = self.started.lock().unwrap().take() {
            let _ = started.send(());
        }
        bytes
    }
}

#[tokio::test(start_paused = true)]
async fn mid_transfer_crash_rejects_old_bytes_after_restart_and_allows_fresh_retry() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    // Larger than SimNet's bounded pipe, so the authenticated server must
    // block partway through the body while this test owns the receive permit.
    let mut fixture = Fixture::with_bytes(false, Bytes::from_source(vec![b'x'; 8 * 1024 * 1024]));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    {
        let mut slot = fixture.provider_snapshot.lock().unwrap();
        let snapshot = Arc::get_mut(slot.as_mut().unwrap()).unwrap();
        snapshot.blobs = Arc::new(SignallingBlobReader {
            inner: snapshot.blobs.clone(),
            started: Mutex::new(Some(started_tx)),
        });
    }
    let (mut permit_writer, mut permit_reader) = tokio::io::duplex(1);
    let held_receive = crate::protocol::recv_exact_blob_body(&mut permit_reader, 1);
    tokio::pin!(held_receive);
    assert!(futures::poll!(&mut held_receive).is_pending());
    let sender = fixture.sender.clone();
    let hash = fixture.hash;
    let fetch =
        tokio::spawn(async move { sender.fetch_blob(hash, INTERACTIVE_FETCH_DEADLINE).await });
    // get_blob runs after both bearer proofs. The server continues until pipe
    // backpressure yields; no timer or arbitrary scheduler-yield count gates
    // this fault. The client cannot consume body bytes while the permit is held.
    started_rx.await.unwrap();
    assert!(!fetch.is_finished());
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    fixture.net.crash(fixture.provider);
    fixture.server.abort();

    let provider_key = SigningKey::from_bytes(&[91; 32]);
    let restored = StoreSnapshot::from_store_changes(
        fixture.store.snapshot().unwrap(),
        &ActiveCollections::new(),
        provider_key.verifying_key(),
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let mut restarted = RecoveryNode::new(&fixture.net, &provider_key, Some(Arc::new(restored)));
    let failed_at = tokio::time::Instant::now();
    permit_writer.write_all(b"x").await.unwrap();
    held_receive.await.unwrap();
    assert!(
        fetch.await.unwrap().is_none(),
        "old connection supplied bytes after restart"
    );
    assert_eq!(
        failed_at.elapsed(),
        Duration::ZERO,
        "reset must not wait for a deadline"
    );
    assert!(
        !fixture
            .client
            .pool
            .lock()
            .unwrap()
            .entries
            .contains_key(&fixture.provider)
    );
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        2
    );
    let snapshot = fixture.store.snapshot().unwrap();
    assert_eq!(snapshot.records().unwrap().count(), 0);
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    assert!(fixture.events.try_recv().is_err());
    restarted.assert_no_events();
}

#[tokio::test(start_paused = true)]
async fn cold_exact_lookup_outlives_background_cap_within_caller_deadline() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(true);
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert!(started.elapsed() > BACKGROUND_LOOKUP_DEADLINE);
    assert!(started.elapsed() < INTERACTIVE_FETCH_DEADLINE);

    let warmed = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(warmed.elapsed(), Duration::ZERO);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn responsive_provider_is_not_held_behind_stalled_secondary_bootstrap() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(true);
    let stalled_key = SigningKey::from_bytes(&[93; 32]);
    let stalled = stalled_key.verifying_key().to_bytes();
    let _stalled_harness = fixture.net.join(&stalled_key);
    fixture.net.stall_dials(stalled);
    let learned_key = SigningKey::from_bytes(&[94; 32]);
    let learned = learned_key.verifying_key().to_bytes();
    let _learned_harness = fixture.net.join(&learned_key);
    fixture.net.stall_dials(learned);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [fixture.provider, stalled]);
    fixture
        .client
        .candidates
        .lock()
        .unwrap()
        .promote_authenticated(learned);

    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::from_secs(7));
    {
        let routes = fixture.client.candidates.lock().unwrap();
        assert_eq!(
            routes.state(fixture.provider),
            Some(crate::routing::RouteState::Verified)
        );
        assert_eq!(
            routes.state(stalled),
            Some(crate::routing::RouteState::Candidate)
        );
        assert_eq!(routes.state(learned), None);
    }
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn configured_only_cold_background_lookup_keeps_its_short_bound() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(true);
    // A configured-only four-second cold dial still cannot complete within
    // the unchanged three-second background window. Failure must retain the
    // configured route, but does not itself warm a cancelled SimNet dial.
    for attempt in 1..=3 {
        let started = tokio::time::Instant::now();
        let error = fixture
            .client
            .fetch_blob(fixture.hash, Some(BACKGROUND_LOOKUP_DEADLINE))
            .await
            .unwrap_err();
        assert_eq!(started.elapsed(), BACKGROUND_LOOKUP_DEADLINE);
        assert!(error.to_string().contains("no remote replica"));
        assert_eq!(
            fixture
                .client
                .candidates
                .lock()
                .unwrap()
                .closest(fixture.hash, K),
            vec![fixture.provider]
        );
        assert_eq!(
            fixture
                .net
                .dial_count(fixture.client.my_id, fixture.provider),
            attempt
        );
    }
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn repeated_directory_gossip_does_not_erase_recent_local_route_failure() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let key = blob_locator(fixture.hash);
    // Warm only the reachable configured directory, so setup latency cannot
    // explain any subsequent full background routing window.
    fixture
        .client
        .find_node(fixture.provider, key)
        .await
        .unwrap();
    let stalled_key = SigningKey::from_bytes(&[93; 32]);
    let stalled = stalled_key.verifying_key().to_bytes();
    let _stalled_harness = fixture.net.join(&stalled_key);
    fixture.net.stall_dials(stalled);
    // The directory still has old direct-liveness evidence, so its production
    // FIND_NODE handler re-advertises this unreachable route on every reply.
    assert!(
        fixture
            .provider_routes
            .lock()
            .unwrap()
            .promote_authenticated(stalled)
    );
    let token = blob_provider_token(fixture.hash, fixture.client.my_id);
    let mut elapsed = Vec::new();
    let mut stalled_dials = Vec::new();
    for _ in 0..3 {
        let started = tokio::time::Instant::now();
        assert_eq!(
            fixture.client.announce_key(key, token).await,
            PublicationResult::Published
        );
        elapsed.push(started.elapsed());
        stalled_dials.push(fixture.net.dial_count(fixture.client.my_id, stalled));
    }
    fixture.assert_no_control_effects();
    // Dropping local evidence at timeout lets unverified gossip immediately
    // restore the stalled route, even though all three publications get ACKs.
    assert_eq!(
        elapsed,
        [BACKGROUND_LOOKUP_DEADLINE, Duration::ZERO, Duration::ZERO],
        "unchanged remote gossip must not repeatedly consume the routing window; stalled dial counts: {stalled_dials:?}"
    );
    assert_eq!(stalled_dials, [1, 1, 1]);
}

#[tokio::test(start_paused = true)]
async fn background_publication_retries_past_a_stale_issued_batch() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let key = blob_locator(fixture.hash);
    // The configured sibling is already responsive. Three learned stale
    // identities closer to this exact locator occupy the whole first batch.
    fixture
        .client
        .find_node(fixture.provider, key)
        .await
        .unwrap();
    let stale_keys: Vec<_> = (0u8..=255)
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .filter(|signer| {
            let peer = signer.verifying_key().to_bytes();
            peer != fixture.client.my_id
                && crate::routing::distance_cmp(key, peer, fixture.provider).is_lt()
        })
        .take(ALPHA)
        .collect();
    assert_eq!(stale_keys.len(), ALPHA);
    let stale: Vec<_> = stale_keys
        .iter()
        .map(|signer| signer.verifying_key().to_bytes())
        .collect();
    let _stale_harnesses: Vec<_> = stale_keys
        .iter()
        .map(|signer| fixture.net.join(signer))
        .collect();
    for peer in &stale {
        fixture.net.stall_dials(*peer);
        assert!(
            fixture
                .client
                .candidates
                .lock()
                .unwrap()
                .promote_authenticated(*peer)
        );
    }
    assert_eq!(
        fixture.client.candidates.lock().unwrap().closest(key, K)[ALPHA],
        fixture.provider
    );

    let now = crate::clock::mono_now();
    let locators = locator_index(&fixture.store.snapshot().unwrap()).unwrap();
    let mut publisher = ProviderPublisher::new(now);
    publisher.install(
        ProviderObservation::from_locators([], false, &locators).into_set(),
        now,
    );
    let work = publisher.next(now).expect("initial publication attempt");
    assert_eq!((work.key, work.identity), (key, fixture.hash));
    let token = blob_provider_token(fixture.hash, fixture.client.my_id);
    let started = tokio::time::Instant::now();
    let result = fixture.client.announce_key(key, token).await;
    assert_eq!(started.elapsed(), BACKGROUND_LOOKUP_DEADLINE);
    assert_eq!(result, PublicationResult::NoAuthenticatedRemoteReplica);
    let completed = now + started.elapsed();
    assert!(
        publisher
            .complete(work, result, completed)
            .topology_outage_started
    );
    assert_eq!(publisher.next(completed), None);

    let retry_at = completed + crate::RETRY_BACKOFF_BASE;
    let retry = publisher.next(retry_at).expect("topology retry probe");
    assert_eq!((retry.key, retry.identity), (key, fixture.hash));
    let retry_started = tokio::time::Instant::now();
    let result = fixture.client.announce_key(key, token).await;
    assert_eq!(result, PublicationResult::Published);
    assert_eq!(retry_started.elapsed(), Duration::ZERO);
    assert!(
        publisher
            .complete(retry, result, retry_at)
            .topology_recovered
    );
    assert_eq!(publisher.next(retry_at), None);
    let advertised = fixture.client.get(fixture.provider, key).await.unwrap();
    assert!(
        advertised.contains(&(fixture.client.my_id, token)),
        "the directory's own resident hint is not evidence of our remote publication"
    );
    assert_eq!(
        fixture
            .provider_directory
            .lock()
            .unwrap()
            .get(key, crate::clock::mono_now()),
        vec![(fixture.client.my_id, token)]
    );
    for peer in stale {
        assert_eq!(fixture.client.candidates.lock().unwrap().state(peer), None);
        assert_eq!(fixture.net.dial_count(fixture.client.my_id, peer), 1);
    }
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn resident_self_hint_needs_no_lease_or_payload_read() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let key = blob_locator(fixture.hash);
    let expected = (
        fixture.provider,
        blob_provider_token(fixture.hash, fixture.provider),
    );

    assert_eq!(
        fixture.client.get(fixture.provider, key).await.unwrap(),
        vec![expected]
    );
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    assert_eq!(
        fixture.provider_directory.lock().unwrap().retained_counts(),
        (0, 0)
    );
    assert_eq!(
        fixture.client.providers.lock().unwrap().retained_counts(),
        (0, 0)
    );
    fixture.assert_no_control_effects();

    // Only the ordinary, DHT-selected bearer GET reads the body.
    assert_eq!(
        fixture.client.fetch_blob(fixture.hash, None).await.unwrap(),
        Some(fixture.bytes.clone())
    );
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture.provider_directory.lock().unwrap().retained_counts(),
        (0, 0)
    );
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn self_hint_requires_a_present_serving_snapshot() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let key = blob_locator(fixture.hash);
    let snapshot = fixture.provider_snapshot.lock().unwrap().take();
    assert!(
        fixture
            .client
            .get(fixture.provider, key)
            .await
            .unwrap()
            .is_empty()
    );

    *fixture.provider_snapshot.lock().unwrap() = snapshot;
    assert_eq!(
        fixture.client.get(fixture.provider, key).await.unwrap(),
        vec![(
            fixture.provider,
            blob_provider_token(fixture.hash, fixture.provider)
        )]
    );
    fixture.provider_snapshot.lock().unwrap().take();
    assert!(
        fixture
            .client
            .get(fixture.provider, key)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture.provider_directory.lock().unwrap().retained_counts(),
        (0, 0)
    );

    // Withdrawal removes the synthesized hint, not independent foreign leases.
    let foreign = fixture.client.my_id;
    let token = blob_provider_token(fixture.hash, foreign);
    assert!(fixture.provider_directory.lock().unwrap().put(
        key,
        foreign,
        token,
        crate::clock::mono_now()
    ));
    assert_eq!(
        fixture.client.get(fixture.provider, key).await.unwrap(),
        vec![(foreign, token)]
    );
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn resident_self_hint_reserves_a_bounded_slot_and_deduplicates_self() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let key = blob_locator(fixture.hash);
    let own = (
        fixture.provider,
        blob_provider_token(fixture.hash, fixture.provider),
    );
    let mut foreign = (1..=crate::provider::MAX_PROVIDERS_PER_KEY)
        .map(|byte| {
            (
                SigningKey::from_bytes(&[byte as u8; 32])
                    .verifying_key()
                    .to_bytes(),
                [0; 32],
            )
        })
        .collect::<Vec<_>>();
    foreign.sort_unstable();
    assert!(
        foreign
            .iter()
            .all(|(peer, token)| blob_provider_token(fixture.hash, *peer) != *token)
    );
    {
        let mut directory = fixture.provider_directory.lock().unwrap();
        for (peer, token) in &foreign {
            assert!(directory.put(key, *peer, *token, crate::clock::mono_now()));
        }
    }
    let reply = fixture.client.get(fixture.provider, key).await.unwrap();
    assert_eq!(reply.len(), crate::provider::MAX_PROVIDERS_PER_KEY);
    assert_eq!(reply[0], own);
    assert_eq!(&reply[1..], &foreign[..foreign.len() - 1]);
    assert_eq!(
        fixture.provider_directory.lock().unwrap().retained_counts(),
        (foreign.len(), 1)
    );

    // An already-stored self entry consumes no extra reply slot. Current
    // resident knowledge replaces even a stale/incorrect stored self token.
    {
        let mut directory = fixture.provider_directory.lock().unwrap();
        *directory = ProviderDirectory::new(fixture.provider);
        assert!(directory.put(key, fixture.provider, [0; 32], crate::clock::mono_now()));
        for (peer, token) in foreign.iter().take(foreign.len() - 1) {
            assert!(directory.put(key, *peer, *token, crate::clock::mono_now()));
        }
    }
    let deduplicated = fixture.client.get(fixture.provider, key).await.unwrap();
    assert_eq!(deduplicated, reply);
    assert_eq!(
        deduplicated
            .iter()
            .filter(|(peer, _)| *peer == fixture.provider)
            .count(),
        1
    );
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    assert!(
        fixture
            .provider_directory
            .lock()
            .unwrap()
            .get(key, crate::clock::mono_now())
            .contains(&(fixture.provider, [0; 32]))
    );
    assert_eq!(
        fixture.client.fetch_blob(fixture.hash, None).await.unwrap(),
        Some(fixture.bytes.clone())
    );
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn resident_descriptor_is_not_a_collection_participant_hint() {
    use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};

    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let collection = fixture
        .store
        .collection(
            "resident-descriptor-without-collection-service",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
        )
        .unwrap();
    let handle = collection.handle();
    let snapshot = StoreSnapshot::from_store_changes(
        fixture.store.snapshot().unwrap(),
        &ActiveCollections::new(),
        VerifyingKey::from_bytes(&fixture.provider).unwrap(),
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    *fixture.provider_snapshot.lock().unwrap() = Some(Arc::new(snapshot));

    assert_eq!(
        fixture
            .client
            .get(fixture.provider, blob_locator(handle.raw))
            .await
            .unwrap(),
        vec![(
            fixture.provider,
            blob_provider_token(handle.raw, fixture.provider)
        )]
    );
    assert!(
        fixture
            .client
            .get(fixture.provider, collection_provider_key(handle))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture.provider_directory.lock().unwrap().retained_counts(),
        (0, 0)
    );
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn known_resident_outside_selected_dht_replicas_is_not_directly_probed() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let key = blob_locator(fixture.hash);
    let closer_keys = (0u64..4096)
        .map(|index| {
            let mut seed = [0; 32];
            seed[..8].copy_from_slice(&index.to_be_bytes());
            SigningKey::from_bytes(&seed)
        })
        .filter(|signer| {
            let peer = signer.verifying_key().to_bytes();
            peer != fixture.client.my_id
                && crate::routing::distance_cmp(key, peer, fixture.provider).is_lt()
        })
        .take(K)
        .collect::<Vec<_>>();
    assert_eq!(closer_keys.len(), K);
    let closer = closer_keys
        .iter()
        .map(|signer| signer.verifying_key().to_bytes())
        .collect::<Vec<_>>();
    let mut servers = Vec::new();
    for signer in &closer_keys {
        let peer = signer.verifying_key().to_bytes();
        let mut harness = fixture.net.join(signer);
        let handler = SnapshotHandler {
            snapshot: Arc::new(Mutex::new(None)),
            candidates: Arc::new(Mutex::new(RoutingTable::new(peer, []))),
            providers: Arc::new(Mutex::new(ProviderDirectory::new(peer))),
            serve_collections: false,
            local_id: peer,
            events: {
                let (sender, _receiver) = tokio::sync::mpsc::channel(1);
                sender
            },
            inbound_connections: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            inbound_requests: Arc::new(tokio::sync::Semaphore::new(MAX_REQUESTS_GLOBAL)),
        };
        servers.push(tokio::spawn(async move {
            while let Some(incoming) = harness.incoming.recv().await {
                let permit = handler
                    .inbound_connections
                    .clone()
                    .try_acquire_owned()
                    .unwrap();
                let handler = handler.clone();
                tokio::spawn(async move {
                    handler.handle::<SimTransport>(incoming.conn, permit).await;
                });
            }
        }));
        pool_get(&fixture.client.transport, &fixture.client.pool, peer)
            .await
            .unwrap();
    }
    *fixture.client.candidates.lock().unwrap() = RoutingTable::new(
        fixture.client.my_id,
        closer.iter().copied().chain([fixture.provider]),
    );
    // The holder is a known, connected, usable directory/provider. Only its
    // exclusion from the exact locator's replica set prevents its use below.
    assert_eq!(
        fixture.client.get(fixture.provider, key).await.unwrap(),
        vec![(
            fixture.provider,
            blob_provider_token(fixture.hash, fixture.provider)
        )]
    );
    let replicas = fixture.client.lookup_replicas(key, None).await;
    assert_eq!(replicas.len(), K);
    assert!(!replicas.contains(&fixture.provider));
    assert!(
        fixture
            .client
            .fetch_blob(fixture.hash, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
    for server in servers {
        server.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn zero_announcement_budget_still_answers_resident_self_hints() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let net = SimNet::new(
                0xC01D_D417,
                SimConfig {
                    latency: Duration::ZERO..Duration::ZERO,
                },
            );
            let server_key = SigningKey::from_bytes(&[91; 32]);
            let client_key = SigningKey::from_bytes(&[92; 32]);
            let server_id = server_key.verifying_key().to_bytes();
            let client_id = client_key.verifying_key().to_bytes();
            let server_harness = net.join(&server_key);
            let client_harness = net.join(&client_key);
            let (sender, mut receiver, wiring) = wire(EndpointId::from_bytes(&server_id).unwrap());
            let mut store = MemoryRepo::default();
            let bytes = Bytes::from_source(b"zero-announcement resident self hint".to_vec());
            let hash = store.put::<UnknownBlob, _>(bytes.clone()).unwrap().raw;
            let serving = StoreSnapshot::from_store_changes(
                store.snapshot().unwrap(),
                &ActiveCollections::new(),
                server_key.verifying_key(),
                None,
                None,
                StoreChanges::ALL,
            )
            .unwrap();
            let observation =
                ProviderObservation::from_locators([], false, serving.bearer_locators());
            sender.update_snapshot(serving, &ActiveCollections::new());
            sender.update_providers(observation);
            let host = tokio::task::spawn_local(run_host(
                server_harness,
                PeerConfig {
                    peers: vec![EndpointAddr::from(
                        EndpointId::from_bytes(&client_id).unwrap(),
                    )],
                    qos: ReconcileQos::default(),
                    provider_publication_budget: Some(0),
                },
                wiring,
            ));
            let client = ProviderClient {
                transport: client_harness.transport,
                pool: new_shared_pool(),
                providers: Arc::new(Mutex::new(ProviderDirectory::new(client_id))),
                candidates: Arc::new(Mutex::new(RoutingTable::new(client_id, [server_id]))),
                my_id: client_id,
            };
            assert_eq!(client.fetch_blob(hash, None).await.unwrap(), Some(bytes));
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(
                net.dial_count(server_id, client_id),
                0,
                "zero budget must not announce even resident hints"
            );
            sender.clear_snapshot();
            assert!(
                client
                    .get(server_id, blob_locator(hash))
                    .await
                    .unwrap()
                    .is_empty(),
                "querying the self hint must not install a lease"
            );
            assert!(receiver.try_recv().is_none());
            let snapshot = store.snapshot().unwrap();
            assert_eq!(snapshot.records().unwrap().count(), 0);
            assert_eq!(snapshot.wants().unwrap().count(), 0);
            host.abort();
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn warm_provider_miss_is_not_a_transport_failure() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    // Neither a directory lease nor the serving snapshot knows this exact H.
    // A warm successful directory miss remains distinct from transport failure.
    let missing = *blake3::hash(b"absent warm provider query").as_bytes();
    pool_get(
        &fixture.client.transport,
        &fixture.client.pool,
        fixture.provider,
    )
    .await
    .unwrap();
    let started = tokio::time::Instant::now();
    assert!(
        fixture
            .client
            .fetch_blob(missing, None)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(started.elapsed(), Duration::ZERO);

    fixture
        .net
        .partition(fixture.client.my_id, fixture.provider);
    let error = fixture.client.fetch_blob(missing, None).await.unwrap_err();
    assert!(error.to_string().contains("no remote replica"));
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn stalled_bootstrap_still_exhausts_the_one_foreground_deadline() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(true);
    fixture.net.stall_dials(fixture.provider);
    let started = tokio::time::Instant::now();
    assert!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .is_none()
    );
    assert_eq!(started.elapsed(), INTERACTIVE_FETCH_DEADLINE);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn exact_receive_contention_remains_inside_the_caller_deadline() {
    use tokio::io::AsyncWriteExt as _;

    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(true);
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let blocked = crate::protocol::recv_exact_blob_body(&mut reader, 1);
    tokio::pin!(blocked);
    // The receive owns the process-wide permit, then waits for its one byte.
    assert!(futures::poll!(&mut blocked).is_pending());

    let started = tokio::time::Instant::now();
    assert!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .is_none()
    );
    assert_eq!(started.elapsed(), INTERACTIVE_FETCH_DEADLINE);
    assert_eq!(
        fixture
            .client
            .candidates
            .lock()
            .unwrap()
            .state(fixture.provider),
        Some(crate::routing::RouteState::Verified),
        "bootstrap authenticated before waiting for the local receive slot"
    );

    writer.write_all(b"x").await.unwrap();
    assert_eq!(blocked.await.unwrap().as_ref(), b"x");
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await,
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    fixture.assert_no_control_effects();
}
