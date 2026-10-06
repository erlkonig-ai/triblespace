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

use tokio::io::AsyncWriteExt as _;

use crate::protocol::{TAG_RECON, send_hash};
use crate::transport::sim::{SimConfig, SimNet, SimTransport};

use super::*;

mod exact_h_diagnostics;
mod repair_refusal;
mod request_backpressure;

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
    provider_snapshot: tokio::sync::watch::Sender<Option<SharedSnapshot>>,
    provider_directory: Arc<Mutex<ProviderDirectory>>,
    provider_health: Health,
    blob_reads: Arc<AtomicUsize>,
    hash: RawHash,
    bytes: Bytes,
    store: MemoryRepo,
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
        let client = ProviderClient::for_test(
            client_harness.transport,
            RoutingTable::new(my_id, [provider]),
        );
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
        let provider_routes = Arc::new(Mutex::new(RoutingTable::new(provider, [])));
        let (provider_snapshot, serving_snapshot) =
            tokio::sync::watch::channel(Some(Arc::new(snapshot)));
        let provider_directory = Arc::new(Mutex::new(providers));
        let provider_health = Health::new(EndpointId::from_bytes(&provider).unwrap());
        let handler = SnapshotHandler {
            snapshot: serving_snapshot,
            health: provider_health.clone(),
            candidates: provider_routes.clone(),
            providers: provider_directory.clone(),
            serve_collections: false,
            local_id: provider,
            recon: None,
        };
        let connections = ConnectionTable::new(server_harness.transport.clone(), handler);
        let server = tokio::spawn(async move {
            while let Some(incoming) = server_harness.incoming.recv().await {
                assert_eq!(incoming.alpn, PILE_SYNC_ALPN);
                connections.accept(incoming.conn);
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
            provider_health,
            blob_reads,
            hash,
            bytes,
            store,
            server,
        }
    }

    fn assert_no_control_effects(&mut self) {
        let snapshot = self.store.snapshot().unwrap();
        assert_eq!(snapshot.records().unwrap().count(), 0);
        assert_eq!(snapshot.wants().unwrap().count(), 0);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// An independent directory or restarted provider using the production RPC
/// handler. Dropping it stops its accept loop. Each restart installs fresh provider-side operational state.
struct RecoveryNode {
    peer: PeerId,
    directory: Arc<Mutex<ProviderDirectory>>,
    server: tokio::task::JoinHandle<()>,
}

impl RecoveryNode {
    fn new(net: &SimNet, key: &SigningKey, snapshot: Option<Arc<StoreSnapshot>>) -> Self {
        let peer = key.verifying_key().to_bytes();
        let mut harness = net.join(key);
        let directory = Arc::new(Mutex::new(ProviderDirectory::new(peer)));
        let handler = SnapshotHandler {
            snapshot: tokio::sync::watch::channel(snapshot).1,
            health: Health::new(EndpointId::from_bytes(&peer).unwrap()),
            candidates: Arc::new(Mutex::new(RoutingTable::new(peer, []))),
            providers: directory.clone(),
            serve_collections: false,
            local_id: peer,
            recon: None,
        };
        let connections = ConnectionTable::new(harness.transport.clone(), handler);
        let server = tokio::spawn(async move {
            while let Some(incoming) = harness.incoming.recv().await {
                assert_eq!(incoming.alpn, PILE_SYNC_ALPN);
                connections.accept(incoming.conn);
            }
        });
        Self {
            peer,
            directory,
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
}

impl Drop for RecoveryNode {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A replica that answers each FIND_VALUE with no routes and fixed hints,
/// after a delay or never. It serves no other request.
struct ScriptedReplica {
    peer: PeerId,
    queries: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl ScriptedReplica {
    fn new(
        net: &SimNet,
        key: &SigningKey,
        hints: Vec<(PeerId, ProviderToken)>,
        delay: Option<Duration>,
    ) -> Self {
        let peer = key.verifying_key().to_bytes();
        let mut harness = net.join(key);
        let queries = Arc::new(AtomicUsize::new(0));
        let counted = queries.clone();
        let server = tokio::spawn(async move {
            while let Some(incoming) = harness.incoming.recv().await {
                let hints = hints.clone();
                let queries = counted.clone();
                tokio::spawn(async move {
                    while let Some((mut send, mut recv)) = incoming.conn.accept_bi().await {
                        let hints = hints.clone();
                        let queries = queries.clone();
                        tokio::spawn(async move {
                            // The dialler's own recon/1 stream carries no request.
                            match recv_u8(&mut recv).await.unwrap() {
                                TAG_RECON => return,
                                tag => assert_eq!(tag, TAG_DHT),
                            }
                            assert_eq!(recv_u8(&mut recv).await.unwrap(), OP_FIND_VALUE);
                            queries.fetch_add(1, Ordering::Relaxed);
                            match delay {
                                Some(delay) => tokio::time::sleep(delay).await,
                                None => std::future::pending::<()>().await,
                            }
                            serve_find_value(&mut recv, &mut send, |_| Vec::new(), |_| hints)
                                .await
                                .unwrap();
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

impl Drop for ScriptedReplica {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl<T: Transport> ProviderClient<T> {
    /// The hints one peer's FIND_VALUE returns for `key`.
    async fn hints(&self, peer: PeerId, key: ProviderKey) -> Vec<(PeerId, ProviderToken)> {
        self.find_value(peer, key).await.unwrap().1
    }
}

#[tokio::test(start_paused = true)]
async fn verified_provider_fetch_does_not_wait_for_a_stalled_lookup_reply() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let slow = ScriptedReplica::new(
        &fixture.net,
        &SigningKey::from_bytes(&[133; 32]),
        Vec::new(),
        None,
    );
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [slow.peer, fixture.provider]);
    for peer in [slow.peer, fixture.provider] {
        fixture.client.connections.connect(peer).await.unwrap();
    }

    let budget = Duration::from_secs(2);
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, budget)
            .await
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
        "a verified provider is usable before unrelated lookup replies complete",
    );
    assert!(started.elapsed() < budget);
    assert_eq!(slow.queries.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn later_lookup_hint_recovers_from_an_unavailable_first_provider() {
    later_lookup_hint_case(false).await;
}

#[tokio::test(start_paused = true)]
async fn later_lookup_hint_recovers_from_a_stalled_first_provider() {
    later_lookup_hint_case(true).await;
}

async fn later_lookup_hint_case(stalled: bool) {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let missing = RecoveryNode::new(&fixture.net, &SigningKey::from_bytes(&[134; 32]), None);
    let first = ScriptedReplica::new(
        &fixture.net,
        &SigningKey::from_bytes(&[135; 32]),
        vec![(
            missing.peer,
            blob_provider_token(fixture.hash, missing.peer),
        )],
        Some(Duration::ZERO),
    );
    let later = ScriptedReplica::new(
        &fixture.net,
        &SigningKey::from_bytes(&[136; 32]),
        vec![(
            fixture.provider,
            blob_provider_token(fixture.hash, fixture.provider),
        )],
        Some(Duration::from_secs(1)),
    );
    for peer in [first.peer, later.peer, fixture.provider] {
        fixture.client.connections.connect(peer).await.unwrap();
    }
    if stalled {
        fixture.net.stall_dials(missing.peer);
    } else {
        fixture
            .client
            .connections
            .connect(missing.peer)
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
            .await
            .map(|blob| blob.bytes),
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
            !fixture.client.connections.peers().contains(&missing.peer),
            "success cancels and releases the unrelated pending provider dial",
        );
    }
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn progressive_fetch_distinguishes_an_empty_lookup_from_an_incomplete_one() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let empty = ScriptedReplica::new(
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
    // A replica whose reply never comes, beside one that answered empty: the
    // lookup window closes on it, and its hints are unknown.
    let stalled = ScriptedReplica::new(
        &fixture.net,
        &SigningKey::from_bytes(&[138; 32]),
        Vec::new(),
        None,
    );
    fixture
        .client
        .connections
        .connect(stalled.peer)
        .await
        .unwrap();
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [empty.peer, stalled.peer]);
    let error = fixture
        .client
        .fetch_blob(fixture.hash, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("DHT provider lookup incomplete"));
    assert_eq!(empty.queries.load(Ordering::Relaxed), 2);
    assert_eq!(stalled.queries.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn progressive_fetch_preserves_unavailable_and_failed_provider_outcomes() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let absent = RecoveryNode::new(&fixture.net, &SigningKey::from_bytes(&[139; 32]), None);
    let directory = ScriptedReplica::new(
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
}

#[tokio::test(start_paused = true)]
async fn progressive_fetch_does_not_dial_an_invalid_provider_hint() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let mut token = blob_provider_token(fixture.hash, fixture.provider);
    token[0] ^= 1;
    let directory = ScriptedReplica::new(
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
    let directory = RecoveryNode::new(&fixture.net, &directory_key, None);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    directory.advertise(fixture.hash, fixture.provider);
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
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
    let serving = fixture.provider_snapshot.borrow().clone();
    let alternate = RecoveryNode::new(&fixture.net, &alternate_key, serving);
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
            .await
            .map(|blob| blob.bytes),
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
            .connections
            .peers()
            .contains(&fixture.provider)
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
    let restarted = RecoveryNode::new(&fixture.net, &provider_key, Some(Arc::new(restored)));
    assert_eq!(restarted.peer, fixture.provider);
    assert_eq!(
        restarted.directory.lock().unwrap().retained_counts(),
        (0, 0)
    );
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
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
}

#[tokio::test(start_paused = true)]
async fn cancelled_discovered_provider_dial_leaves_a_same_client_retry_usable() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let directory_key = SigningKey::from_bytes(&[103; 32]);
    let directory = RecoveryNode::new(&fixture.net, &directory_key, None);
    directory.advertise(fixture.hash, fixture.provider);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    // Warm only the directory, so cancellation lands in the discovered
    // provider's dial rather than the bootstrap lookup.
    fixture
        .client
        .connections
        .connect(directory.peer)
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
    assert_eq!(
        fixture.client.connections.peers(),
        BTreeSet::from([directory.peer])
    );
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    fixture.net.unstall_dials(fixture.provider);
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
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
}

#[tokio::test(start_paused = true)]
async fn alternate_provider_success_cancels_a_stalled_discovered_dial() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let directory_key = SigningKey::from_bytes(&[104; 32]);
    let stalled_key = SigningKey::from_bytes(&[105; 32]);
    let directory = RecoveryNode::new(&fixture.net, &directory_key, None);
    let stalled = stalled_key.verifying_key().to_bytes();
    let _stalled_harness = fixture.net.join(&stalled_key);
    fixture.net.stall_dials(stalled);
    directory.advertise(fixture.hash, stalled);
    directory.advertise(fixture.hash, fixture.provider);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [directory.peer]);
    fixture
        .client
        .connections
        .connect(directory.peer)
        .await
        .unwrap();

    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::from_secs(4));
    assert_eq!(fixture.net.dial_count(fixture.client.my_id, stalled), 1);
    let peers = fixture.client.connections.peers();
    assert!(!peers.contains(&stalled));
    assert_eq!(peers.len(), 2);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
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
    // Larger than SimNet's bounded pipe, so the authenticated server yields
    // during the body. The signalled read gates this crash, not a global
    // receive permit which would also block unrelated transfers.
    let mut fixture = Fixture::with_bytes(false, Bytes::from_source(vec![b'x'; 8 * 1024 * 1024]));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    fixture.provider_snapshot.send_modify(|slot| {
        let snapshot = Arc::get_mut(slot.as_mut().unwrap()).unwrap();
        snapshot.blobs = Arc::new(SignallingBlobReader {
            inner: snapshot.blobs.clone(),
            started: Mutex::new(Some(started_tx)),
        });
    });
    let sender = fixture.sender.clone();
    let hash = fixture.hash;
    let fetch =
        tokio::spawn(async move { sender.fetch_blob(hash, INTERACTIVE_FETCH_DEADLINE).await });
    // get_blob runs after both bearer proofs. The server continues until pipe
    // backpressure yields; no timer or arbitrary scheduler-yield count gates
    // this fault. Receiving may have started, but must not have completed.
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
    let _restarted = RecoveryNode::new(&fixture.net, &provider_key, Some(Arc::new(restored)));
    let failed_at = tokio::time::Instant::now();
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
            .connections
            .peers()
            .contains(&fixture.provider)
    );
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
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
            .await
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
    );
    assert!(started.elapsed() > BACKGROUND_LOOKUP_DEADLINE);
    assert!(started.elapsed() < INTERACTIVE_FETCH_DEADLINE);

    let warmed = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
    );
    assert_eq!(warmed.elapsed(), Duration::ZERO);
    let serving = fixture.provider_health.snapshot().blob_serving.clone();
    assert_eq!(serving.in_flight, 0);
    assert_eq!(
        serving.completed, 2,
        "repeated reads are two operations, not unique coverage"
    );
    assert_eq!(serving.sent_bytes, 2 * fixture.bytes.len() as u64);
    assert_eq!(serving.failed, 0);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn serving_telemetry_counts_live_exchange_but_not_bytes_before_bearer_proof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let conn = fixture
        .client
        .connections
        .connect(fixture.provider)
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send_u8(&mut send, TAG_BLOB).await.unwrap();
    send_hash(&mut send, &blob_locator(fixture.hash))
        .await
        .unwrap();
    assert_eq!(recv_u8(&mut recv).await.unwrap(), 1);
    assert_eq!(
        recv_hash(&mut recv).await.unwrap(),
        crate::bearer::provider_proof(fixture.hash, fixture.client.my_id, fixture.provider)
    );
    let active = fixture.provider_health.snapshot().blob_serving.clone();
    assert_eq!(active.in_flight, 1);
    assert_eq!(active.completed, 0);
    assert_eq!(active.sent_bytes, 0);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
    send_hash(&mut send, &[0; 32]).await.unwrap();
    send.shutdown().await.unwrap();
    let mut response = Vec::new();
    recv.read_to_end(&mut response).await.unwrap();
    assert!(response.is_empty());
    let failed = fixture.provider_health.snapshot().blob_serving.clone();
    assert_eq!(failed.in_flight, 0);
    assert_eq!(failed.failed, 1);
    assert_eq!(failed.completed, 0);
    assert_eq!(failed.sent_bytes, 0);
    assert_eq!(fixture.blob_reads.load(Ordering::Relaxed), 0);
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
            .await
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::from_secs(4));
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
        // Early verified success cancels the remaining lookup; it does not
        // fabricate a routing timeout or demote an unobserved learned peer.
        assert_eq!(
            routes.state(learned),
            Some(crate::routing::RouteState::Verified)
        );
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
        .connections
        .connect(fixture.provider)
        .await
        .unwrap();
    let stalled_key = SigningKey::from_bytes(&[93; 32]);
    let stalled = stalled_key.verifying_key().to_bytes();
    let _stalled_harness = fixture.net.join(&stalled_key);
    fixture.net.stall_dials(stalled);
    // The directory still has old direct-liveness evidence, so its production
    // FIND_VALUE handler re-advertises this unreachable route on every reply.
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
        .connections
        .connect(fixture.provider)
        .await
        .unwrap();
    // The provider is close to this locator, so closer identities are rare:
    // search enough seeds to find three.
    let stale_keys: Vec<_> = (0u64..1 << 16)
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
        ProviderObservation::from_locators(&locators).into_set(),
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
    let advertised = fixture.client.hints(fixture.provider, key).await;
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
        fixture.client.hints(fixture.provider, key).await,
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
        fixture
            .client
            .fetch_blob(fixture.hash, None)
            .await
            .unwrap()
            .map(|blob| blob.bytes),
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
    let snapshot = fixture.provider_snapshot.send_replace(None);
    assert!(fixture.client.hints(fixture.provider, key).await.is_empty());

    fixture.provider_snapshot.send_replace(snapshot);
    assert_eq!(
        fixture.client.hints(fixture.provider, key).await,
        vec![(
            fixture.provider,
            blob_provider_token(fixture.hash, fixture.provider)
        )]
    );
    fixture.provider_snapshot.send_replace(None);
    assert!(fixture.client.hints(fixture.provider, key).await.is_empty());
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
        fixture.client.hints(fixture.provider, key).await,
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
    let mut foreign = (1..=crate::provider::MAX_PROVIDERS_PER_REPLY)
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
    // One uniformly chosen lease makes room for our own hint; the others
    // keep their peer-id order.
    let reply = fixture.client.hints(fixture.provider, key).await;
    assert_eq!(reply.len(), crate::provider::MAX_PROVIDERS_PER_REPLY);
    assert_eq!(reply[0], own);
    assert!(reply[1..].windows(2).all(|pair| pair[0] < pair[1]));
    assert!(reply[1..].iter().all(|lease| foreign.contains(lease)));
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
    let deduplicated = fixture.client.hints(fixture.provider, key).await;
    assert_eq!(deduplicated[0], own);
    assert_eq!(&deduplicated[1..], &foreign[..foreign.len() - 1]);
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
        fixture
            .client
            .fetch_blob(fixture.hash, None)
            .await
            .unwrap()
            .map(|blob| blob.bytes),
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
    fixture
        .provider_snapshot
        .send_replace(Some(Arc::new(snapshot)));

    assert_eq!(
        fixture
            .client
            .hints(fixture.provider, blob_locator(handle.raw))
            .await,
        vec![(
            fixture.provider,
            blob_provider_token(handle.raw, fixture.provider)
        )]
    );
    assert!(
        fixture
            .provider_snapshot
            .borrow()
            .as_ref()
            .unwrap()
            .collection(handle)
            .is_none()
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
    let closer_keys = (0u64..1 << 16)
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
            snapshot: tokio::sync::watch::channel(None).1,
            health: Health::new(EndpointId::from_bytes(&peer).unwrap()),
            candidates: Arc::new(Mutex::new(RoutingTable::new(peer, []))),
            providers: Arc::new(Mutex::new(ProviderDirectory::new(peer))),
            serve_collections: false,
            local_id: peer,
            recon: None,
        };
        let connections = ConnectionTable::new(harness.transport.clone(), handler);
        servers.push(tokio::spawn(async move {
            while let Some(incoming) = harness.incoming.recv().await {
                connections.accept(incoming.conn);
            }
        }));
        fixture.client.connections.connect(peer).await.unwrap();
    }
    *fixture.client.candidates.lock().unwrap() = RoutingTable::new(
        fixture.client.my_id,
        closer.iter().copied().chain([fixture.provider]),
    );
    // The holder is a known, connected, usable directory/provider. Only its
    // exclusion from the exact locator's replica set prevents its use below.
    assert_eq!(
        fixture.client.hints(fixture.provider, key).await,
        vec![(
            fixture.provider,
            blob_provider_token(fixture.hash, fixture.provider)
        )]
    );
    let replicas = fixture.client.lookup(key, None).await.0.replicas();
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
            sender.update_snapshot(serving, &ActiveCollections::new());
            let host = tokio::task::spawn_local(run_host(
                server_harness,
                PeerConfig {
                    peers: vec![EndpointAddr::from(
                        EndpointId::from_bytes(&client_id).unwrap(),
                    )],
                    qos: ReconcileQos::default(),
                    provider_publication_budget: Some(0),
                    bind: None,
                },
                wiring,
            ));
            let client = ProviderClient::for_test(
                client_harness.transport,
                RoutingTable::new(client_id, [server_id]),
            );
            assert_eq!(
                client
                    .fetch_blob(hash, None)
                    .await
                    .unwrap()
                    .map(|blob| blob.bytes),
                Some(bytes)
            );
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(
                net.dial_count(server_id, client_id),
                0,
                "zero budget must not announce even resident hints"
            );
            sender.clear_snapshot();
            assert!(
                client.hints(server_id, blob_locator(hash)).await.is_empty(),
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
    fixture
        .client
        .connections
        .connect(fixture.provider)
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
async fn idle_exact_receive_does_not_block_an_independent_healthy_fetch() {
    use tokio::io::AsyncWriteExt as _;

    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(true);
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let blocked = crate::protocol::recv_exact_blob_body(&mut reader, 1);
    tokio::pin!(blocked);
    // This admitted receive waits indefinitely for its one byte, but retains
    // neither the process scratch buffer nor another receive's progress.
    assert!(futures::poll!(&mut blocked).is_pending());

    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::from_secs(4));
    assert!(futures::poll!(&mut blocked).is_pending());
    assert_eq!(
        fixture
            .client
            .candidates
            .lock()
            .unwrap()
            .state(fixture.provider),
        Some(crate::routing::RouteState::Verified),
        "bootstrap and healthy transfer completed while the other body stalled"
    );

    writer.write_all(b"x").await.unwrap();
    assert_eq!(blocked.await.unwrap().as_ref(), b"x");
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .sender
            .fetch_blob(fixture.hash, INTERACTIVE_FETCH_DEADLINE)
            .await
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn local_receive_saturation_preserves_the_provider_connection() {
    use crate::protocol::ExactBlobReceiveResourceError;

    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(true);
    let mut writers = Vec::new();
    let mut stalled = FuturesUnordered::new();
    // Exercise the fixed sixteen-body admission bound with actual receives,
    // not a mock error injected after the provider operation.
    for _ in 0..16 {
        let (writer, mut reader) = tokio::io::duplex(1);
        writers.push(writer);
        stalled.push(async move { crate::protocol::recv_exact_blob_body(&mut reader, 1).await });
    }
    assert!(futures::poll!(stalled.next()).is_pending());
    let error = fixture
        .client
        .fetch_from_provider(fixture.hash, fixture.provider)
        .await
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<ExactBlobReceiveResourceError>(),
        Some(&ExactBlobReceiveResourceError::BodySlotsExhausted)
    );
    assert!(
        fixture
            .client
            .connections
            .peers()
            .contains(&fixture.provider)
    );
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        1
    );

    drop(stalled);
    drop(writers);
    let started = tokio::time::Instant::now();
    assert_eq!(
        fixture
            .client
            .fetch_from_provider(fixture.hash, fixture.provider)
            .await
            .unwrap()
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone()),
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(
        fixture
            .net
            .dial_count(fixture.client.my_id, fixture.provider),
        1
    );
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn provider_lookup_keeps_only_hints_whose_token_proves_the_identity() {
    let fixture = Fixture::new(false);
    let identity = *blake3::hash(b"provider lookup identity").as_bytes();
    let honest = SigningKey::from_bytes(&[142; 32])
        .verifying_key()
        .to_bytes();
    let forger = SigningKey::from_bytes(&[143; 32])
        .verifying_key()
        .to_bytes();
    let mut forged = blob_provider_token(identity, forger);
    forged[0] ^= 1;
    // Neither a corrupted token nor one valid for another identity proves
    // that the forger knows this one.
    let forgeries = vec![
        (forger, forged),
        (forger, blob_provider_token(fixture.hash, forger)),
    ];
    let mixed = ScriptedReplica::new(
        &fixture.net,
        &SigningKey::from_bytes(&[144; 32]),
        [(honest, blob_provider_token(identity, honest))]
            .into_iter()
            .chain(forgeries.iter().copied())
            .collect(),
        Some(Duration::ZERO),
    );
    let forged_only = ScriptedReplica::new(
        &fixture.net,
        &SigningKey::from_bytes(&[145; 32]),
        forgeries,
        Some(Duration::ZERO),
    );
    for (replica, expected) in [(&mixed, vec![honest]), (&forged_only, Vec::new())] {
        *fixture.client.candidates.lock().unwrap() =
            RoutingTable::new(fixture.client.my_id, [replica.peer]);
        assert_eq!(
            fixture
                .client
                .find_key(blob_locator(identity), blob_provider_token, identity, None)
                .await
                .unwrap(),
            expected,
            "forged hints alone are a plain miss, not a failed lookup"
        );
        assert_eq!(replica.queries.load(Ordering::Relaxed), 1);
    }
    assert_eq!(fixture.net.dial_count(fixture.client.my_id, forger), 0);
}

#[tokio::test(start_paused = true)]
async fn own_directory_answers_once_we_stand_among_the_replicas() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = Fixture::new(false);
    let empty = ScriptedReplica::new(
        &fixture.net,
        &SigningKey::from_bytes(&[146; 32]),
        Vec::new(),
        Some(Duration::ZERO),
    );
    // The provider is no lookup candidate. Only the lease it installed here,
    // as at any other replica of its key, names it.
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [empty.peer]);
    let key = blob_locator(fixture.hash);
    assert!(fixture.client.providers.lock().unwrap().put(
        key,
        fixture.provider,
        blob_provider_token(fixture.hash, fixture.provider),
        crate::clock::mono_now(),
    ));
    assert_eq!(
        fixture
            .client
            .fetch_blob(fixture.hash, None)
            .await
            .unwrap()
            .map(|blob| blob.bytes),
        Some(fixture.bytes.clone())
    );
    assert_eq!(
        fixture
            .client
            .find_key(key, blob_provider_token, fixture.hash, None)
            .await
            .unwrap(),
        [fixture.provider]
    );
    assert_eq!(empty.queries.load(Ordering::Relaxed), 2);
    fixture.assert_no_control_effects();
}
