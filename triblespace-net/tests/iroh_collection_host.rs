//! Real-Iroh collection wake and repair coverage.

use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use iroh::Endpoint;
use iroh::endpoint::presets;
use iroh::test_utils::test_transport::{TestNetwork, TestTransport};
use iroh_base::{EndpointAddr, SecretKey};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionPolicy, CollectionRead,
    CollectionRecord, CollectionStore, CollectionStoreExt, empty_metadata_handle,
};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreList, BlobStorePut, SnapshotSource, WantRead};
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::ReconcileQos;
use triblespace_net::peer::Peer;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
    });
}

fn restart_health(phase: &str, peers: &[(&str, &Peer<MemoryRepo>)]) {
    for (name, peer) in peers {
        let health = peer.health();
        eprintln!(
            "restart health {phase}: {name} node={} started={:?} observed={:?} serving={} published={:?}",
            health.node,
            health.started_at,
            health.observed_at,
            health.store.serving_snapshot,
            health.store.last_snapshot_published_at,
        );
        for collection in &health.collections {
            eprintln!(
                "  C={} local_root={:?} local_change={:?}",
                hex::encode(collection.collection.raw),
                collection
                    .local_frontier
                    .map(|frontier| hex::encode(frontier.wake_root)),
                collection.last_local_change_at,
            );
            for remote in &collection.peers {
                eprintln!(
                    "    peer={} in_flight={} first_started={:?} started={:?} completed={:?} failure_at={:?} failure={:?} progress={:?} remote_change={:?} comparison={:?}",
                    hex::encode(remote.peer),
                    remote.in_flight,
                    remote.first_started_at,
                    remote.last_started_at,
                    remote.last_completed_at,
                    remote.last_failure_at,
                    remote.last_failure,
                    remote.last_progress_at,
                    remote.last_remote_change_at,
                    remote.comparison.map(|comparison| (
                        comparison.observed_at,
                        hex::encode(comparison.local.wake_root),
                        hex::encode(comparison.remote.wake_root),
                        comparison.records_received,
                        comparison.proofs_received,
                        comparison.more,
                    )),
                );
            }
        }
    }
}

async fn test_endpoint(network: &TestNetwork, secret: SecretKey) -> Endpoint {
    let transport = network
        .create_transport(secret.public())
        .expect("create test transport");
    test_endpoint_on_transport(network, secret, transport).await
}

async fn test_endpoint_on_transport(
    network: &TestNetwork,
    secret: SecretKey,
    transport: Arc<TestTransport>,
) -> Endpoint {
    Endpoint::builder(presets::N0)
        .secret_key(secret)
        .relay_mode(iroh::RelayMode::Disabled)
        .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
        .add_custom_transport(transport)
        .clear_ip_transports()
        .clear_address_lookup()
        .address_lookup(network.address_lookup())
        .bind()
        .await
        .expect("bind test endpoint")
}

async fn bring_up(
    endpoint: Endpoint,
    store: MemoryRepo,
    peers: Vec<EndpointAddr>,
) -> Peer<MemoryRepo> {
    bring_up_owned(endpoint, store, peers).await.0
}

async fn bring_up_owned(
    endpoint: Endpoint,
    store: MemoryRepo,
    peers: Vec<EndpointAddr>,
) -> (Peer<MemoryRepo>, tokio::task::JoinHandle<()>) {
    let id = endpoint.id();
    let config = PeerConfig {
        peers,
        qos: ReconcileQos::default(),
        provider_publication_budget: None,
    };
    let harness = triblespace_net::transport::iroh::bind_with_endpoint(endpoint, &config).await;
    let (sender, receiver, wiring) = host::wire(id);
    let owner = tokio::spawn(host::run_host(harness, config, wiring));
    (
        Peer::with_wiring(store, ReconcileQos::default(), sender, receiver),
        owner,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_collection_wake_repairs_before_periodic_fallback() {
    init_tracing();
    let network = TestNetwork::new();
    let server_key = key(0xA1);
    let reader_key = key(0xB1);
    let server_endpoint = test_endpoint(
        &network,
        triblespace_net::identity::iroh_secret(&server_key),
    )
    .await;
    let reader_endpoint = test_endpoint(
        &network,
        triblespace_net::identity::iroh_secret(&reader_key),
    )
    .await;
    let server_addr = server_endpoint.addr();

    let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
    let mut server_store = MemoryRepo::default();
    let collection = server_store
        .collection("real-iroh-collection-wake", policy.clone())
        .unwrap();
    let mut reader_store = MemoryRepo::default();
    let reader_collection = reader_store
        .collection("real-iroh-collection-wake", policy)
        .unwrap();
    assert_eq!(reader_collection.handle(), collection.handle());

    let mut server = bring_up(server_endpoint, server_store, Vec::new()).await;
    let mut reader = bring_up(reader_endpoint, reader_store, vec![server_addr]).await;
    server.activate_collection(collection.handle());
    reader.activate_collection(collection.handle());

    // Let initial empty repair and the exact-handle gossip subscriptions settle.
    tokio::time::sleep(Duration::from_secs(2)).await;
    server.refresh();
    reader.refresh();

    server
        .store()
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &server_key,
            collection.handle(),
            CollectionData::new([0xC7; 32]),
            empty_metadata_handle(),
        )))
        .unwrap();
    server.refresh();

    let started = Instant::now();
    let repaired = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            reader.refresh();
            if reader
                .snapshot()
                .unwrap()
                .records()
                .unwrap()
                .next()
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        repaired.is_ok(),
        "signed wake did not trigger collection repair"
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "repair must precede the 30-second periodic fallback"
    );

    drop((server.into_store(), reader.into_store()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_root_fresh_records_survive_coalesced_refresh() {
    three_root_current_state_scenario(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_root_fresh_records_survive_same_key_restart() {
    three_root_current_state_scenario(true).await;
}

async fn three_root_current_state_scenario(restart: bool) {
    init_tracing();
    let network = TestNetwork::new();
    let source_key = key(0xA3);
    let reader_key = key(0xB3);
    let other_key = key(0xC3);
    let source_secret = triblespace_net::identity::iroh_secret(&source_key);
    // Retain the transport because TestNetwork registers an endpoint ID once.
    // A restarted endpoint uses the same address and key, not a fourth root.
    let source_transport = network.create_transport(source_secret.public()).unwrap();
    let source_endpoint =
        test_endpoint_on_transport(&network, source_secret.clone(), source_transport.clone()).await;
    let reader_endpoint = test_endpoint(
        &network,
        triblespace_net::identity::iroh_secret(&reader_key),
    )
    .await;
    let other_endpoint =
        test_endpoint(&network, triblespace_net::identity::iroh_secret(&other_key)).await;
    let source_addr = source_endpoint.addr();
    let reader_addr = reader_endpoint.addr();
    let other_addr = other_endpoint.addr();
    let admission = AdmissionPolicy::quorum(
        [
            source_key.verifying_key(),
            reader_key.verifying_key(),
            other_key.verifying_key(),
        ],
        1,
        None,
    )
    .unwrap();
    let policy = CollectionPolicy::new(admission.clone(), admission);
    let mut source_store = MemoryRepo::default();
    let collection = source_store
        .collection("real-iroh-three-root-current-state", policy.clone())
        .unwrap()
        .handle();
    let mut reader_store = MemoryRepo::default();
    let mut other_store = MemoryRepo::default();
    for store in [&mut reader_store, &mut other_store] {
        assert_eq!(
            store
                .collection("real-iroh-three-root-current-state", policy.clone())
                .unwrap()
                .handle(),
            collection
        );
    }
    let (mut source, source_owner) = bring_up_owned(
        source_endpoint.clone(),
        source_store,
        vec![reader_addr.clone(), other_addr.clone()],
    )
    .await;
    let mut reader = bring_up(
        reader_endpoint,
        reader_store,
        vec![source_addr.clone(), other_addr.clone()],
    )
    .await;
    let mut other = bring_up(
        other_endpoint,
        other_store,
        vec![source_addr, reader_addr.clone()],
    )
    .await;
    for peer in [&mut source, &mut reader, &mut other] {
        peer.activate_collection(collection);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check both directions, not only that the source can receive. No payload
    // reads or derived-view maintenance can substitute for these exact records.
    let control = CollectionRecord::Commit(CollectionCommit::sign(
        &reader_key,
        collection,
        CollectionData::new(*blake3::hash(b"reader-to-source control").as_bytes()),
        empty_metadata_handle(),
    ));
    reader.store().insert(control).unwrap();
    reader.refresh();
    let mut expected = vec![control];

    for wave in 0..3 {
        for index in 0..16 {
            let payload =
                Bytes::from_source(format!("source wave {wave}, record {index}").into_bytes());
            let data = source.store().put::<UnknownBlob, _>(payload).unwrap();
            let record = CollectionRecord::Commit(CollectionCommit::sign(
                &source_key,
                collection,
                CollectionData::new(data.raw),
                empty_metadata_handle(),
            ));
            source.store().insert(record).unwrap();
            expected.push(record);
            // Publish successive observations without yielding here: only the
            // newest need be processed, but it must contain every prior COMMIT.
            source.refresh();
            source.refresh();
        }
        let repaired = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let mut complete = true;
                for peer in [&mut source, &mut reader, &mut other] {
                    peer.refresh();
                    let snapshot = peer.snapshot().unwrap();
                    let records = snapshot
                        .records()
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    complete &= expected.iter().all(|record| records.contains(record));
                }
                if complete {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            repaired.is_ok(),
            "fresh three-root records did not reach every peer in wave {wave}"
        );
    }

    if !restart {
        drop((source.into_store(), reader.into_store(), other.into_store()));
        tokio::time::timeout(Duration::from_secs(10), source_owner)
            .await
            .expect("source owner did not shut down")
            .expect("source owner panicked");
        return;
    }

    restart_health(
        "before restart",
        &[("source", &source), ("reader", &reader), ("other", &other)],
    );
    let source_store = source.into_store();
    // Await the owner that shuts down the router and endpoint. Calling close
    // ourselves could race its close: Iroh returns early when already closing,
    // before the old custom-transport receiver has necessarily stopped.
    tokio::time::timeout(Duration::from_secs(10), source_owner)
        .await
        .expect("source owner did not shut down before restart")
        .expect("source owner panicked");
    assert!(source_endpoint.is_closed());
    drop(source_endpoint);
    let restarted_endpoint =
        test_endpoint_on_transport(&network, source_secret, source_transport).await;
    let (mut source, restarted_owner) = bring_up_owned(
        restarted_endpoint,
        source_store,
        vec![reader_addr, other_addr],
    )
    .await;
    source.activate_collection(collection);
    let after_restart = CollectionRecord::Commit(CollectionCommit::sign(
        &source_key,
        collection,
        CollectionData::new(*blake3::hash(b"fresh after same-key source restart").as_bytes()),
        empty_metadata_handle(),
    ));
    source.store().insert(after_restart).unwrap();
    source.refresh();
    source.refresh();
    expected.push(after_restart);
    let restarted_at = Instant::now();
    let mut diagnostic_index = 0;
    let diagnostic_thresholds = [1, 31];
    let repaired = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            source.refresh();
            let mut complete = true;
            for peer in [&mut reader, &mut other] {
                peer.refresh();
                let snapshot = peer.snapshot().unwrap();
                let records = snapshot
                    .records()
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                complete &= expected.iter().all(|record| records.contains(record));
            }
            if diagnostic_index < diagnostic_thresholds.len()
                && restarted_at.elapsed()
                    >= Duration::from_secs(diagnostic_thresholds[diagnostic_index])
            {
                restart_health(
                    &format!(
                        "after restart +{:.3}s",
                        restarted_at.elapsed().as_secs_f64()
                    ),
                    &[("source", &source), ("reader", &reader), ("other", &other)],
                );
                diagnostic_index += 1;
            }
            if complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if repaired.is_err() {
        restart_health(
            &format!(
                "restart timeout +{:.3}s",
                restarted_at.elapsed().as_secs_f64()
            ),
            &[("source", &source), ("reader", &reader), ("other", &other)],
        );
    }
    assert!(
        repaired.is_ok(),
        "readers did not receive the fresh record after same-key restart"
    );
    drop((source.into_store(), reader.into_store(), other.into_store()));
    tokio::time::timeout(Duration::from_secs(10), restarted_owner)
        .await
        .expect("restarted source owner did not shut down")
        .expect("restarted source owner panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_acquisition_finds_a_provider_through_a_directory_without_wants() {
    let network = TestNetwork::new();
    let directory_endpoint =
        test_endpoint(&network, triblespace_net::identity::iroh_secret(&key(0xA2))).await;
    let directory_addr = directory_endpoint.addr();
    let server_endpoint =
        test_endpoint(&network, triblespace_net::identity::iroh_secret(&key(0xB2))).await;
    let reader_endpoint =
        test_endpoint(&network, triblespace_net::identity::iroh_secret(&key(0xC2))).await;

    let mut server_store = MemoryRepo::default();
    let payload = Bytes::from_source(b"selected foreground attachment".to_vec());
    let selected = server_store.put::<UnknownBlob, _>(payload.clone()).unwrap();
    let unrelated = server_store
        .put::<UnknownBlob, _>(Bytes::from_source(b"unselected attachment".to_vec()))
        .unwrap();
    let mut directory = bring_up(directory_endpoint, MemoryRepo::default(), Vec::new()).await;
    let mut server = bring_up(server_endpoint, server_store, vec![directory_addr.clone()]).await;
    // This process knows only the directory, not the provider. None of these
    // peers activates a collection: H acquisition is independent of repair.
    let mut reader = bring_up(reader_endpoint, MemoryRepo::default(), vec![directory_addr]).await;
    let before = reader.snapshot().unwrap();
    directory.refresh();
    server.refresh();
    reader.refresh();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let acquired: Bytes = before.get(selected).await.expect("DHT-located payload");
    assert_eq!(acquired.as_ref(), payload.as_ref());
    let after = reader.snapshot().unwrap();
    assert!(!before.contains_blob(selected).unwrap());
    assert!(after.contains_blob(selected).unwrap());
    assert!(!after.contains_blob(unrelated).unwrap());
    assert!(after.wants().unwrap().next().is_none());
    assert!(after.records().unwrap().next().is_none());
    assert!(
        !directory
            .snapshot()
            .unwrap()
            .contains_blob(selected)
            .unwrap()
    );

    // A subsequent acquisition is local even after the provider is gone.
    drop(server.into_store());
    let cached = reader.acquire(selected).await.unwrap().unwrap();
    assert_eq!(cached.as_ref(), payload.as_ref());
    let bytes: Bytes = after.get(selected).await.unwrap();
    assert_eq!(bytes.as_ref(), payload.as_ref());
    drop((directory.into_store(), reader.into_store()));
}
