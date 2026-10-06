//! Collection bootstrap through ordinary descriptor providers in the DHT.
//!
//! These tests run over Iroh's in-memory packet transport, with endpoint
//! lookup restricted to that transport: no DNS, relay, or external DHT service
//! is involved. The provider directory is our real host protocol, and every
//! peer the reader finds, it finds through a FIND_VALUE lookup: DHT providers
//! are the last tier of a collection's peering candidates.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::Endpoint;
use iroh::endpoint::presets;
use iroh::test_utils::test_transport::TestNetwork;
use iroh_base::EndpointAddr;
use tokio::task::JoinHandle;
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt, empty_metadata_handle,
    private_policy,
};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreList, SnapshotSource};
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::ReconcileQos;
use triblespace_net::peer::Peer;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

/// Select `collection` for sync in the pile `key` configures.
fn select(store: &mut MemoryRepo, key: &SigningKey, collection: CollectionHandle) {
    let config = store
        .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
        .unwrap();
    write_sync_selection(store, config, key, collection, true).unwrap();
}

async fn endpoint(network: &TestNetwork, key: &SigningKey) -> Endpoint {
    let secret = triblespace_net::identity::iroh_secret(key);
    let transport = network.create_transport(secret.public()).unwrap();
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
        .unwrap()
}

async fn bring_up(
    endpoint: Endpoint,
    store: MemoryRepo,
    peers: Vec<EndpointAddr>,
    provider_publication_budget: Option<u64>,
) -> (Peer<MemoryRepo>, JoinHandle<()>) {
    let id = endpoint.id();
    let qos = ReconcileQos::default();
    let config = PeerConfig {
        peers,
        qos,
        provider_publication_budget,
        bind: None,
    };
    let harness = triblespace_net::transport::iroh::bind_with_endpoint(endpoint, &config).await;
    let (sender, receiver, wiring) = host::wire(id);
    let owner = tokio::spawn(host::run_host(harness, config, wiring));
    (Peer::with_wiring(store, qos, sender, receiver), owner)
}

fn contains(peer: &mut Peer<MemoryRepo>, expected: CollectionRecord) -> bool {
    peer.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .any(|record| record.unwrap() == expected)
}

async fn drive_until(
    peers: &mut [&mut Peer<MemoryRepo>],
    predicate: impl Fn(&mut [&mut Peer<MemoryRepo>]) -> bool,
) {
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            for peer in peers.iter_mut() {
                peer.refresh();
            }
            if predicate(peers) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    if result.is_err() {
        for peer in peers {
            eprintln!("discovery timeout: {:#?}", peer.health());
        }
        panic!("collection discovery did not satisfy its positive control within 15 seconds");
    }
}

async fn shutdown<const N: usize>(nodes: [(Peer<MemoryRepo>, JoinHandle<()>); N]) {
    for (peer, owner) in nodes {
        drop(peer.into_store());
        tokio::time::timeout(Duration::from_secs(10), owner)
            .await
            .expect("host did not shut down")
            .expect("host panicked");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn descriptor_provider_bootstraps_open_collection_through_directory_only() {
    let network = TestNetwork::new();
    let directory_endpoint = endpoint(&network, &key(0xE1)).await;
    let directory_addr = directory_endpoint.addr();
    let source_key = key(0xE2);
    let source_endpoint = endpoint(&network, &source_key).await;
    let source_id = source_endpoint.id();
    let reader_endpoint = endpoint(&network, &key(0xE3)).await;
    // Open policies deliberately provide no root/AUTH endpoint candidates.
    let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
    let mut source_store = MemoryRepo::default();
    let mut reader_store = MemoryRepo::default();
    let collection = source_store
        .collection("descriptor-provider-bootstrap", policy.clone())
        .unwrap()
        .handle();
    assert_eq!(
        reader_store
            .collection("descriptor-provider-bootstrap", policy)
            .unwrap()
            .handle(),
        collection
    );
    // Both select C, so the reader asks the source it finds to peer for it.
    select(&mut source_store, &source_key, collection);
    select(&mut reader_store, &key(0xE3), collection);
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        &source_key,
        collection,
        CollectionData::new([0xE4; 32]),
        empty_metadata_handle(),
    ));
    source_store.insert(record).unwrap();
    let (mut directory, directory_owner) = bring_up(
        directory_endpoint,
        MemoryRepo::default(),
        Vec::new(),
        Some(0),
    )
    .await;
    let (mut source, source_owner) = bring_up(
        source_endpoint,
        source_store,
        vec![directory_addr.clone()],
        None,
    )
    .await;
    source.activate_collection(collection);
    drive_until(&mut [&mut directory, &mut source], |peers| {
        let health = peers[1].health();
        health.publication.acknowledged != 0
            && health.publication.startup_pending == 0
            && health.publication.in_flight == 0
    })
    .await;
    // Reader knows only the directory. The directory neither activates C nor
    // holds its descriptor, and the source does not know the reader endpoint.
    let (mut reader, reader_owner) =
        bring_up(reader_endpoint, reader_store, vec![directory_addr], Some(0)).await;
    reader.activate_collection(collection);
    drive_until(&mut [&mut directory, &mut source, &mut reader], |peers| {
        contains(peers[2], record)
            && peers[2].health().collections.iter().any(|state| {
                state.collection == collection
                    && state
                        .peers
                        .iter()
                        .any(|peer| peer.peer == *source_id.as_bytes() && peer.comparison.is_some())
            })
    })
    .await;
    assert!(
        !directory
            .snapshot()
            .unwrap()
            .contains_blob(collection)
            .unwrap()
    );
    assert!(directory.health().collections.is_empty());
    assert!(reader.health().collections.iter().any(|state| {
        state.collection == collection
            && state
                .peers
                .iter()
                .any(|peer| peer.peer == *source_id.as_bytes() && peer.comparison.is_some())
    }));
    shutdown([
        (directory, directory_owner),
        (source, source_owner),
        (reader, reader_owner),
    ])
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inactive_descriptor_cache_is_discoverable_but_never_a_repair_participant() {
    let network = TestNetwork::new();
    let directory_endpoint = endpoint(&network, &key(0xF1)).await;
    let directory_addr = directory_endpoint.addr();
    let cache_endpoint = endpoint(&network, &key(0xF2)).await;
    let cache_id = cache_endpoint.id();
    let reader_endpoint = endpoint(&network, &key(0xF3)).await;
    let mut reader_store = MemoryRepo::default();
    let mut cache_store = MemoryRepo::default();
    let collection = cache_store
        .collection(
            "inactive-descriptor-cache",
            CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
        )
        .unwrap()
        .handle();
    let (mut directory, directory_owner) = bring_up(
        directory_endpoint,
        MemoryRepo::default(),
        Vec::new(),
        Some(0),
    )
    .await;
    let (mut cache, cache_owner) = bring_up(
        cache_endpoint,
        cache_store,
        vec![directory_addr.clone()],
        None,
    )
    .await;
    // Resident blobs advertise normally without any active collection.
    cache.refresh();
    drive_until(&mut [&mut directory, &mut cache], |peers| {
        let health = peers[1].health();
        health.publication.acknowledged != 0
            && health.publication.startup_pending == 0
            && health.publication.in_flight == 0
    })
    .await;
    // The reader selects C, so it asks the cache it finds as a provider of
    // C to peer; the cache does not select C.
    select(&mut reader_store, &key(0xF3), collection);
    let (mut reader, reader_owner) =
        bring_up(reader_endpoint, reader_store, vec![directory_addr], Some(0)).await;
    assert!(
        !reader
            .snapshot()
            .unwrap()
            .contains_blob(collection)
            .unwrap()
    );
    // Activate after the empty host's first periodic turn, not in a startup
    // race that accidentally includes C in that turn. Cold activation must
    // acquire its descriptor promptly without waiting for the 30-second retry.
    drive_until(&mut [&mut reader], |peers| {
        let health = peers[0].health();
        health
            .started_at
            .zip(health.observed_at)
            .is_some_and(|(started, observed)| observed > started)
    })
    .await;
    reader.activate_collection(collection);
    drive_until(&mut [&mut directory, &mut cache, &mut reader], |peers| {
        peers[1].health().blob_serving.completed != 0
            && peers[2]
                .snapshot()
                .unwrap()
                .contains_blob(collection)
                .unwrap()
            && peers[2]
                .health()
                .peerings
                .iter()
                .any(|peering| peering.peer == *cache_id.as_bytes() && peering.refused_by_them)
    })
    .await;
    assert!(
        cache.health().blob_serving.completed != 0,
        "positive control: the inactive cache really supplied descriptor bytes"
    );
    // Observe multiple host turns after real discovery, rather than asserting
    // absence before the directory lookup could have happened. No collection
    // repair health entry means no failed/in-flight/completed repair against
    // this descriptor-only endpoint; this is not a general log-volume test.
    let until = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < until {
        for peer in [&mut directory, &mut cache, &mut reader] {
            peer.refresh();
        }
        assert!(cache.health().collections.is_empty());
        assert!(
            reader
                .health()
                .peerings
                .iter()
                .all(|peering| !peering.peered)
        );
        assert!(reader.health().collections.iter().all(|state| {
            state
                .peers
                .iter()
                .all(|peer| peer.peer != *cache_id.as_bytes())
        }));
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        reader
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .all(|record| record.unwrap().collection() != collection)
    );
    shutdown([
        (directory, directory_owner),
        (cache, cache_owner),
        (reader, reader_owner),
    ])
    .await;
}
