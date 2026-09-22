//! Collection bootstrap uses authority hints and ordinary descriptor providers.
//!
//! These tests run stock iroh-gossip over Iroh's in-memory packet transport,
//! with endpoint lookup restricted to that transport: no DNS, relay, or external
//! DHT service is involved. The provider directory is our real host protocol.

use std::time::Duration;

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use iroh::Endpoint;
use iroh::endpoint::presets;
use iroh::test_utils::test_transport::TestNetwork;
use iroh_base::EndpointAddr;
use tokio::task::JoinHandle;
use triblespace_core::blob::IntoBlob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionPolicy, CollectionRead,
    CollectionRecord, CollectionStore, CollectionStoreExt, empty_metadata_handle,
};
use triblespace_core::inline::Inline;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreGet, BlobStoreList, BlobStorePut, SnapshotSource, WantRead};
use triblespace_core::trible::TribleSet;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::ReconcileQos;
use triblespace_net::peer::Peer;
use triblespace_net::reconcile::ReplicationMode;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
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
async fn cold_policy_roots_bootstrap_gossip_without_provider_publication_or_configured_peers() {
    let network = TestNetwork::new();
    let source_key = key(0xD1);
    let reader_key = key(0xD2);
    let source_endpoint = endpoint(&network, &source_key).await;
    let reader_endpoint = endpoint(&network, &reader_key).await;
    let source_id = source_endpoint.id();
    let admission = AdmissionPolicy::quorum(
        [source_key.verifying_key(), reader_key.verifying_key()],
        1,
        None,
    )
    .unwrap();
    let policy = CollectionPolicy::new(admission.clone(), admission);
    let mut source_store = MemoryRepo::default();
    let mut reader_store = MemoryRepo::default();
    let collection = source_store
        .collection("cold-root-gossip-bootstrap", policy.clone())
        .unwrap()
        .handle();
    assert_eq!(
        reader_store
            .collection("cold-root-gossip-bootstrap", policy)
            .unwrap()
            .handle(),
        collection
    );
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        &source_key,
        collection,
        CollectionData::new([0xD3; 32]),
        empty_metadata_handle(),
    ));
    source_store.insert(record).unwrap();
    let (mut source, source_owner) =
        bring_up(source_endpoint, source_store, Vec::new(), Some(0)).await;
    let (mut reader, reader_owner) =
        bring_up(reader_endpoint, reader_store, Vec::new(), Some(0)).await;
    source.activate_collection(collection);
    reader.activate_collection(collection);

    drive_until(&mut [&mut source, &mut reader], |peers| {
        contains(peers[1], record)
            && peers[1].health().collections.iter().any(|state| {
                state.collection == collection
                    && state
                        .peers
                        .iter()
                        .any(|peer| peer.peer == *source_id.as_bytes() && peer.comparison.is_some())
            })
    })
    .await;
    assert_eq!(source.health().publication.attempts, 0);
    assert_eq!(reader.health().publication.attempts, 0);
    assert!(reader.health().collections.iter().any(|state| {
        state.collection == collection
            && state
                .peers
                .iter()
                .any(|peer| peer.peer == *source_id.as_bytes() && peer.comparison.is_some())
    }));
    shutdown([(source, source_owner), (reader, reader_owner)]).await;
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
        .collection("descriptor-provider-gossip-bootstrap", policy.clone())
        .unwrap()
        .handle();
    assert_eq!(
        reader_store
            .collection("descriptor-provider-gossip-bootstrap", policy)
            .unwrap()
            .handle(),
        collection
    );
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
    let (mut reader, reader_owner) = bring_up(
        reader_endpoint,
        MemoryRepo::default(),
        vec![directory_addr],
        Some(0),
    )
    .await;
    assert!(
        !reader
            .snapshot()
            .unwrap()
            .contains_blob(collection)
            .unwrap()
    );
    reader.activate_collection(collection);
    drive_until(&mut [&mut directory, &mut cache, &mut reader], |peers| {
        peers[1].health().blob_serving.completed != 0
            && peers[2]
                .snapshot()
                .unwrap()
                .contains_blob(collection)
                .unwrap()
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
            .next()
            .is_none()
    );
    shutdown([
        (directory, directory_owner),
        (cache, cache_owner),
        (reader, reader_owner),
    ])
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_inventory_fetches_late_child_and_grandchild_without_semantic_changes() {
    let network = TestNetwork::new();
    let directory_endpoint = endpoint(&network, &key(0xC1)).await;
    let directory_addr = directory_endpoint.addr();
    let source_key = key(0xC2);
    let source_endpoint = endpoint(&network, &source_key).await;
    let source_id = source_endpoint.id();
    let reader_endpoint = endpoint(&network, &key(0xC3)).await;
    // With no policy-root candidates, the reader must discover the source
    // through its descriptor's ordinary provider directory, then pass READ.
    let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
    let mut source_store = MemoryRepo::default();
    let collection = source_store
        .collection("late-resident-inventory-over-iroh", policy.clone())
        .unwrap()
        .handle();
    let grandchild_bytes = Bytes::from_source(b"late recursive Iroh grandchild".to_vec());
    let grandchild = *blake3::hash(grandchild_bytes.as_ref()).as_bytes();
    let child_bytes = Bytes::from_source(grandchild.to_vec());
    let child = *blake3::hash(child_bytes.as_ref()).as_bytes();
    let mut parent_bytes = child.to_vec();
    let absent: Vec<_> = (0_u64..128)
        .map(|ordinal| *blake3::hash(&ordinal.to_be_bytes()).as_bytes())
        .collect();
    for word in &absent {
        parent_bytes.extend_from_slice(word);
    }
    let parent = source_store
        .put::<UnknownBlob, _>(Bytes::from_source(parent_bytes))
        .unwrap();
    let metadata = source_store
        .put::<SimpleArchive, _>(TribleSet::new().to_blob())
        .unwrap();
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        &source_key,
        collection,
        Inline::new(parent.raw),
        metadata,
    ));
    source_store.insert(record).unwrap();
    let mut reader_store = MemoryRepo::default();
    assert_eq!(
        reader_store
            .collection("late-resident-inventory-over-iroh", policy)
            .unwrap()
            .handle(),
        collection
    );
    // Preload only direct bodies, not the record or its recursive descendants.
    // Later acquisition cannot pass merely by fetching a COMMIT's direct roots.
    for handle in [parent.raw, metadata.raw] {
        let bytes = BlobStoreGet::get::<Bytes, UnknownBlob>(
            &source_store.snapshot().unwrap(),
            Inline::new(handle),
        )
        .unwrap();
        reader_store.put::<UnknownBlob, _>(bytes).unwrap();
    }
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
        let publication = &peers[1].health().publication;
        publication.acknowledged != 0
            && publication.startup_pending == 0
            && publication.in_flight == 0
    })
    .await;
    let (mut reader, reader_owner) =
        bring_up(reader_endpoint, reader_store, vec![directory_addr], Some(0)).await;
    reader.activate_collection(collection);
    reader.set_replication(ReplicationMode::Full, [collection]);
    let frontier = |peer: &Peer<MemoryRepo>| {
        peer.health()
            .collections
            .iter()
            .find(|state| state.collection == collection)
            .and_then(|state| state.local_frontier)
            .expect("active collection must expose its serving frontier")
    };
    drive_until(&mut [&mut directory, &mut source, &mut reader], |peers| {
        contains(peers[2], record)
            && frontier(peers[1]) == frontier(peers[2])
            && peers[2].health().collections.iter().any(|state| {
                state.collection == collection
                    && state
                        .peers
                        .iter()
                        .any(|peer| peer.peer == *source_id.as_bytes() && peer.comparison.is_some())
            })
    })
    .await;
    let initial = frontier(&source);
    let first = reader.reconcile().await;
    assert_eq!(first.landed, 0);
    assert_eq!(first.replication.pending, 0);
    assert_eq!(first.replication.speculative_attempted, 0);
    assert_eq!(first.replication.speculative_misses, 0);
    assert_eq!(first.replication.candidates, 0);
    for handle in [child, grandchild] {
        assert!(source.try_local(handle).is_none());
        assert!(reader.try_local(handle).is_none());
    }
    assert!(
        absent
            .iter()
            .all(|handle| source.try_local(*handle).is_none())
    );

    let mut last_root = initial.wake_root;
    for (bytes, expected) in [(child_bytes, child), (grandchild_bytes, grandchild)] {
        let acknowledged_before = source.health().publication.acknowledged;
        let served_before = source.health().blob_serving.completed;
        assert_eq!(
            source
                .store()
                .put::<UnknownBlob, _>(bytes.clone())
                .unwrap()
                .raw,
            expected
        );
        source.refresh();
        // Publication is a positive control, not inferred from a local put.
        // Neither endpoint gains a new record or AUTH proof during this stage.
        drive_until(&mut [&mut directory, &mut source, &mut reader], |peers| {
            let health = peers[1].health();
            let publication = &health.publication;
            frontier(peers[1]).wake_root != last_root
                && publication.acknowledged > acknowledged_before
                && publication.startup_pending == 0
                && publication.incremental_pending == 0
                && publication.in_flight == 0
        })
        .await;
        let observed = frontier(&source);
        assert_eq!(observed.records, initial.records);
        assert_eq!(
            observed.authorization_evidence,
            initial.authorization_evidence
        );
        assert_ne!(observed.wake_root, last_root);
        last_root = observed.wake_root;

        let (offered, landed) = tokio::time::timeout(Duration::from_secs(20), async {
            let mut offered = 0;
            let mut landed = 0;
            loop {
                for peer in [&mut directory, &mut source, &mut reader] {
                    peer.refresh();
                }
                let stats = reader.reconcile().await;
                assert_eq!(stats.replication.pending, 0);
                assert_eq!(stats.replication.speculative_attempted, 0);
                assert_eq!(stats.replication.speculative_misses, 0);
                assert_eq!(stats.replication.candidates, 0);
                assert_eq!(stats.replication.filtered, 0);
                offered += stats.replication.inventory;
                landed += stats.landed;
                if reader.try_local(expected).is_some() {
                    break (offered, landed);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("blob-only inventory growth did not hydrate its descendant within 20 seconds");
        assert!(
            offered > 0,
            "READ repair must provide positive inventory hints"
        );
        assert!(landed > 0, "the reader must land a real network payload");
        assert_eq!(reader.try_local(expected).unwrap().as_ref(), bytes.as_ref());
        assert!(source.health().blob_serving.completed > served_before);
        assert_eq!(frontier(&reader).records, initial.records);
        assert_eq!(
            frontier(&reader).authorization_evidence,
            initial.authorization_evidence
        );
        if expected == child {
            assert!(reader.try_local(grandchild).is_none());
        }
    }
    assert!(
        absent
            .iter()
            .all(|handle| reader.try_local(*handle).is_none())
    );
    let snapshot = reader.snapshot().unwrap();
    assert_eq!(
        snapshot
            .records()
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>(),
        [record]
    );
    assert_eq!(snapshot.wants().unwrap().count(), 0);
    assert!(directory.health().collections.is_empty());
    assert!(
        !directory
            .snapshot()
            .unwrap()
            .contains_blob(collection)
            .unwrap()
    );
    shutdown([
        (directory, directory_owner),
        (source, source_owner),
        (reader, reader_owner),
    ])
    .await;
}
