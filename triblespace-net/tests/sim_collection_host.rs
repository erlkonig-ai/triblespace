//! End-to-end collection-host cutover coverage over deterministic transport.
#![cfg(feature = "sim")]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, OnceLock};

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use triblespace_core::attribute::Attribute;
use triblespace_core::blob::IntoBlob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::locator::blob_locator;
use triblespace_core::capability::{CapabilityHandle, CapabilityProof, CapabilityResource};
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::reference_summary::{
    ReferenceSummaryBlob, ReferenceSummaryLayout, ReferenceSummaryView,
};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionCommit, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionSnapshotExt, CollectionStore, CollectionStoreExt,
    read_capability, write_capability,
};
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::macros::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreGet, BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore,
    SnapshotSource, StorageFlush, WantRead, WantRequest, WantStore,
};
use triblespace_core::trible::TribleSet;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::{ReconcileDirection, ReconcileQos};
use triblespace_net::peer::Peer;
use triblespace_net::reconcile::{
    RECONCILE_SPECULATIVE_FETCHES_PER_TICK, ReconcileStats, Reconciler, ReplicationMode,
};
use triblespace_net::transport::sim::{SimConfig, SimNet};

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn virtual_clock() -> Arc<VirtualClock> {
    static CLOCK: OnceLock<Arc<VirtualClock>> = OnceLock::new();
    CLOCK
        .get_or_init(|| {
            let clock =
                VirtualClock::new(hifitime::Epoch::from_gregorian_utc_at_midnight(2026, 1, 1));
            clock::install_virtual(clock.clone()).expect("first virtual-clock install");
            clock
        })
        .clone()
}

fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn proof(
    root: &SigningKey,
    leaf: &SigningKey,
    action: CapabilityHandle,
    collection: CollectionHandle,
) -> CapabilityProof {
    CapabilityProof::new(
        CapabilityResource::from(collection),
        root,
        action,
        leaf.verifying_key(),
    )
}

fn register(store: &mut MemoryRepo, policy: CollectionPolicy) -> Collection<SimpleArchive> {
    store.collection("collection-host-e2e", policy).unwrap()
}

fn bring_up(
    net: &SimNet,
    endpoint: &SigningKey,
    store: MemoryRepo,
    peers: Vec<[u8; 32]>,
    direction: ReconcileDirection,
) -> Peer<MemoryRepo> {
    bring_up_with_publication_budget(net, endpoint, store, peers, direction, None)
}

fn bring_up_with_publication_budget(
    net: &SimNet,
    endpoint: &SigningKey,
    store: MemoryRepo,
    peers: Vec<[u8; 32]>,
    direction: ReconcileDirection,
    provider_publication_budget: Option<u64>,
) -> Peer<MemoryRepo> {
    let id = endpoint.verifying_key().to_bytes();
    let harness = net.join(endpoint);
    let (sender, receiver, wiring) =
        host::wire(EndpointId::from_bytes(&id).expect("valid endpoint id"));
    let qos = ReconcileQos { direction };
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            peers: peers
                .into_iter()
                .map(|peer| {
                    iroh_base::EndpointAddr::from(
                        EndpointId::from_bytes(&peer).expect("valid configured peer"),
                    )
                })
                .collect(),
            qos,
            provider_publication_budget,
        },
        wiring,
    ));
    Peer::with_wiring(store, qos, sender, receiver)
}

async fn advance(clock: &Arc<VirtualClock>, peers: &mut [&mut Peer<MemoryRepo>], seconds: u64) {
    for _ in 0..seconds * 10 {
        SimNet::step(clock, std::time::Duration::from_millis(100)).await;
        for peer in peers.iter_mut() {
            peer.refresh();
        }
    }
}

async fn reconcile_once(
    clock: &Arc<VirtualClock>,
    reconciler: &mut Reconciler,
    peer: &mut Peer<MemoryRepo>,
    others: &mut [&mut Peer<MemoryRepo>],
) -> ReconcileStats {
    let mut tick = Box::pin(reconciler.tick(peer));
    loop {
        tokio::select! {
            stats = &mut tick => break stats,
            () = SimNet::step(clock, std::time::Duration::from_millis(100)) => {
                for other in others.iter_mut() {
                    other.refresh();
                }
            }
        }
    }
}

async fn acquire_once(
    clock: &Arc<VirtualClock>,
    peer: &mut Peer<MemoryRepo>,
    handle: Inline<Handle<UnknownBlob>>,
    others: &mut [&mut Peer<MemoryRepo>],
) -> Option<Bytes> {
    let mut acquire = Box::pin(peer.acquire(handle));
    loop {
        tokio::select! {
            result = &mut acquire => break result.unwrap(),
            () = SimNet::step(clock, std::time::Duration::from_millis(100)) => {
                for other in others.iter_mut() {
                    other.refresh();
                }
            }
        }
    }
}

#[test]
fn issuer_held_read_proof_bootstraps_a_handle_only_recipient() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC70, SimConfig::default());
        let issuer_key = key(71);
        let recipient_key = key(72);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(issuer_key.verifying_key()),
            AdmissionPolicy::direct(issuer_key.verifying_key()),
        );

        let mut issuer_store = MemoryRepo::default();
        let collection = register(&mut issuer_store, policy);
        let read_proof = proof(
            &issuer_key,
            &recipient_key,
            read_capability(),
            collection.handle(),
        );
        issuer_store.insert_proof(read_proof.clone()).unwrap();
        let payload_facts = entity! {
            triblespace_core::metadata::tag: triblespace_core::metadata::KIND_MULTI,
        }
        .facts()
        .clone();
        let payload_handle = issuer_store
            .put::<SimpleArchive, _>(payload_facts.clone())
            .unwrap();
        issuer_store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &issuer_key,
                collection.handle(),
                Handle::<SimpleArchive>::to_hash(payload_handle),
                payload_handle,
            )))
            .unwrap();
        let issuer_id = issuer_key.verifying_key().to_bytes();
        let mut issuer = bring_up(
            &net,
            &issuer_key,
            issuer_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
        );
        let mut recipient = bring_up(
            &net,
            &recipient_key,
            MemoryRepo::default(),
            vec![issuer_id],
            ReconcileDirection::ReadOnly,
        );
        issuer.activate_collection(collection.handle());
        recipient.activate_collection(collection.handle());

        // The recipient begins with only C and one issuer endpoint. An initial
        // exact-H lookup also gives the issuer's provider leases a reachable
        // DHT replica; a retry then obtains the self-describing C bytes.
        let descriptor = acquire_once(
            &clock,
            &mut recipient,
            Inline::new(collection.handle().raw),
            &mut [&mut issuer],
        )
        .await;
        if descriptor.is_none() {
            advance(&clock, &mut [&mut issuer, &mut recipient], 32).await;
            assert!(
                acquire_once(
                    &clock,
                    &mut recipient,
                    Inline::new(collection.handle().raw),
                    &mut [&mut issuer],
                )
                .await
                .is_some()
            );
        }
        let recipient_collection = {
            let snapshot = recipient.snapshot().unwrap();
            Collection::<SimpleArchive>::open(&snapshot, collection.handle()).unwrap()
        };

        // With C resident, the issuer can authorize the endpoint using its
        // resident READ definition. Repair sends only proof/collection records;
        // the recipient still needs the named definitions to interpret them.
        advance(&clock, &mut [&mut issuer, &mut recipient], 32).await;
        let dangling = recipient.snapshot().unwrap();
        assert_eq!(dangling.records().unwrap().count(), 1);
        let received = dangling
            .proofs()
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(received, [read_proof]);
        assert!(!dangling.contains_blob(read_capability()).unwrap());
        assert!(!dangling.contains_blob(write_capability()).unwrap());
        assert!(!dangling.contains_blob(payload_handle).unwrap());
        assert!(
            !recipient_collection
                .reader_is_admitted(&dangling, recipient_key.verifying_key())
                .unwrap(),
            "proof bytes alone do not interpret a nonresident capability definition",
        );
        assert!(recipient_collection.admitted(&dangling).unwrap().is_empty());
        assert!(
            dangling
                .collection(recipient_collection)
                .unwrap()
                .cover()
                .is_empty()
        );
        assert_eq!(dangling.wants().unwrap().count(), 0);

        assert!(
            acquire_once(
                &clock,
                &mut recipient,
                Inline::new(read_capability().raw),
                &mut [&mut issuer],
            )
            .await
            .is_some(),
            "the named READ definition uses the ordinary exact-H DHT path",
        );
        let read_ready = recipient.snapshot().unwrap();
        assert!(
            recipient_collection
                .reader_is_admitted(&read_ready, recipient_key.verifying_key())
                .unwrap()
        );
        assert!(
            !recipient_collection
                .reader_is_admitted(&dangling, recipient_key.verifying_key())
                .unwrap()
        );
        assert!(!read_ready.contains_blob(write_capability()).unwrap());
        assert!(
            recipient_collection
                .admitted(&read_ready)
                .unwrap()
                .is_empty()
        );
        assert!(!read_ready.contains_blob(payload_handle).unwrap());
        assert_eq!(read_ready.wants().unwrap().count(), 0);

        assert!(
            acquire_once(
                &clock,
                &mut recipient,
                Inline::new(write_capability().raw),
                &mut [&mut issuer],
            )
            .await
            .is_some(),
            "interpreting COMMIT producer authority fetches its definition, not its payload",
        );
        let admitted = recipient.snapshot().unwrap();
        assert_eq!(recipient_collection.admitted(&admitted).unwrap().len(), 1);
        assert!(!admitted.contains_blob(payload_handle).unwrap());
        assert!(
            admitted
                .collection(recipient_collection)
                .unwrap()
                .cover()
                .is_empty()
        );
        assert_eq!(admitted.records().unwrap().count(), 1);
        assert_eq!(admitted.proofs().unwrap().count(), 1);
        assert_eq!(admitted.wants().unwrap().count(), 0);

        // The committed payload remains an ordinary exact-H bearer read.
        // Repair manufactures no durable WANT.
        assert!(
            acquire_once(
                &clock,
                &mut recipient,
                Inline::new(payload_handle.raw),
                &mut [&mut issuer],
            )
            .await
            .is_some(),
            "the repaired commit payload follows the ordinary exact-H path",
        );

        let ready = recipient.snapshot().unwrap();
        assert!(
            recipient_collection
                .reader_is_admitted(&ready, recipient_key.verifying_key())
                .unwrap()
        );
        assert_eq!(recipient_collection.admitted(&ready).unwrap().len(), 1,);
        assert_eq!(
            ready
                .collection(recipient_collection)
                .unwrap()
                .cover()
                .len(),
            1
        );
        let facts = recipient_collection.read::<TribleSet, _>(&ready).unwrap();
        assert_eq!(facts, payload_facts);
        assert!(
            admitted
                .collection(recipient_collection)
                .unwrap()
                .cover()
                .is_empty()
        );
        assert_eq!(ready.wants().unwrap().count(), 0);
    }));
}

#[test]
fn write_proof_later_activates_repaired_commit_without_reaching_publisher() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC71, SimConfig::default());
        let server_key = key(1);
        let reader_key = key(2);
        let read_root = key(3);
        let write_root = key(4);
        let writer = key(5);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(read_root.verifying_key()),
            AdmissionPolicy::direct(write_root.verifying_key()),
        );

        let mut server_store = MemoryRepo::default();
        let collection = register(&mut server_store, policy.clone());
        let payload = TribleSet::new().to_blob();
        let payload_handle = server_store.put::<SimpleArchive, _>(payload).unwrap();
        server_store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &writer,
                collection.handle(),
                Handle::<SimpleArchive>::to_hash(payload_handle),
                payload_handle,
            )))
            .unwrap();
        let write = proof(
            &write_root,
            &writer,
            write_capability(),
            collection.handle(),
        );

        let mut reader_store = MemoryRepo::default();
        let reader_collection = register(&mut reader_store, policy);
        assert_eq!(reader_collection.handle(), collection.handle());
        reader_store
            .insert_proof(proof(
                &read_root,
                &reader_key,
                read_capability(),
                collection.handle(),
            ))
            .unwrap();

        let server_id = server_key.verifying_key().to_bytes();
        let mut server = bring_up(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
        );
        let mut reader = bring_up(
            &net,
            &reader_key,
            reader_store,
            vec![server_id],
            ReconcileDirection::ReadOnly,
        );
        server.activate_collection(collection.handle());
        reader.activate_collection(collection.handle());

        advance(&clock, &mut [&mut server, &mut reader], 3).await;
        let before = reader.snapshot().unwrap();
        // Background collection repair may already have transferred the
        // signed record. Without WRITE evidence it remains semantically inert.
        assert!(reader_collection.admitted(&before).unwrap().is_empty());

        let bootstrap = reconcile_once(
            &clock,
            &mut Reconciler::default(),
            &mut server,
            &mut [&mut reader],
        )
        .await;
        assert_eq!(
            bootstrap.fulfilled, 0,
            "proof receipt must not manufacture a durable blob WANT"
        );
        assert_eq!(server.snapshot().unwrap().wants().unwrap().count(), 0);

        advance(&clock, &mut [&mut server, &mut reader], 32).await;
        let repaired = reader.snapshot().unwrap();
        assert_eq!(repaired.records().unwrap().count(), 1);
        assert!(reader_collection.admitted(&repaired).unwrap().is_empty());

        assert!(
            acquire_once(
                &clock,
                &mut reader,
                Inline::new(payload_handle.raw),
                &mut [&mut server],
            )
            .await
            .is_some(),
            "active collection use acquires the exact committed payload",
        );
        assert_eq!(reader.snapshot().unwrap().wants().unwrap().count(), 0);

        // The grant can arrive after the record at the receiver. The
        // WriteOnly publisher never receives or presents it.
        reader.store().insert_proof(write).unwrap();
        reader.refresh();
        let after = reader.snapshot().unwrap();
        assert_eq!(after.records().unwrap().count(), 1);
        assert_eq!(after.proofs().unwrap().count(), 2);
        assert_eq!(reader_collection.admitted(&after).unwrap().len(), 1);
        let publisher = server.snapshot().unwrap();
        assert_eq!(publisher.proofs().unwrap().count(), 1);
        assert!(collection.admitted(&publisher).unwrap().is_empty());
    }));
}

#[test]
fn native_read_proof_bootstraps_on_retry_and_rejects_writer_only_peer() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC72, SimConfig::default());
        let server_key = key(11);
        let reader_key = key(12);
        let writer_key = key(13);
        let read_root = key(14);
        let write_root = key(15);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(read_root.verifying_key()),
            AdmissionPolicy::direct(write_root.verifying_key()),
        );

        let mut server_store = MemoryRepo::default();
        let collection = register(&mut server_store, policy.clone());
        let write = proof(
            &write_root,
            &writer_key,
            write_capability(),
            collection.handle(),
        );
        server_store.insert_proof(write.clone()).unwrap();
        let payload_facts = entity! {
            triblespace_core::metadata::tag: triblespace_core::metadata::KIND_MULTI,
        }
        .facts()
        .clone();
        let payload_handle = server_store
            .put::<SimpleArchive, _>(payload_facts.clone())
            .unwrap();
        server_store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &writer_key,
                collection.handle(),
                Handle::<SimpleArchive>::to_hash(payload_handle),
                payload_handle,
            )))
            .unwrap();

        let mut reader_store = MemoryRepo::default();
        let reader_collection = register(&mut reader_store, policy.clone());
        reader_store
            .insert_proof(proof(
                &read_root,
                &reader_key,
                read_capability(),
                collection.handle(),
            ))
            .unwrap();
        let mut writer_store = MemoryRepo::default();
        register(&mut writer_store, policy);
        writer_store.insert_proof(write).unwrap();

        let server_id = server_key.verifying_key().to_bytes();
        let mut server = bring_up(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
        );
        let mut reader = bring_up(
            &net,
            &reader_key,
            reader_store,
            vec![server_id],
            ReconcileDirection::ReadOnly,
        );
        let mut writer_only = bring_up(
            &net,
            &writer_key,
            writer_store,
            vec![server_id],
            ReconcileDirection::ReadOnly,
        );
        for peer in [&mut server, &mut reader, &mut writer_only] {
            peer.activate_collection(collection.handle());
        }

        advance(&clock, &mut [&mut server, &mut reader, &mut writer_only], 4).await;
        let stats = reconcile_once(
            &clock,
            &mut Reconciler::default(),
            &mut server,
            &mut [&mut reader, &mut writer_only],
        )
        .await;
        assert_eq!(
            stats.fulfilled, 0,
            "proof receipt must not manufacture a durable blob WANT"
        );
        assert_eq!(server.snapshot().unwrap().wants().unwrap().count(), 0);
        advance(
            &clock,
            &mut [&mut server, &mut reader, &mut writer_only],
            32,
        )
        .await;
        assert_eq!(reader.snapshot().unwrap().records().unwrap().count(), 1);
        let stats = reconcile_once(
            &clock,
            &mut Reconciler::default(),
            &mut reader,
            &mut [&mut server, &mut writer_only],
        )
        .await;
        assert_eq!(
            stats.fulfilled, 0,
            "proof repair must not manufacture a durable blob WANT"
        );
        let dangling = reader.snapshot().unwrap();
        assert_eq!(
            dangling.proofs().unwrap().count(),
            2,
            "the signed WRITE proof repairs with the collection records",
        );
        assert!(dangling.contains_blob(write_capability()).unwrap());
        let admitted = reader_collection.admitted(&dangling).unwrap();
        assert_eq!(
            admitted.len(),
            1,
            "resident policy definitions and the repaired proof admit the COMMIT independently of its payload",
        );
        assert!(admitted.contains(payload_handle));
        assert!(!dangling.contains_blob(payload_handle).unwrap());
        let unavailable = dangling.collection(reader_collection).unwrap();
        assert!(unavailable.cover().is_empty());
        assert!(unavailable.support().is_empty());
        assert!(reader_collection.read::<TribleSet, _>(&dangling).unwrap().is_empty());
        assert_eq!(dangling.wants().unwrap().count(), 0);
        assert!(
            acquire_once(
                &clock,
                &mut reader,
                Inline::new(payload_handle.raw),
                &mut [&mut server, &mut writer_only],
            )
            .await
            .is_some(),
            "active collection use acquires the exact committed payload",
        );
        assert_eq!(reader.snapshot().unwrap().wants().unwrap().count(), 0);
        let reader_snapshot = reader.snapshot().unwrap();
        assert_eq!(reader_collection.admitted(&reader_snapshot).unwrap(), admitted);
        let available = reader_snapshot.collection(reader_collection).unwrap();
        assert_eq!(available.cover().len(), 1);
        assert_eq!(available.support(), &admitted);
        assert_eq!(reader_collection.read::<TribleSet, _>(&reader_snapshot).unwrap(), payload_facts);
        assert!(!dangling.contains_blob(payload_handle).unwrap());
        assert!(dangling.collection(reader_collection).unwrap().cover().is_empty());
        let writer_snapshot = writer_only.snapshot().unwrap();
        assert_eq!(
            writer_snapshot.records().unwrap().count(),
            0,
            "WRITE(C) without READ(C) must not learn even the collection manifest"
        );
        assert_eq!(writer_snapshot.proofs().unwrap().count(), 1);
        assert!(!reader_collection
            .reader_is_admitted(&writer_snapshot, writer_key.verifying_key())
            .unwrap());
        assert!(!writer_snapshot.contains_blob(payload_handle).unwrap());
        assert_eq!(writer_snapshot.wants().unwrap().count(), 0);
    }));
}

#[test]
fn collection_wake_recovery_survives_a_partition_without_dht_or_restart() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC75, SimConfig::default());
        let server_key = key(51);
        let reader_key = key(52);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::Open,
            AdmissionPolicy::direct(server_key.verifying_key()),
        );

        let mut first_facts = TribleSet::new();
        let mut first_raw = [1; triblespace_core::trible::TRIBLE_LEN];
        first_raw[16..32].fill(2);
        first_facts.insert(
            &triblespace_core::trible::Trible::force_raw(first_raw)
                .expect("non-nil entity and attribute"),
        );

        let mut server_store = MemoryRepo::default();
        let collection = register(&mut server_store, policy.clone());
        let first_payload = server_store
            .put::<SimpleArchive, _>(first_facts.to_blob())
            .unwrap();
        server_store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &server_key,
                collection.handle(),
                Handle::<SimpleArchive>::to_hash(first_payload),
                first_payload,
            )))
            .unwrap();

        let mut reader_store = MemoryRepo::default();
        let reader_collection = register(&mut reader_store, policy);
        assert_eq!(reader_collection.handle(), collection.handle());

        let server_id = server_key.verifying_key().to_bytes();
        let reader_id = reader_key.verifying_key().to_bytes();
        let mut server = bring_up_with_publication_budget(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
            Some(0),
        );
        let mut reader = bring_up_with_publication_budget(
            &net,
            &reader_key,
            reader_store,
            vec![server_id],
            ReconcileDirection::ReadOnly,
            Some(0),
        );
        server.activate_collection(collection.handle());
        reader.activate_collection(collection.handle());

        advance(&clock, &mut [&mut server, &mut reader], 5).await;
        assert_eq!(reader.snapshot().unwrap().records().unwrap().count(), 1);

        net.partition(server_id, reader_id);
        let mut second_facts = TribleSet::new();
        let mut second_raw = [3; triblespace_core::trible::TRIBLE_LEN];
        second_raw[16..32].fill(4);
        second_facts.insert(
            &triblespace_core::trible::Trible::force_raw(second_raw)
                .expect("non-nil entity and attribute"),
        );
        let second_payload = server
            .put::<SimpleArchive, _>(second_facts.to_blob())
            .unwrap();
        server
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &server_key,
                collection.handle(),
                Handle::<SimpleArchive>::to_hash(second_payload),
                second_payload,
            )))
            .unwrap();
        server.refresh();

        // Let the signed wake be lost, periodic repair fail, and at least one
        // recovery resubscription happen while the partition is still closed.
        advance(&clock, &mut [&mut server, &mut reader], 40).await;
        assert_eq!(reader.snapshot().unwrap().records().unwrap().count(), 1);

        // Healing alone must suffice: there is no DHT publication, new write,
        // process restart, or direct collection repair to a configured route.
        net.heal(server_id, reader_id);
        advance(&clock, &mut [&mut server, &mut reader], 95).await;
        assert_eq!(reader.snapshot().unwrap().records().unwrap().count(), 2);
    }));
}

#[test]
fn durable_bearer_want_materializes_without_any_collection() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC74, SimConfig::default());
        let server_key = key(41);
        let reader_key = key(42);
        let mut server_store = MemoryRepo::default();
        let payload = Bytes::from_source(b"durable H-only WANT".to_vec());
        let payload_handle = server_store.put::<UnknownBlob, _>(payload.clone()).unwrap();

        let mut reader_store = MemoryRepo::default();
        let wanted = WantRequest::blob(payload_handle);
        let absent = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([0xFF; 32]));
        for request in [wanted, absent] {
            reader_store.want(request).unwrap();
        }
        reader_store.flush().unwrap();

        let server_id = server_key.verifying_key().to_bytes();
        let mut server = bring_up(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
        );
        let mut reader = bring_up(
            &net,
            &reader_key,
            reader_store,
            vec![server_id],
            ReconcileDirection::ReadOnly,
        );
        advance(&clock, &mut [&mut server, &mut reader], 4).await;

        let mut reconciler = Reconciler::with_backoff(
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        )
        .with_fetch_budget(std::time::Duration::from_secs(2));
        let mut tick = Box::pin(reconciler.tick(&mut reader));
        let stats = loop {
            tokio::select! {
                stats = &mut tick => break stats,
                () = SimNet::step(&clock, std::time::Duration::from_millis(100)) => {
                    server.refresh();
                }
            }
        };
        drop(tick);
        assert_eq!(
            stats,
            ReconcileStats {
                wants: 2,
                missing: 2,
                attempted: 2,
                fulfilled: 1,
                pending: 1,
                replication: Default::default(),
            },
            "the exact resident H resolves globally while a wrong H stays pending"
        );
        assert_eq!(reader.try_local(payload_handle.raw), Some(payload));
        let wants: BTreeSet<_> = {
            let snapshot = reader.snapshot().unwrap();
            snapshot.wants().unwrap().map(Result::unwrap).collect()
        };
        assert_eq!(wants, BTreeSet::from([wanted, absent]));
    }));
}

#[test]
fn demand_shallow_full_preserve_exact_wants_and_only_hydrate_selected_record_roots() {
    let _guard = test_guard();
    let clock = virtual_clock();
    for mode in [
        ReplicationMode::Demand,
        ReplicationMode::Shallow,
        ReplicationMode::Full,
    ] {
        clock.reset();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        runtime.block_on(local.run_until(async {
            let net = SimNet::new(0xC011_EC80, SimConfig::default());
            let server_key = key(81);
            let reader_key = key(82);
            let policy_key = key(83);
            let inert_writer = key(84);
            let policy = CollectionPolicy::new(
                AdmissionPolicy::direct(policy_key.verifying_key()),
                AdmissionPolicy::direct(policy_key.verifying_key()),
            );
            let mut server_store = MemoryRepo::default();
            let collection = register(&mut server_store, policy.clone());
            let unrelated = server_store.collection("not-selected", policy).unwrap();
            let leaf = server_store
                .put::<UnknownBlob, _>(Bytes::from_source(b"recursive leaf".to_vec()))
                .unwrap();
            let child = server_store
                .put::<UnknownBlob, _>(Bytes::from_source(leaf.raw.to_vec()))
                .unwrap();
            let unaligned = server_store
                .put::<UnknownBlob, _>(Bytes::from_source(b"unaligned only".to_vec()))
                .unwrap();
            // Hydration is structural, without an encoding dispatch. The
            // first complete word is a child; the handle at offset 33 is not.
            let mut data_bytes = child.raw.to_vec();
            data_bytes.push(7);
            data_bytes.extend_from_slice(&unaligned.raw);
            let metadata = server_store
                .put::<SimpleArchive, _>(TribleSet::new().to_blob())
                .unwrap();
            let data_bytes = (0_u64..1_000_000)
                .find_map(|nonce| {
                    let mut bytes = data_bytes.clone();
                    bytes.extend_from_slice(&nonce.to_le_bytes());
                    let hash = *blake3::hash(&bytes).as_bytes();
                    (hash < collection.handle().raw && hash < metadata.raw).then_some(bytes)
                })
                .expect("a deterministic fixture with data first in scan order");
            let data = server_store
                .put::<UnknownBlob, _>(Bytes::from_source(data_bytes))
                .unwrap();
            let record = CollectionRecord::Commit(CollectionCommit::sign(
                &inert_writer,
                collection.handle(),
                Inline::new(data.raw),
                metadata,
            ));
            server_store.insert(record).unwrap();
            let unrelated_data = server_store
                .put::<UnknownBlob, _>(Bytes::from_source(b"unselected payload".to_vec()))
                .unwrap();
            let unrelated_record = CollectionRecord::Commit(CollectionCommit::sign(
                &policy_key,
                unrelated.handle(),
                Inline::new(unrelated_data.raw),
                metadata,
            ));
            server_store.insert(unrelated_record).unwrap();
            let demand_child = server_store
                .put::<UnknownBlob, _>(Bytes::from_source(b"not a recursive WANT".to_vec()))
                .unwrap();
            let demand_blob = server_store
                .put::<UnknownBlob, _>(Bytes::from_source(demand_child.raw.to_vec()))
                .unwrap();
            let demand = WantRequest::blob(demand_blob);
            let mut reader_store = MemoryRepo::default();
            for descriptor in [collection.handle(), unrelated.handle()] {
                let bytes = BlobStoreGet::get::<Bytes, UnknownBlob>(
                    &server_store.snapshot().unwrap(),
                    Inline::new(descriptor.raw),
                )
                .unwrap();
                reader_store.put::<UnknownBlob, _>(bytes).unwrap();
            }
            reader_store.insert(record).unwrap();
            reader_store.insert(unrelated_record).unwrap();
            reader_store
                .insert_proof(proof(
                    &policy_key,
                    &reader_key,
                    read_capability(),
                    unrelated.handle(),
                ))
                .unwrap();
            reader_store.want(demand).unwrap();
            let mut server = bring_up_with_publication_budget(
                &net,
                &server_key,
                server_store,
                Vec::new(),
                ReconcileDirection::WriteOnly,
                Some(0),
            );
            let mut reader = bring_up_with_publication_budget(
                &net,
                &reader_key,
                reader_store,
                vec![server_key.verifying_key().to_bytes()],
                ReconcileDirection::ReadOnly,
                Some(0),
            );
            // Neither endpoint activates C or obtains READ(C). Ordinary H
            // discovery/bearer serving is sufficient for every acquisition.
            advance(&clock, &mut [&mut server, &mut reader], 4).await;
            let mut reconciler = Reconciler::with_backoff(
                std::time::Duration::from_millis(100),
                std::time::Duration::from_secs(1),
            )
            .with_replication(mode, [collection.handle()])
            .with_fetch_budget(std::time::Duration::from_secs(2));
            let mut fulfilled = 0;
            for _ in 0..120 {
                let stats =
                    reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
                fulfilled += stats.fulfilled;
                assert!(
                    stats.replication.speculative_attempted
                        <= RECONCILE_SPECULATIVE_FETCHES_PER_TICK
                );
                let complete = match mode {
                    ReplicationMode::Demand => stats.pending == 0,
                    ReplicationMode::Shallow => {
                        stats.pending == 0 && stats.replication.pending == 0
                    }
                    ReplicationMode::Full => reader.try_local(leaf.raw).is_some(),
                };
                if complete {
                    break;
                }
                advance(&clock, &mut [&mut server, &mut reader], 1).await;
            }
            assert_eq!(
                fulfilled, 1,
                "all modes service the same explicit exact WANT"
            );
            assert!(reader.try_local(demand_blob.raw).is_some());
            assert!(
                reader.try_local(demand_child.raw).is_none(),
                "Full does not widen a plain Blob(H) WANT"
            );
            assert_eq!(
                reader.try_local(data.raw).is_some(),
                mode != ReplicationMode::Demand
            );
            assert_eq!(
                reader.try_local(metadata.raw).is_some(),
                mode != ReplicationMode::Demand
            );
            assert_eq!(
                reader.try_local(child.raw).is_some(),
                mode == ReplicationMode::Full
            );
            assert_eq!(
                reader.try_local(leaf.raw).is_some(),
                mode == ReplicationMode::Full
            );
            assert!(reader.try_local(unaligned.raw).is_none());
            assert!(
                reader.try_local(unrelated_data.raw).is_none(),
                "a grant and unrelated records do not select their collection"
            );
            let snapshot = reader.snapshot().unwrap();
            assert_eq!(snapshot.records().unwrap().count(), 2);
            assert_eq!(snapshot.proofs().unwrap().count(), 1);
            assert_eq!(
                snapshot
                    .wants()
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>(),
                [demand]
            );
            assert!(
                !collection
                    .writer_is_admitted(&snapshot, inert_writer.verifying_key())
                    .unwrap()
            );
        }));
    }
}

#[test]
fn full_replication_fair_selection_reaches_a_child_beyond_the_startup_window() {
    selection_fairness_case(false);
}

#[test]
fn full_replication_fair_selection_recurses_through_a_resident_child() {
    selection_fairness_case(true);
}

fn selection_fairness_case(resident_child: bool) {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC85, SimConfig::default());
        let server_key = key(123);
        let reader_key = key(124);
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let large = server_store
            .collection("large selection", policy.clone())
            .unwrap();
        let small = server_store.collection("small selection", policy).unwrap();
        let metadata = server_store
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        let leaf = server_store
            .put::<UnknownBlob, _>(Bytes::from_source(b"fair selection leaf".to_vec()))
            .unwrap();
        let mut words = Vec::new();
        for word in 0_u64..128 {
            words.extend_from_slice(blake3::hash(&word.to_be_bytes()).as_bytes());
        }
        let mut reader_store = MemoryRepo::default();
        let target = if resident_child {
            let mut bytes = words.clone();
            bytes.extend_from_slice(&leaf.raw);
            let bytes = Bytes::from_source(bytes);
            let child = server_store.put::<UnknownBlob, _>(bytes.clone()).unwrap();
            reader_store.put::<UnknownBlob, _>(bytes).unwrap();
            child
        } else {
            leaf
        };
        words.extend_from_slice(&target.raw);
        // Put the small payload in the middle of the initial global H sweep.
        let (data, data_bytes) = (0_u64..100_000)
            .find_map(|nonce| {
                let mut bytes = words.clone();
                bytes.extend_from_slice(&nonce.to_le_bytes());
                let hash = *blake3::hash(&bytes).as_bytes();
                (hash[0] >= 96 && hash[0] < 160).then_some((hash, Bytes::from_source(bytes)))
            })
            .unwrap();
        server_store
            .put::<UnknownBlob, _>(data_bytes.clone())
            .unwrap();
        reader_store.put::<UnknownBlob, _>(data_bytes).unwrap();
        for handle in [large.handle().raw, small.handle().raw, metadata.raw] {
            let bytes = BlobStoreGet::get::<Bytes, UnknownBlob>(
                &server_store.snapshot().unwrap(),
                Inline::new(handle),
            )
            .unwrap();
            reader_store.put::<UnknownBlob, _>(bytes).unwrap();
        }
        // Shared roots must not be assigned exclusively to the large selection.
        for collection in [large.handle(), small.handle()] {
            let record = CollectionRecord::Commit(CollectionCommit::sign(
                &server_key,
                collection,
                Inline::new(data),
                metadata,
            ));
            server_store.insert(record).unwrap();
            reader_store.insert(record).unwrap();
        }
        let mut lower = 0;
        let mut higher = 0;
        for nonce in 0_u64..100_000 {
            let mut bytes = Vec::new();
            for word in 0_u64..256 {
                let mut seed = [0; 16];
                seed[..8].copy_from_slice(&nonce.to_le_bytes());
                seed[8..].copy_from_slice(&word.to_le_bytes());
                bytes.extend_from_slice(blake3::hash(&seed).as_bytes());
            }
            let hash = *blake3::hash(&bytes).as_bytes();
            let count = if hash < data { &mut lower } else { &mut higher };
            if *count == 256 {
                continue;
            }
            *count += 1;
            let bytes = Bytes::from_source(bytes);
            server_store.put::<UnknownBlob, _>(bytes.clone()).unwrap();
            reader_store.put::<UnknownBlob, _>(bytes).unwrap();
            let record = CollectionRecord::Commit(CollectionCommit::sign(
                &server_key,
                large.handle(),
                Inline::new(hash),
                metadata,
            ));
            server_store.insert(record).unwrap();
            reader_store.insert(record).unwrap();
            if lower == 256 && higher == 256 {
                break;
            }
        }
        assert_eq!((lower, higher), (256, 256));
        let mut server = bring_up_with_publication_budget(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
            Some(0),
        );
        let mut reader = bring_up_with_publication_budget(
            &net,
            &reader_key,
            reader_store,
            vec![server_key.verifying_key().to_bytes()],
            ReconcileDirection::ReadOnly,
            Some(0),
        );
        advance(&clock, &mut [&mut server, &mut reader], 4).await;
        let mut reconciler = Reconciler::with_backoff(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(1),
        )
        .with_replication(ReplicationMode::Full, [large.handle(), small.handle()])
        .with_fetch_budget(std::time::Duration::from_secs(2));
        for _ in 0..128 {
            let stats =
                reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
            assert_eq!(
                stats.replication.roots, 516,
                "physical roots stay deduplicated"
            );
            assert_eq!(stats.replication.pending, 0);
            assert!(
                stats.replication.speculative_attempted <= RECONCILE_SPECULATIVE_FETCHES_PER_TICK
            );
            assert!(
                stats.replication.candidates
                    <= triblespace_net::reconcile::RECONCILE_SCAN_CANDIDATES_PER_TICK
            );
            if reader.try_local(leaf.raw).is_some() {
                break;
            }
            advance(&clock, &mut [&mut server, &mut reader], 1).await;
        }
        assert!(
            reader.try_local(leaf.raw).is_some(),
            "a small selection must reach word 129 without draining another selection's roots"
        );
        assert_eq!(reader.snapshot().unwrap().wants().unwrap().count(), 0);
        assert_eq!(reader.snapshot().unwrap().records().unwrap().count(), 514);
    }));
}

#[test]
fn full_replication_fetches_a_recent_descriptor_name_before_old_blob_eof() {
    descriptor_name_case(false);
}

#[test]
fn full_replication_fetches_a_startup_descriptor_name_before_the_resident_backlog() {
    descriptor_name_case(true);
}

fn descriptor_name_case(at_startup: bool) {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC84, SimConfig::default());
        let server_key = key(121);
        let reader_key = key(122);
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let old = register(&mut server_store, policy.clone());
        let metadata = server_store
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        let (fresh, name, descriptor_bytes) = (0..100)
            .find_map(|nonce| {
                let text = format!("recent descriptor name, several words in: {nonce}");
                let fresh = server_store.collection(&text, policy.clone()).unwrap();
                let name = server_store
                    .put::<UnknownBlob, _>(Bytes::from_source(text.into_bytes()))
                    .unwrap();
                let bytes = BlobStoreGet::get::<Bytes, UnknownBlob>(
                    &server_store.snapshot().unwrap(),
                    Inline::new(fresh.handle().raw),
                )
                .unwrap();
                let word = bytes.chunks_exact(32).position(|word| word == name.raw)?;
                (word >= 3 && word < 32).then_some((fresh, name, bytes))
            })
            .expect("a canonical descriptor whose name is beyond its first word");
        let mut junk = Vec::new();
        for word in 0_u64..8_192 {
            junk.extend_from_slice(blake3::hash(&word.to_le_bytes()).as_bytes());
        }
        let (old_data, old_bytes) = (0_u64..10_000)
            .find_map(|nonce| {
                let mut bytes = junk.clone();
                bytes.extend_from_slice(&nonce.to_le_bytes());
                let hash = *blake3::hash(&bytes).as_bytes();
                let sorted = if at_startup {
                    hash > old.handle().raw && hash > metadata.raw && hash > fresh.handle().raw
                } else {
                    hash < old.handle().raw && hash < metadata.raw
                };
                sorted.then_some((hash, bytes))
            })
            .expect("old binary sorts first in the baseline lane under test");
        server_store
            .put::<UnknownBlob, _>(Bytes::from_source(old_bytes.clone()))
            .unwrap();
        let old_record = CollectionRecord::Commit(CollectionCommit::sign(
            &server_key,
            old.handle(),
            Inline::new(old_data),
            metadata,
        ));
        server_store.insert(old_record).unwrap();
        let fresh_record = CollectionRecord::Commit(CollectionCommit::sign(
            &server_key,
            fresh.handle(),
            metadata.into(),
            metadata,
        ));
        server_store.insert(fresh_record).unwrap();
        let mut reader_store = MemoryRepo::default();
        for handle in [old.handle().raw, old_data, metadata.raw] {
            let bytes = BlobStoreGet::get::<Bytes, UnknownBlob>(
                &server_store.snapshot().unwrap(),
                Inline::new(handle),
            )
            .unwrap();
            reader_store.put::<UnknownBlob, _>(bytes).unwrap();
        }
        reader_store.insert(old_record).unwrap();
        let mut background_records = 0;
        if at_startup {
            reader_store
                .put::<UnknownBlob, _>(descriptor_bytes.clone())
                .unwrap();
            reader_store.insert(fresh_record).unwrap();
            // These resident roots keep the regular cursor ahead of the
            // descriptor; the large highest-H binary holds the old recent lane.
            for nonce in 0_u64..100_000 {
                let bytes =
                    Bytes::from_source(blake3::hash(&nonce.to_le_bytes()).as_bytes().to_vec());
                let hash = *blake3::hash(&bytes).as_bytes();
                if hash >= fresh.handle().raw {
                    continue;
                }
                server_store.put::<UnknownBlob, _>(bytes.clone()).unwrap();
                reader_store.put::<UnknownBlob, _>(bytes).unwrap();
                let record = CollectionRecord::Commit(CollectionCommit::sign(
                    &server_key,
                    old.handle(),
                    Inline::new(hash),
                    metadata,
                ));
                server_store.insert(record).unwrap();
                reader_store.insert(record).unwrap();
                background_records += 1;
                if background_records == 512 {
                    break;
                }
            }
            assert_eq!(background_records, 512);
        }
        let mut server = bring_up_with_publication_budget(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
            Some(0),
        );
        let mut reader = bring_up_with_publication_budget(
            &net,
            &reader_key,
            reader_store,
            vec![server_key.verifying_key().to_bytes()],
            ReconcileDirection::ReadOnly,
            Some(0),
        );
        advance(&clock, &mut [&mut server, &mut reader], 4).await;
        let mut reconciler = Reconciler::with_backoff(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(1),
        )
        .with_replication(ReplicationMode::Full, [old.handle(), fresh.handle()])
        .with_fetch_budget(std::time::Duration::from_secs(2));
        assert!(reader.try_local(name.raw).is_none());
        if !at_startup {
            let first =
                reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
            assert!(first.replication.speculative_misses > 0);
            assert!(reader.try_local(name.raw).is_none());
            reader
                .store()
                .put::<UnknownBlob, _>(descriptor_bytes)
                .unwrap();
            reader.store().insert(fresh_record).unwrap();
            reader.refresh();
        }
        for _ in 0..if at_startup { 12 } else { 48 } {
            let stats =
                reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
            assert!(
                stats.replication.speculative_attempted <= RECONCILE_SPECULATIVE_FETCHES_PER_TICK
            );
            if reader.try_local(name.raw).is_some() {
                break;
            }
            advance(&clock, &mut [&mut server, &mut reader], 1).await;
        }
        assert!(
            reader.try_local(name.raw).is_some(),
            "the new name must not await 8,192 old speculative words"
        );
        let snapshot = reader.snapshot().unwrap();
        assert_eq!(snapshot.wants().unwrap().count(), 0);
        assert_eq!(snapshot.records().unwrap().count(), 2 + background_records);
    }));
}

#[test]
fn full_replication_retries_a_missing_child_after_unchanged_parent_progress() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC81, SimConfig::default());
        let server_key = key(91);
        let reader_key = key(92);
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let collection = register(&mut server_store, policy);
        let leaf = server_store
            .put::<UnknownBlob, _>(Bytes::from_source(b"late recursive leaf".to_vec()))
            .unwrap();
        let child_bytes = Bytes::from_source(leaf.raw.to_vec());
        let child = *blake3::hash(child_bytes.as_ref()).as_bytes();
        let metadata = server_store
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        // Put this small parent before the descriptor in scan order, so the
        // first tick definitely observes its absent child before yielding.
        let data = (0_u64..1_000_000)
            .find_map(|nonce| {
                let mut bytes = child.to_vec();
                bytes.extend_from_slice(&nonce.to_le_bytes());
                let hash = *blake3::hash(&bytes).as_bytes();
                (hash < collection.handle().raw && hash < metadata.raw).then_some((hash, bytes))
            })
            .expect("a deterministic fixture with data first in scan order");
        server_store
            .put::<UnknownBlob, _>(Bytes::from_source(data.1.clone()))
            .unwrap();
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &server_key,
            collection.handle(),
            Inline::new(data.0),
            metadata,
        ));
        let mut reader_store = MemoryRepo::default();
        for handle in [collection.handle().raw, data.0, metadata.raw] {
            let bytes = BlobStoreGet::get::<Bytes, UnknownBlob>(
                &server_store.snapshot().unwrap(),
                Inline::new(handle),
            )
            .unwrap();
            reader_store.put::<UnknownBlob, _>(bytes).unwrap();
        }
        reader_store.insert(record).unwrap();
        let mut server = bring_up_with_publication_budget(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
            Some(0),
        );
        let mut reader = bring_up_with_publication_budget(
            &net,
            &reader_key,
            reader_store,
            vec![server_key.verifying_key().to_bytes()],
            ReconcileDirection::ReadOnly,
            Some(0),
        );
        advance(&clock, &mut [&mut server, &mut reader], 4).await;
        let mut reconciler = Reconciler::with_backoff(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(1),
        )
        .with_replication(ReplicationMode::Full, [collection.handle()])
        .with_fetch_budget(std::time::Duration::from_secs(2));
        let first = reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
        assert_eq!(first.replication.pending, 0);
        assert!(first.replication.speculative_misses > 0);
        assert!(reader.try_local(child).is_none());
        assert_eq!(
            server
                .store()
                .put::<UnknownBlob, _>(child_bytes)
                .unwrap()
                .raw,
            child
        );
        server.refresh();
        for _ in 0..120 {
            advance(&clock, &mut [&mut server, &mut reader], 1).await;
            let stats =
                reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
            assert!(
                stats.replication.speculative_attempted <= RECONCILE_SPECULATIVE_FETCHES_PER_TICK
            );
            if reader.try_local(leaf.raw).is_some() {
                break;
            }
        }
        assert!(
            reader.try_local(child).is_some(),
            "the same parent must be rescanned after a miss"
        );
        assert!(
            reader.try_local(leaf.raw).is_some(),
            "late children become recursive sources"
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
    }));
}

#[test]
fn full_replication_reuses_a_known_summary_without_filtering_later_source_support() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC82, SimConfig::default());
        let server_key = key(101);
        let reader_key = key(102);
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let collection = register(&mut server_store, policy.clone());
        let summaries = server_store
            .derive::<ReferenceSummaryBlob>(collection, ReferenceSummaryLayout::default(), policy)
            .unwrap();
        let reference = Attribute::<Handle<UnknownBlob>>::named("summary-reuse-reference");
        let absent = Inline::<Handle<UnknownBlob>>::new(
            *blake3::hash(b"an absent aligned summary fixture word").as_bytes(),
        );
        let leaf_a = server_store
            .put::<UnknownBlob, _>(Bytes::from_source(b"summary A leaf".to_vec()))
            .unwrap();
        let mut child_a_bytes = leaf_a.raw.to_vec();
        child_a_bytes.extend_from_slice(&absent.raw);
        let child_a = server_store
            .put::<UnknownBlob, _>(Bytes::from_source(child_a_bytes))
            .unwrap();
        let commit_a = server_store
            .commit(
                collection,
                &server_key,
                entity! { reference*: [child_a, absent] },
            )
            .unwrap();
        // Only this complete producer performs maintenance. The later
        // consumer must acquire its known output, never derive a partial image.
        let maintained = server_store.maintain(summaries, &server_key).await.unwrap();
        let produced = maintained.collection(summaries).unwrap();
        assert_eq!(produced.support().len(), 1);
        assert!(
            produced
                .support()
                .contains(Inline::new(commit_a.data().raw))
        );
        assert_eq!(produced.cover().len(), 1);
        let output = produced.cover().members().next().unwrap();
        let produced_view = produced
            .view::<ReferenceSummaryView>()
            .unwrap()
            .query()
            .unwrap();
        assert!(produced_view.contains_locator(blob_locator(child_a.raw)));
        assert!(produced_view.contains_locator(blob_locator(leaf_a.raw)));
        assert!(!produced_view.contains_locator(blob_locator(absent.raw)));
        drop(produced);
        drop(maintained);

        // B appears after summary(A) was published. It is real selected
        // support, but no known summary describes its separate closure.
        let leaf_b = server_store
            .put::<UnknownBlob, _>(Bytes::from_source(b"uncovered B leaf".to_vec()))
            .unwrap();
        let child_b = server_store
            .put::<UnknownBlob, _>(Bytes::from_source(leaf_b.raw.to_vec()))
            .unwrap();
        let commit_b = server_store
            .commit(collection, &server_key, entity! { reference: child_b })
            .unwrap();
        assert!(
            !produced_view.contains_locator(blob_locator(child_b.raw)),
            "a mistakenly global summary would hide B's existing child"
        );
        let omitted = BTreeSet::from([
            commit_a.data().raw,
            commit_b.data().raw,
            output.raw,
            child_a.raw,
            leaf_a.raw,
            child_b.raw,
            leaf_b.raw,
        ]);
        let producer = server_store.snapshot().unwrap();
        let records: BTreeSet<_> = producer.records().unwrap().map(Result::unwrap).collect();
        assert_eq!(
            records.len(),
            3,
            "two COMMITs and only the existing DERIVE(A)"
        );
        let mut reader_store = MemoryRepo::default();
        for info in producer.blobs().map(Result::unwrap) {
            if !omitted.contains(&info.handle.raw) {
                let bytes = BlobStoreGet::get::<Bytes, _>(&producer, info.handle).unwrap();
                reader_store.put::<UnknownBlob, _>(bytes).unwrap();
            }
        }
        for record in &records {
            reader_store.insert(*record).unwrap();
        }
        let before = reader_store.snapshot().unwrap();
        assert!(before.collection(summaries).unwrap().support().is_empty());
        assert_eq!(before.wants().unwrap().count(), 0);
        assert_eq!(before.proofs().unwrap().count(), 0);
        for handle in &omitted {
            assert!(
                !before
                    .contains_blob(Inline::<Handle<UnknownBlob>>::new(*handle))
                    .unwrap()
            );
        }
        drop(before);
        drop(producer);

        let mut server = bring_up_with_publication_budget(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
            Some(0),
        );
        let mut reader = bring_up_with_publication_budget(
            &net,
            &reader_key,
            reader_store,
            vec![server_key.verifying_key().to_bytes()],
            ReconcileDirection::ReadOnly,
            Some(0),
        );
        advance(&clock, &mut [&mut server, &mut reader], 4).await;
        let mut reconciler = Reconciler::with_backoff(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(1),
        )
        .with_replication(
            ReplicationMode::Full,
            [collection.handle(), summaries.handle()],
        )
        .with_fetch_budget(std::time::Duration::from_secs(2));
        let mut filtered = 0;
        let mut acquired = 0;
        for _ in 0..400 {
            let stats =
                reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
            assert_eq!(stats.wants, 0);
            assert_eq!(stats.attempted, 0);
            assert_eq!(stats.fulfilled, 0);
            assert_eq!(stats.pending, 0);
            assert!(
                stats.replication.speculative_attempted <= RECONCILE_SPECULATIVE_FETCHES_PER_TICK
            );
            filtered += stats.replication.filtered;
            acquired += stats.replication.acquired;
            if omitted
                .iter()
                .all(|handle| reader.try_local(*handle).is_some())
                && filtered > 0
            {
                break;
            }
            advance(&clock, &mut [&mut server, &mut reader], 1).await;
        }
        for handle in &omitted {
            assert!(
                reader.try_local(*handle).is_some(),
                "missing expected blob {handle:?}"
            );
        }
        assert_eq!(
            acquired,
            omitted.len(),
            "all acquisitions land existing exact-H bytes"
        );
        assert!(
            filtered > 0,
            "the fetched summary rejects absent aligned words locally"
        );
        assert!(reader.try_local(absent.raw).is_none());
        let after = reader.snapshot().unwrap();
        let observed = after.collection(summaries).unwrap();
        assert_eq!(observed.support().len(), 1);
        assert!(
            observed
                .support()
                .contains(Inline::new(commit_a.data().raw))
        );
        assert!(
            !observed
                .support()
                .contains(Inline::new(commit_b.data().raw))
        );
        assert_eq!(observed.cover().members().collect::<Vec<_>>(), [output]);
        assert!(
            !observed
                .view::<ReferenceSummaryView>()
                .unwrap()
                .query()
                .unwrap()
                .contains_locator(blob_locator(child_b.raw)),
            "B was hydrated despite the older summary's negative answer"
        );
        assert_eq!(
            after
                .records()
                .unwrap()
                .map(Result::unwrap)
                .collect::<BTreeSet<_>>(),
            records
        );
        assert_eq!(after.wants().unwrap().count(), 0);
        assert_eq!(after.proofs().unwrap().count(), 0);
    }));
}

#[test]
fn full_replication_does_not_apply_a_projected_summary_to_foundational_payloads() {
    use triblespace_core::capability::policy::resource_policy;
    use triblespace_core::collection::{
        CollectionDerive, KIND_COLLECTION_DESCRIPTOR, KIND_COLLECTION_MAPPING, collection_mapping,
        collection_representation, collection_source, mapping_algorithm,
    };
    use triblespace_core::metadata::{self, MetaDescribe};

    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(0xC011_EC83, SimConfig::default());
        let server_key = key(111);
        let reader_key = key(112);
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut server_store = MemoryRepo::default();
        let collection = register(&mut server_store, policy.clone());
        let child = server_store
            .put::<UnknownBlob, _>(Bytes::from_source(b"not in the projection".to_vec()))
            .unwrap();
        let reference = Attribute::<Handle<UnknownBlob>>::named("projected-summary-reference");
        let commit = server_store
            .commit(collection, &server_key, entity! { reference: child })
            .unwrap();
        // The constant-bottom map preserves union but intentionally discards
        // every reference. Its ordinary descriptor/equation suffice here;
        // no executable test mapping or production registry is necessary.
        let projection = server_store
            .register_collection::<SimpleArchive>(entity! {
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_source: collection.handle(),
                collection_representation*: SimpleArchive::describe(),
                resource_policy*: policy.fragment(),
                collection_mapping*: entity! {
                    metadata::tag: KIND_COLLECTION_MAPPING,
                    mapping_algorithm*: entity! {
                        metadata::name: "test-only SimpleArchive constant-bottom map",
                    },
                },
            })
            .unwrap();
        let projected = server_store
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        server_store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &server_key,
                projection.handle(),
                (commit.data(), commit.fingerprint()),
                Handle::<SimpleArchive>::to_hash(projected),
            )))
            .unwrap();
        let summaries = server_store
            .derive::<ReferenceSummaryBlob>(projection, ReferenceSummaryLayout::default(), policy)
            .unwrap();
        let producer = server_store.maintain(summaries, &server_key).await.unwrap();
        let observed = producer.collection(summaries).unwrap();
        assert_eq!(
            observed.support().collection().handle(),
            collection.handle()
        );
        assert!(observed.support().contains(Inline::new(commit.data().raw)));
        assert_eq!(observed.cover().len(), 1);
        assert!(
            !observed
                .view::<ReferenceSummaryView>()
                .unwrap()
                .query()
                .unwrap()
                .contains_locator(blob_locator(child.raw)),
            "the correct summary of the empty projection cannot describe C's payload"
        );
        drop(observed);
        let records: BTreeSet<_> = producer.records().unwrap().map(Result::unwrap).collect();
        assert_eq!(records.len(), 3);
        let mut reader_store = MemoryRepo::default();
        for info in producer.blobs().map(Result::unwrap) {
            if info.handle != child {
                let bytes = BlobStoreGet::get::<Bytes, _>(&producer, info.handle).unwrap();
                reader_store.put::<UnknownBlob, _>(bytes).unwrap();
            }
        }
        for record in &records {
            reader_store.insert(*record).unwrap();
        }
        drop(producer);
        let mut server = bring_up_with_publication_budget(
            &net,
            &server_key,
            server_store,
            Vec::new(),
            ReconcileDirection::WriteOnly,
            Some(0),
        );
        let mut reader = bring_up_with_publication_budget(
            &net,
            &reader_key,
            reader_store,
            vec![server_key.verifying_key().to_bytes()],
            ReconcileDirection::ReadOnly,
            Some(0),
        );
        advance(&clock, &mut [&mut server, &mut reader], 4).await;
        assert!(reader.try_local(child.raw).is_none());
        let mut reconciler = Reconciler::with_backoff(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(1),
        )
        .with_replication(
            ReplicationMode::Full,
            [collection.handle(), projection.handle(), summaries.handle()],
        )
        .with_fetch_budget(std::time::Duration::from_secs(2));
        for _ in 0..240 {
            let stats =
                reconcile_once(&clock, &mut reconciler, &mut reader, &mut [&mut server]).await;
            assert_eq!(stats.wants, 0);
            assert_eq!(
                stats.replication.filtered, 0,
                "no selected summary describes C directly"
            );
            if reader.try_local(child.raw).is_some() {
                break;
            }
            advance(&clock, &mut [&mut server, &mut reader], 1).await;
        }
        assert!(
            reader.try_local(child.raw).is_some(),
            "foundational support is provenance, not permission to filter other physical bytes"
        );
        let after = reader.snapshot().unwrap();
        assert_eq!(
            after
                .records()
                .unwrap()
                .map(Result::unwrap)
                .collect::<BTreeSet<_>>(),
            records
        );
        assert_eq!(after.wants().unwrap().count(), 0);
    }));
}
