//! Lost root announcements recover after a partition, beside a healthy replica.
//!
//! SimNet directly delivers topic wakes to unpartitioned subscribers. It models
//! packet loss and periodic-announcement recovery here, not stock gossip mesh
//! membership, forwarding, discovery, or partition reconnection.
#![cfg(feature = "sim")]

use std::sync::Arc;
use std::time::Duration;

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use iroh_base::{EndpointAddr, EndpointId};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt, empty_metadata_handle,
};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};
use triblespace_net::health::RepairFrontier;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::{ReconcileDirection, ReconcileQos};
use triblespace_net::peer::Peer;
use triblespace_net::transport::sim::{SimConfig, SimNet};

fn bring_up(
    net: &SimNet,
    key: &SigningKey,
    store: MemoryRepo,
    peers: &[[u8; 32]],
    direction: ReconcileDirection,
) -> Peer<MemoryRepo> {
    let id = EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let (sender, receiver, wiring) = host::wire(id);
    let qos = ReconcileQos { direction };
    tokio::task::spawn_local(host::run_host(
        net.join(key),
        PeerConfig {
            peers: peers
                .iter()
                .map(|peer| EndpointAddr::from(EndpointId::from_bytes(peer).unwrap()))
                .collect(),
            qos,
            // Gossip discovers the initial participants. This test measures
            // repair recovery, not the timing of provider publication.
            provider_publication_budget: Some(0),
        },
        wiring,
    ));
    Peer::with_wiring(store, qos, sender, receiver)
}

fn append(
    store: &mut MemoryRepo,
    key: &SigningKey,
    collection: CollectionHandle,
    body: &[u8],
) -> CollectionRecord {
    let data = store
        .put::<UnknownBlob, _>(Bytes::from_source(body.to_vec()))
        .unwrap();
    let record = CollectionRecord::Commit(CollectionCommit::sign(
        key,
        collection,
        CollectionData::new(data.raw),
        empty_metadata_handle(),
    ));
    store.insert(record).unwrap();
    record
}

fn contains(peer: &mut Peer<MemoryRepo>, expected: CollectionRecord) -> bool {
    peer.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .any(|record| record.unwrap() == expected)
}

fn frontier(peer: &Peer<MemoryRepo>, collection: CollectionHandle) -> Option<RepairFrontier> {
    peer.health()
        .collections
        .iter()
        .find(|state| state.collection == collection)
        .and_then(|state| state.local_frontier)
}

async fn step(clock: &Arc<VirtualClock>, peers: &mut [&mut Peer<MemoryRepo>]) {
    SimNet::step(clock, Duration::from_millis(100)).await;
    for peer in peers {
        peer.refresh();
    }
}

#[test]
fn periodic_root_announcements_recover_a_healed_partition_beside_a_healthy_replica() {
    // This integration-test binary has one independent virtual timeline.
    let clock = VirtualClock::new(hifitime::Epoch::from_gregorian_utc_at_midnight(2026, 1, 1));
    clock::install_virtual(clock.clone()).expect("install virtual clock before any store use");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime.block_on(local.run_until(async {
        let net = SimNet::new(
            0xA11C_E123,
            SimConfig {
                latency: Duration::ZERO..Duration::ZERO,
            },
        );
        let a_key = SigningKey::from_bytes(&[121; 32]);
        let b_key = SigningKey::from_bytes(&[122; 32]);
        let c_key = SigningKey::from_bytes(&[123; 32]);
        let a_id = a_key.verifying_key().to_bytes();
        let b_id = b_key.verifying_key().to_bytes();
        let c_id = c_key.verifying_key().to_bytes();
        let roots = [
            a_key.verifying_key(),
            b_key.verifying_key(),
            c_key.verifying_key(),
        ];
        let admission = AdmissionPolicy::quorum(roots, 1, None).unwrap();
        let policy = CollectionPolicy::new(admission.clone(), admission);
        let mut a_store = MemoryRepo::default();
        let collection = a_store
            .collection("transient-replica-recovery", policy.clone())
            .unwrap()
            .handle();
        let mut b_store = MemoryRepo::default();
        let mut c_store = MemoryRepo::default();
        for store in [&mut b_store, &mut c_store] {
            assert_eq!(
                store
                    .collection("transient-replica-recovery", policy.clone())
                    .unwrap()
                    .handle(),
                collection,
            );
        }
        let original = append(&mut a_store, &a_key, collection, b"initial shared record");
        // Both sources begin with the exact same signed record. B is not a
        // relay for later A writes: WriteOnly is an explicit supported mode.
        b_store.insert(original).unwrap();
        // An exact blob read will prove B's connection stays usable without
        // making a new collection root or forcing a gratuitous repair pull.
        let control_bytes =
            Bytes::from_source(b"B remains reachable during A's partition".to_vec());
        let control = b_store
            .put::<UnknownBlob, _>(control_bytes.clone())
            .unwrap();
        let mut a = bring_up(
            &net,
            &a_key,
            a_store,
            &[c_id],
            ReconcileDirection::WriteOnly,
        );
        let mut b = bring_up(
            &net,
            &b_key,
            b_store,
            &[c_id],
            ReconcileDirection::WriteOnly,
        );
        let mut c = bring_up(
            &net,
            &c_key,
            c_store,
            &[a_id, b_id],
            ReconcileDirection::ReadOnly,
        );
        for peer in [&mut a, &mut b, &mut c] {
            peer.activate_collection(collection);
        }
        let mut initial_root = None;
        for _ in 0..400 {
            step(&clock, &mut [&mut a, &mut b, &mut c]).await;
            let root = frontier(&a, collection);
            if root.is_some()
                && [&b, &c].into_iter().all(|peer| {
                    frontier(peer, collection).is_some_and(|other| {
                        let root = root.unwrap();
                        other.records == root.records
                            && other.authorization_evidence == root.authorization_evidence
                    })
                })
                && contains(&mut c, original)
            {
                initial_root = root;
                break;
            }
        }
        let initial_root = initial_root.expect("all three replicas must start at R0");
        // These peers share semantic state, not necessarily payload residency.
        // Keep each peer's own product root as the unchanged-state control.
        let initial_b = frontier(&b, collection).unwrap();
        let initial_c = frontier(&c, collection).unwrap();
        assert!(contains(&mut c, original));
        let cut_at = clock::mono_now();
        net.partition(a_id, c_id);
        net.partition(a_id, b_id);
        let fresh = append(
            &mut *a.store(),
            &a_key,
            collection,
            b"only A has this later record",
        );
        a.refresh();
        // A's first changed-root wake, and later announcements while isolated,
        // cannot cross either cut. There should be no blind repair request to
        // manufacture an error for a root that C has not heard about.
        for _ in 0..400 {
            step(&clock, &mut [&mut a, &mut b, &mut c]).await;
        }
        let isolated_root = frontier(&a, collection).expect("A has the new R1");
        assert_ne!(isolated_root, initial_root);
        assert!(contains(&mut a, fresh));
        assert_eq!(frontier(&b, collection), Some(initial_b));
        assert_eq!(frontier(&c, collection), Some(initial_c));
        assert!(!contains(&mut c, fresh));
        assert!(
            !contains(&mut b, fresh),
            "the healthy replica must not mask A's loss"
        );

        let serves_before = b.health().blob_serving.completed;
        let acquired = {
            let mut read = Box::pin(c.acquire(control));
            let mut acquired = None;
            for _ in 0..400 {
                tokio::select! {
                    result = &mut read => {
                        acquired = result.unwrap();
                        break;
                    }
                    () = async { step(&clock, &mut [&mut a, &mut b]).await } => {}
                }
            }
            acquired
        };
        assert_eq!(
            acquired,
            Some(control_bytes),
            "the uncut C-to-B path must work"
        );
        step(&clock, &mut [&mut a, &mut b, &mut c]).await;
        assert!(b.health().blob_serving.completed > serves_before);
        assert_eq!(frontier(&b, collection), Some(initial_b));
        assert_eq!(frontier(&c, collection), Some(initial_c));
        assert!(!contains(&mut c, fresh));

        // Healing SimNet only restores dialing; it emits no gossip wake or
        // NeighborUp. A's root does not change again. Its next periodic
        // announcement must rescue C while B remains healthy at R0. The A-B
        // cut stays in place, preventing B from masking the direct recovery.
        let healed_at = clock::mono_now();
        net.heal(a_id, c_id);
        let mut recovered = false;
        for _ in 0..1_000 {
            step(&clock, &mut [&mut a, &mut b, &mut c]).await;
            if contains(&mut c, fresh) {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "A's lost root wake did not recover periodically beside healthy B",
        );
        assert!(clock::mono_now().duration_since(healed_at) <= Duration::from_secs(100));
        assert!(clock::mono_now().duration_since(cut_at) < Duration::from_secs(300));
        assert!(contains(&mut c, original));
        assert!(
            !contains(&mut b, fresh),
            "B cannot supply A's missing record"
        );
        assert_eq!(frontier(&a, collection), Some(isolated_root));
        for peer in [&a, &b, &c] {
            assert_eq!(peer.health().publication.attempts, 0);
        }
        drop((a.into_store(), b.into_store(), c.into_store()));
    }));
}
