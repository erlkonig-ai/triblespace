//! A reachable second replica must not erase recovery work for a failed first one.
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

async fn step(clock: &Arc<VirtualClock>, peers: &mut [&mut Peer<MemoryRepo>]) {
    SimNet::step(clock, Duration::from_millis(100)).await;
    for peer in peers {
        peer.refresh();
    }
}

#[test]
fn transient_failed_replica_remains_retryable_with_a_healthy_other_replica() {
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
        let mut initially_compared = false;
        for _ in 0..400 {
            step(&clock, &mut [&mut a, &mut b, &mut c]).await;
            let health = c.health();
            initially_compared = [a_id, b_id].into_iter().all(|id| {
                health.collections.iter().any(|state| {
                    state.collection == collection
                        && state
                            .peers
                            .iter()
                            .any(|peer| peer.peer == id && peer.comparison.is_some())
                })
            });
            if initially_compared && contains(&mut c, original) {
                break;
            }
        }
        assert!(
            initially_compared,
            "both replicas must be known before the fault"
        );
        assert!(contains(&mut c, original));
        let cut_at = clock::mono_now();
        net.partition(a_id, c_id);
        let fresh = append(
            &mut *a.store(),
            &a_key,
            collection,
            b"only A has this later record",
        );
        a.refresh();
        let mut failed_at = None;
        let mut healthy_b_after_cut = false;
        for _ in 0..400 {
            step(&clock, &mut [&mut a, &mut b, &mut c]).await;
            let health = c.health();
            for state in &health.collections {
                if state.collection != collection {
                    continue;
                }
                for peer in &state.peers {
                    if peer.peer == a_id {
                        failed_at = peer.last_failure_at.filter(|at| *at >= cut_at);
                    } else if peer.peer == b_id {
                        healthy_b_after_cut = peer.comparison.is_some()
                            && peer.last_completed_at.is_some_and(|at| at > cut_at)
                            && peer.last_failure_at.is_none();
                    }
                }
            }
            if failed_at.is_some() && healthy_b_after_cut {
                break;
            }
        }
        assert!(
            failed_at.is_some(),
            "the A repair must actually fail before healing"
        );
        assert!(
            healthy_b_after_cut,
            "B must remain a successfully repaired candidate"
        );
        assert!(!contains(&mut c, fresh));
        assert!(
            !contains(&mut b, fresh),
            "the healthy replica must not mask A's loss"
        );

        // Healing SimNet only restores dialing; it emits no gossip wake or
        // NeighborUp. A's new root was published while cut, so there is no new
        // root transition to rescue a forgotten participant. Recovery must
        // use bounded periodic retries before the existing five-minute lease.
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
            "a transiently failed A was forgotten while healthy B suppressed rediscovery",
        );
        assert!(clock::mono_now().duration_since(cut_at) < Duration::from_secs(300));
        drop((a.into_store(), b.into_store(), c.into_store()));
    }));
}
