//! Per-collection peering through whole hosts over the deterministic
//! transport: a host peers for a collection only while its pile selects it.
#![cfg(feature = "sim")]

use std::sync::{Arc, Mutex, OnceLock};

use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::capability::{CapabilityProof, CapabilityResource};
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionHandle, CollectionPolicy, CollectionStoreExt,
    private_policy, read_capability,
};
use triblespace_core::repo::CapabilityProofStore;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_net::health::PeeringHealth;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::inventory::{ReconcileDirection, ReconcileQos};
use triblespace_net::peer::Peer;
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

/// A pile holding the collection `policy` names and its configuration.
struct Pile {
    key: SigningKey,
    store: MemoryRepo,
    config: Collection<SimpleArchive>,
    collection: CollectionHandle,
}

impl Pile {
    fn new(key: SigningKey, policy: CollectionPolicy) -> Self {
        let mut store = MemoryRepo::default();
        let config = store
            .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
            .unwrap();
        let collection = store.collection("peered", policy).unwrap().handle();
        Self {
            key,
            store,
            config,
            collection,
        }
    }
}

fn bring_up(net: &SimNet, key: &SigningKey, store: MemoryRepo) -> Peer<MemoryRepo> {
    let id = EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let harness = net.join(key);
    let (sender, receiver, wiring) = host::wire(id);
    let qos = ReconcileQos {
        direction: ReconcileDirection::Bidirectional,
    };
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            peers: Vec::new(),
            qos,
            provider_publication_budget: Some(0),
            bind: None,
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

fn peerings(peer: &Peer<MemoryRepo>) -> Vec<PeeringHealth> {
    peer.health().peerings.clone()
}

#[test]
fn a_host_peers_for_a_collection_only_while_its_pile_selects_it() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let net = SimNet::new(0x9EE7_1001, SimConfig::default());
        let owner_key = key(91);
        let reader_key = key(92);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner_key.verifying_key()),
            AdmissionPolicy::direct(owner_key.verifying_key()),
        );
        let mut owner_pile = Pile::new(owner_key.clone(), policy.clone());
        let mut reader_pile = Pile::new(reader_key.clone(), policy);
        let collection = owner_pile.collection;
        assert_eq!(reader_pile.collection, collection);
        // Both hold the reader's grant, so each finds the other a candidate.
        let grant = CapabilityProof::new(
            CapabilityResource::from(collection),
            &owner_key,
            read_capability(),
            reader_key.verifying_key(),
        );
        owner_pile.store.insert_proof(grant.clone()).unwrap();
        reader_pile.store.insert_proof(grant).unwrap();
        write_sync_selection(
            &mut owner_pile.store,
            owner_pile.config,
            &owner_pile.key,
            collection,
            true,
        )
        .unwrap();
        let (owner_id, reader_id) = (
            owner_key.verifying_key().to_bytes(),
            reader_key.verifying_key().to_bytes(),
        );
        let reader_config = reader_pile.config;
        let mut owner = bring_up(&net, &owner_key, owner_pile.store);
        let mut reader = bring_up(&net, &reader_key, reader_pile.store);
        owner.activate_collection(collection);
        reader.activate_collection(collection);

        // The reader holds C but has not selected it, so it refuses.
        advance(&clock, &mut [&mut owner, &mut reader], 5).await;
        let refused = peerings(&owner);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].peer == reader_id && refused[0].refused_by_them);
        let refusing = peerings(&reader);
        assert_eq!(refusing.len(), 1, "{refusing:?}");
        assert!(refusing[0].peer == owner_id && refusing[0].refused_by_me);

        // Selecting it invites the owner over the connection the refusal
        // left open.
        write_sync_selection(
            &mut *reader.store(),
            reader_config,
            &reader_key,
            collection,
            true,
        )
        .unwrap();
        reader.refresh();
        advance(&clock, &mut [&mut owner, &mut reader], 5).await;
        for (peer, other) in [(&owner, reader_id), (&reader, owner_id)] {
            let peered = peerings(peer);
            assert_eq!(peered.len(), 1, "{peered:?}");
            let peering = peered[0];
            assert!(peering.peer == other && peering.collection == collection);
            assert!(
                peering.peered && peering.sends && peering.receives,
                "{peering:?}"
            );
        }
        assert_eq!(net.dial_count(reader_id, owner_id), 0);
        assert_eq!(net.dial_count(owner_id, reader_id), 1);
    }));
}
