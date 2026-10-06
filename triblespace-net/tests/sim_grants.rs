//! The grant exchange through whole hosts over the deterministic transport:
//! a grant reaches its subject, and a peering waits for the definitions a
//! credential names.
#![cfg(feature = "sim")]

use std::sync::{Arc, Mutex, OnceLock};

use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, IntoBlob};
use triblespace_core::capability::policy::resource_policy;
use triblespace_core::capability::{
    CapabilityHandle, CapabilityProof, CapabilityResource, capability_action,
};
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    ACTION_READ, AdmissionPolicy, Collection, CollectionHandle, CollectionPolicy,
    CollectionStoreExt, KIND_COLLECTION_DESCRIPTOR, private_policy, read_capability,
    write_capability,
};
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace_core::trible::TribleSet;
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

fn grant(
    issuer: &SigningKey,
    subject: &SigningKey,
    action: CapabilityHandle,
    collection: CollectionHandle,
) -> CapabilityProof {
    CapabilityProof::new(
        CapabilityResource::from(collection),
        issuer,
        action,
        subject.verifying_key(),
    )
}

/// A host on `net`. One that does not pull also does not warm its active
/// collections' definitions, so what it holds came by the exchange.
fn bring_up(
    net: &SimNet,
    key: &SigningKey,
    store: MemoryRepo,
    direction: ReconcileDirection,
) -> Peer<MemoryRepo> {
    let id = EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let harness = net.join(key);
    let (sender, receiver, wiring) = host::wire(id);
    let qos = ReconcileQos { direction };
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

fn run(test: impl AsyncFnOnce()) {
    let _guard = test_guard();
    virtual_clock().reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(test()));
}

fn holds_blob(peer: &mut Peer<MemoryRepo>, handle: CapabilityHandle) -> bool {
    peer.snapshot().unwrap().contains_blob(handle).unwrap()
}

fn proofs(peer: &mut Peer<MemoryRepo>) -> Vec<CapabilityProof> {
    peer.snapshot()
        .unwrap()
        .proofs()
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// A grant written while its subject is unknown to the owner's host reaches
/// the subject: the host dials it, and the subject asks for the proof. The
/// subject holds no descriptor, so the proof waits in memory and lists the
/// collection as available, and its definition is fetched from the owner.
/// It lands once the descriptor does.
#[test]
fn a_signed_grant_dials_its_subject() {
    run(async || {
        let net = SimNet::new(0x6EA7_0001, SimConfig::default());
        let clock = virtual_clock();
        let owner_key = key(61);
        let subject_key = key(62);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner_key.verifying_key()),
            AdmissionPolicy::direct(owner_key.verifying_key()),
        );
        let mut owner_store = MemoryRepo::default();
        let collection = owner_store
            .collection("granted", policy.clone())
            .unwrap()
            .handle();
        let mut owner = bring_up(
            &net,
            &owner_key,
            owner_store,
            ReconcileDirection::Bidirectional,
        );
        let mut subject = bring_up(
            &net,
            &subject_key,
            MemoryRepo::default(),
            ReconcileDirection::Bidirectional,
        );
        owner.activate_collection(collection);
        subject.refresh();
        advance(&clock, &mut [&mut owner, &mut subject], 5).await;
        let (owner_id, subject_id) = (
            owner_key.verifying_key().to_bytes(),
            subject_key.verifying_key().to_bytes(),
        );
        assert_eq!(net.dial_count(owner_id, subject_id), 0);

        let read = grant(&owner_key, &subject_key, read_capability(), collection);
        owner.store().insert_proof(read.clone()).unwrap();
        owner.refresh();
        advance(&clock, &mut [&mut owner, &mut subject], 5).await;
        assert_eq!(net.dial_count(owner_id, subject_id), 1);
        assert_eq!(net.dial_count(subject_id, owner_id), 0);
        assert_eq!(subject.health().available, [collection]);
        assert!(proofs(&mut subject).is_empty());
        assert!(holds_blob(&mut subject, read_capability()));

        // The descriptor arrives by any path; the waiting proof lands.
        subject.store().collection("granted", policy).unwrap();
        subject.refresh();
        advance(&clock, &mut [&mut owner, &mut subject], 2).await;
        assert_eq!(proofs(&mut subject), [read]);
        assert!(subject.health().available.is_empty());
    });
}

/// One node's pile for the custom-definition collection.
struct Pile {
    key: SigningKey,
    store: MemoryRepo,
    config: Collection<SimpleArchive>,
}

impl Pile {
    fn new(key: SigningKey, descriptor: &TribleSet) -> (Self, CollectionHandle) {
        let mut store = MemoryRepo::default();
        let config = store
            .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
            .unwrap();
        let collection = store.put::<SimpleArchive, _>(descriptor.clone()).unwrap();
        (Self { key, store, config }, collection)
    }

    fn select(&mut self, collection: CollectionHandle) {
        write_sync_selection(&mut self.store, self.config, &self.key, collection, true).unwrap();
    }
}

/// READ is bound to a custom definition only the owner holds for sure. A
/// reader asks an acceptor that lacks it, presenting its grant. The
/// acceptor refuses, fetches the definition from the reader, or, when the
/// reader lacks it too, from the grant's root among its connected peers, and
/// then invites the reader.
#[test]
fn a_custom_definition_credential_is_admitted_after_its_definition_is_fetched() {
    for presenter_holds in [true, false] {
        run(async || {
            let net = SimNet::new(0x6EA7_0002, SimConfig::default());
            let clock = virtual_clock();
            let owner_key = key(71);
            let reader_key = key(72);
            let acceptor_key = key(73);
            let definition: Blob<SimpleArchive> = entity! {
                capability_action: ACTION_READ,
                metadata::name: "custom read",
            }
            .facts()
            .clone()
            .to_blob();
            let custom = definition.get_handle();
            let owner_root = AdmissionPolicy::direct(owner_key.verifying_key());
            let descriptor = entity! {
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                resource_policy*: owner_root.binding(custom)
                    + owner_root.binding(write_capability()),
            }
            .facts()
            .clone();
            let (mut owner, collection) = Pile::new(owner_key.clone(), &descriptor);
            let (mut reader, _) = Pile::new(reader_key.clone(), &descriptor);
            let (mut acceptor, _) = Pile::new(acceptor_key.clone(), &descriptor);
            owner
                .store
                .put::<SimpleArchive, _>(definition.clone())
                .unwrap();
            if presenter_holds {
                reader.store.put::<SimpleArchive, _>(definition).unwrap();
            }
            // The reader holds the acceptor's WRITE grant, which makes the
            // acceptor its candidate and admits the acceptor's invitation.
            let write = grant(&owner_key, &acceptor_key, write_capability(), collection);
            let read = grant(&owner_key, &reader_key, custom, collection);
            for proof in [&write, &read] {
                owner.store.insert_proof(proof.clone()).unwrap();
                reader.store.insert_proof(proof.clone()).unwrap();
            }
            acceptor.store.insert_proof(write).unwrap();
            // The owner does not select C, so it asks nobody, and nobody
            // learns the definition from a request of its own.
            acceptor.select(collection);
            let reader_config = reader.config;
            let serving = ReconcileDirection::WriteOnly;
            let mut owner = bring_up(&net, &owner_key, owner.store, serving);
            let mut acceptor = bring_up(&net, &acceptor_key, acceptor.store, serving);
            let mut reader = bring_up(&net, &reader_key, reader.store, serving);
            for peer in [&mut owner, &mut acceptor, &mut reader] {
                peer.activate_collection(collection);
            }
            let (owner_id, acceptor_id, reader_id) = (
                owner_key.verifying_key().to_bytes(),
                acceptor_key.verifying_key().to_bytes(),
                reader_key.verifying_key().to_bytes(),
            );
            // The owner dials the subjects of the grants it signed, so the
            // acceptor is connected to it before the reader asks.
            advance(&clock, &mut [&mut owner, &mut acceptor, &mut reader], 5).await;
            assert_eq!(net.dial_count(owner_id, acceptor_id), 1);
            assert!(!holds_blob(&mut acceptor, custom));

            write_sync_selection(
                &mut *reader.store(),
                reader_config,
                &reader_key,
                collection,
                true,
            )
            .unwrap();
            reader.refresh();
            advance(&clock, &mut [&mut owner, &mut acceptor, &mut reader], 10).await;
            assert!(holds_blob(&mut acceptor, custom), "{presenter_holds}");
            assert_eq!(holds_blob(&mut reader, custom), presenter_holds);
            let peerings = acceptor.health().peerings.clone();
            let peering = peerings
                .iter()
                .find(|peering| peering.peer == reader_id)
                .unwrap_or_else(|| panic!("{peerings:?}"));
            assert!(peering.peered && peering.sends, "{peering:?}");
            assert!(!peering.refused_by_me);
        });
    }
}
