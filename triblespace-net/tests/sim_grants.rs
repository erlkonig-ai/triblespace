//! Grants through whole hosts over the deterministic transport: a grant
//! reaches its subject with its collection's descriptor once discovery
//! connects them, a peering waits for the definitions a credential names,
//! and a definition is fetched no larger than policy metadata. Nobody dials
//! on a grant's behalf.
#![cfg(feature = "sim")]

use std::sync::{Arc, Mutex, OnceLock};

use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::utf8string::UTF8String;
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

/// A host on `net`. No host publishes provider records or starts with a
/// route, so the warmup of its active collections finds no holder of a
/// definition it lacks, and what it holds came by the exchange.
fn bring_up(net: &SimNet, key: &SigningKey, store: MemoryRepo) -> Peer<MemoryRepo> {
    let id = EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let harness = net.join(key);
    let (sender, receiver, wiring) = host::wire(id);
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            daemon: None,
            provider_publication_budget: Some(0),
            bind: None,
        },
        wiring,
    ));
    Peer::with_wiring(store, sender, receiver)
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

/// The owner's host selects C, so its discovery dials C's READ grantee, a
/// key its grants name, and lists C to it. The subject holds no descriptor,
/// has not selected the collection, and can look nothing up (no host
/// publishes to the DHT): it walks C's grants from the owner, keeps the one
/// naming it in memory, and fetches the descriptor from the owner over the
/// same connection, with the definition the proof names and the
/// collection's name; the proof lands. The subject dialled nobody, and the
/// collection is not active on it.
#[test]
fn discovery_brings_a_read_grantee_its_grant_and_descriptor() {
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
        select(&mut owner_store, &owner_key, collection);
        let mut owner = bring_up(&net, &owner_key, owner_store);
        let mut subject = bring_up(&net, &subject_key, MemoryRepo::default());
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
        advance(&clock, &mut [&mut owner, &mut subject], 10).await;
        assert!(net.dial_count(owner_id, subject_id) >= 1);
        assert_eq!(net.dial_count(subject_id, owner_id), 0);
        assert!(
            holds_blob(&mut subject, collection),
            "the descriptor came from the owner"
        );
        assert!(holds_blob(&mut subject, read_capability()));
        assert_eq!(proofs(&mut subject), [read]);
        let name = IntoBlob::<UTF8String>::to_blob("granted").get_handle();
        assert!(
            subject.snapshot().unwrap().contains_blob(name).unwrap(),
            "the collection's name came with the descriptor"
        );
        assert!(
            subject.health().peerings.is_empty(),
            "the collection is not active on the subject"
        );
    });
}

/// A stranger grants the subject a capability whose definition is a 4 MiB
/// archive of its choosing: a valid definition naming READ, padded with
/// filler, so the stranger's own index offers the grant (a definition that
/// does not read as one is junk and never offered). The grant reaches the
/// subject, which fetches the descriptor and the definitions a proof naming
/// it names, but no more than policy metadata can take: the descriptor is
/// stored, the definition is not.
/// The grant is evidence under the stranger's own descriptor, so it lands,
/// as any proof naming this node does once its descriptor is held; what a
/// stranger can make the subject store per grant is bounded to that proof
/// and two metadata blobs.
#[test]
fn a_stranger_cannot_make_the_subject_store_a_large_definition() {
    run(async || {
        let net = SimNet::new(0x6EA7_0003, SimConfig::default());
        let clock = virtual_clock();
        let stranger_key = key(81);
        let subject_key = key(82);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(stranger_key.verifying_key()),
            AdmissionPolicy::direct(stranger_key.verifying_key()),
        );
        let mut stranger_store = MemoryRepo::default();
        let collection = stranger_store.collection("bait", policy).unwrap().handle();
        select(&mut stranger_store, &stranger_key, collection);
        let junk: Blob<SimpleArchive> = {
            use triblespace_core::trible::Trible;
            let mut facts = entity! { capability_action: ACTION_READ }.facts().clone();
            for index in 0..(4u64 << 20) / 64 {
                let mut raw = [0x5A_u8; 64];
                raw[..8].copy_from_slice(&index.to_be_bytes());
                facts.insert(&Trible::force_raw(raw).unwrap());
            }
            facts.to_blob()
        };
        assert!(junk.bytes.len() >= 4 << 20);
        let junk_handle = junk.get_handle();
        stranger_store.put::<SimpleArchive, _>(junk).unwrap();
        let bait = grant(&stranger_key, &subject_key, junk_handle, collection);
        stranger_store.insert_proof(bait.clone()).unwrap();
        let mut stranger = bring_up(&net, &stranger_key, stranger_store);
        let mut subject = bring_up(&net, &subject_key, MemoryRepo::default());
        stranger.activate_collection(collection);
        subject.refresh();
        advance(&clock, &mut [&mut stranger, &mut subject], 10).await;
        assert!(
            holds_blob(&mut subject, collection),
            "the grant arrived, and its descriptor with it"
        );
        assert!(
            !holds_blob(&mut subject, junk_handle),
            "the subject stored the stranger's 4 MiB definition"
        );
        assert_eq!(proofs(&mut subject), [bait]);
    });
}

/// Select `collection` for sync in `store`'s configuration.
fn select(store: &mut MemoryRepo, key: &SigningKey, collection: CollectionHandle) {
    let config = store
        .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
        .unwrap();
    write_sync_selection(store, config, key, collection, true).unwrap();
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
/// then invites the reader. A reader that lacks the definition completes its
/// own grant the same way.
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
            // Only the reader holds its own READ grant: the acceptor, which
            // takes part in C, learns of it no earlier than the reader asks.
            let write = grant(&owner_key, &acceptor_key, write_capability(), collection);
            let read = grant(&owner_key, &reader_key, custom, collection);
            owner.store.insert_proof(write.clone()).unwrap();
            for proof in [&write, &read] {
                reader.store.insert_proof(proof.clone()).unwrap();
            }
            acceptor.store.insert_proof(write).unwrap();
            // The owner does not select C, so it asks nobody, and nobody
            // learns the definition from a request of its own.
            acceptor.select(collection);
            let reader_config = reader.config;
            let mut owner = bring_up(&net, &owner_key, owner.store);
            let mut acceptor = bring_up(&net, &acceptor_key, acceptor.store);
            let mut reader = bring_up(&net, &reader_key, reader.store);
            for peer in [&mut owner, &mut acceptor, &mut reader] {
                peer.activate_collection(collection);
            }
            let (owner_id, acceptor_id, reader_id) = (
                owner_key.verifying_key().to_bytes(),
                acceptor_key.verifying_key().to_bytes(),
                reader_key.verifying_key().to_bytes(),
            );
            // The acceptor's discovery dials C's root, so the acceptor is
            // connected to the owner before the reader asks.
            advance(&clock, &mut [&mut owner, &mut acceptor, &mut reader], 5).await;
            assert!(net.dial_count(acceptor_id, owner_id) >= 1);
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
            // A grantee completes its own waiting grant: a reader that
            // lacked the definition fetched it too.
            assert!(holds_blob(&mut reader, custom), "{presenter_holds}");
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
