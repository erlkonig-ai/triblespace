//! Per-collection peering through whole hosts over the deterministic
//! transport: a host peers for a collection only while its pile selects it,
//! and a writer that cannot read delivers without receiving.
#![cfg(feature = "sim")]

use std::sync::{Arc, Mutex, OnceLock};

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::capability::{CapabilityHandle, CapabilityProof, CapabilityResource};
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionHandle, CollectionPolicy, CollectionStoreExt,
    private_policy, read_capability, write_capability,
};
use triblespace_core::collection::{
    CollectionCommit, CollectionData, CollectionRead, CollectionRecord, CollectionStore, HeldRead,
    empty_metadata_handle,
};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{
    BlobStoreGet, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace_net::health::{PeeringHealth, RepairHealth};
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::peer::Peer;
use triblespace_net::reconcile::ReplicationMode;
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

/// An owner's and a reader's piles of one collection, both holding the
/// reader's READ grant, so each finds the other a candidate.
fn granted_pair(owner_key: &SigningKey, reader_key: &SigningKey) -> (Pile, Pile) {
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(owner_key.verifying_key()),
        AdmissionPolicy::direct(owner_key.verifying_key()),
    );
    let mut owner = Pile::new(owner_key.clone(), policy.clone());
    let mut reader = Pile::new(reader_key.clone(), policy);
    assert_eq!(reader.collection, owner.collection);
    let grant = CapabilityProof::new(
        CapabilityResource::from(owner.collection),
        owner_key,
        read_capability(),
        reader_key.verifying_key(),
    );
    owner.store.insert_proof(grant.clone()).unwrap();
    reader.store.insert_proof(grant).unwrap();
    (owner, reader)
}

fn select(pile: &mut Pile) {
    write_sync_selection(
        &mut pile.store,
        pile.config,
        &pile.key,
        pile.collection,
        true,
    )
    .unwrap();
}

fn bring_up(net: &SimNet, key: &SigningKey, store: MemoryRepo) -> Peer<MemoryRepo> {
    let id = EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let harness = net.join(key);
    let (sender, receiver, wiring) = host::wire(id);
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            peers: Vec::new(),
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

fn peerings(peer: &Peer<MemoryRepo>) -> Vec<PeeringHealth> {
    peer.health().peerings.clone()
}

/// `root` grants `subject` the `action` on `collection`.
fn grant(
    root: &SigningKey,
    action: CapabilityHandle,
    subject: &SigningKey,
    collection: CollectionHandle,
) -> CapabilityProof {
    CapabilityProof::new(
        CapabilityResource::from(collection),
        root,
        action,
        subject.verifying_key(),
    )
}

/// A record of `collection` that `key` signs over fresh data, kept in `store`
/// with its data.
fn commit(
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

fn holds(peer: &mut Peer<MemoryRepo>, record: CollectionRecord) -> bool {
    peer.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .any(|held| held.unwrap() == record)
}

/// What `peer` recorded of its record pulls of `collection` from `from`.
fn pulls(
    peer: &Peer<MemoryRepo>,
    collection: CollectionHandle,
    from: [u8; 32],
) -> Option<RepairHealth> {
    peer.health()
        .collections
        .iter()
        .find(|health| health.collection == collection)?
        .peers
        .iter()
        .find(|pulls| pulls.peer == from)
        .cloned()
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
        let (mut owner_pile, reader_pile) = granted_pair(&owner_key, &reader_key);
        let collection = owner_pile.collection;
        select(&mut owner_pile);
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

/// Two hosts peer for a collection neither changes, so only announcements
/// cross their connection. They keep it open far past the 120-second idle
/// deadline: nobody dials again.
#[test]
fn announcements_alone_keep_a_peered_connection_open() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let net = SimNet::new(0x9EE7_1002, SimConfig::default());
        let owner_key = key(93);
        let reader_key = key(94);
        let (mut owner_pile, mut reader_pile) = granted_pair(&owner_key, &reader_key);
        let collection = owner_pile.collection;
        select(&mut owner_pile);
        select(&mut reader_pile);
        let mut owner = bring_up(&net, &owner_key, owner_pile.store);
        let mut reader = bring_up(&net, &reader_key, reader_pile.store);
        owner.activate_collection(collection);
        reader.activate_collection(collection);
        let peered = |peer: &Peer<MemoryRepo>| {
            let peerings = peerings(peer);
            peerings.len() == 1 && peerings[0].peered && peerings[0].sends && peerings[0].receives
        };
        advance(&clock, &mut [&mut owner, &mut reader], 5).await;
        assert!(peered(&owner) && peered(&reader));
        let (owner_id, reader_id) = (
            owner_key.verifying_key().to_bytes(),
            reader_key.verifying_key().to_bytes(),
        );
        let dials = || {
            (
                net.dial_count(owner_id, reader_id),
                net.dial_count(reader_id, owner_id),
            )
        };
        let settled = dials();

        advance(&clock, &mut [&mut owner, &mut reader], 300).await;
        assert!(peered(&owner) && peered(&reader));
        assert_eq!(dials(), settled);
    }));
}

/// The owner and the reader hold one record whose data names two blobs, each
/// holding one of them. With `reader_full` both replicate the collection in
/// full, and returns whether each ends up holding both blobs in it.
fn held_blobs_after_peering(reader_full: bool) -> [bool; 2] {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let net = SimNet::new(0x9EE7_1003, SimConfig::default());
        let owner_key = key(95);
        let reader_key = key(96);
        let (mut owner_pile, mut reader_pile) = granted_pair(&owner_key, &reader_key);
        let collection = owner_pile.collection;
        select(&mut owner_pile);
        select(&mut reader_pile);
        let blobs = [b"the owner holds this".as_slice(), b"the reader holds this"]
            .map(|bytes| Blob::<UnknownBlob>::new(Bytes::from_source(bytes.to_vec())));
        let data = Blob::<UnknownBlob>::new(Bytes::from_source(
            blobs
                .iter()
                .flat_map(|blob| blob.get_handle().raw)
                .collect::<Vec<_>>(),
        ));
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &owner_key,
            collection,
            CollectionData::new(data.get_handle().raw),
            empty_metadata_handle(),
        ));
        for (pile, blob) in [(&mut owner_pile, &blobs[0]), (&mut reader_pile, &blobs[1])] {
            pile.store.put::<UnknownBlob, _>(blob.clone()).unwrap();
            pile.store.put::<UnknownBlob, _>(data.clone()).unwrap();
            pile.store.insert(record).unwrap();
        }
        let mut owner = bring_up(&net, &owner_key, owner_pile.store);
        let mut reader = bring_up(&net, &reader_key, reader_pile.store);
        owner.activate_collection(collection);
        reader.activate_collection(collection);
        owner.set_replication(ReplicationMode::Full, [collection]);
        if reader_full {
            reader.set_replication(ReplicationMode::Full, [collection]);
        }
        advance(&clock, &mut [&mut owner, &mut reader], 180).await;
        [&mut owner, &mut reader].map(|peer| {
            let snapshot = peer.snapshot().unwrap();
            let held = snapshot.held(collection).unwrap_or_default();
            blobs.iter().all(|blob| {
                let handle = blob.get_handle();
                held.has_prefix(&handle.raw)
                    && BlobStoreGet::get::<Bytes, UnknownBlob>(&snapshot, handle).is_ok()
            })
        })
    }))
}

/// Astra's R1 through whole hosts: two Full hosts with equal records and
/// different blobs held in a collection announce their held digests, pull
/// each other's references over `blob/1`, and both hold the union.
#[test]
fn full_hosts_with_equal_records_converge_on_their_held_blobs() {
    assert_eq!(held_blobs_after_peering(true), [true, true]);
}

/// A Demand host neither sends nor receives a held digest, so neither side
/// pulls the other's references: only Full neighbours compare held sets.
#[test]
fn a_demand_host_and_a_full_host_compare_no_held_blobs() {
    assert_eq!(held_blobs_after_peering(false), [false, false]);
}

/// Astra's R3 through whole hosts. A writer that cannot read asks the
/// collection's owner to peer with its send flag set, presenting its WRITE
/// grant. The owner accepts without sending: it pulls the writer's record and
/// grant and sends nothing back. The owner keeps a record of its own, so the
/// two roots stay different, and every later announcement of the writer's
/// unchanged root equals the last pull from it that completed: it starts no
/// second walk.
#[test]
fn a_writer_that_cannot_read_delivers_receives_nothing_and_walks_once() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let net = SimNet::new(0x9EE7_1004, SimConfig::default());
        let owner_key = key(97);
        let writer_key = key(98);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner_key.verifying_key()),
            AdmissionPolicy::direct(owner_key.verifying_key()),
        );
        let mut owner_pile = Pile::new(owner_key.clone(), policy.clone());
        let mut writer_pile = Pile::new(writer_key.clone(), policy);
        let collection = owner_pile.collection;
        let write = grant(&owner_key, write_capability(), &writer_key, collection);
        writer_pile.store.insert_proof(write.clone()).unwrap();
        let owned = commit(
            &mut owner_pile.store,
            &owner_key,
            collection,
            b"the owner's",
        );
        let written = commit(
            &mut writer_pile.store,
            &writer_key,
            collection,
            b"the writer's",
        );
        select(&mut owner_pile);
        select(&mut writer_pile);
        let (owner_id, writer_id) = (
            owner_key.verifying_key().to_bytes(),
            writer_key.verifying_key().to_bytes(),
        );
        let mut owner = bring_up(&net, &owner_key, owner_pile.store);
        let mut writer = bring_up(&net, &writer_key, writer_pile.store);
        owner.activate_collection(collection);
        writer.activate_collection(collection);

        advance(&clock, &mut [&mut owner, &mut writer], 30).await;
        assert!(holds(&mut owner, written));
        let delivered = owner.snapshot().unwrap();
        assert!(
            delivered
                .proofs()
                .unwrap()
                .any(|proof| proof.unwrap() == write)
        );
        let peering = |peer: &Peer<MemoryRepo>, other| {
            let peerings = peerings(peer);
            assert!(
                peerings.len() == 1 && peerings[0].peer == other && peerings[0].peered,
                "{peerings:?}"
            );
            peerings[0]
        };
        let at_owner = peering(&owner, writer_id);
        assert!(!at_owner.sends && at_owner.receives, "{at_owner:?}");
        let at_writer = peering(&writer, owner_id);
        assert!(at_writer.sends && !at_writer.receives, "{at_writer:?}");
        let walked = pulls(&owner, collection, writer_id).expect("the owner pulled");
        assert!(walked.last_completed_at.is_some() && !walked.in_flight);
        assert_eq!(walked.first_started_at, walked.last_started_at);

        // Five announcement intervals at their sixty-second cap.
        advance(&clock, &mut [&mut owner, &mut writer], 300).await;
        let later = pulls(&owner, collection, writer_id).unwrap();
        assert_eq!(
            later.last_started_at, walked.last_started_at,
            "the writer's unchanged root started a second walk"
        );
        assert!(!holds(&mut writer, owned));
        assert!(pulls(&writer, collection, owner_id).is_none());
    }));
}
