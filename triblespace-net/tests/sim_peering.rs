//! Per-collection peering through whole hosts over the deterministic
//! transport: a host peers for a collection only while its pile selects it
//! and is pushed to within two minimum intervals of peering, a local append
//! goes out within the timer, a writer that cannot read delivers without
//! receiving, and neighbour groups split by a partition merge at a swap once
//! it heals.
#![cfg(feature = "sim")]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

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
use triblespace_net::health::{PeerHealth, PeeringHealth};
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
    bring_up_with_publication_budget(net, key, store, Some(0))
}

fn bring_up_with_publication_budget(
    net: &SimNet,
    key: &SigningKey,
    store: MemoryRepo,
    provider_publication_budget: Option<u64>,
) -> Peer<MemoryRepo> {
    let id = EndpointId::from_bytes(&key.verifying_key().to_bytes()).unwrap();
    let harness = net.join(key);
    let (sender, receiver, wiring) = host::wire(id);
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            daemon: None,
            provider_publication_budget,
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

/// Step until `done`, for at most `seconds`; how long it took.
async fn until(
    clock: &Arc<VirtualClock>,
    peers: &mut [&mut Peer<MemoryRepo>],
    seconds: u64,
    what: &str,
    mut done: impl FnMut(&mut [&mut Peer<MemoryRepo>]) -> bool,
) -> Duration {
    let started = clock::mono_now();
    for _ in 0..seconds * 10 {
        if done(peers) {
            return clock::mono_now().duration_since(started);
        }
        SimNet::step(clock, Duration::from_millis(100)).await;
        for peer in peers.iter_mut() {
            peer.refresh();
        }
    }
    panic!("no {what} within {seconds} s");
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

/// What `peer` recorded of its pushes to and receives from `other` for
/// `collection`.
fn pair(
    peer: &Peer<MemoryRepo>,
    collection: CollectionHandle,
    other: [u8; 32],
) -> Option<PeerHealth> {
    peer.health()
        .collections
        .iter()
        .find(|health| health.collection == collection)?
        .peers
        .iter()
        .find(|pair| pair.peer == other)
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
        let owned = commit(
            &mut owner_pile.store,
            &owner_key,
            collection,
            b"the owner's",
        );
        let mut owner = bring_up(&net, &owner_key, owner_pile.store);
        let mut reader = bring_up(&net, &reader_key, reader_pile.store);
        owner.activate_collection(collection);
        reader.activate_collection(collection);

        // The reader holds C but has not selected it, so it refuses, and
        // nothing is pushed to it.
        advance(&clock, &mut [&mut owner, &mut reader], 5).await;
        let refused = peerings(&owner);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].peer == reader_id && refused[0].refused_by_them);
        let refusing = peerings(&reader);
        assert_eq!(refusing.len(), 1, "{refusing:?}");
        assert!(refusing[0].peer == owner_id && refusing[0].refused_by_me);
        assert!(!holds(&mut reader, owned));
        assert!(pair(&owner, collection, reader_id).is_none());

        // Selecting it invites the owner over the connection the refusal
        // left open, and the new peering is pushed to within two minimum
        // intervals.
        write_sync_selection(
            &mut *reader.store(),
            reader_config,
            &reader_key,
            collection,
            true,
        )
        .unwrap();
        reader.refresh();
        let peered = |peer: &Peer<MemoryRepo>, other| {
            peerings(peer).iter().any(|peering| {
                peering.peer == other
                    && peering.collection == collection
                    && peering.peered
                    && peering.sends
                    && peering.receives
            })
        };
        until(
            &clock,
            &mut [&mut owner, &mut reader],
            10,
            "peering",
            |peers| peered(peers[0], reader_id) && peered(peers[1], owner_id),
        )
        .await;
        let pushed = until(
            &clock,
            &mut [&mut owner, &mut reader],
            10,
            "the owner's record",
            |peers| holds(peers[1], owned),
        )
        .await;
        assert!(pushed <= Duration::from_secs(4), "{pushed:?}");
        let confirmed = pair(&owner, collection, reader_id).unwrap();
        assert!(confirmed.pushes.last_ok && confirmed.confirmed.records.is_some());
        assert_eq!(net.dial_count(reader_id, owner_id), 0);
        assert_eq!(net.dial_count(owner_id, reader_id), 1);
    }));
}

/// Two quiet hosts peered for a collection reach the timer's sixty-second
/// cap. An append at the owner then resets its timer, and the reader holds
/// the record within two minimum intervals.
#[test]
fn a_local_append_reaches_the_peer_within_the_timer() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let net = SimNet::new(0x9EE7_1007, SimConfig::default());
        let owner_key = key(106);
        let reader_key = key(107);
        let (mut owner_pile, mut reader_pile) = granted_pair(&owner_key, &reader_key);
        let collection = owner_pile.collection;
        select(&mut owner_pile);
        select(&mut reader_pile);
        let reader_id = reader_key.verifying_key().to_bytes();
        let mut owner = bring_up(&net, &owner_key, owner_pile.store);
        let mut reader = bring_up(&net, &reader_key, reader_pile.store);
        owner.activate_collection(collection);
        reader.activate_collection(collection);
        // Quiet long enough for the timer to reach its cap.
        advance(&clock, &mut [&mut owner, &mut reader], 200).await;
        let before = pair(&owner, collection, reader_id).unwrap();
        assert!(before.pushes.last_ok, "{before:?}");

        let appended = commit(&mut *owner.store(), &owner_key, collection, b"appended");
        owner.refresh();
        let landed = until(
            &clock,
            &mut [&mut owner, &mut reader],
            10,
            "the appended record",
            |peers| holds(peers[1], appended),
        )
        .await;
        assert!(landed <= Duration::from_secs(4), "{landed:?}");
        let after = pair(&owner, collection, reader_id).unwrap();
        assert!(after.pushes.ok > before.pushes.ok);
        assert_ne!(after.confirmed.records, before.confirmed.records);
    }));
}

/// Two hosts peer for a collection neither changes, so only pushes of the
/// confirmed roots cross their connection. They keep it open far past the
/// 120-second idle deadline: nobody dials again.
#[test]
fn pushes_alone_keep_a_peered_connection_open() {
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
        for (peer, other) in [(&owner, reader_id), (&reader, owner_id)] {
            let pair = pair(peer, collection, other).unwrap();
            assert!(pair.pushes.ok >= 5 && pair.pushes.failed == 0, "{pair:?}");
            assert!(
                pair.receives.ok >= 5 && pair.receives.failed == 0,
                "{pair:?}"
            );
        }
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
/// different blobs held in a collection push their references trees to each
/// other, fetch the blobs over `blob/1`, and both hold the union.
#[test]
fn full_hosts_with_equal_records_converge_on_their_held_blobs() {
    assert_eq!(held_blobs_after_peering(true), [true, true]);
}

/// A Demand host is pushed no references tree and pushes none, so neither
/// side fetches the other's blobs: only Full neighbours share held sets.
#[test]
fn a_demand_host_and_a_full_host_compare_no_held_blobs() {
    assert_eq!(held_blobs_after_peering(false), [false, false]);
}

/// Astra's R3 through whole hosts. A writer that cannot read asks the
/// collection's owner to peer with its send flag set, presenting its WRITE
/// grant. The owner accepts without sending: the writer's pushes land its
/// record and grant, and the owner starts no push back. The shared agreed
/// tree contains the writer's delta, never the owner's private record, and
/// the writer holds nothing of the
/// owner's, however long the peering stands.
#[test]
fn a_writer_that_cannot_read_delivers_and_receives_nothing() {
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
        assert!(
            holds(&mut owner, written),
            "owner={:?} writer={:?} owner_peerings={:?} writer_peerings={:?}",
            pair(&owner, collection, writer_id),
            pair(&writer, collection, owner_id),
            peerings(&owner),
            peerings(&writer),
        );
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
        let received = pair(&owner, collection, writer_id).expect("the owner received");
        assert!(received.receives.last_ok && received.receives.ok >= 1);
        assert_eq!((received.pushes.ok, received.pushes.failed), (0, 0));
        let delivered = pair(&writer, collection, owner_id).expect("the writer pushed");
        assert!(delivered.pushes.last_ok && delivered.pushes.ok >= 1);
        assert_eq!((delivered.receives.ok, delivered.receives.failed), (0, 0));
        assert!(received.confirmed.records.is_some(), "{received:?}");
        assert_eq!(received.confirmed.records, delivered.confirmed.records);
        assert!(!holds(&mut writer, owned));

        // Five intervals at their sixty-second cap: the writer's unchanged
        // root goes out as ROOT then DONE each time, and nothing comes back.
        advance(&clock, &mut [&mut owner, &mut writer], 300).await;
        let later = pair(&owner, collection, writer_id).unwrap();
        assert!(later.receives.ok > received.receives.ok && later.receives.failed == 0);
        assert_eq!((later.pushes.ok, later.pushes.failed), (0, 0));
        assert_eq!(later.confirmed.records, received.confirmed.records);
        assert!(!holds(&mut writer, owned));
        let later = pair(&writer, collection, owner_id).unwrap();
        assert_eq!((later.receives.ok, later.receives.failed), (0, 0));
    }));
}

/// Astra's R6 through whole hosts: two neighbour groups formed during a
/// partition merge once it heals, after each side's candidate order was
/// walked to its end and drawn again.
///
/// Each of two readers asks for five of ten servers. Servers write but
/// cannot read: nothing reaches them but the credentials of the readers that
/// ask them, so a server's candidates are the policy root, which is never on
/// the network, and its own group's reader. The partition puts each reader
/// with five servers from the start, and its five asked-for neighbours are
/// healthy servers of its own group. Its swaps walk its order to the end and
/// draw it again, dialling every server of the other group at least twice.
/// Once the partition heals, a reader's walk or its next swap brings in a
/// server of the other group, and with it that group's new record.
/// Credentials the readers present make them candidates of each other once
/// they reach a common server, so the groups may also join reader to reader.
#[test]
fn two_neighbour_groups_merge_after_their_partition_heals() {
    // SWAP_INTERVAL, which the peering task counts from its first tick with
    // the collection selected.
    const SWAP: u64 = 600;
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let net = SimNet::new(0x9EE7_1005, SimConfig::default());
        let root = key(100);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(root.verifying_key()),
            AdmissionPolicy::direct(root.verifying_key()),
        );
        let readers = [key(101), key(102)];
        let servers = [110..115, 120..125].map(|keys| keys.map(key).collect::<Vec<_>>());
        let mut server_piles = servers
            .iter()
            .flatten()
            .map(|server| Pile::new(server.clone(), policy.clone()))
            .collect::<Vec<_>>();
        let collection = server_piles[0].collection;
        let mut reader_piles = readers
            .iter()
            .map(|reader| {
                let mut pile = Pile::new(reader.clone(), policy.clone());
                let read = grant(&root, read_capability(), reader, collection);
                pile.store.insert_proof(read).unwrap();
                pile
            })
            .collect::<Vec<_>>();
        // Each server's WRITE grant and a record it signed. The readers hold
        // them all, which makes every server a candidate of theirs.
        for pile in &mut server_piles {
            let write = grant(&root, write_capability(), &pile.key, collection);
            pile.store.insert_proof(write.clone()).unwrap();
            let record = commit(&mut pile.store, &pile.key, collection, b"a server's");
            for reader in &mut reader_piles {
                reader.store.insert_proof(write.clone()).unwrap();
                reader.store.insert(record).unwrap();
            }
        }
        let id = |key: &SigningKey| key.verifying_key().to_bytes();
        let groups = [0, 1].map(|group| {
            std::iter::once(id(&readers[group]))
                .chain(servers[group].iter().map(id))
                .collect::<Vec<_>>()
        });
        for a in &groups[0] {
            for b in &groups[1] {
                net.partition(*a, *b);
            }
        }
        let mut hosts = reader_piles
            .into_iter()
            .chain(server_piles)
            .map(|mut pile| {
                select(&mut pile);
                let key = pile.key.clone();
                bring_up(&net, &key, pile.store)
            })
            .collect::<Vec<_>>();
        // Servers select first, so that none refuses a reader for want of
        // its own observation and then invites it: an invited peering is not
        // one the reader asked for, and would leave it a slot to fill.
        for host in &mut hosts[2..] {
            host.activate_collection(collection);
        }
        let mut all = hosts.iter_mut().collect::<Vec<_>>();
        advance(&clock, &mut all, 5).await;
        let started = clock::mono_now();
        for host in &mut hosts[..2] {
            host.activate_collection(collection);
        }
        // Readers first, then the servers of group 0 and of group 1.
        let server = |group: usize, index: usize| 2 + 5 * group + index;
        let until = |seconds: u64| {
            (started + Duration::from_secs(seconds))
                .duration_since(clock::mono_now())
                .as_secs()
        };
        let mut all = hosts.iter_mut().collect::<Vec<_>>();
        advance(&clock, &mut all, 60).await;
        for group in 0..2 {
            let mut asked = peerings(&hosts[group])
                .into_iter()
                .filter(|peering| peering.peered && peering.asked)
                .map(|peering| peering.peer)
                .collect::<Vec<_>>();
            asked.sort_unstable();
            let mut own = servers[group].iter().map(id).collect::<Vec<_>>();
            own.sort_unstable();
            assert_eq!(asked, own, "reader {group} asks the servers of its group");
        }

        // A new record in each group, which every server of the group holds.
        let fresh = [0, 1].map(|group| {
            let first = server(group, 0);
            let record = commit(
                &mut *hosts[first].store(),
                &servers[group][0],
                collection,
                b"new in its group",
            );
            for index in 1..5 {
                hosts[server(group, index)].store().insert(record).unwrap();
            }
            record
        });
        let mut all = hosts.iter_mut().collect::<Vec<_>>();
        advance(&clock, &mut all, until(2 * SWAP + 90)).await;
        for group in 0..2 {
            // Each reached the end of its first draw and drew again: it
            // dialled every server of the other group, and one of them twice,
            // which a failed key never is within one draw.
            let dials = servers[1 - group]
                .iter()
                .map(|other| net.dial_count(id(&readers[group]), id(other)))
                .collect::<Vec<_>>();
            assert!(
                dials.iter().all(|dials| *dials >= 1) && dials.iter().any(|dials| *dials >= 2),
                "reader {group} dialled the other group's servers {dials:?} times"
            );
            assert!(holds(&mut hosts[group], fresh[group]));
            assert!(!holds(&mut hosts[group], fresh[1 - group]));
        }

        for a in &groups[0] {
            for b in &groups[1] {
                net.heal(*a, *b);
            }
        }
        // A swap whose replacement fails refills the slot from the order,
        // which can give it back to the neighbour it swapped out: the
        // unreachable root heads every fresh draw, so here about one swap in
        // six merges nothing.
        let healed = clock::mono_now();
        let merged = |hosts: &mut [Peer<MemoryRepo>]| {
            (0..2).all(|group| holds(&mut hosts[group], fresh[1 - group]))
        };
        while !merged(&mut hosts) {
            assert!(
                clock::mono_now().duration_since(healed) < Duration::from_secs(6 * SWAP),
                "the groups did not merge within six swap intervals"
            );
            let mut all = hosts.iter_mut().collect::<Vec<_>>();
            advance(&clock, &mut all, 10).await;
        }
        for group in 0..2 {
            let others = &groups[1 - group];
            assert!(
                peerings(&hosts[group])
                    .iter()
                    .any(|peering| peering.peered && others.contains(&peering.peer)),
                "reader {group} peers with nobody of the other group"
            );
        }
    }));
}

/// JP's two-phase content bootstrap (2026-10-06) through whole hosts. A has
/// no route at all; its pile holds a record of an Open collection that B
/// signed, which makes B its one candidate (phase 1). The connection to B
/// puts B in A's routing table (phase 2), so the provider lookup of A's next
/// draw has a contact, and through B it finds C: a provider of the
/// collection that nothing in A's pile names. C reached B the same way,
/// through B's record in its own pile, and published to B.
#[test]
fn a_host_with_no_routes_finds_a_provider_through_the_signer_its_pile_names() {
    let _guard = test_guard();
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(async {
        let net = SimNet::new(0x9EE7_1006, SimConfig::default());
        let [a_key, b_key, c_key] = [103, 104, 105].map(key);
        let [a_id, b_id, c_id] = [&a_key, &b_key, &c_key].map(|key| key.verifying_key().to_bytes());
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let mut b_pile = Pile::new(b_key.clone(), policy.clone());
        let collection = b_pile.collection;
        let record = commit(&mut b_pile.store, &b_key, collection, b"B's");
        let mut a_pile = Pile::new(a_key.clone(), policy.clone());
        let mut c_pile = Pile::new(c_key.clone(), policy);
        for pile in [&mut a_pile, &mut c_pile] {
            pile.store.insert(record).unwrap();
        }
        for pile in [&mut a_pile, &mut b_pile, &mut c_pile] {
            select(pile);
        }
        let mut b = bring_up(&net, &b_key, b_pile.store);
        let mut c = bring_up_with_publication_budget(&net, &c_key, c_pile.store, None);
        b.activate_collection(collection);
        c.activate_collection(collection);
        advance(&clock, &mut [&mut b, &mut c], 120).await;
        assert!(
            c.health().publication.acknowledged != 0,
            "C published to B: {:?}",
            c.health().publication
        );

        let mut a = bring_up(&net, &a_key, a_pile.store);
        a.activate_collection(collection);
        advance(&clock, &mut [&mut a, &mut b, &mut c], 150).await;
        let peered = |with| {
            peerings(&a).iter().any(|peering| {
                peering.peer == with && peering.collection == collection && peering.peered
            })
        };
        assert!(peered(b_id), "{:?}", peerings(&a));
        assert!(peered(c_id), "A found C through B: {:?}", peerings(&a));
        assert!(net.dial_count(a_id, c_id) >= 1);
    }));
}
