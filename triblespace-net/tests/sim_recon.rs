//! The one `recon/1` stream of a connection and the `walk/1` streams beside
//! it, through whole hosts on the deterministic transport: 130 collections
//! converge both ways between two neighbours within the push estimate, a
//! partition ends the peering and the push after it asks only for what was
//! appended meanwhile, a receiver that already holds part of a tree from a
//! third peer is pushed less, and `recon/1` takes none of the request
//! permits blob streams
//! wait for. When `recon/1` ends the connection closes: a peer that stops
//! reading it loses the connection, a neighbour whose stream ends comes back
//! through a fresh dial, and a key that ends every stream is dialled no more
//! than once per reshuffle interval. A peer that speaks `recon/1` by hand
//! encodes its frames with [`Frame`]; what crosses a tapped host's streams
//! is counted by frame kind.
#![cfg(feature = "sim")]

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use futures::FutureExt as _;
use iroh_base::EndpointId;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt, empty_metadata_handle,
    private_policy,
};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};
use triblespace_net::health::PeerHealth;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::peer::Peer;
use triblespace_net::protocol::{OP_FIND_VALUE, PILE_SYNC_ALPN, TAG_DHT, TAG_RECON, TAG_WALK};
use triblespace_net::recon::{FRAME_OPEN, Flags, Frame};
use triblespace_net::transport::sim::{
    Crossed, SimConfig, SimConn, SimNet, SimRecvStream, SimSendStream, Taps,
};
use triblespace_net::transport::{Conn, Harness, PeerId, RecvStream, SendStream, Transport};
use triblespace_net::walk_stream::{FRAME_OPEN as FRAME_WALK_OPEN, FRAME_VALUE_REQUEST};

// Test-only leaf classification from the uniform SUBTREE depth, not a wire kind.
const FRAME_LEAF: u8 = 254;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn id(key: &SigningKey) -> PeerId {
    key.verifying_key().to_bytes()
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

fn run(test: impl AsyncFnOnce(Arc<VirtualClock>)) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let clock = virtual_clock();
    clock.reset();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(tokio::task::LocalSet::new().run_until(test(clock)));
}

/// A host on `harness` over `store`. Its DHT lookups go through the peers
/// its pile names, once it has connected to them. It publishes no provider
/// records.
fn bring_up<T: Transport>(
    harness: Harness<T>,
    key: &SigningKey,
    store: MemoryRepo,
) -> Peer<MemoryRepo> {
    let (sender, receiver, wiring) = host::wire(EndpointId::from_bytes(&id(key)).unwrap());
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

async fn step(clock: &VirtualClock, peers: &mut [&mut Peer<MemoryRepo>]) {
    SimNet::step(clock, Duration::from_millis(100)).await;
    for peer in peers.iter_mut() {
        peer.refresh();
    }
}

async fn advance(clock: &VirtualClock, peers: &mut [&mut Peer<MemoryRepo>], seconds: u64) {
    for _ in 0..seconds * 10 {
        step(clock, peers).await;
    }
}

/// Step until `done` answers, for at most `seconds`.
async fn until<T>(
    clock: &VirtualClock,
    peers: &mut [&mut Peer<MemoryRepo>],
    seconds: u64,
    what: &str,
    mut done: impl FnMut(&mut [&mut Peer<MemoryRepo>]) -> Option<T>,
) -> T {
    for _ in 0..seconds * 10 {
        if let Some(done) = done(peers) {
            return done;
        }
        step(clock, peers).await;
    }
    panic!("no {what} within {seconds} s");
}

/// Hold the collection `name` names, which anyone may read and `writers` may
/// write.
fn hold(store: &mut MemoryRepo, name: &str, writers: &[&SigningKey]) -> CollectionHandle {
    let writers = AdmissionPolicy::quorum(writers.iter().map(|key| key.verifying_key()), 1, None);
    let policy = CollectionPolicy::new(AdmissionPolicy::Open, writers.unwrap());
    store.collection(name, policy).unwrap().handle()
}

/// Select `collection` for sync in the pile `key` configures.
fn select(store: &mut MemoryRepo, key: &SigningKey, collection: CollectionHandle) {
    let config = store
        .collection(CONFIG_COLLECTION_NAME, private_policy(key.verifying_key()))
        .unwrap();
    write_sync_selection(store, config, key, collection, true).unwrap();
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

fn peered(peer: &Peer<MemoryRepo>, other: PeerId) -> bool {
    peer.health()
        .peerings
        .iter()
        .any(|peering| peering.peer == other && peering.peered)
}

/// What `peer` recorded of its pushes to and receives from `other` for
/// `collection`.
fn pair(
    peer: &Peer<MemoryRepo>,
    collection: CollectionHandle,
    other: PeerId,
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

fn records_of(peer: &mut Peer<MemoryRepo>, collection: CollectionHandle) -> usize {
    peer.snapshot()
        .unwrap()
        .records()
        .unwrap()
        .filter(|record| record.as_ref().unwrap().collection() == collection)
        .count()
}

/// The frames that crossed `taps` on walk streams to `peer` since the first
/// `from`: those this side sent, and those it heard, by kind.
fn walked(taps: &Taps, from: usize, peer: PeerId) -> (Vec<u8>, Vec<u8>) {
    let crossed = taps.since(from, peer, TAG_WALK);
    let kinds = |sent: bool| {
        crossed
            .iter()
            .filter(|crossed: &&Crossed| crossed.sent == sent)
            .map(|crossed| {
                if crossed.walk_depth == Some(32) {
                    FRAME_LEAF
                } else {
                    crossed.kind
                }
            })
            .collect::<Vec<_>>()
    };
    (kinds(true), kinds(false))
}

fn count(kinds: &[u8], kind: u8) -> usize {
    kinds.iter().filter(|crossed| **crossed == kind).count()
}

/// One `recon/1` frame as written: kind, big-endian length, payload.
fn encoded(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![kind];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn send_frame(send: &mut SimSendStream, frame: &Frame) {
    let (kind, payload) = frame.encode();
    send.write_all(&encoded(kind, &payload)).await.unwrap();
}

/// Open `recon/1` on a connection this side dialled: its tag, and the
/// opening frame with the dialler's `sequence`.
async fn open_recon(conn: &SimConn, sequence: u64) -> (SimSendStream, Frames) {
    let (mut send, recv) = conn.open_bi().await.unwrap();
    send.write_all(&[TAG_RECON]).await.unwrap();
    send.write_all(&encoded(FRAME_OPEN, &sequence.to_be_bytes()))
        .await
        .unwrap();
    (send, Frames::new(recv))
}

/// The frames read off one `recon/1` stream.
struct Frames {
    recv: SimRecvStream,
    /// What was read of frames not yet taken.
    buffer: Vec<u8>,
}

impl Frames {
    fn new(recv: SimRecvStream) -> Self {
        Self {
            recv,
            buffer: Vec::new(),
        }
    }

    /// The next frame's kind and payload, or `None` at the end of the
    /// stream. Cancelling it loses nothing.
    async fn next(&mut self) -> io::Result<Option<(u8, Vec<u8>)>> {
        loop {
            if let Some(length) = self.buffer.get(1..5) {
                let length = 5 + u32::from_be_bytes(length.try_into().unwrap()) as usize;
                if self.buffer.len() >= length {
                    let frame = self.buffer.drain(..length).collect::<Vec<_>>();
                    return Ok(Some((frame[0], frame[5..].to_vec())));
                }
            }
            let mut chunk = [0; 4096];
            let read = self.recv.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// The next frame that has arrived, skipping kinds [`Frame`] does not
    /// know.
    fn arrived(&mut self) -> Option<Frame> {
        loop {
            let (kind, payload) = self.next().now_or_never()?.unwrap().unwrap();
            if let Some(frame) = Frame::decode(kind, &payload).unwrap() {
                return Some(frame);
            }
        }
    }

    /// The dialler's sequence number, once its opening frame has arrived.
    fn opening(&mut self) -> Option<u64> {
        let (kind, payload) = self.next().now_or_never()?.unwrap().unwrap();
        assert_eq!(kind, FRAME_OPEN);
        Some(u64::from_be_bytes(payload.try_into().unwrap()))
    }
}

/// 130 collections, each with a record on either side, converge both ways
/// between two neighbours on one connection, and the pushes that follow
/// stay within the design's estimate (section 6: 130 collections, ten
/// neighbours each, the 60 s cap: about 22 roots per second, which is two
/// `walk/1` streams per root here, one per tree). Each side counts the walk
/// streams it opens on the wire. After the first push of each collection
/// both sides hold equal records, so every later push is a periodic one of
/// the confirmed root: ROOT then DONE, answered with LANDED.
///
/// The rate is per node and per neighbour, over 20 quiet minutes of virtual
/// time on the simulated transport, scaled by ten to compare with the
/// estimate; the assertion message prints it.
#[test]
fn one_hundred_thirty_collections_converge_both_ways_within_the_push_estimate() {
    const COLLECTIONS: usize = 130;
    const WINDOW: u64 = 20 * 60;
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0001, SimConfig::default());
        let owner_key = key(50);
        let reader_key = key(51);
        let mut owner_store = MemoryRepo::default();
        let mut reader_store = MemoryRepo::default();
        let mut collections = Vec::new();
        for index in 0..COLLECTIONS {
            let name = format!("collection {index}");
            let collection = hold(&mut owner_store, &name, &[&owner_key, &reader_key]);
            assert_eq!(
                hold(&mut reader_store, &name, &[&owner_key, &reader_key]),
                collection
            );
            commit(&mut owner_store, &owner_key, collection, name.as_bytes());
            commit(&mut reader_store, &reader_key, collection, name.as_bytes());
            select(&mut owner_store, &owner_key, collection);
            select(&mut reader_store, &reader_key, collection);
            collections.push(collection);
        }
        let (harness, owner_taps) = net.tap(&owner_key);
        let mut owner = bring_up(harness, &owner_key, owner_store);
        let (harness, reader_taps) = net.tap(&reader_key);
        let mut reader = bring_up(harness, &reader_key, reader_store);
        owner.activate_collections(collections.iter().copied());
        reader.activate_collections(collections.iter().copied());

        // Each may write every collection, so each is the other's one
        // candidate for all of them, and they peer on one connection.
        advance(&clock, &mut [&mut owner, &mut reader], 300).await;
        for peer in [&owner, &reader] {
            let health = peer.health();
            let peered = health
                .peerings
                .iter()
                .filter(|peering| peering.peered && peering.sends && peering.receives)
                .count();
            assert_eq!(peered, COLLECTIONS);
        }
        for peer in [&mut owner, &mut reader] {
            for collection in &collections {
                assert_eq!(records_of(peer, *collection), 2);
            }
        }
        let (owner_id, reader_id) = (id(&owner_key), id(&reader_key));
        for (peer, other) in [(&owner, reader_id), (&reader, owner_id)] {
            for collection in &collections {
                let pair = pair(peer, *collection, other).unwrap();
                assert!(pair.pushes.last_ok && pair.receives.last_ok, "{pair:?}");
            }
        }
        let dials = (
            net.dial_count(reader_id, owner_id),
            net.dial_count(owner_id, reader_id),
        );
        assert!(dials.0 + dials.1 >= 1, "{dials:?}");

        let from = [&owner_taps, &reader_taps].map(Taps::len);
        advance(&clock, &mut [&mut owner, &mut reader], WINDOW).await;
        let mut opened = 0;
        let mut values = 0;
        for ((taps, from), other) in [(&owner_taps, from[0]), (&reader_taps, from[1])]
            .into_iter()
            .zip([reader_id, owner_id])
        {
            let (sent, heard) = walked(taps, from, other);
            opened += count(&sent, FRAME_WALK_OPEN);
            values += count(&heard, FRAME_VALUE_REQUEST);
        }
        assert_eq!(values, 0, "a quiet pair pushed values");
        assert_eq!(
            (
                net.dial_count(reader_id, owner_id),
                net.dial_count(owner_id, reader_id)
            ),
            dials
        );
        let per_neighbour = opened as f64 / 2.0 / WINDOW as f64;
        let estimate = COLLECTIONS as f64 * 10.0 / 60.0 * 2.0;
        assert!(
            per_neighbour * 10.0 <= estimate * 1.1,
            "{opened} walk streams in {WINDOW} s: {per_neighbour:.2} per second per node and \
             neighbour, {:.1} at ten neighbours against the estimate of {estimate:.1}",
            per_neighbour * 10.0,
        );
        println!(
            "{opened} walk streams in {WINDOW} s: {per_neighbour:.2} per second per node and \
             neighbour, {:.1} at ten neighbours against the estimate of {estimate:.1}",
            per_neighbour * 10.0,
        );
    });
}

/// A partition ends the peering with its connection, and nothing is pushed
/// to a peer without one: the confirmed root stays as the last landed push
/// left it, with no failed push. Records appended meanwhile go out when the
/// pair peers again after the heal, and that push asks only for them: the
/// receiver's HELD prunes everything it landed before.
#[test]
fn a_partition_ends_the_peering_and_the_push_after_the_heal_asks_only_for_what_was_appended() {
    const BEFORE: usize = 400;
    const APPENDED: usize = 100;
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0008, SimConfig::default());
        let owner_key = key(60);
        let reader_key = key(61);
        let (owner_id, reader_id) = (id(&owner_key), id(&reader_key));
        let mut owner_store = MemoryRepo::default();
        let mut reader_store = MemoryRepo::default();
        let collection = hold(&mut owner_store, "cut", &[&owner_key]);
        assert_eq!(hold(&mut reader_store, "cut", &[&owner_key]), collection);
        for index in 0..BEFORE {
            commit(
                &mut owner_store,
                &owner_key,
                collection,
                &(index as u64).to_be_bytes(),
            );
        }
        select(&mut owner_store, &owner_key, collection);
        select(&mut reader_store, &reader_key, collection);
        let (harness, taps) = net.tap(&owner_key);
        let mut owner = bring_up(harness, &owner_key, owner_store);
        let mut reader = bring_up(net.join(&reader_key), &reader_key, reader_store);
        owner.activate_collection(collection);
        reader.activate_collection(collection);
        until(
            &clock,
            &mut [&mut owner, &mut reader],
            120,
            "the records",
            |peers| (records_of(peers[1], collection) == BEFORE).then_some(()),
        )
        .await;
        advance(&clock, &mut [&mut owner, &mut reader], 5).await;
        let confirmed = pair(&owner, collection, reader_id).unwrap();
        assert!(confirmed.pushes.last_ok, "{confirmed:?}");
        let (sent, heard) = walked(&taps, 0, reader_id);
        assert_eq!(count(&heard, FRAME_VALUE_REQUEST), BEFORE);
        assert_eq!(count(&sent, FRAME_LEAF), BEFORE);

        // Cut, and appended while cut: no push runs, none fails.
        net.partition(owner_id, reader_id);
        advance(&clock, &mut [&mut owner, &mut reader], 10).await;
        assert!(!peered(&owner, reader_id));
        for index in BEFORE..BEFORE + APPENDED {
            commit(
                &mut *owner.store(),
                &owner_key,
                collection,
                &(index as u64).to_be_bytes(),
            );
        }
        owner.refresh();
        advance(&clock, &mut [&mut owner, &mut reader], 70).await;
        let cut = pair(&owner, collection, reader_id).unwrap();
        assert_eq!(
            cut.pushes, confirmed.pushes,
            "a push ran without a connection"
        );
        assert_eq!(cut.confirmed, confirmed.confirmed);
        assert_eq!(records_of(&mut reader, collection), BEFORE);

        // Healed, the pair peers again at the next draw, and the push that
        // follows asks only for what was appended.
        let from = taps.len();
        net.heal(owner_id, reader_id);
        until(
            &clock,
            &mut [&mut owner, &mut reader],
            200,
            "the rest",
            |peers| (records_of(peers[1], collection) == BEFORE + APPENDED).then_some(()),
        )
        .await;
        advance(&clock, &mut [&mut owner, &mut reader], 5).await;
        let (sent, heard) = walked(&taps, from, reader_id);
        assert_eq!(count(&heard, FRAME_VALUE_REQUEST), APPENDED);
        assert!(count(&sent, FRAME_LEAF) < BEFORE + APPENDED);
        let healed = pair(&owner, collection, reader_id).unwrap();
        assert!(healed.pushes.last_ok && healed.pushes.ok > confirmed.pushes.ok);
        assert_eq!(healed.pushes.failed, 0);
        assert_ne!(healed.confirmed.records, confirmed.confirmed.records);
        println!(
            "the first push asked for {BEFORE} values; after the partition the next asked for \
             {APPENDED}"
        );
    });
}

/// Three roots of one collection. Y holds three hundred records and X those
/// and three hundred more; Z holds nothing and reaches Y first, which
/// pushes it Y's three hundred. When Z then peers with X, X's push is pruned
/// by what Z already holds: Z asks for exactly X's own three hundred, and
/// fewer leaves than the whole tree cross.
#[test]
fn a_receiver_holding_a_subtree_from_a_third_peer_prunes_it() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0009, SimConfig::default());
        let [x_key, y_key, z_key] = [70, 71, 72].map(key);
        let [x_id, y_id, z_id] = [&x_key, &y_key, &z_key].map(id);
        let roots = [&x_key, &y_key, &z_key];
        let mut x_store = MemoryRepo::default();
        let mut y_store = MemoryRepo::default();
        let mut z_store = MemoryRepo::default();
        let collection = hold(&mut x_store, "shared", &roots);
        assert_eq!(hold(&mut y_store, "shared", &roots), collection);
        assert_eq!(hold(&mut z_store, "shared", &roots), collection);
        let shared = (0..300_u64)
            .map(|index| commit(&mut y_store, &y_key, collection, &index.to_be_bytes()))
            .collect::<Vec<_>>();
        for record in &shared {
            x_store.insert(*record).unwrap();
        }
        for index in 300..600_u64 {
            commit(&mut x_store, &x_key, collection, &index.to_be_bytes());
        }
        select(&mut x_store, &x_key, collection);
        select(&mut y_store, &y_key, collection);
        select(&mut z_store, &z_key, collection);
        // Z reaches Y alone; X reaches nobody until the cuts heal.
        net.partition(x_id, z_id);
        net.partition(x_id, y_id);
        let (harness, taps) = net.tap(&x_key);
        let mut x = bring_up(harness, &x_key, x_store);
        let mut y = bring_up(net.join(&y_key), &y_key, y_store);
        let mut z = bring_up(net.join(&z_key), &z_key, z_store);
        for host in [&mut x, &mut y, &mut z] {
            host.activate_collection(collection);
        }
        until(
            &clock,
            &mut [&mut x, &mut y, &mut z],
            60,
            "Y's records at Z",
            |peers| (records_of(peers[2], collection) == 300).then_some(()),
        )
        .await;
        assert_eq!(records_of(&mut x, collection), 600);
        assert!(taps.since(0, z_id, TAG_WALK).is_empty());

        net.heal(x_id, z_id);
        until(
            &clock,
            &mut [&mut x, &mut y, &mut z],
            200,
            "X's records at Z",
            |peers| (records_of(peers[2], collection) == 600).then_some(()),
        )
        .await;
        advance(&clock, &mut [&mut x, &mut y, &mut z], 5).await;
        let (sent, heard) = walked(&taps, 0, z_id);
        assert_eq!(count(&heard, FRAME_VALUE_REQUEST), 300);
        let leaves = count(&sent, FRAME_LEAF);
        assert!((300..600).contains(&leaves), "{leaves} leaves crossed");
        println!("X pushed {leaves} leaves to Z, which asked for 300 values");
    });
}

/// Answer one FIND_VALUE: no routes, and `provider` with its token where
/// `tokens` has one for the key.
async fn find_value(
    mut send: SimSendStream,
    mut recv: SimRecvStream,
    provider: PeerId,
    tokens: Arc<HashMap<[u8; 32], [u8; 32]>>,
) {
    let mut request = [0; 33];
    if recv.read_exact(&mut request).await.is_err() || request[0] != OP_FIND_VALUE {
        return;
    }
    let mut reply = vec![0];
    match tokens.get(&request[1..]) {
        Some(token) => {
            reply.push(1);
            reply.extend(provider);
            reply.extend(token);
        }
        None => reply.push(0),
    }
    let _ = send.write_all(&reply).await;
    let _ = send.shutdown().await;
}

/// Seventeen neighbour connections each hold `recon/1` while blob streams
/// run: `recon/1` takes none of the 16 request permits a host serves at once.
/// Seventeen hosts peer with one hub, nine for one collection and eight for
/// another, as the hub takes at most 16 peerings per collection it did not
/// ask for. Then each fetches a blob only the hub holds.
#[test]
fn seventeen_neighbours_hold_recon_while_blob_streams_run() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0003, SimConfig::default());
        let hub_key = key(30);
        let names = ["odd", "even"];
        let mut store = MemoryRepo::default();
        let collections = names.map(|name| hold(&mut store, name, &[&hub_key]));
        for collection in collections {
            select(&mut store, &hub_key, collection);
        }
        let bytes = Bytes::from_source(b"only the hub holds this".to_vec());
        let blob = store.put::<UnknownBlob, _>(bytes.clone()).unwrap();
        let mut hub = bring_up(net.join(&hub_key), &hub_key, store);
        hub.activate_collections(collections);
        let mut leaves = (0..17_u8)
            .map(|index| {
                let key = key(40 + index);
                let mut store = MemoryRepo::default();
                let collection = hold(&mut store, names[usize::from(index % 2)], &[&hub_key]);
                select(&mut store, &key, collection);
                let mut leaf = bring_up(net.join(&key), &key, store);
                leaf.activate_collection(collection);
                leaf
            })
            .collect::<Vec<_>>();
        let neighbours = |hub: &Peer<MemoryRepo>| {
            let health = hub.health();
            let peered = health.peerings.iter().filter(|peering| peering.peered);
            peered
                .map(|peering| peering.peer)
                .collect::<BTreeSet<_>>()
                .len()
        };

        let mut peers = std::iter::once(&mut hub)
            .chain(&mut leaves)
            .collect::<Vec<_>>();
        until(&clock, &mut peers, 30, "seventeen neighbours", |peers| {
            (neighbours(&peers[0]) == 17).then_some(())
        })
        .await;
        let fetches = peers[1..]
            .iter()
            .map(|leaf| {
                let fetch = leaf.fetch_blob_with_deadline(blob.raw, Duration::from_secs(60));
                tokio::task::spawn_local(fetch)
            })
            .collect::<Vec<_>>();
        until(&clock, &mut peers, 60, "fetches", |_| {
            fetches
                .iter()
                .all(|fetch| fetch.is_finished())
                .then_some(())
        })
        .await;
        for fetch in fetches {
            assert_eq!(fetch.await.unwrap(), Some(bytes.clone()));
        }
        assert_eq!(neighbours(&peers[0]), 17);
    });
}

/// A peer that stops reading `recon/1` loses its connection. It peers with a
/// host for a collection and then asks to peer for a collection the host
/// does not hold, thousands of times over, a thousand a second, reading
/// nothing more: fewer at a time than the host leaves unanswered. The
/// refusals fill the stream's credit, and the 60 s a writer waits for credit
/// later the host closes the connection, which ends the peering.
#[test]
fn a_peer_that_stops_reading_recon_loses_its_connection() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0004, SimConfig::default());
        let host_key = key(10);
        let host_id = id(&host_key);
        let mut store = MemoryRepo::default();
        let collection = hold(&mut store, "stalled", &[&host_key]);
        select(&mut store, &host_key, collection);
        let mut host = bring_up(net.join(&host_key), &host_key, store);
        host.activate_collection(collection);
        let peers: &mut [&mut Peer<MemoryRepo>] = &mut [&mut host];
        let reader = net.join(&key(11)).transport;
        let reader_id = reader.local_id();
        let conn = reader.dial(host_id, PILE_SYNC_ALPN).await.unwrap();
        let (mut send, mut frames) = open_recon(&conn, 1).await;
        let request = Frame::PeerRequest {
            collection,
            flags: Flags::default(),
            invitation: false,
            credentials: Vec::new(),
        };
        send_frame(&mut send, &request).await;
        until(&clock, peers, 10, "acceptance", |_| {
            loop {
                if let Frame::PeerAccept { collection: c, .. } = frames.arrived()?
                    && c == collection
                {
                    return Some(());
                }
            }
        })
        .await;
        assert!(peered(&peers[0], reader_id));

        let (kind, payload) = Frame::PeerRequest {
            collection: CollectionHandle::new([0xEE; 32]),
            flags: Flags::default(),
            invitation: false,
            credentials: Vec::new(),
        }
        .encode();
        let request = encoded(kind, &payload);
        for _ in 0..40 {
            send.write_all(&request.repeat(1000)).await.unwrap();
            advance(&clock, peers, 1).await;
        }
        assert!(!closed(&conn), "closed early");
        // Past the 60 s a writer waits for credit.
        advance(&clock, peers, 70).await;
        assert!(closed(&conn));
        let closed = frames.next().now_or_never().unwrap().unwrap_err();
        assert!(closed.to_string().contains("connection reset"), "{closed}");
        assert!(
            peers[0]
                .health()
                .peerings
                .iter()
                .all(|peering| peering.peer != reader_id),
            "the peering outlived its connection"
        );
    });
}

/// Whether `conn` has closed, taking the streams the host opens on it, its
/// pushes, as they come: a stream that arrives is not a close.
fn closed(conn: &SimConn) -> bool {
    loop {
        match conn.accept_bi().now_or_never() {
            None => return false,
            Some(None) => return true,
            Some(Some(_)) => {}
        }
    }
}

/// A key driven by hand. It numbers the connections it accepts, from one,
/// and hands each `recon/1` stream to the test with its connection's number;
/// a connection's number arrives on the second channel once it closes. It
/// answers FIND_VALUE with nothing.
#[allow(clippy::type_complexity)]
fn driven(
    net: &SimNet,
    key: &SigningKey,
) -> (
    tokio::sync::mpsc::UnboundedReceiver<(usize, SimSendStream, Frames)>,
    tokio::sync::mpsc::UnboundedReceiver<usize>,
) {
    let mut harness = net.join(key);
    let id = harness.transport.local_id();
    let (recons, opened) = tokio::sync::mpsc::unbounded_channel();
    let (closes, closed) = tokio::sync::mpsc::unbounded_channel();
    tokio::task::spawn_local(async move {
        let mut number = 0;
        while let Some(incoming) = harness.incoming.recv().await {
            number += 1;
            let (recons, closes) = (recons.clone(), closes.clone());
            tokio::task::spawn_local(async move {
                while let Some((send, mut recv)) = incoming.conn.accept_bi().await {
                    match recv.read_u8().await {
                        Ok(TAG_RECON) => {
                            let _ = recons.send((number, send, Frames::new(recv)));
                        }
                        Ok(TAG_DHT) => {
                            let none = Arc::default();
                            tokio::task::spawn_local(find_value(send, recv, id, none));
                        }
                        _ => {}
                    }
                }
                let _ = closes.send(number);
            });
        }
    });
    (opened, closed)
}

/// A neighbour whose `recon/1` ends is lost with its connection and comes
/// back through a fresh dial. A host selects C and D, both writable by a key
/// it dials, and the key, driven by hand, accepts both peerings. Then it
/// resets `recon/1`. The host closes the connection at once and the
/// peerings end with it. The key is the host's one candidate, so once the
/// exhausted candidate order is drawn again, 60 s after the last draw
/// (`MIN_RESHUFFLE_INTERVAL`), the host dials it again and asks for both on
/// the new connection's one `recon/1`.
#[test]
fn a_neighbour_whose_recon_ends_comes_back_through_a_fresh_dial() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0005, SimConfig::default());
        let host_key = key(14);
        let peer_key = key(15);
        let (host_id, peer_id) = (id(&host_key), id(&peer_key));
        let mut store = MemoryRepo::default();
        let collections = ["first", "second"].map(|name| {
            let collection = hold(&mut store, name, &[&host_key, &peer_key]);
            select(&mut store, &host_key, collection);
            collection
        });
        let mut host = bring_up(net.join(&host_key), &host_key, store);
        let (mut opened, mut closed) = driven(&net, &peer_key);
        host.activate_collections(collections);
        let peers: &mut [&mut Peer<MemoryRepo>] = &mut [&mut host];
        let peered_for = |peer: &Peer<MemoryRepo>, collection| {
            peer.health().peerings.iter().any(|peering| {
                peering.peer == peer_id && peering.collection == collection && peering.peered
            })
        };
        let flags = Flags {
            send: true,
            full: false,
        };

        let mut sequences = Vec::new();
        for connection in 1..=2 {
            let (number, mut recon, mut frames) =
                until(&clock, peers, 70, "recon/1", |_| opened.try_recv().ok()).await;
            assert_eq!(number, connection, "a recon/1 on an earlier connection");
            assert_eq!(net.dial_count(host_id, peer_id), connection);
            sequences.push(until(&clock, peers, 1, "opening frame", |_| frames.opening()).await);
            let mut asked = BTreeSet::new();
            until(&clock, peers, 10, "both requests", |_| {
                while let Some(frame) = frames.arrived() {
                    if let Frame::PeerRequest { collection, .. } = frame {
                        asked.insert(collection);
                    }
                }
                (asked == BTreeSet::from(collections)).then_some(())
            })
            .await;
            for collection in collections {
                send_frame(&mut recon, &Frame::PeerAccept { collection, flags }).await;
            }
            until(&clock, peers, 10, "both peerings", |peers| {
                collections
                    .iter()
                    .all(|collection| peered_for(&peers[0], *collection))
                    .then_some(())
            })
            .await;
            if connection == 2 {
                break;
            }

            recon.reset(7);
            frames.recv.stop(7);
            let gone = until(&clock, peers, 1, "the connection's close", |_| {
                closed.try_recv().ok()
            })
            .await;
            assert_eq!(gone, connection);
            assert!(
                collections
                    .iter()
                    .all(|collection| !peered_for(&peers[0], *collection))
            );
        }
        assert!(opened.try_recv().is_err(), "a second recon/1");
        assert!(
            sequences[0] < sequences[1],
            "the second dial outranks the first"
        );
    });
}

/// A key that ends every `recon/1` as it arrives is dialled at most once per
/// reshuffle interval, with no loop of streams or dials. A host selects a
/// collection the key may write, so the key is its one candidate. Each dial
/// carries one `recon/1`, whose end closes its connection, and the host's
/// exhausted candidate order draws the key again only 60 s
/// (`MIN_RESHUFFLE_INTERVAL`) after the last draw. Over ten minutes that is
/// one dial at the start and one per interval after it.
#[test]
fn a_key_that_ends_every_recon_is_dialled_once_per_reshuffle_interval() {
    const WINDOW: u64 = 10 * 60;
    const MIN_RESHUFFLE_INTERVAL: u64 = 60;
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0007, SimConfig::default());
        let host_key = key(12);
        let peer_key = key(13);
        let (host_id, peer_id) = (id(&host_key), id(&peer_key));
        let mut store = MemoryRepo::default();
        let collection = hold(&mut store, "ended", &[&host_key, &peer_key]);
        select(&mut store, &host_key, collection);
        let mut host = bring_up(net.join(&host_key), &host_key, store);
        let (mut opened, _closed) = driven(&net, &peer_key);
        host.activate_collection(collection);
        let peers: &mut [&mut Peer<MemoryRepo>] = &mut [&mut host];

        let mut opens = Vec::new();
        for _ in 0..WINDOW * 10 {
            while let Ok((number, mut recon, mut frames)) = opened.try_recv() {
                recon.reset(7);
                frames.recv.stop(7);
                opens.push(number);
            }
            step(&clock, peers).await;
        }
        let dials = net.dial_count(host_id, peer_id);
        println!(
            "{dials} dials and {} recon/1 streams in {WINDOW} s",
            opens.len()
        );
        let connections = opens.iter().collect::<BTreeSet<_>>().len();
        assert_eq!(
            opens.len(),
            connections,
            "recon/1 streams on {connections} connections"
        );
        assert!(
            (WINDOW / MIN_RESHUFFLE_INTERVAL - 1..=WINDOW / MIN_RESHUFFLE_INTERVAL + 1)
                .contains(&(dials as u64)),
            "{dials} dials in {WINDOW} s"
        );
        assert!(opens.len() <= dials && opens.len() + 1 >= dials);
    });
}
