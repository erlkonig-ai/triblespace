//! The one `recon/1` stream of a connection, through whole hosts on the
//! deterministic transport: 130 collections share it between two neighbours
//! within the announcement estimate, it takes none of the request permits
//! blob streams wait for, a peer that stops reading it gets it reset, it
//! reopens beside blob streams at their cap, and the dialler reopens it at
//! once when it ends, when each side sends again the peering frames it may
//! have lost. A peer that speaks `recon/1` by hand encodes its frames with
//! [`Frame`], and walk requests by the frame table of `triblespace_net::walk`.
#![cfg(feature = "sim")]

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anybytes::Bytes;
use ed25519_dalek::SigningKey;
use futures::FutureExt as _;
use iroh_base::{EndpointAddr, EndpointId};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::locator::blob_locator;
use triblespace_core::clock::{self, VirtualClock};
use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionCommit, CollectionData, CollectionHandle, CollectionPolicy,
    CollectionRead, CollectionRecord, CollectionStore, CollectionStoreExt, empty_metadata_handle,
    private_policy,
};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStorePut, SnapshotSource};
use triblespace_net::connection::RESET_STALLED;
use triblespace_net::host::{self, PeerConfig};
use triblespace_net::peer::Peer;
use triblespace_net::protocol::{OP_FIND_VALUE, PILE_SYNC_ALPN, TAG_BLOB, TAG_DHT, TAG_RECON};
use triblespace_net::provider::blob_provider_token;
use triblespace_net::recon::{FRAME_OPEN, FRAME_WALK_REQUEST, Flags, Frame};
use triblespace_net::transport::sim::{
    SimConfig, SimConn, SimNet, SimRecvStream, SimSendStream, SimTransport,
};
use triblespace_net::transport::{
    Alpn, Conn, Harness, Incoming, PeerId, RecvStream, SendStream, Transport,
};

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

/// A host on `harness` over `store`, with `routes` for its DHT lookups. It
/// publishes no provider records.
fn bring_up<T: Transport>(
    harness: Harness<T>,
    key: &SigningKey,
    store: MemoryRepo,
    routes: &[PeerId],
) -> Peer<MemoryRepo> {
    let (sender, receiver, wiring) = host::wire(EndpointId::from_bytes(&id(key)).unwrap());
    tokio::task::spawn_local(host::run_host(
        harness,
        PeerConfig {
            peers: routes
                .iter()
                .map(|route| EndpointAddr::from(EndpointId::from_bytes(route).unwrap()))
                .collect(),
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

/// A request of walk number 0 over the records of `collection`: to open it,
/// or for the value under `key`.
fn walk_request(collection: CollectionHandle, key: Option<[u8; 32]>) -> Vec<u8> {
    let mut payload = collection.raw.to_vec();
    // The records kind, then the walk number.
    payload.extend([0, 0, 0]);
    match key {
        None => payload.push(0),
        Some(key) => {
            payload.push(2);
            payload.extend(key);
        }
    }
    encoded(FRAME_WALK_REQUEST, &payload)
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

/// The announcements one node hears on `recon/1`: the stream each came on,
/// numbered across the test, and its collection.
type Heard = Arc<Mutex<Vec<(u64, CollectionHandle)>>>;

static STREAMS: AtomicU64 = AtomicU64::new(0);

/// A node's simulated transport, noting each announcement it receives.
#[derive(Clone)]
struct Tap {
    inner: SimTransport,
    heard: Heard,
}

impl Tap {
    fn join(net: &SimNet, key: &SigningKey) -> (Harness<Tap>, Heard) {
        let Harness {
            transport,
            mut incoming,
        } = net.join(key);
        let tap = Tap {
            inner: transport,
            heard: Heard::default(),
        };
        let (forward, accepted) = tokio::sync::mpsc::channel(1024);
        let wrapping = tap.clone();
        tokio::task::spawn_local(async move {
            while let Some(Incoming { alpn, conn }) = incoming.recv().await {
                let conn = wrapping.conn(conn);
                if forward.send(Incoming { alpn, conn }).await.is_err() {
                    return;
                }
            }
        });
        let heard = tap.heard.clone();
        let harness = Harness {
            transport: tap,
            incoming: accepted,
        };
        (harness, heard)
    }

    fn conn(&self, inner: SimConn) -> TapConn {
        TapConn {
            inner,
            heard: self.heard.clone(),
        }
    }
}

impl Transport for Tap {
    type Conn = TapConn;

    fn local_id(&self) -> PeerId {
        self.inner.local_id()
    }

    async fn dial(&self, peer: PeerId, alpn: Alpn) -> anyhow::Result<TapConn> {
        Ok(self.conn(self.inner.dial(peer, alpn).await?))
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await
    }
}

#[derive(Clone)]
struct TapConn {
    inner: SimConn,
    heard: Heard,
}

impl Conn for TapConn {
    type SendHalf = TapSend;
    type RecvHalf = TapRecv;

    fn remote_id(&self) -> PeerId {
        self.inner.remote_id()
    }

    async fn open_bi(&self) -> anyhow::Result<(TapSend, TapRecv)> {
        let (send, recv) = self.inner.open_bi().await?;
        let tag = Arc::new(OnceLock::new());
        let recv = TapRecv::new(recv, Some(tag.clone()), &self.heard);
        Ok((TapSend { inner: send, tag }, recv))
    }

    async fn accept_bi(&self) -> Option<(TapSend, TapRecv)> {
        let (send, recv) = self.inner.accept_bi().await?;
        let tag = Arc::new(OnceLock::new());
        Some((
            TapSend { inner: send, tag },
            TapRecv::new(recv, None, &self.heard),
        ))
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code, reason)
    }
}

/// A sending half. On a stream this side opened, its first byte is the tag.
struct TapSend {
    inner: SimSendStream,
    tag: Arc<OnceLock<u8>>,
}

impl AsyncWrite for TapSend {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(first) = buf.first() {
            let _ = this.tag.set(*first);
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl SendStream for TapSend {
    fn reset(&mut self, code: u32) {
        self.inner.reset(code)
    }
}

/// A receiving half that parses the frames of a `recon/1` stream as they
/// are read.
struct TapRecv {
    inner: SimRecvStream,
    /// The tag this side wrote, on a stream it opened; on an accepted one the
    /// tag is the first byte read.
    opened: Option<Arc<OnceLock<u8>>>,
    /// Whether the stream is `recon/1`, once its tag is known.
    recon: Option<bool>,
    stream: u64,
    read: Vec<u8>,
    heard: Heard,
}

impl TapRecv {
    fn new(inner: SimRecvStream, opened: Option<Arc<OnceLock<u8>>>, heard: &Heard) -> Self {
        Self {
            inner,
            opened,
            recon: None,
            stream: STREAMS.fetch_add(1, Ordering::Relaxed),
            read: Vec::new(),
            heard: heard.clone(),
        }
    }

    fn parse(&mut self, mut bytes: &[u8]) {
        if self.recon.is_none() {
            let tag = match &self.opened {
                Some(tag) => tag.get().copied(),
                None => {
                    let Some((&tag, rest)) = bytes.split_first() else {
                        return;
                    };
                    bytes = rest;
                    Some(tag)
                }
            };
            self.recon = Some(tag == Some(TAG_RECON));
        }
        if self.recon != Some(true) {
            return;
        }
        self.read.extend_from_slice(bytes);
        while let Some(length) = self.read.get(1..5) {
            let length = 5 + u32::from_be_bytes(length.try_into().unwrap()) as usize;
            if self.read.len() < length {
                break;
            }
            let frame = self.read.drain(..length).collect::<Vec<_>>();
            if let Ok(Some(Frame::Announce { collection, .. })) =
                Frame::decode(frame[0], &frame[5..])
            {
                self.heard.lock().unwrap().push((self.stream, collection));
            }
        }
    }
}

impl AsyncRead for TapRecv {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            this.parse(&buf.filled()[before..]);
        }
        polled
    }
}

impl RecvStream for TapRecv {
    fn stop(&mut self, code: u32) {
        self.inner.stop(code)
    }
}

/// 130 collections share the one `recon/1` between two neighbours, and their
/// announcements stay within the design's estimate (section 6: 130
/// collections, ten neighbours each, the 60 s cap: about 22 per second).
/// Each side counts the announcements it hears on the wire. After the first
/// pull of each collection both sides hold equal records, so every later
/// announcement is a periodic one, and one heard equal suppresses the next
/// one to its sender.
///
/// The rate is per node and per neighbour, over 20 quiet minutes of virtual
/// time on the simulated transport, scaled by ten to compare with the
/// estimate; the assertion message prints it. One run heard 2598 in 20
/// minutes, 1.08 per second per node and neighbour: one per collection and
/// minute between the two, 10.8 at ten neighbours against the estimate's
/// 21.7.
#[test]
fn one_hundred_thirty_collections_share_one_recon_within_the_announcement_estimate() {
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
            let collection = hold(&mut owner_store, &name, &[&owner_key]);
            assert_eq!(hold(&mut reader_store, &name, &[&owner_key]), collection);
            commit(&mut owner_store, &owner_key, collection, name.as_bytes());
            select(&mut owner_store, &owner_key, collection);
            select(&mut reader_store, &reader_key, collection);
            collections.push(collection);
        }
        let (harness, heard_by_owner) = Tap::join(&net, &owner_key);
        let mut owner = bring_up(harness, &owner_key, owner_store, &[]);
        let (harness, heard_by_reader) = Tap::join(&net, &reader_key);
        let mut reader = bring_up(harness, &reader_key, reader_store, &[]);
        owner.activate_collections(collections.iter().copied());
        reader.activate_collections(collections.iter().copied());

        // The owner, which may write each collection, is the reader's one
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
        let pulled = reader
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .filter(|record| collections.contains(&record.as_ref().unwrap().collection()))
            .count();
        assert_eq!(pulled, COLLECTIONS);
        let (owner_id, reader_id) = (id(&owner_key), id(&reader_key));
        assert_eq!(
            (
                net.dial_count(reader_id, owner_id),
                net.dial_count(owner_id, reader_id)
            ),
            (1, 0)
        );

        let from = [&heard_by_owner, &heard_by_reader].map(|heard| heard.lock().unwrap().len());
        advance(&clock, &mut [&mut owner, &mut reader], WINDOW).await;
        let mut announced = BTreeSet::new();
        let mut heard = 0;
        for (side, from) in [&heard_by_owner, &heard_by_reader].into_iter().zip(from) {
            let side = &side.lock().unwrap()[from..];
            let streams = side
                .iter()
                .map(|(stream, _)| stream)
                .collect::<BTreeSet<_>>();
            assert_eq!(streams.len(), 1, "announcements came on several streams");
            announced.extend(side.iter().map(|(_, collection)| collection.raw));
            heard += side.len();
        }
        assert_eq!(announced.len(), COLLECTIONS);
        let per_neighbour = heard as f64 / 2.0 / WINDOW as f64;
        let estimate = COLLECTIONS as f64 * 10.0 / 60.0;
        assert!(
            per_neighbour * 10.0 <= estimate,
            "{heard} announcements in {WINDOW} s: {per_neighbour:.2} per second per node and \
             neighbour, {:.1} at ten neighbours against the estimate of {estimate:.1}",
            per_neighbour * 10.0,
        );
        println!(
            "{heard} announcements in {WINDOW} s: {per_neighbour:.2} per second per node and \
             neighbour, {:.1} at ten neighbours against the estimate of {estimate:.1}",
            per_neighbour * 10.0,
        );
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

/// Whether the peer still holds the stream: it has neither finished nor
/// abandoned it.
fn open(recv: &mut SimRecvStream) -> bool {
    loop {
        match recv.read(&mut [0; 64]).now_or_never() {
            None => return true,
            Some(Ok(0) | Err(_)) => return false,
            Some(Ok(_)) => {}
        }
    }
}

/// `recon/1` reopens beside blob streams at their cap, and the connection's
/// peerings stay. A host dials a key that may write a collection the host
/// selects, and they peer on that connection. The host then wants 120
/// blobs, and every lookup names that key their provider; the key answers
/// none of the blob requests. The host opens 16 of them on the connection,
/// its cap, below the 100 streams a QUIC peer allows, so when the key resets
/// `recon/1` the host's next announcement opens a new one at once beside
/// them, with no new request for the collection.
#[test]
fn recon_reopens_beside_blob_streams_at_their_cap_and_keeps_its_peerings() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0002, SimConfig::default());
        let host_key = key(20);
        let peer_key = key(21);
        let peer_id = id(&peer_key);
        let mut store = MemoryRepo::default();
        let collection = hold(&mut store, "beside blobs", &[&host_key, &peer_key]);
        select(&mut store, &host_key, collection);
        let mut host = bring_up(net.join(&host_key), &host_key, store, &[peer_id]);

        let blobs = (0..120_u32)
            .map(|number| {
                let bytes = Bytes::from_source(number.to_be_bytes().to_vec());
                Blob::<UnknownBlob>::new(bytes).get_handle().raw
            })
            .collect::<Vec<_>>();
        let tokens = Arc::new(
            blobs
                .iter()
                .map(|hash| (blob_locator(*hash), blob_provider_token(*hash, peer_id)))
                .collect::<HashMap<_, _>>(),
        );
        let mut harness = net.join(&peer_key);
        let (recons, mut opened) = tokio::sync::mpsc::unbounded_channel();
        let held = Arc::new(Mutex::new(Vec::new()));
        let holding = held.clone();
        tokio::task::spawn_local(async move {
            let conn = harness.incoming.recv().await.unwrap().conn;
            while let Some((send, mut recv)) = conn.accept_bi().await {
                match recv.read_u8().await {
                    Ok(TAG_RECON) => {
                        let _ = recons.send((send, Frames::new(recv)));
                    }
                    Ok(TAG_DHT) => {
                        tokio::task::spawn_local(find_value(send, recv, peer_id, tokens.clone()));
                    }
                    Ok(TAG_BLOB) => holding.lock().unwrap().push((send, recv)),
                    _ => {}
                }
            }
        });

        host.activate_collection(collection);
        let peers: &mut [&mut Peer<MemoryRepo>] = &mut [&mut host];
        let (mut recon, mut frames) =
            until(&clock, peers, 10, "recon/1", |_| opened.try_recv().ok()).await;
        let sequence = until(&clock, peers, 1, "opening frame", |_| frames.opening()).await;
        until(&clock, peers, 10, "peering request", |_| {
            loop {
                if let Frame::PeerRequest { collection: c, .. } = frames.arrived()?
                    && c == collection
                {
                    return Some(());
                }
            }
        })
        .await;
        let flags = Flags {
            send: true,
            full: false,
        };
        send_frame(&mut recon, &Frame::PeerAccept { collection, flags }).await;
        until(&clock, peers, 10, "peering", |peers| {
            peered(&peers[0], peer_id).then_some(())
        })
        .await;

        let fetches = blobs
            .iter()
            .map(|hash| {
                let fetch = peers[0].fetch_blob_with_deadline(*hash, Duration::from_secs(600));
                tokio::task::spawn_local(fetch)
            })
            .collect::<Vec<_>>();
        advance(&clock, peers, 5).await;
        assert_eq!(
            held.lock().unwrap().len(),
            16,
            "blob streams on one connection"
        );

        recon.reset(7);
        frames.recv.stop(7);
        // A change the host announces within two seconds.
        commit(&mut *peers[0].store(), &host_key, collection, b"announced");
        let (_recon, mut frames) =
            until(&clock, peers, 10, "new recon/1", |_| opened.try_recv().ok()).await;
        let reopened = until(&clock, peers, 1, "opening frame", |_| frames.opening()).await;
        assert_eq!(reopened, sequence);
        until(&clock, peers, 10, "announcement on the new stream", |_| {
            loop {
                match frames.arrived()? {
                    Frame::Announce { collection: c, .. } if c == collection => return Some(()),
                    Frame::PeerRequest { .. } => panic!("the host asked again"),
                    _ => {}
                }
            }
        })
        .await;
        let mut held = held.lock().unwrap();
        assert_eq!(held.len(), 16);
        assert!(held.iter_mut().all(|(_, recv)| open(recv)));
        assert!(peered(&peers[0], peer_id));
        for fetch in fetches {
            fetch.abort();
        }
    });
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
        let hub_id = id(&hub_key);
        let names = ["odd", "even"];
        let mut store = MemoryRepo::default();
        let collections = names.map(|name| hold(&mut store, name, &[&hub_key]));
        for collection in collections {
            select(&mut store, &hub_key, collection);
        }
        let bytes = Bytes::from_source(b"only the hub holds this".to_vec());
        let blob = store.put::<UnknownBlob, _>(bytes.clone()).unwrap();
        let mut hub = bring_up(net.join(&hub_key), &hub_key, store, &[]);
        hub.activate_collections(collections);
        let mut leaves = (0..17_u8)
            .map(|index| {
                let key = key(40 + index);
                let mut store = MemoryRepo::default();
                let collection = hold(&mut store, names[usize::from(index % 2)], &[&hub_key]);
                select(&mut store, &key, collection);
                let mut leaf = bring_up(net.join(&key), &key, store, &[hub_id]);
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

/// A peer that stops reading `recon/1` gets it reset. It peers with a host
/// for a collection and then asks for the collection's one record thousands
/// of times over, reading nothing more. The answers fill the stream's credit,
/// and the 60 s a writer waits for credit later the host resets the stream
/// with [`RESET_STALLED`] and stops reading it. The connection and the peering
/// stay: the peer's next `recon/1` carries the host's frames again, among
/// them an announcement of the collection, with no new request.
#[test]
fn a_peer_that_stops_reading_recon_gets_it_reset_and_keeps_its_peering() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0004, SimConfig::default());
        let host_key = key(10);
        let host_id = id(&host_key);
        let mut store = MemoryRepo::default();
        let collection = hold(&mut store, "stalled", &[&host_key]);
        let record = commit(
            &mut store,
            &host_key,
            collection,
            b"asked for over and over",
        );
        select(&mut store, &host_key, collection);
        let mut host = bring_up(net.join(&host_key), &host_key, store, &[]);
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

        let mut requests = walk_request(collection, None);
        for _ in 0..12_000 {
            requests.extend(walk_request(collection, Some(record.fingerprint().raw())));
        }
        send.write_all(&requests).await.unwrap();
        // Past the 60 s a writer waits for credit.
        advance(&clock, peers, 70).await;
        let reset = loop {
            match frames.next().now_or_never().expect("recon/1 was not reset") {
                Ok(Some(_)) => {}
                Ok(None) => panic!("recon/1 was finished, not reset"),
                Err(error) => break error,
            }
        };
        let stalled = format!("code {RESET_STALLED}");
        assert!(reset.to_string().contains(&stalled), "{reset}");
        let stopped = send.write_all(&requests[..1]).now_or_never();
        let stopped = stopped
            .expect("a write after stop fails at once")
            .unwrap_err();
        assert!(stopped.to_string().contains(&stalled), "{stopped}");
        assert!(peered(&peers[0], reader_id));

        let (_send, mut frames) = open_recon(&conn, 1).await;
        until(&clock, peers, 120, "announcement on the new stream", |_| {
            loop {
                match frames.arrived()? {
                    Frame::Announce { collection: c, .. } if c == collection => return Some(()),
                    Frame::PeerRequest { .. } | Frame::PeerAccept { .. } | Frame::Unpeer { .. } => {
                        panic!("the peering was renegotiated")
                    }
                    _ => {}
                }
            }
        })
        .await;
        assert!(peered(&peers[0], reader_id));
        assert_eq!(net.dial_count(reader_id, host_id), 1);
    });
}

/// A reader dials a key that may write a collection it selects but may not
/// read it, and peers with it: the writer sends and the reader sends nothing
/// (design 2.3, Astra R3). The writer, driven by hand, resets `recon/1` with
/// [`RESET_STALLED`], as a writer that waited 60 s for credit does, and keeps
/// the connection in use with a `FIND_VALUE` every 30 s. Only the dialler can
/// open `recon/1`, and the writer's frames wait for one, so the reader opens
/// a new one at once, though it has nothing to send.
#[test]
fn the_dialler_reopens_an_ended_recon_at_once() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0005, SimConfig::default());
        let reader_key = key(12);
        let writer_key = key(13);
        let writer_id = id(&writer_key);
        let mut store = MemoryRepo::default();
        let keys = [reader_key.verifying_key(), writer_key.verifying_key()];
        let writers = AdmissionPolicy::quorum(keys, 1, None).unwrap();
        let readers = AdmissionPolicy::direct(reader_key.verifying_key());
        let policy = CollectionPolicy::new(readers, writers);
        let collection = store.collection("written only", policy).unwrap().handle();
        select(&mut store, &reader_key, collection);
        let mut reader = bring_up(net.join(&reader_key), &reader_key, store, &[]);

        let mut harness = net.join(&writer_key);
        let (recons, mut opened) = tokio::sync::mpsc::unbounded_channel();
        let (conns, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        tokio::task::spawn_local(async move {
            let conn = harness.incoming.recv().await.unwrap().conn;
            let _ = conns.send(conn.clone());
            while let Some((send, mut recv)) = conn.accept_bi().await {
                match recv.read_u8().await {
                    Ok(TAG_RECON) => {
                        let _ = recons.send((send, Frames::new(recv)));
                    }
                    Ok(TAG_DHT) => {
                        let none = Arc::default();
                        tokio::task::spawn_local(find_value(send, recv, writer_id, none));
                    }
                    _ => {}
                }
            }
        });

        reader.activate_collection(collection);
        let peers: &mut [&mut Peer<MemoryRepo>] = &mut [&mut reader];
        let (mut recon, mut frames) =
            until(&clock, peers, 10, "recon/1", |_| opened.try_recv().ok()).await;
        let conn = accepted.try_recv().unwrap();
        let theirs = until(&clock, peers, 10, "peering request", |_| {
            loop {
                if let Frame::PeerRequest {
                    collection: c,
                    flags,
                    ..
                } = frames.arrived()?
                    && c == collection
                {
                    return Some(flags);
                }
            }
        })
        .await;
        assert!(!theirs.send, "the reader sends nothing");
        let flags = Flags {
            send: true,
            full: false,
        };
        send_frame(&mut recon, &Frame::PeerAccept { collection, flags }).await;
        until(&clock, peers, 10, "peering", |peers| {
            peered(&peers[0], writer_id).then_some(())
        })
        .await;

        recon.reset(RESET_STALLED);
        frames.recv.stop(RESET_STALLED);
        let mut steps = 0;
        until(&clock, peers, 600, "a new recon/1", |_| {
            if steps % 300 == 0 {
                let conn = conn.clone();
                tokio::task::spawn_local(async move {
                    let Ok((mut send, mut recv)) = conn.open_bi().await else {
                        return;
                    };
                    let mut request = vec![TAG_DHT, OP_FIND_VALUE];
                    request.extend([7; 32]);
                    let _ = send.write_all(&request).await;
                    let _ = send.shutdown().await;
                    let _ = recv.read_to_end(&mut Vec::new()).await;
                });
            }
            steps += 1;
            opened.try_recv().ok()
        })
        .await;
        assert_eq!(net.dial_count(id(&reader_key), writer_id), 1);
    });
}

/// A host selects C and D, both writable by a key it dials, and the key,
/// driven by hand, accepts both peerings. Its acceptance of C is lost the way
/// an ended `recon/1` loses what its reader had not read: written, then the
/// stream reset with [`RESET_STALLED`] before the host read it, as a writer
/// that waited 60 s for credit does. The key is peered for C and the host
/// still waits for the answer, so the host sends its request for C again on
/// the next `recon/1`; once that is accepted, the key's announcement of a
/// root of C the host lacks starts a pull.
#[test]
fn a_request_whose_acceptance_was_lost_is_sent_again() {
    run(async |clock| {
        let net = SimNet::new(0x5EC0_0006, SimConfig::default());
        let host_key = key(14);
        let peer_key = key(15);
        let peer_id = id(&peer_key);
        let mut store = MemoryRepo::default();
        let wedged = hold(&mut store, "wedged", &[&host_key, &peer_key]);
        let carrier = hold(&mut store, "carrier", &[&host_key, &peer_key]);
        select(&mut store, &host_key, wedged);
        select(&mut store, &host_key, carrier);
        let mut host = bring_up(net.join(&host_key), &host_key, store, &[]);

        let mut harness = net.join(&peer_key);
        let (recons, mut opened) = tokio::sync::mpsc::unbounded_channel();
        tokio::task::spawn_local(async move {
            let conn = harness.incoming.recv().await.unwrap().conn;
            while let Some((send, mut recv)) = conn.accept_bi().await {
                if let Ok(TAG_RECON) = recv.read_u8().await {
                    let _ = recons.send((send, Frames::new(recv)));
                }
            }
        });
        host.activate_collections([wedged, carrier]);
        let peers: &mut [&mut Peer<MemoryRepo>] = &mut [&mut host];
        let peered_for = |peer: &Peer<MemoryRepo>, collection| {
            peer.health().peerings.iter().any(|peering| {
                peering.peer == peer_id && peering.collection == collection && peering.peered
            })
        };
        let (mut recon, mut frames) =
            until(&clock, peers, 10, "recon/1", |_| opened.try_recv().ok()).await;
        let mut asked = BTreeSet::new();
        until(&clock, peers, 10, "both requests", |_| {
            while let Some(frame) = frames.arrived() {
                if let Frame::PeerRequest { collection, .. } = frame {
                    asked.insert(collection);
                }
            }
            (asked == BTreeSet::from([wedged, carrier])).then_some(())
        })
        .await;
        let flags = Flags {
            send: true,
            full: false,
        };
        let accept = |collection| Frame::PeerAccept { collection, flags };
        send_frame(&mut recon, &accept(carrier)).await;
        until(&clock, peers, 10, "the peering for D", |peers| {
            peered_for(&peers[0], carrier).then_some(())
        })
        .await;
        send_frame(&mut recon, &accept(wedged)).await;
        recon.reset(RESET_STALLED);
        frames.recv.stop(RESET_STALLED);

        let (mut recon, mut frames) =
            until(&clock, peers, 10, "a new recon/1", |_| opened.try_recv().ok()).await;
        until(&clock, peers, 10, "the request for C again", |_| {
            loop {
                if let Frame::PeerRequest { collection, .. } = frames.arrived()?
                    && collection == wedged
                {
                    return Some(());
                }
            }
        })
        .await;
        send_frame(&mut recon, &accept(wedged)).await;
        until(&clock, peers, 10, "the peering for C", |peers| {
            peered_for(&peers[0], wedged).then_some(())
        })
        .await;
        let announcement = Frame::Announce {
            collection: wedged,
            root: [7; 32],
            held_digest: None,
            reply: false,
        };
        send_frame(&mut recon, &announcement).await;
        until(&clock, peers, 10, "a pull of C", |_| {
            loop {
                if let frame @ Frame::Walk(_) = frames.arrived()?
                    && frame.collection() == Some(wedged)
                {
                    return Some(());
                }
            }
        })
        .await;
    });
}
