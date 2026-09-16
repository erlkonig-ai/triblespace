//! Bounded, test-only application-RPC counts and causal stage controls.
//!
//! SimNet delays dialing, not established-stream traffic. None of these
//! virtual-time observations measures QUIC throughput or application latency.
//! The client and server run the production RPC functions and SnapshotHandler;
//! the wrappers below only count bytes or suspend one selected receive stage.

use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use super::*;
use crate::transport::sim::SimConn;
use crate::transport::{Alpn, Conn, Transport};

const REPEATS: usize = 16;
const BODY_BYTES: usize = 223;
const TRACE_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug)]
struct Event {
    at: Instant,
    order: usize,
}

#[derive(Debug)]
struct Call {
    clock: Arc<AtomicUsize>,
    peer: PeerId,
    op: Option<u8>,
    opened: Event,
    request_bytes: usize,
    response_bytes: usize,
    first_body_byte: Option<Event>,
    response_eof: Option<Event>,
    receiver_dropped: Option<Event>,
}

impl Call {
    fn mark(&self) -> Event {
        Event {
            at: Instant::now(),
            order: self.clock.fetch_add(1, Ordering::SeqCst),
        }
    }
}

#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<Arc<Mutex<Call>>>>>, Arc<AtomicUsize>);

impl Trace {
    fn mark(&self) -> Event {
        Event {
            at: Instant::now(),
            order: self.1.fetch_add(1, Ordering::SeqCst),
        }
    }

    fn open(&self, peer: PeerId) -> Arc<Mutex<Call>> {
        let call = Arc::new(Mutex::new(Call {
            clock: self.1.clone(),
            peer,
            op: None,
            opened: self.mark(),
            request_bytes: 0,
            response_bytes: 0,
            first_body_byte: None,
            response_eof: None,
            receiver_dropped: None,
        }));
        let mut calls = self.0.lock().unwrap();
        assert!(
            calls.len() < TRACE_LIMIT,
            "fixture trace must remain bounded"
        );
        calls.push(call.clone());
        call
    }

    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for call in self.0.lock().unwrap().iter() {
            let call = call.lock().unwrap();
            match call.op {
                Some(OP_FIND_NODE) => counts.find += 1,
                Some(OP_PROVIDER_GET) => counts.directory += 1,
                Some(OP_PROVIDER_PUT) => counts.put += 1,
                Some(OP_GET_BLOB) => counts.body += 1,
                None => counts.no_opcode += 1,
                Some(op) => panic!("unexpected fixture opcode {op:#x}"),
            }
            counts.request_bytes += call.request_bytes;
            counts.response_bytes += call.response_bytes;
            counts.completed += usize::from(call.response_eof.is_some());
            // This is an observation of stream ownership, not a generic error
            // classifier. The stalled cases establish cancellation separately.
            counts.dropped_without_eof +=
                usize::from(call.receiver_dropped.is_some() && call.response_eof.is_none());
        }
        counts
    }

    fn assert_stage_order(&self, holder: PeerId, returned: Event) {
        let calls = self.0.lock().unwrap();
        let body = calls
            .iter()
            .find(|call| call.lock().unwrap().op == Some(OP_GET_BLOB))
            .unwrap()
            .lock()
            .unwrap();
        assert_eq!(body.peer, holder);
        let opened = body.opened;
        let first_body = body.first_body_byte.unwrap();
        let body_eof = body.response_eof.unwrap();
        drop(body);
        let hint_completed = calls.iter().any(|call| {
            let call = call.lock().unwrap();
            call.op == Some(OP_PROVIDER_GET)
                && call.response_bytes >= 65
                && call
                    .response_eof
                    .is_some_and(|end| end.order < opened.order)
        });
        assert!(
            hint_completed,
            "body starts only after a completed usable hint"
        );
        // Paused-clock timestamps can coincide. Sequence numbers establish
        // actual observed order even within one virtual instant.
        assert!(opened.order < first_body.order);
        assert!(first_body.order < body_eof.order);
        assert!(body_eof.order < returned.order);
        for call in calls.iter() {
            let call = call.lock().unwrap();
            if call.op == Some(OP_FIND_NODE) {
                // Either routing completed or its request was cancelled before
                // the provider phase. This does not infer a network RTT.
                assert!(call.response_eof.or(call.receiver_dropped).unwrap().order < opened.order);
            }
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    find: usize,
    directory: usize,
    put: usize,
    body: usize,
    no_opcode: usize,
    request_bytes: usize,
    response_bytes: usize,
    completed: usize,
    dropped_without_eof: usize,
}

#[derive(Default)]
struct Gate {
    opcode: u8,
    blocked: AtomicBool,
    entered: tokio::sync::Notify,
    // Each fixture gates exactly one stream, not multiple concurrent waiters.
    waker: AtomicWaker,
}

impl Gate {
    fn new(opcode: u8) -> Arc<Self> {
        Arc::new(Self {
            opcode,
            blocked: AtomicBool::new(true),
            ..Self::default()
        })
    }

    fn release(&self) {
        self.blocked.store(false, Ordering::SeqCst);
        self.waker.wake();
    }
}

/// A transparent transport tap. Request opcodes are counted only after an
/// actual successful byte write/read, not merely when a future is constructed.
struct Tap<S> {
    inner: S,
    call: Arc<Mutex<Call>>,
    request: bool,
    track_receiver_drop: bool,
    gate: Option<Arc<Gate>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(gate) = &self.gate {
            gate.waker.register(cx.waker());
            if self.call.lock().unwrap().op == Some(gate.opcode)
                && gate.blocked.load(Ordering::SeqCst)
            {
                // The opcode has been delivered to the actual handler; stall
                // its next read without consuming or manufacturing any bytes.
                gate.entered.notify_one();
                return Poll::Pending;
            }
        }
        let before = buf.filled().len();
        let available = buf.remaining();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let bytes = &buf.filled()[before..];
            let mut call = self.call.lock().unwrap();
            if self.request {
                if call.op.is_none() {
                    call.op = bytes.first().copied();
                }
                call.request_bytes += bytes.len();
            } else {
                let prior = call.response_bytes;
                call.response_bytes += bytes.len();
                // Successful GET: status1 + provider proof32 + length8,
                // followed by body bytes. An empty read with spare capacity
                // is the protocol's EOF observation, not a zero-length poll.
                if call.op == Some(OP_GET_BLOB) && prior <= 41 && call.response_bytes > 41 {
                    call.first_body_byte = Some(call.mark());
                }
                if bytes.is_empty() && available != 0 && call.response_eof.is_none() {
                    call.response_eof = Some(call.mark());
                }
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            let mut call = self.call.lock().unwrap();
            if self.request {
                if call.op.is_none() {
                    call.op = bytes[..*count].first().copied();
                }
                call.request_bytes += *count;
            } else {
                call.response_bytes += *count;
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> Drop for Tap<S> {
    fn drop(&mut self) {
        if self.track_receiver_drop {
            let mut call = self.call.lock().unwrap();
            call.receiver_dropped = Some(call.mark());
        }
    }
}

#[derive(Clone)]
struct TracedConn {
    inner: SimConn,
    trace: Trace,
    gate: Option<Arc<Gate>>,
}

impl Conn for TracedConn {
    type SendHalf = Tap<<SimConn as Conn>::SendHalf>;
    type RecvHalf = Tap<<SimConn as Conn>::RecvHalf>;

    fn remote_id(&self) -> PeerId {
        self.inner.remote_id()
    }

    async fn open_bi(&self) -> anyhow::Result<(Self::SendHalf, Self::RecvHalf)> {
        let (send, recv) = self.inner.open_bi().await?;
        let call = self.trace.open(self.remote_id());
        Ok((
            Tap {
                inner: send,
                call: call.clone(),
                request: true,
                track_receiver_drop: false,
                gate: None,
            },
            Tap {
                inner: recv,
                call,
                request: false,
                track_receiver_drop: true,
                gate: None,
            },
        ))
    }

    async fn accept_bi(&self) -> Option<(Self::SendHalf, Self::RecvHalf)> {
        let (send, recv) = self.inner.accept_bi().await?;
        let call = self.trace.open(self.remote_id());
        Some((
            Tap {
                inner: send,
                call: call.clone(),
                request: false,
                track_receiver_drop: false,
                gate: None,
            },
            Tap {
                inner: recv,
                call,
                request: true,
                track_receiver_drop: false,
                gate: self.gate.clone(),
            },
        ))
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

#[derive(Clone)]
struct TracedTransport {
    inner: SimTransport,
    trace: Trace,
}

impl Transport for TracedTransport {
    type Conn = TracedConn;
    type WakePlane = <SimTransport as Transport>::WakePlane;

    fn local_id(&self) -> PeerId {
        self.inner.local_id()
    }

    async fn dial(&self, peer: PeerId, alpn: Alpn) -> anyhow::Result<Self::Conn> {
        Ok(TracedConn {
            inner: self.inner.dial(peer, alpn).await?,
            trace: self.trace.clone(),
            gate: None,
        })
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }

    fn collection_wake_plane(&self) -> Self::WakePlane {
        self.inner.collection_wake_plane()
    }
}

struct Node {
    peer: PeerId,
    trace: Trace,
    directory: Arc<Mutex<ProviderDirectory>>,
    events: tokio::sync::mpsc::Receiver<NetEventBatch>,
    gate: Option<Arc<Gate>>,
    server: tokio::task::JoinHandle<()>,
}

impl Node {
    fn new(
        net: &SimNet,
        key: &SigningKey,
        snapshot: Option<Arc<StoreSnapshot>>,
        gate: Option<Arc<Gate>>,
    ) -> Self {
        let peer = key.verifying_key().to_bytes();
        let mut harness = net.join(key);
        let trace = Trace::default();
        let directory = Arc::new(Mutex::new(ProviderDirectory::new(peer)));
        let (events_tx, events) = tokio::sync::mpsc::channel(16);
        let handler = SnapshotHandler {
            snapshot: Arc::new(Mutex::new(snapshot)),
            candidates: Arc::new(Mutex::new(RoutingTable::new(peer, []))),
            providers: directory.clone(),
            serve_collections: false,
            local_id: peer,
            events: events_tx,
            inbound_connections: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            inbound_requests: Arc::new(tokio::sync::Semaphore::new(MAX_REQUESTS_GLOBAL)),
        };
        let server_trace = trace.clone();
        let server_gate = gate.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Some(incoming) = harness.incoming.recv().await {
                assert_eq!(incoming.alpn, PILE_SYNC_ALPN);
                let permit = handler
                    .inbound_connections
                    .clone()
                    .try_acquire_owned()
                    .unwrap();
                let handler = handler.clone();
                let connection = TracedConn {
                    inner: incoming.conn,
                    trace: server_trace.clone(),
                    gate: server_gate.clone(),
                };
                connections.spawn(async move {
                    handler.handle::<TracedTransport>(connection, permit).await;
                });
            }
        });
        Self {
            peer,
            trace,
            directory,
            events,
            gate,
            server,
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(gate) = &self.gate {
            gate.release();
        }
        self.server.abort();
    }
}

struct ThreeNodes {
    net: SimNet,
    client: ProviderClient<TracedTransport>,
    holder: Node,
    other: Node,
    store: MemoryRepo,
    hash: RawHash,
    bytes: Bytes,
    reads: Arc<AtomicUsize>,
}

impl ThreeNodes {
    fn new(advertise: bool, gate: Option<Arc<Gate>>) -> Self {
        let latency = Duration::from_millis(20);
        let net = SimNet::new(
            731,
            SimConfig {
                latency: latency..latency,
            },
        );
        // Deterministic fixture keys, not new protocol/schema identifiers.
        let holder_key = SigningKey::from_bytes(&[151; 32]);
        let other_key = SigningKey::from_bytes(&[152; 32]);
        let client_key = SigningKey::from_bytes(&[153; 32]);
        let mut store = MemoryRepo::default();
        let bytes = Bytes::from_source(vec![0x5a_u8; BODY_BYTES]);
        assert_eq!(bytes.len(), BODY_BYTES);
        let hash = store.put::<UnknownBlob, _>(bytes.clone()).unwrap().raw;
        let mut snapshot = StoreSnapshot::from_store_changes(
            store.snapshot().unwrap(),
            &ActiveCollections::new(),
            holder_key.verifying_key(),
            None,
            None,
            StoreChanges::ALL,
        )
        .unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        snapshot.blobs = Arc::new(CountedBlobReader {
            inner: snapshot.blobs,
            reads: reads.clone(),
        });
        let holder = Node::new(&net, &holder_key, Some(Arc::new(snapshot)), None);
        let other = Node::new(&net, &other_key, None, gate);
        if advertise {
            // Known valid directory lease, independent of the holder's
            // snapshot-backed self hint. No production publication loop runs.
            assert!(other.directory.lock().unwrap().put(
                blob_locator(hash),
                holder.peer,
                blob_provider_token(hash, holder.peer),
                crate::clock::mono_now(),
            ));
        }
        let my_id = client_key.verifying_key().to_bytes();
        let transport = net.join(&client_key).transport;
        let client = ProviderClient {
            transport: TracedTransport {
                inner: transport,
                trace: Trace::default(),
            },
            pool: new_shared_pool(),
            providers: Arc::new(Mutex::new(ProviderDirectory::new(my_id))),
            candidates: Arc::new(Mutex::new(RoutingTable::new(
                my_id,
                [holder.peer, other.peer],
            ))),
            my_id,
        };
        Self {
            net,
            client,
            holder,
            other,
            store,
            hash,
            bytes,
            reads,
        }
    }

    async fn warm_connections(&self) {
        for peer in [self.holder.peer, self.other.peer] {
            pool_get(&self.client.transport, &self.client.pool, peer)
                .await
                .unwrap();
        }
        assert_eq!(self.client.transport.trace.counts(), Counts::default());
    }

    fn assert_no_control_effects(&mut self) {
        let snapshot = self.store.snapshot().unwrap();
        assert_eq!(snapshot.records().unwrap().count(), 0);
        assert_eq!(snapshot.wants().unwrap().count(), 0);
        assert!(self.holder.events.try_recv().is_err());
        assert!(self.other.events.try_recv().is_err());
    }

    fn dials(&self) -> usize {
        [self.holder.peer, self.other.peer]
            .into_iter()
            .map(|peer| self.net.dial_count(self.client.my_id, peer))
            .sum()
    }
}

#[tokio::test(start_paused = true)]
async fn exact_h_repeated_fetches_count_rpcs_not_simulator_throughput() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    for prewarmed in [false, true] {
        for advertised in [false, true] {
            let mut fixture = ThreeNodes::new(advertised, None);
            if prewarmed {
                fixture.warm_connections().await;
            }
            // Without prewarming only the first fetch is cold. Later fetches
            // deliberately retain connections and the learned routing table.
            for iteration in 0..REPEATS {
                let trace = &fixture.client.transport.trace;
                trace.clear();
                let started = Instant::now();
                let bytes = tokio::time::timeout(
                    Duration::from_secs(2),
                    fixture.client.fetch_blob(fixture.hash, None),
                )
                .await
                .unwrap()
                .unwrap()
                .unwrap();
                let returned = trace.mark();
                assert_eq!(bytes, fixture.bytes);
                trace.assert_stage_order(fixture.holder.peer, returned);
                let counts = trace.counts();
                assert_eq!(
                    (counts.find, counts.directory, counts.body, counts.put),
                    (2, 2, 1, 0)
                );
                assert_eq!(
                    (
                        counts.no_opcode,
                        counts.completed,
                        counts.dropped_without_eof
                    ),
                    (0, 5, 0)
                );
                assert_eq!(counts.request_bytes, 4 * 33 + 65);
                assert_eq!(
                    counts.response_bytes,
                    2 + 2 + 64 * (1 + usize::from(advertised)) + 41 + BODY_BYTES
                );
                assert_eq!(
                    fixture.dials(),
                    2,
                    "warm requests reuse connections, not routing answers"
                );
                assert_eq!(fixture.reads.load(Ordering::Relaxed), iteration + 1);
                println!(
                    "exact_h_fetch prewarmed={prewarmed} advertised={advertised} iteration={iteration} dials={} virtual_us={} {counts:?}",
                    fixture.dials(),
                    returned.at.duration_since(started).as_micros()
                );
                // Do not put returned bytes in a consumer store: every repeat
                // deliberately exercises ProviderClient, not a resident hit.
                drop(bytes);
            }
            fixture.assert_no_control_effects();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn exact_h_stall_location_separates_routing_from_directory_barrier() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    for opcode in [OP_FIND_NODE, OP_PROVIDER_GET] {
        let gate = Gate::new(opcode);
        let mut fixture = ThreeNodes::new(false, Some(gate.clone()));
        fixture.warm_connections().await;
        let started = Instant::now();
        {
            let fetch = fixture.client.fetch_blob(fixture.hash, None);
            tokio::pin!(fetch);
            tokio::select! {
                _ = gate.entered.notified() => {},
                result = &mut fetch => panic!("fetch completed before controlled stage was reached: {result:?}"),
                _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("fixture did not reach controlled stage"),
            }
            let entered = fixture.other.trace.counts();
            assert_eq!(entered.find, 1);
            if opcode == OP_FIND_NODE {
                let before = fixture.client.transport.trace.counts();
                assert_eq!((before.directory, before.body), (0, 0));
            } else {
                assert_eq!(entered.directory, 1);
            }
            let bytes = tokio::time::timeout(Duration::from_secs(4), &mut fetch)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(bytes, fixture.bytes);
        }
        let returned = fixture.client.transport.trace.mark();
        let counts = fixture.client.transport.trace.counts();
        fixture
            .client
            .transport
            .trace
            .assert_stage_order(fixture.holder.peer, returned);
        assert_eq!(
            (counts.find, counts.body, counts.put, counts.no_opcode),
            (2, 1, 0, 0)
        );
        assert_eq!(counts.dropped_without_eof, 1);
        if opcode == OP_FIND_NODE {
            assert_eq!(
                returned.at.duration_since(started),
                BACKGROUND_LOOKUP_DEADLINE
            );
            assert_eq!((counts.directory, counts.completed), (1, 3));
        } else {
            assert!(returned.at.duration_since(started) < Duration::from_secs(1));
            assert_eq!((counts.directory, counts.completed), (2, 4));
        }
        println!(
            "exact_h_stall opcode={opcode:#x} virtual_us={} {counts:?}",
            returned.at.duration_since(started).as_micros()
        );
        fixture.assert_no_control_effects();
    }
}

#[tokio::test(start_paused = true)]
async fn exact_h_direct_bearer_control_has_one_rpc_and_329_application_bytes() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let mut fixture = ThreeNodes::new(false, None);
    fixture.warm_connections().await;
    let returned = fixture
        .client
        .fetch_from_provider(fixture.hash, fixture.holder.peer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(returned, fixture.bytes);
    let counts = fixture.client.transport.trace.counts();
    assert_eq!(
        (counts.find, counts.directory, counts.put, counts.body),
        (0, 0, 0, 1)
    );
    assert_eq!(
        (counts.request_bytes, counts.response_bytes),
        (65, 41 + BODY_BYTES)
    );
    assert_eq!(counts.request_bytes + counts.response_bytes, 329);
    assert_eq!((counts.completed, counts.dropped_without_eof), (1, 0));
    assert_eq!(fixture.holder.trace.counts().body, 1);
    assert_eq!(fixture.reads.load(Ordering::Relaxed), 1);
    println!("exact_h_direct {counts:?}");
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn exact_h_warm_publication_repeats_routing_and_remote_puts() {
    let mut fixture = ThreeNodes::new(false, None);
    fixture.warm_connections().await;
    for iteration in 0..REPEATS {
        fixture.client.transport.trace.clear();
        assert_eq!(
            fixture
                .client
                .announce_key(
                    blob_locator(fixture.hash),
                    blob_provider_token(fixture.hash, fixture.client.my_id)
                )
                .await,
            PublicationResult::Published
        );
        let counts = fixture.client.transport.trace.counts();
        assert_eq!(
            (counts.find, counts.put, counts.directory, counts.body),
            (2, 2, 0, 0)
        );
        assert_eq!(
            (counts.request_bytes, counts.response_bytes),
            (2 * 33 + 2 * 65, 4)
        );
        assert_eq!(counts.completed, 4);
        assert_eq!(fixture.dials(), 2);
        println!("exact_h_publication iteration={iteration} {counts:?}");
    }
    assert_eq!(fixture.reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
}
