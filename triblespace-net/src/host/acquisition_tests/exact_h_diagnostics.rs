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

    fn call(&self, peer: PeerId, opcode: u8) -> Arc<Mutex<Call>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|call| {
                let call = call.lock().unwrap();
                call.peer == peer && call.op == Some(opcode)
            })
            .unwrap()
            .clone()
    }

    fn assert_request_bound(&self) -> usize {
        let mut events = Vec::new();
        for call in self.0.lock().unwrap().iter() {
            let call = call.lock().unwrap();
            events.push((call.opened.order, true));
            if let Some(dropped) = call.receiver_dropped {
                events.push((dropped.order, false));
            }
        }
        events.sort_unstable_by_key(|(order, _)| *order);
        let mut active = 0;
        let mut peak = 0;
        for (_, opened) in events {
            if opened {
                active += 1;
                peak = peak.max(active);
                assert!(active <= ALPHA, "routing and data share one ALPHA budget");
            } else {
                assert!(active > 0);
                active -= 1;
            }
        }
        peak
    }

    fn assert_closed_before(&self, returned: Event) {
        for call in self.0.lock().unwrap().iter() {
            let call = call.lock().unwrap();
            assert!(call.receiver_dropped.unwrap().order < returned.order);
        }
        self.assert_request_bound();
    }

    fn assert_authenticated_directories(&self) {
        let calls = self.0.lock().unwrap();
        let mut queried = BTreeSet::new();
        for call in calls.iter() {
            let call = call.lock().unwrap();
            if call.op != Some(OP_PROVIDER_GET) {
                continue;
            }
            let peer = call.peer;
            let opened = call.opened;
            drop(call);
            assert!(queried.insert(peer), "directory targets are deduplicated");
            assert!(
                calls.iter().any(|find| {
                    let find = find.lock().unwrap();
                    find.peer == peer
                        && find.op == Some(OP_FIND_NODE)
                        && find
                            .response_eof
                            .is_some_and(|end| end.order < opened.order)
                }),
                "a directory target must first answer FIND directly; referrals are not authentication"
            );
        }
    }

    fn assert_stage_order(&self, holder: PeerId, returned: Event) {
        self.assert_authenticated_directories();
        self.assert_closed_before(returned);
        let calls = self.0.lock().unwrap();
        let body = calls
            .iter()
            .find(|call| {
                let call = call.lock().unwrap();
                call.peer == holder && call.op == Some(OP_GET_BLOB)
            })
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
    stream: AtomicUsize,
    waker: AtomicWaker,
}

impl Gate {
    fn new(opcode: u8) -> Arc<Self> {
        Arc::new(Self {
            opcode,
            blocked: AtomicBool::new(true),
            stream: AtomicUsize::new(usize::MAX),
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
            let call = self.call.lock().unwrap();
            if call.op == Some(gate.opcode) && gate.blocked.load(Ordering::SeqCst) {
                if let Err(stream) = gate.stream.compare_exchange(
                    usize::MAX,
                    call.opened.order,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    assert_eq!(stream, call.opened.order, "one stream per gate");
                }
                gate.waker.register(cx.waker());
                // The opcode has been delivered to the actual handler; stall
                // its next read without consuming or manufacturing any bytes.
                if gate.blocked.load(Ordering::SeqCst) {
                    gate.entered.notify_one();
                    return Poll::Pending;
                }
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
    candidates: Arc<Mutex<RoutingTable>>,
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
        let candidates = Arc::new(Mutex::new(RoutingTable::new(peer, [])));
        let directory = Arc::new(Mutex::new(ProviderDirectory::new(peer)));
        let (events_tx, events) = tokio::sync::mpsc::channel(16);
        let handler = SnapshotHandler {
            snapshot: tokio::sync::watch::channel(snapshot).1,
            health: Health::new(EndpointId::from_bytes(&peer).unwrap()),
            candidates: candidates.clone(),
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
            candidates,
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
        Self::with_gates(advertise, None, gate)
    }

    fn with_gates(
        advertise: bool,
        holder_gate: Option<Arc<Gate>>,
        other_gate: Option<Arc<Gate>>,
    ) -> Self {
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
        let holder = Node::new(&net, &holder_key, Some(Arc::new(snapshot)), holder_gate);
        let other = Node::new(&net, &other_key, None, other_gate);
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
                assert_eq!(bytes.bytes, fixture.bytes);
                trace.assert_stage_order(fixture.holder.peer, returned);
                let counts = trace.counts();
                assert_eq!(
                    (counts.find, counts.body, counts.put, counts.no_opcode),
                    (2, 1, 0, 0)
                );
                // Success may cancel an unrelated reply, or return before its
                // directory query starts. Audit every observed RPC's framing
                // instead of requiring a particular completion race.
                assert!((1..=2).contains(&counts.directory));
                assert_eq!(
                    counts.completed + counts.dropped_without_eof,
                    counts.find + counts.directory + counts.body
                );
                assert_eq!(
                    counts.request_bytes,
                    (counts.find + counts.directory) * 33 + 65
                );
                for call in trace.0.lock().unwrap().iter() {
                    let call = call.lock().unwrap();
                    let response_bytes = match call.op.unwrap() {
                        OP_FIND_NODE => 1,
                        OP_PROVIDER_GET => {
                            1 + 64 * usize::from(call.peer == fixture.holder.peer || advertised)
                        }
                        OP_GET_BLOB => 41 + BODY_BYTES,
                        op => panic!("unexpected fetch opcode {op:#x}"),
                    };
                    if call.response_eof.is_some() {
                        assert_eq!(call.response_bytes, response_bytes);
                    } else {
                        assert!(call.response_bytes <= response_bytes);
                    }
                }
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
async fn exact_h_responsive_body_precedes_stalled_routing_or_directory_drop() {
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
            if opcode == OP_PROVIDER_GET {
                assert_eq!(entered.directory, 1);
            }
            let bytes = tokio::time::timeout(Duration::from_secs(1), &mut fetch)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(bytes.bytes, fixture.bytes);
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
        assert!(returned.at.duration_since(started) < Duration::from_secs(1));
        let body = fixture
            .client
            .transport
            .trace
            .call(fixture.holder.peer, OP_GET_BLOB);
        let body_eof = body.lock().unwrap().response_eof.unwrap();
        let stalled = fixture
            .client
            .transport
            .trace
            .call(fixture.other.peer, opcode);
        let stalled = stalled.lock().unwrap();
        assert!(stalled.response_eof.is_none());
        assert_eq!(stalled.response_bytes, 0);
        assert!(stalled.opened.order < body_eof.order);
        assert!(body_eof.order < stalled.receiver_dropped.unwrap().order);
        if opcode == OP_FIND_NODE {
            assert_eq!((counts.directory, counts.completed), (1, 3));
        } else {
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
async fn exact_h_routing_expiry_keeps_a_pending_body_within_the_caller_deadline() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let body_gate = Gate::new(OP_GET_BLOB);
    let find_gate = Gate::new(OP_FIND_NODE);
    let mut fixture =
        ThreeNodes::with_gates(false, Some(body_gate.clone()), Some(find_gate.clone()));
    fixture.warm_connections().await;
    let trace = fixture.client.transport.trace.clone();
    let started = Instant::now();
    let caller_deadline = started + INTERACTIVE_FETCH_DEADLINE;
    let routing_dropped;
    let released;
    {
        let fetch = tokio::time::timeout_at(
            caller_deadline,
            fixture.client.fetch_blob(fixture.hash, None),
        );
        tokio::pin!(fetch);
        tokio::select! {
            _ = async {
                tokio::join!(body_gate.entered.notified(), find_gate.entered.notified());
            } => {},
            result = &mut fetch => panic!("fetch ended before both controlled streams were reached: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("controlled streams were not reached"),
        }
        let authenticated = trace
            .call(fixture.holder.peer, OP_FIND_NODE)
            .lock()
            .unwrap()
            .response_eof
            .unwrap();
        let routing_deadline = authenticated.at + BACKGROUND_LOOKUP_DEADLINE;
        tokio::select! {
            result = &mut fetch => panic!("routing expiry ended a live provider request: {result:?}"),
            _ = tokio::time::sleep_until(routing_deadline + Duration::from_secs(1)) => {},
        }
        let find = trace.call(fixture.other.peer, OP_FIND_NODE);
        let find = find.lock().unwrap();
        assert!(find.response_eof.is_none());
        routing_dropped = find.receiver_dropped.unwrap();
        assert_eq!(routing_dropped.at, routing_deadline);
        drop(find);
        let body = trace.call(fixture.holder.peer, OP_GET_BLOB);
        let body = body.lock().unwrap();
        assert!(body.opened.order < routing_dropped.order);
        assert!(body.response_eof.is_none());
        assert!(body.receiver_dropped.is_none());
        drop(body);
        let counts = trace.counts();
        assert_eq!(
            (counts.find, counts.directory, counts.body, counts.completed),
            (2, 1, 1, 2)
        );
        assert_eq!(counts.dropped_without_eof, 1);
        trace.assert_authenticated_directories();
        trace.assert_request_bound();
        released = trace.mark();
        assert!(routing_dropped.order < released.order);
        body_gate.release();
        assert_eq!(
            fetch.await.unwrap().unwrap().map(|blob| blob.bytes),
            Some(fixture.bytes.clone())
        );
    }
    let returned = trace.mark();
    trace.assert_stage_order(fixture.holder.peer, returned);
    let body = trace.call(fixture.holder.peer, OP_GET_BLOB);
    assert!(released.order < body.lock().unwrap().response_eof.unwrap().order);
    assert!(returned.at < caller_deadline);
    assert_eq!(returned.at.duration_since(started), Duration::from_secs(4));
    let counts = trace.counts();
    assert_eq!((counts.completed, counts.dropped_without_eof), (3, 1));
    assert_eq!(fixture.reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn exact_h_empty_early_directory_waits_for_referred_holder_authentication() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let gate = Gate::new(OP_FIND_NODE);
    let mut fixture = ThreeNodes::with_gates(false, Some(gate.clone()), None);
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [fixture.other.peer]);
    fixture
        .other
        .candidates
        .lock()
        .unwrap()
        .promote_authenticated(fixture.holder.peer);
    fixture.warm_connections().await;
    let trace = fixture.client.transport.trace.clone();
    let released;
    {
        let fetch = fixture.client.fetch_blob(fixture.hash, None);
        tokio::pin!(fetch);
        tokio::select! {
            _ = gate.entered.notified() => {},
            result = &mut fetch => panic!("fetch ended before the referred holder answered: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("holder FIND was not reached"),
        }
        // Allow ready empty-directory work to drain while the holder's FIND
        // remains suspended. The ordinals below, not this paused-clock delay,
        // prove that the empty answer was consumed before authentication.
        tokio::select! {
            result = &mut fetch => panic!("an early empty directory ended live routing: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {},
        }
        let counts = trace.counts();
        assert_eq!(
            (counts.find, counts.directory, counts.body, counts.completed),
            (2, 1, 0, 2)
        );
        trace.assert_authenticated_directories();
        trace.assert_request_bound();
        let empty = trace.call(fixture.other.peer, OP_PROVIDER_GET);
        let empty = empty.lock().unwrap();
        assert_eq!(empty.response_bytes, 1);
        let empty_eof = empty.response_eof.unwrap();
        drop(empty);
        let holder_find = trace.call(fixture.holder.peer, OP_FIND_NODE);
        assert!(holder_find.lock().unwrap().response_eof.is_none());
        released = trace.mark();
        assert!(empty_eof.order < released.order);
        gate.release();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), &mut fetch)
                .await
                .unwrap()
                .unwrap()
                .map(|blob| blob.bytes),
            Some(fixture.bytes.clone())
        );
    }
    let returned = trace.mark();
    trace.assert_stage_order(fixture.holder.peer, returned);
    let holder_find = trace.call(fixture.holder.peer, OP_FIND_NODE);
    assert!(released.order < holder_find.lock().unwrap().response_eof.unwrap().order);
    let counts = trace.counts();
    assert_eq!(
        (counts.find, counts.directory, counts.body, counts.completed),
        (2, 2, 1, 5)
    );
    assert_eq!(counts.dropped_without_eof, 0);
    assert_eq!(fixture.reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
}

#[tokio::test(start_paused = true)]
async fn exact_h_stale_early_hints_leave_room_for_fresh_routing_and_final_holder() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let holder_gate = Gate::new(OP_FIND_NODE);
    let relay_gate = Gate::new(OP_FIND_NODE);
    let mut fixture = ThreeNodes::with_gates(false, Some(holder_gate.clone()), None);
    let mut relay = Node::new(
        &fixture.net,
        &SigningKey::from_bytes(&[159; 32]),
        None,
        Some(relay_gate.clone()),
    );
    let key = blob_locator(fixture.hash);
    // Deterministic fixture identities, bounded independently of routing.
    // Every stale hint and the later directory are farther than the holder:
    // routing reaches the holder first, its directory precedes the later one,
    // and its useful hint outranks the third still-pending stale provider.
    let mut farther: Vec<_> = (0_u16..4096)
        .filter_map(|seed| {
            let mut secret = [156; 32];
            secret[..2].copy_from_slice(&seed.to_le_bytes());
            let signing = SigningKey::from_bytes(&secret);
            let peer = signing.verifying_key().to_bytes();
            (![
                fixture.client.my_id,
                fixture.holder.peer,
                fixture.other.peer,
                relay.peer,
            ]
            .contains(&peer)
                && crate::routing::distance_cmp(key, peer, fixture.holder.peer).is_gt())
            .then_some(signing)
        })
        .take(4)
        .collect();
    assert_eq!(
        farther.len(),
        4,
        "bounded fixture must supply four farther peers"
    );
    let mut later_directory = Node::new(
        &fixture.net,
        &farther.pop().unwrap(),
        None,
        Some(Gate::new(OP_PROVIDER_GET)),
    );
    let mut slow: Vec<_> = farther
        .into_iter()
        .map(|signing| {
            let gate = Gate::new(OP_GET_BLOB);
            (
                Node::new(&fixture.net, &signing, None, Some(gate.clone())),
                gate,
            )
        })
        .collect();
    assert_eq!(
        slow.len(),
        3,
        "bounded fixture must supply three farther hints"
    );
    slow.sort_unstable_by(|(left, _), (right, _)| {
        crate::routing::distance_cmp(key, left.peer, right.peer)
    });
    for (node, _) in &slow {
        assert!(fixture.other.directory.lock().unwrap().put(
            key,
            node.peer,
            blob_provider_token(fixture.hash, node.peer),
            crate::clock::mono_now(),
        ));
    }
    *fixture.client.candidates.lock().unwrap() =
        RoutingTable::new(fixture.client.my_id, [fixture.other.peer]);
    fixture
        .other
        .candidates
        .lock()
        .unwrap()
        .promote_authenticated(relay.peer);
    for peer in [fixture.holder.peer, later_directory.peer] {
        relay.candidates.lock().unwrap().promote_authenticated(peer);
    }
    fixture.warm_connections().await;
    for peer in [relay.peer, later_directory.peer]
        .into_iter()
        .chain(slow.iter().map(|(node, _)| node.peer))
    {
        pool_get(&fixture.client.transport, &fixture.client.pool, peer)
            .await
            .unwrap();
    }
    let trace = fixture.client.transport.trace.clone();
    let started = Instant::now();
    let caller_deadline = started + Duration::from_secs(2);
    {
        let fetch = tokio::time::timeout_at(
            caller_deadline,
            fixture.client.fetch_blob(fixture.hash, None),
        );
        tokio::pin!(fetch);
        tokio::select! {
            _ = async {
                tokio::join!(
                    relay_gate.entered.notified(),
                    slow[0].1.entered.notified(),
                    slow[1].1.entered.notified()
                );
            } => {},
            result = &mut fetch => panic!("fetch ended before early hints filled the data slots: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("early hints did not reach both data slots"),
        }
        assert_eq!(trace.counts().body, 2);
        assert_eq!(slow[2].0.trace.counts(), Counts::default());
        assert_eq!(trace.assert_request_bound(), ALPHA);
        let relay_released = trace.mark();
        for (node, _) in slow.iter().take(2) {
            let body = trace.call(node.peer, OP_GET_BLOB);
            let body = body.lock().unwrap();
            assert!(body.opened.order < relay_released.order);
            assert!(body.receiver_dropped.is_none());
        }
        relay_gate.release();
        tokio::select! {
            _ = holder_gate.entered.notified() => {},
            result = &mut fetch => panic!("fetch ended before fresh holder routing: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("stale providers occupied the reserved routing slot"),
        }
        let holder_find = trace.call(fixture.holder.peer, OP_FIND_NODE);
        assert!(relay_released.order < holder_find.lock().unwrap().opened.order);
        assert_eq!(trace.counts().body, 2);
        assert_eq!(slow[2].0.trace.counts(), Counts::default());
        assert_eq!(later_directory.trace.counts(), Counts::default());
        trace.assert_request_bound();
        holder_gate.release();
        assert_eq!(
            fetch.await.unwrap().unwrap().map(|blob| blob.bytes),
            Some(fixture.bytes.clone())
        );
    }
    let returned = trace.mark();
    trace.assert_stage_order(fixture.holder.peer, returned);
    assert!(returned.at < caller_deadline);
    let later_find = trace.call(later_directory.peer, OP_FIND_NODE);
    let later_find_eof = later_find.lock().unwrap().response_eof.unwrap();
    let directory = trace.call(fixture.holder.peer, OP_PROVIDER_GET);
    let directory = directory.lock().unwrap();
    assert!(later_find_eof.order < directory.opened.order);
    let directory_eof = directory.response_eof.unwrap();
    drop(directory);
    let body = trace.call(fixture.holder.peer, OP_GET_BLOB);
    let body = body.lock().unwrap();
    assert!(directory_eof.order < body.opened.order);
    let body_eof = body.response_eof.unwrap();
    drop(body);
    for (node, _) in slow.iter().take(2) {
        let stale = trace.call(node.peer, OP_GET_BLOB);
        let stale = stale.lock().unwrap();
        assert!(stale.response_eof.is_none());
        assert!(body_eof.order < stale.receiver_dropped.unwrap().order);
    }
    assert_eq!(slow[2].0.trace.counts(), Counts::default());
    let later_counts = later_directory.trace.counts();
    assert_eq!((later_counts.find, later_counts.directory), (1, 0));
    assert_eq!(
        trace
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.lock().unwrap().peer == later_directory.peer)
            .count(),
        1,
        "the later directory has only its completed FIND; its GET must remain unstarted"
    );
    let counts = trace.counts();
    assert_eq!(
        (counts.find, counts.body, counts.dropped_without_eof),
        (4, 3, 2)
    );
    assert_eq!(fixture.reads.load(Ordering::Relaxed), 1);
    fixture.assert_no_control_effects();
    assert!(relay.events.try_recv().is_err());
    assert!(later_directory.events.try_recv().is_err());
    for (node, _) in &mut slow {
        assert!(node.events.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn exact_h_routing_and_data_share_alpha_and_caller_cancellation_drops_both() {
    let _guard = crate::protocol::exact_blob_receive_test_guard();
    let holder_gate = Gate::new(OP_PROVIDER_GET);
    let other_gate = Gate::new(OP_FIND_NODE);
    let third_gate = Gate::new(OP_FIND_NODE);
    let late_gate = Gate::new(OP_FIND_NODE);
    let mut fixture =
        ThreeNodes::with_gates(false, Some(holder_gate.clone()), Some(other_gate.clone()));
    let mut third = Node::new(
        &fixture.net,
        &SigningKey::from_bytes(&[154; 32]),
        None,
        Some(third_gate.clone()),
    );
    let mut late = Node::new(
        &fixture.net,
        &SigningKey::from_bytes(&[155; 32]),
        None,
        Some(late_gate),
    );
    *fixture.client.candidates.lock().unwrap() = RoutingTable::new(
        fixture.client.my_id,
        [fixture.holder.peer, fixture.other.peer, third.peer],
    );
    fixture
        .holder
        .candidates
        .lock()
        .unwrap()
        .promote_authenticated(late.peer);
    fixture.warm_connections().await;
    pool_get(&fixture.client.transport, &fixture.client.pool, third.peer)
        .await
        .unwrap();
    let trace = fixture.client.transport.trace.clone();
    let cancelled;
    {
        let fetch = fixture.client.fetch_blob(fixture.hash, None);
        tokio::pin!(fetch);
        tokio::select! {
            _ = async {
                tokio::join!(
                    holder_gate.entered.notified(),
                    other_gate.entered.notified(),
                    third_gate.entered.notified()
                );
            } => {},
            result = &mut fetch => panic!("fetch ended with three deliberately suspended requests: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("combined routing/data window was not filled"),
        }
        let counts = trace.counts();
        assert_eq!(
            (counts.find, counts.directory, counts.body, counts.completed),
            (3, 1, 0, 1)
        );
        assert_eq!(trace.assert_request_bound(), ALPHA);
        trace.assert_authenticated_directories();
        assert_eq!(late.trace.counts(), Counts::default());
        assert_eq!(fixture.net.dial_count(fixture.client.my_id, late.peer), 0);
        cancelled = trace.mark();
        // Dropping the caller owns cancellation of both future sets. No
        // background task may retain these routing or directory receivers.
    }
    let returned = trace.mark();
    trace.assert_closed_before(returned);
    let counts = trace.counts();
    assert_eq!(counts.dropped_without_eof, ALPHA);
    for call in trace.0.lock().unwrap().iter() {
        let call = call.lock().unwrap();
        if call.response_eof.is_none() {
            assert!(call.opened.order < cancelled.order);
            assert!(cancelled.order < call.receiver_dropped.unwrap().order);
        }
    }
    assert_eq!(fixture.reads.load(Ordering::Relaxed), 0);
    fixture.assert_no_control_effects();
    assert!(third.events.try_recv().is_err());
    assert!(late.events.try_recv().is_err());
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
    assert_eq!(returned.get_handle().raw, fixture.hash);
    assert_eq!(returned.bytes, fixture.bytes);
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
