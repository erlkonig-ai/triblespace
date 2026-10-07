//! Deterministic in-memory transport for simulation testing.
//!
//! [`SimNet`] is a process-local network: nodes join it, get a
//! [`Harness<SimTransport>`] back, and from there the *entire*
//! production protocol stack — host loop, collection-authorized repair,
//! and bearer DHT/provider operations — runs unmodified over
//! in-memory pipes instead of iroh QUIC.
//!
//! # Determinism contract
//!
//! A simulated execution is a pure function of `(seed, scenario)`
//! provided the harness follows the rules:
//!
//! 1. **One thread.** Everything runs on a single
//!    `current_thread` tokio runtime built with `.start_paused(true)`.
//!    No cross-thread races exist because there is no second thread.
//! 2. **Virtual time only.** Install a [`crate::clock::VirtualClock`]
//!    before the first time read, and advance it in lockstep with
//!    `tokio::time::advance` via [`SimNet::step`]. Time moves only
//!    when the scenario script says so; every latency sleep and
//!    cooldown check resolves in deterministic order on the paused
//!    timer wheel.
//! 3. **Seeded randomness.** Link latencies draw from the net's own seeded RNG;
//!    protocol-side id minting is seeded via
//!    `triblespace_core::id::rngid::seed_ids` (the `deterministic`
//!    feature this module's `sim` feature pulls in). Node keys are
//!    derived from the seed by the test harness.
//!
//! # Fault injection
//!
//! [`SimNet::partition`] / [`SimNet::heal`] block dialing between pairs;
//! [`SimNet::crash`] takes a node off the network entirely until
//! [`SimNet::revive`]. Faults affect *delivery*, never identity —
//! `Conn::remote_id` always reports the true dialer, so
//! identity-dependent per-request READ(C) subject binding is exercised honestly.
//!
//! # Observation
//!
//! [`SimNet::tap`] joins through a [`Tapped`] transport, whose streams note
//! every frame crossing a `recon/1` or `walk/1` stream in its [`Taps`]: a
//! test counts what a protocol put on the wire without the protocol
//! reporting it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use super::{Alpn, Conn, Harness, Incoming, PeerId, Transport};
use crate::protocol::{TAG_RECON, TAG_WALK};

/// Bytes one direction of a stream holds unread before its writer blocks:
/// the credit QUIC grants each stream, noq-proto 1.2.0's default
/// `stream_receive_window` (12.5 MB/s over a 100 ms round trip). A reader
/// grants credit only by reading.
const STREAM_WINDOW: usize = 1_250_000;

/// Bidirectional streams one end of a connection holds open, noq-proto
/// 1.2.0's default `max_concurrent_bidi_streams`. The next `open_bi` waits
/// until the peer has closed one.
const MAX_BIDI_STREAMS: usize = 100;

/// Tunables for the simulated network.
#[derive(Clone, Debug)]
pub struct SimConfig {
    /// Per-message one-way latency, drawn uniformly per delivery.
    pub latency: Range<Duration>,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(1)..Duration::from_millis(30),
        }
    }
}

struct NodeSlot {
    incoming_tx: mpsc::UnboundedSender<Incoming<SimConn>>,
    up: bool,
}

struct SimNetInner {
    nodes: BTreeMap<PeerId, NodeSlot>,
    /// Every live conn pair, for fault injection: crash() resets all
    /// conns touching the node, like a dead process's QUIC conns.
    conns: Vec<ConnHandle>,
    dials: Vec<(PeerId, PeerId)>,
    /// Symmetric partition set; (a, b) stored with a <= b.
    partitions: BTreeSet<(PeerId, PeerId)>,
    /// Dial targets whose connection setup stalls forever (the
    /// connection setup neither completes nor errors). Models a peer that
    /// is routable enough to start a dial but never finishes it —
    /// the failure shape connection deadlines exist to catch. Unlike
    /// `crash` (dials error fast), this keeps the dial future
    /// pending, so an un-deadlined singleflight pool wedges every
    /// later walk to that peer behind one stalled attempt.
    stalled_dials: BTreeSet<PeerId>,
    rng: StdRng,
    config: SimConfig,
}

struct ConnHandle {
    a: PeerId,
    b: PeerId,
    closed: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl SimNetInner {
    fn latency(&mut self) -> Duration {
        let lo = self.config.latency.start;
        let hi = self.config.latency.end;
        if hi <= lo {
            return lo;
        }
        let span = (hi - lo).as_nanos() as u64;
        lo + Duration::from_nanos(self.rng.gen_range(0..span))
    }

    fn partitioned(&self, a: &PeerId, b: &PeerId) -> bool {
        let key = if a <= b { (*a, *b) } else { (*b, *a) };
        self.partitions.contains(&key)
    }
}

/// The simulated network. Cheap to clone (Arc).
#[derive(Clone)]
pub struct SimNet {
    inner: Arc<Mutex<SimNetInner>>,
}

impl SimNet {
    /// A fresh network with seeded link randomness.
    pub fn new(seed: u64, config: SimConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SimNetInner {
                nodes: BTreeMap::new(),
                conns: Vec::new(),
                dials: Vec::new(),
                partitions: BTreeSet::new(),
                stalled_dials: BTreeSet::new(),
                rng: StdRng::seed_from_u64(seed),
                config,
            })),
        }
    }

    /// Join the network as `id`. Returns the transport harness for the node's
    /// host loop.
    pub fn join(&self, signing_key: &SigningKey) -> Harness<SimTransport> {
        let id = signing_key.verifying_key().to_bytes();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        let mut inner = self.inner.lock().unwrap();
        inner.nodes.insert(
            id,
            NodeSlot {
                incoming_tx,
                up: true,
            },
        );
        drop(inner);

        let transport = SimTransport {
            net: self.clone(),
            id,
        };
        // The bounded receivers the host loop expects: bridge from our
        // unbounded internals. (Unbounded internally so fault-time
        // sends never block the simulator's lock scope.)
        let (b_incoming_tx, b_incoming_rx) = mpsc::channel(1024);
        tokio::spawn(bridge(incoming_rx, b_incoming_tx));
        Harness {
            transport,
            incoming: b_incoming_rx,
        }
    }

    /// Sever the link between `a` and `b` in both directions.
    ///
    /// New dials fail and established connections crossing the cut are reset.
    /// Leaving those connections
    /// alive would let later operations traverse an allegedly partitioned
    /// link forever because simulated streams are channels rather than a
    /// finite kernel packet buffer.
    pub fn partition(&self, a: PeerId, b: PeerId) {
        let key = if a <= b { (a, b) } else { (b, a) };
        let mut inner = self.inner.lock().unwrap();
        inner.partitions.insert(key);
        inner.conns.retain(|conn| {
            let crosses_cut = (conn.a == a && conn.b == b) || (conn.a == b && conn.b == a);
            if crosses_cut {
                conn.closed.store(true, Ordering::SeqCst);
                conn.notify.notify_waiters();
                false
            } else {
                true
            }
        });
    }

    /// Restore the link between `a` and `b`.
    pub fn heal(&self, a: PeerId, b: PeerId) {
        let key = if a <= b { (a, b) } else { (b, a) };
        self.inner.lock().unwrap().partitions.remove(&key);
    }

    /// Take `id` off the network: dials to it fail.
    /// Its host loop keeps running (a crashed process is modeled by
    /// also dropping the node's Peer + harness; a *disconnected* node
    /// is modeled by this alone).
    /// Make connection setup toward `id` stall forever (pending, not
    /// erroring) until [`SimNet::unstall_dials`]. Established
    /// connections are unaffected.
    pub fn stall_dials(&self, id: PeerId) {
        self.inner.lock().unwrap().stalled_dials.insert(id);
    }

    /// Lift a [`SimNet::stall_dials`] fault. Dials already pending
    /// stay pending — like production, where a wedged connection setup
    /// doesn't retroactively complete; recovery comes from the
    /// caller's deadline + retry.
    pub fn unstall_dials(&self, id: PeerId) {
        self.inner.lock().unwrap().stalled_dials.remove(&id);
    }

    pub fn crash(&self, id: PeerId) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(n) = inner.nodes.get_mut(&id) {
            n.up = false;
        }
        // A dead process's QUIC connections reset: close every conn
        // pair touching the node so the surviving side's in-flight
        // ops fail fast (open_bi errors, accept_bi ends, reads EOF)
        // instead of silently succeeding against a "crashed" peer.
        // The pool's evict-on-error path then clears the cached conn
        // and later walks re-dial — which fails until revive.
        inner.conns.retain(|c| {
            if c.a == id || c.b == id {
                c.closed.store(true, Ordering::SeqCst);
                c.notify.notify_waiters();
                false
            } else {
                true
            }
        });
    }

    /// Bring `id` back onto the network.
    pub fn revive(&self, id: PeerId) {
        if let Some(n) = self.inner.lock().unwrap().nodes.get_mut(&id) {
            n.up = true;
        }
    }

    /// Advance the simulation by `dur`: moves the virtual clock and
    /// the paused tokio timer wheel together, then yields enough
    /// times for woken tasks to run to their next await point.
    ///
    /// This is the discrete-event scheduler's tick. Requires the
    /// caller to be inside a `start_paused(true)` current-thread
    /// runtime with `clock` installed virtual.
    pub async fn step(clock: &crate::clock::VirtualClock, dur: Duration) {
        // Quiescence-driven stepping: on a `start_paused(true)`
        // runtime, `sleep` only resolves after the runtime has fully
        // parked — i.e. every runnable task has run to its next await
        // — at which point tokio auto-advances to the next timer
        // deadline. Intermediate timers (sim latencies, host poll
        // sleeps) fire and their wake cascades drain COMPLETELY
        // before time moves again. This is what makes the step
        // deterministic AND starvation-free: a fixed yield budget
        // (the previous design) silently starved the task-queue tail
        // once enough concurrent walks piled up, freezing in-flight
        // streams for tens of virtual seconds.
        //
        // The virtual wall clock advances in lockstep AFTER the
        // sleep: protocol-visible time (cooldowns, rebroadcast
        // ticks, expiry) lags tokio's timer wheel by at most one
        // step — a bounded, deterministic skew.
        tokio::time::sleep(dur).await;
        clock.advance(dur);
    }

    /// Number of attempted direct dials between two exact endpoints.
    pub fn dial_count(&self, from: PeerId, to: PeerId) -> usize {
        self.inner
            .lock()
            .unwrap()
            .dials
            .iter()
            .filter(|(actual_from, actual_to)| *actual_from == from && *actual_to == to)
            .count()
    }
}

/// Forward from the unbounded internal channel to the bounded one the
/// harness exposes.
async fn bridge<T: Send + 'static>(mut rx: mpsc::UnboundedReceiver<T>, tx: mpsc::Sender<T>) {
    while let Some(item) = rx.recv().await {
        if tx.send(item).await.is_err() {
            return;
        }
    }
}

/// One node's transport handle onto the [`SimNet`].
#[derive(Clone)]
pub struct SimTransport {
    net: SimNet,
    id: PeerId,
}

impl Transport for SimTransport {
    type Conn = SimConn;

    fn local_id(&self) -> PeerId {
        self.id
    }

    async fn dial(&self, peer: PeerId, alpn: Alpn) -> anyhow::Result<Self::Conn> {
        let (latency, incoming_tx, stalled) = {
            let mut inner = self.net.inner.lock().unwrap();
            inner.dials.push((self.id, peer));
            if inner.partitioned(&self.id, &peer) {
                anyhow::bail!(
                    "simnet: {} -> {}: partitioned",
                    hex_prefix(&self.id),
                    hex_prefix(&peer)
                );
            }
            let incoming_tx = {
                let Some(slot) = inner.nodes.get(&peer) else {
                    anyhow::bail!("simnet: dial {}: unknown node", hex_prefix(&peer));
                };
                if !slot.up {
                    anyhow::bail!("simnet: dial {}: node down", hex_prefix(&peer));
                }
                let me = inner.nodes.get(&self.id);
                if me.map(|m| !m.up).unwrap_or(true) {
                    anyhow::bail!("simnet: dial from downed node {}", hex_prefix(&self.id));
                }
                slot.incoming_tx.clone()
            };
            let stalled = inner.stalled_dials.contains(&peer);
            (inner.latency(), incoming_tx, stalled)
        };

        if stalled {
            // Pending forever — the dial neither completes nor
            // errors. See `stalled_dials`.
            std::future::pending::<()>().await;
            unreachable!();
        }

        // Connection setup costs one round trip.
        tokio::time::sleep(latency * 2).await;

        let (dialer, acceptor) = SimConn::pair(self.id, peer);
        {
            let mut inner = self.net.inner.lock().unwrap();
            // Re-check liveness after the dial latency: a crash that
            // landed mid-connection-setup kills the attempt.
            let target_up = inner.nodes.get(&peer).map(|n| n.up).unwrap_or(false);
            if !target_up || inner.partitioned(&self.id, &peer) {
                anyhow::bail!(
                    "simnet: dial {}: peer lost during connection setup",
                    hex_prefix(&peer)
                );
            }
            inner.conns.push(ConnHandle {
                a: self.id,
                b: peer,
                closed: dialer.closed.clone(),
                notify: dialer.notify_close.clone(),
            });
        }
        incoming_tx
            .send(Incoming {
                alpn,
                conn: acceptor,
            })
            .map_err(|_| anyhow::anyhow!("simnet: dial {}: node gone", hex_prefix(&peer)))?;
        Ok(dialer)
    }

    async fn shutdown(&self) {}
}

/// A simulated connection: two endpoints exchanging bidirectional
/// streams over in-memory pipes.
#[derive(Clone)]
pub struct SimConn {
    local: PeerId,
    remote: PeerId,
    /// Streams we open land on the remote's accept queue.
    open_tx: mpsc::UnboundedSender<(SimSendStream, SimRecvStream)>,
    /// Streams the remote opens land here.
    accept_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<(SimSendStream, SimRecvStream)>>>,
    /// Slots for the streams this end opens, [`MAX_BIDI_STREAMS`] of them.
    streams: Arc<Semaphore>,
    /// Shared close flag — either end closing kills both directions.
    closed: Arc<AtomicBool>,
    notify_close: Arc<tokio::sync::Notify>,
}

/// One simulated stream: its two directions and the opener's slot.
struct Stream {
    /// The opener's direction, then the acceptor's.
    directions: [Direction; 2],
    /// Held until the stream is closed on the acceptor's side.
    slot: Option<OwnedSemaphorePermit>,
}

/// One direction of a stream, shared by its writing and its reading half.
#[derive(Default)]
struct Direction {
    /// Written and not yet read, never more than [`STREAM_WINDOW`] bytes.
    buffer: VecDeque<u8>,
    sending: Sending,
    receiving: Receiving,
    writer: Option<Waker>,
    reader: Option<Waker>,
}

/// The writing half's state. Dropping an open writer finishes it, as noq's
/// `SendStream` does.
#[derive(Clone, Copy, Default, PartialEq)]
enum Sending {
    #[default]
    Open,
    Finished,
    Reset(u32),
}

/// The reading half's state. `Closed` means it read the end or the reset.
/// Dropping an open reader stops it with code 0, as noq's `RecvStream` does.
#[derive(Clone, Copy, Default, PartialEq)]
enum Receiving {
    #[default]
    Open,
    Closed,
    Stopped(u32),
}

impl Stream {
    /// Gives the opener's slot back once the acceptor has closed both its
    /// halves: its own direction finished or reset, and the opener's read to
    /// the end, its reset read, or stopped once its writer ended. noq-proto
    /// raises the opener's stream limit at the same point (`stream_freed`).
    fn release_closed_slot(&mut self) {
        let [opener, acceptor] = &self.directions;
        if opener.sending != Sending::Open
            && opener.receiving != Receiving::Open
            && acceptor.sending != Sending::Open
        {
            self.slot = None;
        }
    }
}

impl Direction {
    fn finish(&mut self) {
        if self.sending == Sending::Open {
            self.sending = Sending::Finished;
            wake(&mut self.reader);
        }
    }

    /// Abandon sending: unread bytes are dropped and the reader fails with
    /// `code`. A finished writer has delivered everything already.
    fn reset(&mut self, code: u32) {
        if self.sending == Sending::Open {
            self.sending = Sending::Reset(code);
            self.buffer.clear();
            wake(&mut self.reader);
        }
    }

    /// Stop reading: unread bytes are dropped and the writer fails with
    /// `code`.
    fn stop(&mut self, code: u32) {
        if self.receiving == Receiving::Open {
            self.receiving = Receiving::Stopped(code);
            self.buffer.clear();
            wake(&mut self.writer);
        }
    }
}

fn wake(waker: &mut Option<Waker>) {
    if let Some(waker) = waker.take() {
        waker.wake();
    }
}

/// The peer reset or stopped the stream with `code`.
fn stream_error(code: u32) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, super::Reset(code))
}

/// One half of a simulated stream, permanently bound to its original
/// connection: closing the connection fails every read and write, and
/// healing or rejoining an endpoint cannot reopen it. No driver task is
/// needed: each half owns one cancellation-safe notification future.
struct Half {
    stream: Arc<Mutex<Stream>>,
    /// The index of the direction this half writes or reads.
    direction: usize,
    closed: Arc<AtomicBool>,
    on_close: Pin<Box<tokio::sync::futures::OwnedNotified>>,
}

impl Half {
    fn new(stream: &Arc<Mutex<Stream>>, direction: usize, connection: &SimConn) -> Self {
        Self {
            stream: stream.clone(),
            direction,
            closed: connection.closed.clone(),
            // notify_waiters reaches futures created before the notification,
            // even before their first poll. Construct eagerly, not after the
            // open-state check: otherwise a close could land in that gap.
            on_close: Box::pin(connection.notify_close.clone().notified_owned()),
        }
    }

    fn check_open(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) || self.on_close.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "simnet: connection reset",
            ));
        }
        Ok(())
    }

    fn update(&self, change: impl FnOnce(&mut Direction)) {
        let mut stream = self.stream.lock().unwrap();
        change(&mut stream.directions[self.direction]);
        stream.release_closed_slot();
    }
}

/// The sending half of a simulated stream.
pub struct SimSendStream(Half);

/// The receiving half of a simulated stream.
pub struct SimRecvStream(Half);

impl super::SendStream for SimSendStream {
    fn reset(&mut self, code: u32) {
        self.0.update(|direction| direction.reset(code));
    }
}

impl super::RecvStream for SimRecvStream {
    fn stop(&mut self, code: u32) {
        self.0.update(|direction| direction.stop(code));
    }
}

impl Drop for SimSendStream {
    fn drop(&mut self) {
        self.0.update(Direction::finish);
    }
}

impl Drop for SimRecvStream {
    fn drop(&mut self) {
        self.0.update(|direction| direction.stop(0));
    }
}

impl AsyncRead for SimRecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let half = &mut self.get_mut().0;
        half.check_open(cx)?;
        let mut stream = half.stream.lock().unwrap();
        let stream = &mut *stream;
        let direction = &mut stream.directions[half.direction];
        match (direction.receiving, direction.sending) {
            (Receiving::Stopped(code), _) => {
                return Poll::Ready(Err(stream_error(code)));
            }
            (_, Sending::Reset(code)) => {
                direction.receiving = Receiving::Closed;
                stream.release_closed_slot();
                return Poll::Ready(Err(stream_error(code)));
            }
            _ => {}
        }
        if !direction.buffer.is_empty() {
            let read = buf.remaining().min(direction.buffer.len());
            let (front, back) = direction.buffer.as_slices();
            let from_front = read.min(front.len());
            buf.put_slice(&front[..from_front]);
            buf.put_slice(&back[..read - from_front]);
            direction.buffer.drain(..read);
            wake(&mut direction.writer);
            return Poll::Ready(Ok(()));
        }
        if direction.sending == Sending::Finished {
            direction.receiving = Receiving::Closed;
            stream.release_closed_slot();
            return Poll::Ready(Ok(()));
        }
        direction.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for SimSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let half = &mut self.get_mut().0;
        half.check_open(cx)?;
        let mut stream = half.stream.lock().unwrap();
        let direction = &mut stream.directions[half.direction];
        match (direction.sending, direction.receiving) {
            (Sending::Reset(code), _) => return Poll::Ready(Err(stream_error(code))),
            (_, Receiving::Stopped(code)) => {
                return Poll::Ready(Err(stream_error(code)));
            }
            (Sending::Finished, _) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "simnet: write after finish",
                )));
            }
            (Sending::Open, _) => {}
        }
        let credit = STREAM_WINDOW - direction.buffer.len();
        if credit == 0 {
            direction.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let written = credit.min(buf.len());
        direction.buffer.extend(&buf[..written]);
        wake(&mut direction.reader);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().0.check_open(cx)?;
        Poll::Ready(Ok(()))
    }

    /// Finishing is harmless once the reader stopped, as in noq.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let half = &mut self.get_mut().0;
        half.check_open(cx)?;
        let mut stream = half.stream.lock().unwrap();
        if let Sending::Reset(code) = stream.directions[half.direction].sending {
            return Poll::Ready(Err(stream_error(code)));
        }
        stream.directions[half.direction].finish();
        stream.release_closed_slot();
        Poll::Ready(Ok(()))
    }
}

impl SimConn {
    fn pair(dialer: PeerId, acceptor: PeerId) -> (SimConn, SimConn) {
        let (d2a_tx, d2a_rx) = mpsc::unbounded_channel();
        let (a2d_tx, a2d_rx) = mpsc::unbounded_channel();
        let closed = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(tokio::sync::Notify::new());
        let dialer_end = SimConn {
            local: dialer,
            remote: acceptor,
            open_tx: d2a_tx,
            accept_rx: Arc::new(tokio::sync::Mutex::new(a2d_rx)),
            streams: Arc::new(Semaphore::new(MAX_BIDI_STREAMS)),
            closed: closed.clone(),
            notify_close: notify.clone(),
        };
        let acceptor_end = SimConn {
            local: acceptor,
            remote: dialer,
            open_tx: a2d_tx,
            accept_rx: Arc::new(tokio::sync::Mutex::new(d2a_rx)),
            streams: Arc::new(Semaphore::new(MAX_BIDI_STREAMS)),
            closed,
            notify_close: notify,
        };
        (dialer_end, acceptor_end)
    }
}

impl Conn for SimConn {
    type SendHalf = SimSendStream;
    type RecvHalf = SimRecvStream;

    fn remote_id(&self) -> PeerId {
        self.remote
    }

    async fn open_bi(&self) -> anyhow::Result<(SimSendStream, SimRecvStream)> {
        // As in accept_bi, capture close before checking the flag.
        let on_close = self.notify_close.notified();
        let slot = if self.closed.load(Ordering::SeqCst) {
            None
        } else {
            tokio::select! {
                biased;
                _ = on_close => None,
                slot = self.streams.clone().acquire_owned() => Some(slot?),
            }
        };
        let Some(slot) = slot else {
            anyhow::bail!(
                "simnet: open_bi on closed conn {} -> {}",
                hex_prefix(&self.local),
                hex_prefix(&self.remote)
            );
        };
        let stream = Arc::new(Mutex::new(Stream {
            directions: Default::default(),
            slot: Some(slot),
        }));
        self.open_tx
            .send((
                SimSendStream(Half::new(&stream, 1, self)),
                SimRecvStream(Half::new(&stream, 0, self)),
            ))
            .map_err(|_| anyhow::anyhow!("simnet: open_bi: remote end dropped"))?;
        Ok((
            SimSendStream(Half::new(&stream, 0, self)),
            SimRecvStream(Half::new(&stream, 1, self)),
        ))
    }

    async fn accept_bi(&self) -> Option<(SimSendStream, SimRecvStream)> {
        // Capture close before checking the flag, and keep it in the select
        // while waiting for either the queue lock or the next stream.
        let on_close = self.notify_close.notified();
        if self.closed.load(Ordering::SeqCst) {
            return None;
        }
        tokio::select! {
            biased;
            _ = on_close => None,
            stream = async {
                let mut rx = self.accept_rx.lock().await;
                rx.recv().await
            } => stream,
        }
    }

    fn close(&self, _code: u32, _reason: &[u8]) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify_close.notify_waiters();
    }
}

/// A frame that crossed a stream of a [`Tapped`] transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Crossed {
    /// The remote peer of the stream's connection.
    pub peer: PeerId,
    /// The stream, numbered across the tap as streams are opened and
    /// accepted.
    pub stream: u64,
    /// The stream's tag: its first byte, which its opener wrote.
    pub tag: u8,
    /// Whether the tapped side sent the frame.
    pub sent: bool,
    /// The frame's kind byte.
    pub kind: u8,
    /// Exact frame bytes, including its five-byte framing header.
    pub wire_bytes: usize,
    /// Prefix depth for a complete walk subtree announcement, if applicable.
    pub walk_depth: Option<u8>,
}

/// Every frame that crossed a `recon/1` or `walk/1` stream of a [`Tapped`]
/// transport, in the order its halves saw them.
#[derive(Clone, Default)]
pub struct Taps(Arc<Mutex<Vec<Crossed>>>);

impl Taps {
    pub fn crossed(&self) -> Vec<Crossed> {
        self.0.lock().unwrap().clone()
    }

    /// How many frames crossed so far.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The frames that crossed since the first `from` did, on streams to
    /// `peer`, with their tag.
    pub fn since(&self, from: usize, peer: PeerId, tag: u8) -> Vec<Crossed> {
        self.0.lock().unwrap()[from..]
            .iter()
            .filter(|crossed| crossed.peer == peer && crossed.tag == tag)
            .copied()
            .collect()
    }
}

impl SimNet {
    /// Join the network as `key` through a tap: the transport is a
    /// [`SimTransport`] whose streams note every frame crossing them.
    pub fn tap(&self, key: &SigningKey) -> (Harness<Tapped>, Taps) {
        let Harness {
            transport,
            mut incoming,
        } = self.join(key);
        let tapped = Tapped {
            inner: transport,
            taps: Taps::default(),
            streams: Arc::new(AtomicU64::new(0)),
        };
        let (forward, accepted) = mpsc::channel(1024);
        let wrapping = tapped.clone();
        tokio::spawn(async move {
            while let Some(Incoming { alpn, conn }) = incoming.recv().await {
                let conn = wrapping.conn(conn);
                if forward.send(Incoming { alpn, conn }).await.is_err() {
                    return;
                }
            }
        });
        let taps = tapped.taps.clone();
        (
            Harness {
                transport: tapped,
                incoming: accepted,
            },
            taps,
        )
    }
}

/// A [`SimTransport`] whose streams note every frame crossing them in its
/// [`Taps`].
#[derive(Clone)]
pub struct Tapped {
    inner: SimTransport,
    taps: Taps,
    streams: Arc<AtomicU64>,
}

impl Tapped {
    fn conn(&self, inner: SimConn) -> TappedConn {
        TappedConn {
            inner,
            taps: self.taps.clone(),
            streams: self.streams.clone(),
        }
    }
}

impl Transport for Tapped {
    type Conn = TappedConn;

    fn local_id(&self) -> PeerId {
        self.inner.local_id()
    }

    async fn dial(&self, peer: PeerId, alpn: Alpn) -> anyhow::Result<TappedConn> {
        Ok(self.conn(self.inner.dial(peer, alpn).await?))
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await
    }
}

#[derive(Clone)]
pub struct TappedConn {
    inner: SimConn,
    taps: Taps,
    streams: Arc<AtomicU64>,
}

impl TappedConn {
    /// The halves of one stream, which share its tag; `opened` says this
    /// side opened it and writes the tag.
    fn halves(
        &self,
        (send, recv): (SimSendStream, SimRecvStream),
        opened: bool,
    ) -> (TappedSend, TappedRecv) {
        let tag = Arc::new(OnceLock::new());
        let stream = self.streams.fetch_add(1, Ordering::Relaxed);
        let tap = |sent| Tap {
            taps: self.taps.clone(),
            peer: self.inner.remote_id(),
            stream,
            tag: tag.clone(),
            first: sent == opened,
            sent,
            buffer: Vec::new(),
        };
        (
            TappedSend {
                inner: send,
                tap: tap(true),
            },
            TappedRecv {
                inner: recv,
                tap: tap(false),
            },
        )
    }
}

impl Conn for TappedConn {
    type SendHalf = TappedSend;
    type RecvHalf = TappedRecv;

    fn remote_id(&self) -> PeerId {
        self.inner.remote_id()
    }

    async fn open_bi(&self) -> anyhow::Result<(TappedSend, TappedRecv)> {
        Ok(self.halves(self.inner.open_bi().await?, true))
    }

    async fn accept_bi(&self) -> Option<(TappedSend, TappedRecv)> {
        Some(self.halves(self.inner.accept_bi().await?, false))
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.inner.close(code, reason)
    }
}

/// One half's view of its stream: the tag the halves share, and the bytes
/// of a frame not yet whole.
struct Tap {
    taps: Taps,
    peer: PeerId,
    stream: u64,
    tag: Arc<OnceLock<u8>>,
    /// The tag is this half's first byte.
    first: bool,
    sent: bool,
    buffer: Vec<u8>,
}

impl Tap {
    /// Note `bytes` crossing: the tag first, then whole frames of the
    /// framing `recon/1` and `walk/1` share. Other tags are not parsed.
    fn note(&mut self, mut bytes: &[u8]) {
        if self.first && self.tag.get().is_none() {
            let Some((&tag, rest)) = bytes.split_first() else {
                return;
            };
            let _ = self.tag.set(tag);
            bytes = rest;
        }
        self.buffer.extend_from_slice(bytes);
        let Some(&tag) = self.tag.get() else {
            return;
        };
        if tag != TAG_RECON && tag != TAG_WALK {
            self.buffer.clear();
            return;
        }
        while let Some(length) = self.buffer.get(1..5) {
            let length = 5 + u32::from_be_bytes(length.try_into().unwrap()) as usize;
            if self.buffer.len() < length {
                break;
            }
            let kind = self.buffer[0];
            let walk_depth = (tag == TAG_WALK
                && kind == crate::walk_stream::FRAME_SUBTREE
                && length == 5 + crate::walk_stream::SUBTREE_BYTES)
                .then(|| self.buffer[5]);
            self.buffer.drain(..length);
            self.taps.0.lock().unwrap().push(Crossed {
                peer: self.peer,
                stream: self.stream,
                tag,
                sent: self.sent,
                kind,
                wire_bytes: length,
                walk_depth,
            });
        }
    }
}

pub struct TappedSend {
    inner: SimSendStream,
    tap: Tap,
}

pub struct TappedRecv {
    inner: SimRecvStream,
    tap: Tap,
}

impl AsyncWrite for TappedSend {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            this.tap.note(&buf[..written]);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl super::SendStream for TappedSend {
    fn reset(&mut self, code: u32) {
        self.inner.reset(code)
    }
}

impl AsyncRead for TappedRecv {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            this.tap.note(&buf.filled()[before..]);
        }
        polled
    }
}

impl super::RecvStream for TappedRecv {
    fn stop(&mut self, code: u32) {
        self.inner.stop(code)
    }
}

fn hex_prefix(id: &PeerId) -> String {
    hex::encode(&id[..4])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct WakeCount(std::sync::atomic::AtomicUsize);

    impl futures::task::ArcWake for WakeCount {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn close_between_open_check_and_listener_poll_is_not_lost() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let (mut send, mut recv) = dialer.open_bi().await.unwrap();
        let (_s_send, _s_recv) = acceptor.accept_bi().await.unwrap();
        // Split check_open at exactly its flag-check/listener-poll boundary.
        // Both listeners already exist but neither has registered a waker.
        assert!(!send.0.closed.load(Ordering::SeqCst));
        assert!(!recv.0.closed.load(Ordering::SeqCst));
        dialer.close(0, b"close in registration gap");
        let wake = Arc::new(WakeCount::default());
        let waker = futures::task::waker_ref(&wake);
        let mut context = Context::from_waker(&waker);
        assert!(send.0.on_close.as_mut().poll(&mut context).is_ready());
        assert!(recv.0.on_close.as_mut().poll(&mut context).is_ready());
        assert!(send.write_all(b"late").await.is_err());
        assert!(recv.read(&mut [0]).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn close_wakes_blocked_read_and_write_and_discards_buffered_bytes() {
        use std::future::Future as _;
        use std::task::Context;

        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let (mut c_send, mut c_recv) = dialer.open_bi().await.unwrap();
        let (mut s_send, mut s_recv) = acceptor.accept_bi().await.unwrap();
        c_send.write_all(&vec![b'x'; STREAM_WINDOW]).await.unwrap();
        let wake = Arc::new(WakeCount::default());
        let waker = futures::task::waker_ref(&wake);
        let mut context = Context::from_waker(&waker);
        let mut buf = [0; 1];
        let mut read = Box::pin(c_recv.read_exact(&mut buf));
        let mut write = Box::pin(c_send.write_all(b"y"));
        assert!(read.as_mut().poll(&mut context).is_pending());
        assert!(write.as_mut().poll(&mut context).is_pending());
        dialer.close(0, b"reset");
        assert_eq!(
            wake.0.load(Ordering::SeqCst),
            2,
            "both parked I/O tasks must wake"
        );
        assert_eq!(
            read.await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            write.await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert!(
            s_recv.read_exact(&mut buf).await.is_err(),
            "buffered bytes survived reset"
        );
        assert!(s_send.write_all(b"late").await.is_err());
        assert!(s_send.flush().await.is_err());
        assert!(s_send.shutdown().await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn crash_and_partition_keep_old_streams_closed_after_recovery() {
        for partition in [false, true] {
            // Test-only endpoint seeds and network seed.
            let net = SimNet::new(
                19,
                SimConfig {
                    latency: Duration::ZERO..Duration::ZERO,
                },
            );
            let client_key = SigningKey::from_bytes(&[1; 32]);
            let server_key = SigningKey::from_bytes(&[2; 32]);
            let client = net.join(&client_key);
            let mut server = net.join(&server_key);
            let a = client.transport.local_id();
            let b = server.transport.local_id();
            let old = client
                .transport
                .dial(b, crate::protocol::PILE_SYNC_ALPN)
                .await
                .unwrap();
            let accepted = server.incoming.recv().await.unwrap().conn;
            let (_old_send, mut old_recv) = old.open_bi().await.unwrap();
            let (mut old_server_send, _old_server_recv) = accepted.accept_bi().await.unwrap();
            old_server_send.write_all(b"old").await.unwrap();
            if partition {
                net.partition(a, b);
                net.heal(a, b);
            } else {
                net.crash(b);
                server = net.join(&server_key);
            }
            let mut bytes = [0; 3];
            assert!(old_recv.read_exact(&mut bytes).await.is_err());
            assert!(old_server_send.write_all(b"old").await.is_err());
            assert!(old.open_bi().await.is_err());
            let fresh = client
                .transport
                .dial(b, crate::protocol::PILE_SYNC_ALPN)
                .await
                .unwrap();
            let accepted = server.incoming.recv().await.unwrap().conn;
            let (_send, mut recv) = fresh.open_bi().await.unwrap();
            let (mut send, _recv) = accepted.accept_bi().await.unwrap();
            send.write_all(b"new").await.unwrap();
            recv.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"new");
        }
    }

    /// The close/drop contract the protocol's evict-and-retry paths
    /// rely on (and that iroh QUIC provides in production): a conn
    /// whose remote end is gone must FAIL FAST — open_bi errors,
    /// accept_bi returns None, in-flight stream reads see EOF —
    /// never silently black-hole.

    #[tokio::test(start_paused = true)]
    async fn drop_of_acceptor_fails_dialer_open_bi() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        drop(acceptor);
        assert!(
            dialer.open_bi().await.is_err(),
            "open_bi to a dropped remote must error, not queue"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn drop_of_dialer_ends_acceptor_accept_loop() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        drop(dialer);
        assert!(
            acceptor.accept_bi().await.is_none(),
            "accept_bi must end when the remote end is dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn close_wakes_blocked_accept() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let acceptor2 = acceptor.clone();
        let waiter = tokio::spawn(async move { acceptor2.accept_bi().await.is_none() });
        tokio::task::yield_now().await;
        dialer.close(0, b"bye");
        assert!(
            waiter.await.unwrap(),
            "close() must wake a parked accept_bi with None"
        );
        assert!(
            dialer.open_bi().await.is_err(),
            "open_bi after close errors"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn close_while_accept_waits_for_queue_lock_is_not_lost() {
        for queued_stream in [false, true] {
            let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
            let _stream = if queued_stream {
                Some(dialer.open_bi().await.unwrap())
            } else {
                None
            };
            let queue = acceptor.accept_rx.lock().await;
            let accept = acceptor.accept_bi();
            tokio::pin!(accept);
            assert!(futures::poll!(&mut accept).is_pending());
            dialer.close(0, b"close while queue lock held");
            drop(queue);
            assert!(
                matches!(futures::poll!(&mut accept), Poll::Ready(None)),
                "accept must remember close and prefer it over a queued stream"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn close_wakes_accept_without_waiting_for_queue_lock() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let _queue = acceptor.accept_rx.lock().await;
        let mut accept = Box::pin(acceptor.accept_bi());
        let wake = Arc::new(WakeCount::default());
        let waker = futures::task::waker_ref(&wake);
        let mut context = Context::from_waker(&waker);
        assert!(accept.as_mut().poll(&mut context).is_pending());
        dialer.close(0, b"close before queue lock released");
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(
            matches!(accept.as_mut().poll(&mut context), Poll::Ready(None)),
            "closing must cancel even a mutex-blocked accept"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reset_and_stop_fail_only_their_own_stream() {
        use crate::transport::{RecvStream as _, SendStream as _};

        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let (mut c_send, mut c_recv) = dialer.open_bi().await.unwrap();
        let (mut s_send, mut s_recv) = acceptor.accept_bi().await.unwrap();
        // A parked read wakes on reset, and buffered bytes are not delivered.
        s_send.write_all(b"discarded").await.unwrap();
        let mut buf = [0; 16];
        let mut read = Box::pin(c_recv.read(&mut buf));
        assert!(matches!(futures::poll!(&mut read), Poll::Ready(Ok(9))));
        drop(read);
        let mut read = Box::pin(c_recv.read(&mut buf));
        assert!(futures::poll!(&mut read).is_pending());
        s_send.write_all(b"late").await.unwrap();
        s_send.reset(7);
        let error = read.await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(error.to_string().contains("code 7"), "{error}");
        assert!(s_send.write_all(b"after reset").await.is_err());

        // Stop fails the remote writer, including one waiting for capacity.
        c_send.write_all(&vec![b'x'; STREAM_WINDOW]).await.unwrap();
        let mut write = Box::pin(c_send.write_all(b"y"));
        assert!(futures::poll!(&mut write).is_pending());
        s_recv.stop(9);
        let error = write.await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(error.to_string().contains("code 9"), "{error}");

        // The connection itself keeps carrying other streams.
        let (mut send, _recv) = dialer.open_bi().await.unwrap();
        let (_send, mut recv) = acceptor.accept_bi().await.unwrap();
        send.write_all(b"ok").await.unwrap();
        let mut bytes = [0; 2];
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
    }

    #[tokio::test(start_paused = true)]
    async fn open_bi_beyond_the_limit_waits_until_the_acceptor_closes_a_stream() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let mut opened = Vec::new();
        for _ in 0..MAX_BIDI_STREAMS {
            opened.push(dialer.open_bi().await.unwrap());
        }
        let mut next = Box::pin(dialer.open_bi());
        assert!(futures::poll!(&mut next).is_pending());
        // The limit is per direction.
        let _reverse = acceptor.open_bi().await.unwrap();

        // A stream closes when the acceptor has read the opener's end and
        // finished its own direction, whoever still holds the halves.
        let (send, _recv) = &mut opened[0];
        send.write_all(b"request").await.unwrap();
        send.shutdown().await.unwrap();
        assert!(futures::poll!(&mut next).is_pending());
        let (mut s_send, mut s_recv) = acceptor.accept_bi().await.unwrap();
        let mut request = Vec::new();
        s_recv.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        assert!(futures::poll!(&mut next).is_pending());
        s_send.write_all(b"response").await.unwrap();
        s_send.shutdown().await.unwrap();
        next.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_writer_blocks_while_its_reader_does_not_read() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let (mut send, _recv) = dialer.open_bi().await.unwrap();
        let (_send, mut recv) = acceptor.accept_bi().await.unwrap();
        send.write_all(&vec![b'x'; STREAM_WINDOW]).await.unwrap();
        let mut write = Box::pin(send.write_all(b"more"));
        assert!(futures::poll!(&mut write).is_pending());
        // Reading four bytes grants credit for four.
        recv.read_exact(&mut [0; 4]).await.unwrap();
        write.await.unwrap();
        assert!(futures::poll!(Box::pin(send.write_all(b"!"))).is_pending());
    }

    #[tokio::test(start_paused = true)]
    async fn reset_surfaces_its_code_on_the_peer_read_which_frees_the_slot() {
        use crate::transport::SendStream as _;

        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let mut opened = Vec::new();
        for _ in 0..MAX_BIDI_STREAMS {
            opened.push(dialer.open_bi().await.unwrap());
        }
        let (mut s_send, mut s_recv) = acceptor.accept_bi().await.unwrap();
        s_send.shutdown().await.unwrap();
        let mut next = Box::pin(dialer.open_bi());
        let (send, _recv) = &mut opened[0];
        send.write_all(b"discarded").await.unwrap();
        send.reset(7);
        // The stream holds its slot until the acceptor has read the reset.
        assert!(futures::poll!(&mut next).is_pending());
        let error = s_recv.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(error.to_string().contains("code 7"), "{error}");
        next.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn handler_dropping_stream_halves_eofs_client_read() {
        let (dialer, acceptor) = SimConn::pair([1; 32], [2; 32]);
        let (mut c_send, mut c_recv) = dialer.open_bi().await.unwrap();
        let (s_send, mut s_recv) = acceptor.accept_bi().await.unwrap();
        c_send.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        s_recv.read_exact(&mut buf).await.unwrap();
        // Server abandons the stream without replying (handler died).
        drop(s_send);
        drop(s_recv);
        let mut resp = [0u8; 1];
        assert!(
            c_recv.read_exact(&mut resp).await.is_err(),
            "client read on an abandoned stream must EOF, not hang"
        );
    }
}
