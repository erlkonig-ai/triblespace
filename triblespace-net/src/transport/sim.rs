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

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh_base::EndpointId;
use iroh_gossip::proto::DeliveryScope;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;

use super::{Alpn, Conn, Harness, Incoming, PeerId, Transport};
use crate::wake::{
    CollectionWake, CollectionWakeEvent, CollectionWakeNetwork, CollectionWakeRoot,
    CollectionWakeSubscription, ReceivedCollectionWake,
};

/// Capacity of each in-memory stream pipe. Bounded inventory blob ranges are
/// at most 1 MiB; larger exact reads rely on normal concurrent backpressure.
const PIPE_CAPACITY: usize = 4 * 1024 * 1024;

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
    wake_topics:
        BTreeMap<[u8; 32], BTreeMap<PeerId, (u64, mpsc::UnboundedSender<CollectionWakeEvent>)>>,
    next_wake_subscription: u64,
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
                wake_topics: BTreeMap::new(),
                next_wake_subscription: 0,
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
            signing_key: Arc::new(signing_key.clone()),
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
    signing_key: Arc<SigningKey>,
}

impl Transport for SimTransport {
    type Conn = SimConn;
    type WakePlane = SimWakePlane;

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

    fn collection_wake_plane(&self) -> Self::WakePlane {
        SimWakePlane {
            net: self.net.clone(),
            signing_key: self.signing_key.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SimWakePlane {
    net: SimNet,
    signing_key: Arc<SigningKey>,
}

pub struct SimWakeTopic {
    net: SimNet,
    collection: triblespace_core::collection::CollectionHandle,
    signing_key: Arc<SigningKey>,
    id: PeerId,
    subscription: u64,
    sequence: AtomicU64,
    rx: mpsc::UnboundedReceiver<CollectionWakeEvent>,
}

impl CollectionWakeNetwork for SimWakePlane {
    type Topic = SimWakeTopic;

    async fn subscribe_network(
        &self,
        collection: triblespace_core::collection::CollectionHandle,
        _bootstrap: Vec<EndpointId>,
    ) -> anyhow::Result<Self::Topic> {
        let id = self.signing_key.verifying_key().to_bytes();
        let (tx, rx) = mpsc::unbounded_channel();
        let (subscription, existing) = {
            let mut inner = self.net.inner.lock().unwrap();
            let subscription = inner.next_wake_subscription;
            inner.next_wake_subscription = subscription.wrapping_add(1);
            let existing = inner
                .wake_topics
                .get(&collection.raw)
                .map(|topics| {
                    topics
                        .iter()
                        .map(|(peer, (_, tx))| (*peer, tx.clone()))
                        .collect()
                })
                .unwrap_or_else(Vec::new);
            inner
                .wake_topics
                .entry(collection.raw)
                .or_default()
                .insert(id, (subscription, tx.clone()));
            (subscription, existing)
        };
        for (peer, existing_tx) in existing {
            let peer_id = EndpointId::from_bytes(&peer)?;
            let id_endpoint = EndpointId::from_bytes(&id)?;
            let _ = existing_tx.send(CollectionWakeEvent::NeighborUp(id_endpoint));
            let _ = tx.send(CollectionWakeEvent::NeighborUp(peer_id));
        }
        Ok(SimWakeTopic {
            net: self.net.clone(),
            collection,
            signing_key: self.signing_key.clone(),
            id,
            subscription,
            sequence: AtomicU64::new(0),
            rx,
        })
    }
}

impl CollectionWakeSubscription for SimWakeTopic {
    async fn join_wake_peers(&self, _peers: Vec<EndpointId>) -> anyhow::Result<()> {
        Ok(())
    }

    async fn broadcast_wake(&self, root: CollectionWakeRoot) -> anyhow::Result<CollectionWake> {
        let mut nonce = [0; 16];
        nonce[..8].copy_from_slice(&self.subscription.to_be_bytes());
        nonce[8..].copy_from_slice(&self.sequence.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        let wake = CollectionWake::sign(self.collection, root, nonce, &self.signing_key);
        self.relay_wake(&wake).await?;
        Ok(wake)
    }

    async fn relay_wake(&self, wake: &CollectionWake) -> anyhow::Result<()> {
        wake.verify(self.collection)?;
        let recipients = {
            let inner = self.net.inner.lock().unwrap();
            inner
                .wake_topics
                .get(&self.collection.raw)
                .into_iter()
                .flat_map(|topics| topics.iter())
                .filter(|(peer, _)| **peer != self.id)
                .filter(|(peer, _)| {
                    inner.nodes.get(*peer).is_some_and(|slot| slot.up)
                        && !inner.partitioned(&self.id, peer)
                })
                .map(|(_, (_, tx))| tx.clone())
                .collect::<Vec<_>>()
        };
        let delivered_from = EndpointId::from_bytes(&self.id)?;
        for tx in recipients {
            let _ = tx.send(CollectionWakeEvent::Received(ReceivedCollectionWake {
                wake: wake.clone(),
                delivered_from,
                scope: DeliveryScope::Neighbors,
            }));
        }
        Ok(())
    }

    async fn next_wake_event(&mut self) -> anyhow::Result<Option<CollectionWakeEvent>> {
        Ok(self.rx.recv().await)
    }
}

impl Drop for SimWakeTopic {
    fn drop(&mut self) {
        let mut inner = self.net.inner.lock().unwrap();
        let empty = if let Some(topics) = inner.wake_topics.get_mut(&self.collection.raw) {
            if topics
                .get(&self.id)
                .is_some_and(|(subscription, _)| *subscription == self.subscription)
            {
                topics.remove(&self.id);
            }
            topics.is_empty()
        } else {
            false
        };
        if empty {
            inner.wake_topics.remove(&self.collection.raw);
        }
    }
}

/// A simulated connection: two endpoints exchanging bidirectional
/// streams over in-memory pipes.
#[derive(Clone)]
pub struct SimConn {
    local: PeerId,
    remote: PeerId,
    /// Streams we open land on the remote's accept queue.
    open_tx: mpsc::UnboundedSender<(SimStream, SimStream)>,
    /// Streams the remote opens land here.
    accept_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<(SimStream, SimStream)>>>,
    /// Shared close flag — either end closing kills both directions.
    closed: Arc<AtomicBool>,
    notify_close: Arc<tokio::sync::Notify>,
}

/// One simulated stream half, permanently bound to its original connection.
/// A reset discards buffered bytes and wakes pending reads and writes; healing
/// or rejoining an endpoint cannot reopen this connection. No driver task is
/// needed: each half owns one cancellation-safe notification future.
pub struct SimStream {
    inner: DuplexStream,
    closed: Arc<AtomicBool>,
    on_close: Pin<Box<tokio::sync::futures::OwnedNotified>>,
}

impl SimStream {
    fn new(inner: DuplexStream, connection: &SimConn) -> Self {
        Self {
            inner,
            closed: connection.closed.clone(),
            // notify_waiters reaches futures created before the notification,
            // even before their first poll. Construct eagerly, not after the
            // open-state check: otherwise a close could land in that gap.
            on_close: Box::pin(connection.notify_close.clone().notified_owned()),
        }
    }

    fn poll_open(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) || self.on_close.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "simnet: connection reset",
            ));
        }
        Ok(())
    }
}

impl AsyncRead for SimStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SimStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_open(cx)?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
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
            closed: closed.clone(),
            notify_close: notify.clone(),
        };
        let acceptor_end = SimConn {
            local: acceptor,
            remote: dialer,
            open_tx: a2d_tx,
            accept_rx: Arc::new(tokio::sync::Mutex::new(d2a_rx)),
            closed,
            notify_close: notify,
        };
        (dialer_end, acceptor_end)
    }
}

impl Conn for SimConn {
    type SendHalf = SimStream;
    type RecvHalf = SimStream;

    fn remote_id(&self) -> PeerId {
        self.remote
    }

    async fn open_bi(&self) -> anyhow::Result<(SimStream, SimStream)> {
        if self.closed.load(Ordering::SeqCst) {
            anyhow::bail!(
                "simnet: open_bi on closed conn {} -> {}",
                hex_prefix(&self.local),
                hex_prefix(&self.remote)
            );
        }
        // Two pipes per bi-stream: one per direction. Each duplex()
        // call returns a connected pair; we use one side for writing
        // and hand the other to the remote for reading (and vice
        // versa).
        let (local_send, remote_recv) = tokio::io::duplex(PIPE_CAPACITY);
        let (remote_send, local_recv) = tokio::io::duplex(PIPE_CAPACITY);
        self.open_tx
            .send((
                SimStream::new(remote_send, self),
                SimStream::new(remote_recv, self),
            ))
            .map_err(|_| anyhow::anyhow!("simnet: open_bi: remote end dropped"))?;
        Ok((
            SimStream::new(local_send, self),
            SimStream::new(local_recv, self),
        ))
    }

    async fn accept_bi(&self) -> Option<(SimStream, SimStream)> {
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

fn hex_prefix(id: &PeerId) -> String {
    hex::encode(&id[..4])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn wake_relay_preserves_signed_origin_and_rejects_another_collection() {
        let net = SimNet::new(0x41, SimConfig::default());
        let relay_key = SigningKey::from_bytes(&[0x42; 32]);
        let reader_key = SigningKey::from_bytes(&[0x43; 32]);
        let source_key = SigningKey::from_bytes(&[0x44; 32]);
        let relay_harness = net.join(&relay_key);
        let reader_harness = net.join(&reader_key);
        let collection = triblespace_core::collection::CollectionHandle::new([0x45; 32]);
        let mut relay = relay_harness
            .transport
            .collection_wake_plane()
            .subscribe_network(collection, Vec::new())
            .await
            .unwrap();
        let mut reader = reader_harness
            .transport
            .collection_wake_plane()
            .subscribe_network(collection, Vec::new())
            .await
            .unwrap();
        assert!(matches!(
            relay.next_wake_event().await.unwrap(),
            Some(CollectionWakeEvent::NeighborUp(_))
        ));
        assert!(matches!(
            reader.next_wake_event().await.unwrap(),
            Some(CollectionWakeEvent::NeighborUp(_))
        ));

        let offered = CollectionWake::sign(
            collection,
            CollectionWakeRoot::new([0x46; 32]),
            [0x47; 16],
            &source_key,
        );
        relay.relay_wake(&offered).await.unwrap();
        let Some(CollectionWakeEvent::Received(received)) = reader.next_wake_event().await.unwrap()
        else {
            panic!("expected the unchanged signed offer");
        };
        assert_eq!(received.wake.to_bytes(), offered.to_bytes());
        assert_eq!(
            received.delivered_from.as_bytes(),
            relay_key.verifying_key().as_bytes()
        );
        assert_ne!(received.wake.origin(), received.delivered_from);
        assert_eq!(received.scope, DeliveryScope::Neighbors);

        let other_collection = triblespace_core::collection::CollectionHandle::new([0x48; 32]);
        let wrong_context =
            CollectionWake::sign(other_collection, offered.root(), [0x49; 16], &source_key);
        let error = relay.relay_wake(&wrong_context).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<crate::wake::CollectionWakeError>(),
            Some(&crate::wake::CollectionWakeError::InvalidSignature)
        );
        assert!(matches!(
            reader.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

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
        // Split poll_open at exactly its flag-check/listener-poll boundary.
        // Both listeners already exist but neither has registered a waker.
        assert!(!send.closed.load(Ordering::SeqCst));
        assert!(!recv.closed.load(Ordering::SeqCst));
        dialer.close(0, b"close in registration gap");
        let wake = Arc::new(WakeCount::default());
        let waker = futures::task::waker_ref(&wake);
        let mut context = Context::from_waker(&waker);
        assert!(send.on_close.as_mut().poll(&mut context).is_ready());
        assert!(recv.on_close.as_mut().poll(&mut context).is_ready());
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
        c_send.write_all(&vec![b'x'; PIPE_CAPACITY]).await.unwrap();
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
