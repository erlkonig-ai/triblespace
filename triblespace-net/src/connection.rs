//! One connection per peer pair, carrying typed streams.
//!
//! A [`ConnectionTable`] holds the connections of both directions, keyed by
//! the remote's TLS-authenticated [`PeerId`]. Every connection, dialled or
//! accepted, runs one accept loop. The first byte of each stream is its type
//! tag ([`TAG_RECON`], [`TAG_DHT`], [`TAG_BLOB`] and the transitional
//! [`TAG_REPAIR`]). The loop reads the tag before it takes any permit:
//! `recon/1` takes none, a request stream takes one of its connection's (or
//! is reset when none is left) and waits for one of the table's, and an
//! unknown tag resets only its own stream.
//!
//! The dialler opens `recon/1`, and its first frame carries the dialler's
//! sequence number. When a pair holds two connections, both sides keep the
//! same one: of crossed dials, the one dialled by the lower key; of two dials
//! by one side, the higher sequence number. The loser drains: nothing new is
//! opened on it, and it closes once no request stream is in flight on it and
//! no frame has crossed it for [`DRAIN_GRACE`], or like any other connection
//! when it goes idle.
//!
//! A connection closes after [`CONNECTION_IDLE_DEADLINE`] without a frame on
//! any of its streams, sent or received. Above [`MAX_CONNECTIONS`] in one
//! direction, the least recently used connection is evicted. A neighbour
//! connection is never evicted.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tracing::{Instrument as _, debug, debug_span, info_span, warn};

use crate::protocol::{PILE_SYNC_ALPN, TAG_BLOB, TAG_DHT, TAG_RECON, TAG_REPAIR, recv_u8, send_u8};
use crate::transport::{Conn, PeerId, RecvStream, SendStream, Transport};

/// Bound on a dial, including its opening `recon/1` frame.
const DIAL_DEADLINE: Duration = Duration::from_secs(10);
/// A connection closes after this long without a frame on any stream.
pub(crate) const CONNECTION_IDLE_DEADLINE: Duration = Duration::from_secs(120);
/// A retired connection closes after this long without a frame once no
/// request stream is in flight on it. The peer keeps using it only until it
/// has seen the winner too.
pub(crate) const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// Bound on serving one request stream.
const REQUEST_DEADLINE: Duration = Duration::from_secs(300);
/// A stream delivers its tag within this bound or is dropped.
const TAG_DEADLINE: Duration = Duration::from_secs(10);
/// Connections per direction, neighbours not counted. Above it the least
/// recently used one is evicted.
pub(crate) const MAX_CONNECTIONS: usize = 64;
/// Request streams each side opens on one connection. QUIC allows 100 open
/// bidirectional streams per direction, so `recon/1` can always reopen.
pub(crate) const MAX_REQUESTS_PER_CONNECTION: usize = 16;
/// Request streams the accepting side holds on one connection, waiting for a
/// permit or being served; one more is reset at once. An opener's own cap
/// lapses when it abandons a stream the acceptor still holds, so this bound
/// is what keeps stream credit free for `recon/1`. It is twice the opener's
/// cap, so an opener within its cap never meets it.
pub(crate) const MAX_HELD_REQUESTS_PER_CONNECTION: usize = 2 * MAX_REQUESTS_PER_CONNECTION;
/// Request streams served at once across every connection.
pub(crate) const MAX_REQUESTS_GLOBAL: usize = 16;

// A `recon/1` frame is its kind, a big-endian `u32` payload length and the
// payload. Readers skip kinds they do not know, so later frames can be added
// without breaking them; broken framing is a protocol violation.
/// Largest `recon/1` frame payload.
pub(crate) const MAX_RECON_FRAME_BYTES: u32 = 64 * 1024;
/// The dialler's first frame: its sequence number as a big-endian `u64`.
pub(crate) const FRAME_OPEN: u8 = 0x01;

// Connection close codes.
const CLOSE_NORMAL: u32 = 0;
const CLOSE_VIOLATION: u32 = 1;
/// Stream reset code: the stream's tag, or its `dht/1` operation, is unknown.
pub const RESET_UNKNOWN: u32 = 1;
/// Stream reset code: a newer `recon/1` stream replaced this one.
pub const RESET_REPLACED: u32 = 2;
/// Stream reset code: the connection already holds
/// [`MAX_HELD_REQUESTS_PER_CONNECTION`] request streams.
pub const RESET_BUSY: u32 = 3;

/// What request streams mean. The table decides which streams reach it and
/// holds their permits; the service answers them.
pub trait Service: Clone + Send + Sync + 'static {
    /// Serve one `dht/1`, `blob/1` or `repair/0` stream after its tag.
    fn serve<W, R>(
        &self,
        peer: PeerId,
        tag: u8,
        send: &mut W,
        recv: &mut R,
    ) -> impl Future<Output = anyhow::Result<()>> + Send
    where
        W: SendStream,
        R: RecvStream;
}

/// The connections of one node, of both directions, keyed by peer.
pub struct ConnectionTable<T: Transport, S> {
    shared: Arc<Shared<T, S>>,
}

impl<T: Transport, S> Clone for ConnectionTable<T, S> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

struct Shared<T: Transport, S> {
    transport: T,
    service: S,
    requests: Arc<Semaphore>,
    /// This node's dial counter. It starts at the wall clock in nanoseconds,
    /// so a restarted node's dials outrank the ones it made before.
    sequence: AtomicU64,
    next_id: AtomicU64,
    table: Mutex<Table<T::Conn>>,
}

struct Table<C> {
    /// Every live connection, by local id.
    connections: HashMap<u64, Entry<C>>,
    /// The connection each peer's streams are opened on.
    current: HashMap<PeerId, u64>,
    /// Dials in progress, shared by every caller waiting for one peer.
    dials: HashMap<PeerId, Arc<Dial<C>>>,
}

#[derive(Clone)]
struct Entry<C> {
    conn: C,
    state: Arc<State>,
}

struct Dial<C> {
    result: tokio::sync::OnceCell<Result<Connection<C>, Arc<anyhow::Error>>>,
}

/// One connection's shared state, held by its handles and stream halves.
struct State {
    id: u64,
    peer: PeerId,
    /// Whether this node dialled the connection.
    dialled: bool,
    /// The key that dialled it.
    dialler: PeerId,
    /// The dialler's sequence number: known at once for this node's dials,
    /// and from the opening `recon/1` frame for accepted ones.
    sequence: OnceLock<u64>,
    epoch: Instant,
    /// Nanoseconds after `epoch` of the last frame sent or received.
    last_frame: AtomicU64,
    /// Request streams open on the connection, in either direction.
    in_flight: AtomicUsize,
    /// Callers holding a [`Connection`] handle to it.
    handles: AtomicUsize,
    retired: AtomicBool,
    neighbour: AtomicBool,
    /// The accept order of the newest `recon/1` stream; a reader that is no
    /// longer the newest yields to its replacement.
    recon: AtomicU64,
    /// Woken on retirement, on the last in-flight stream, and on a new
    /// `recon/1` stream.
    changed: Notify,
    opened: Arc<Semaphore>,
    held: Arc<Semaphore>,
}

impl State {
    fn new(id: u64, peer: PeerId, local: PeerId, dialled: bool) -> Arc<Self> {
        Arc::new(Self {
            id,
            peer,
            dialled,
            dialler: if dialled { local } else { peer },
            sequence: OnceLock::new(),
            epoch: Instant::now(),
            last_frame: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            handles: AtomicUsize::new(0),
            retired: AtomicBool::new(false),
            neighbour: AtomicBool::new(false),
            recon: AtomicU64::new(0),
            changed: Notify::new(),
            opened: Arc::new(Semaphore::new(MAX_REQUESTS_PER_CONNECTION)),
            held: Arc::new(Semaphore::new(MAX_HELD_REQUESTS_PER_CONNECTION)),
        })
    }

    fn touch(&self) {
        let elapsed = self.epoch.elapsed().as_nanos() as u64;
        self.last_frame.fetch_max(elapsed, Ordering::Relaxed);
    }

    fn last_frame(&self) -> Instant {
        self.epoch + Duration::from_nanos(self.last_frame.load(Ordering::Relaxed))
    }

    /// When the connection closes unless a frame crosses it first. A retired
    /// connection waits only [`DRAIN_GRACE`] once no request stream is in
    /// flight on it.
    fn deadline(&self) -> Instant {
        let drained =
            self.retired.load(Ordering::SeqCst) && self.in_flight.load(Ordering::SeqCst) == 0;
        self.last_frame()
            + if drained {
                DRAIN_GRACE
            } else {
                CONNECTION_IDLE_DEADLINE
            }
    }

    /// Whether a request stream or a caller's handle uses the connection.
    fn in_use(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst) > 0 || self.handles.load(Ordering::SeqCst) > 0
    }

    fn retire(&self) {
        if !self.retired.swap(true, Ordering::SeqCst) {
            self.changed.notify_waiters();
        }
    }

    /// Whether this connection is kept over `other` by both sides.
    fn outranks(&self, other: &State) -> bool {
        let (Some(mine), Some(theirs)) = (self.sequence.get(), other.sequence.get()) else {
            return false;
        };
        self.dialler < other.dialler || (self.dialler == other.dialler && mine > theirs)
    }
}

/// Counts one request stream as in flight until dropped.
struct InFlight {
    state: Arc<State>,
    _permit: Option<OwnedSemaphorePermit>,
    /// The handle an outgoing request was opened through.
    handle: Option<Arc<Handle>>,
}

impl InFlight {
    fn new(
        state: &Arc<State>,
        permit: Option<OwnedSemaphorePermit>,
        handle: Option<Arc<Handle>>,
    ) -> Self {
        state.in_flight.fetch_add(1, Ordering::SeqCst);
        Self {
            state: state.clone(),
            _permit: permit,
            handle,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.state.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.state.changed.notify_waiters();
        }
    }
}

/// One caller's hold on a connection, shared by the clones of its
/// [`Connection`].
struct Handle {
    state: Arc<State>,
    /// A stream opened through this handle failed in the transport: the peer
    /// reset or stopped it, or the connection was lost.
    aborted: AtomicBool,
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.state.handles.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A connection handed out by a [`ConnectionTable`].
///
/// Streams opened through it are request streams: each holds one of the
/// connection's opener permits until both its halves drop. While a handle
/// lives, eviction prefers other connections. The table's accept loop is
/// the only acceptor, so [`Conn::accept_bi`] on a handle yields nothing.
pub struct Connection<C> {
    conn: C,
    handle: Arc<Handle>,
}

impl<C: Clone> Clone for Connection<C> {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            handle: self.handle.clone(),
        }
    }
}

/// Two handles are equal when they name the same connection.
impl<C> PartialEq for Connection<C> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.handle.state, &other.handle.state)
    }
}

impl<C> Eq for Connection<C> {}

impl<C> Connection<C> {
    fn new(conn: C, state: Arc<State>) -> Self {
        state.handles.fetch_add(1, Ordering::SeqCst);
        Self {
            conn,
            handle: Arc::new(Handle {
                state,
                aborted: AtomicBool::new(false),
            }),
        }
    }

    fn state(&self) -> &Arc<State> {
        &self.handle.state
    }

    /// The key that dialled this connection.
    pub fn dialler(&self) -> PeerId {
        self.state().dialler
    }

    /// The dialler's sequence number, once known.
    pub fn sequence(&self) -> Option<u64> {
        self.state().sequence.get().copied()
    }

    /// Mark or unmark this as a neighbour connection, which eviction spares.
    pub fn set_neighbour(&self, neighbour: bool) {
        self.state().neighbour.store(neighbour, Ordering::SeqCst);
    }
}

impl<C: Conn> Conn for Connection<C> {
    type SendHalf = Tracked<C::SendHalf>;
    type RecvHalf = Tracked<C::RecvHalf>;

    fn remote_id(&self) -> PeerId {
        self.conn.remote_id()
    }

    async fn open_bi(&self) -> anyhow::Result<(Self::SendHalf, Self::RecvHalf)> {
        let state = self.state();
        let permit = state
            .opened
            .clone()
            .acquire_owned()
            .await
            .expect("connection opener permits are never closed");
        let (send, recv) = self.conn.open_bi().await?;
        let request = Arc::new(InFlight::new(
            state,
            Some(permit),
            Some(self.handle.clone()),
        ));
        Ok((
            Tracked::new(send, state, Some(request.clone())),
            Tracked::new(recv, state, Some(request)),
        ))
    }

    async fn accept_bi(&self) -> Option<(Self::SendHalf, Self::RecvHalf)> {
        None
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(code, reason);
    }
}

/// A stream half whose frames keep its connection from going idle.
pub struct Tracked<S> {
    inner: S,
    state: Arc<State>,
    request: Option<Arc<InFlight>>,
}

impl<S> Tracked<S> {
    fn new(inner: S, state: &Arc<State>, request: Option<Arc<InFlight>>) -> Self {
        Self {
            inner,
            state: state.clone(),
            request,
        }
    }

    /// Note one poll of the inner half: progress keeps the connection from
    /// going idle, and an error marks the handle the request was opened
    /// through.
    fn note<T>(&self, polled: Poll<io::Result<T>>, progressed: bool) -> Poll<io::Result<T>> {
        match polled {
            Poll::Ready(Ok(_)) if progressed => self.state.touch(),
            Poll::Ready(Err(_)) => {
                let handle = self
                    .request
                    .as_ref()
                    .and_then(|request| request.handle.as_ref());
                if let Some(handle) = handle {
                    handle.aborted.store(true, Ordering::SeqCst);
                }
            }
            _ => {}
        }
        polled
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Tracked<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.note(polled, buf.filled().len() > before)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Tracked<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        let progressed = matches!(polled, Poll::Ready(Ok(written)) if written > 0);
        self.note(polled, progressed)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        let progressed = matches!(polled, Poll::Ready(Ok(written)) if written > 0);
        self.note(polled, progressed)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.note(polled, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.note(polled, false)
    }
}

impl<W: SendStream> SendStream for Tracked<W> {
    fn reset(&mut self, code: u32) {
        self.inner.reset(code);
    }
}

impl<R: RecvStream> RecvStream for Tracked<R> {
    fn stop(&mut self, code: u32) {
        self.inner.stop(code);
    }
}

impl<T: Transport, S: Service> ConnectionTable<T, S> {
    pub fn new(transport: T, service: S) -> Self {
        let now = crate::clock::epoch_now().to_duration_since_j1900();
        Self {
            shared: Arc::new(Shared {
                transport,
                service,
                requests: Arc::new(Semaphore::new(MAX_REQUESTS_GLOBAL)),
                sequence: AtomicU64::new(now.total_nanoseconds() as u64),
                next_id: AtomicU64::new(0),
                table: Mutex::new(Table {
                    connections: HashMap::new(),
                    current: HashMap::new(),
                    dials: HashMap::new(),
                }),
            }),
        }
    }

    pub fn transport(&self) -> &T {
        &self.shared.transport
    }

    /// The connection streams to `peer` are opened on, if there is one.
    pub fn current(&self, peer: PeerId) -> Option<Connection<T::Conn>> {
        self.shared.table.lock().unwrap().current(peer)
    }

    /// Live connections, including undecided and draining ones.
    pub fn len(&self) -> usize {
        self.shared.table.lock().unwrap().connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Request streams that could start serving now, across the table.
    #[cfg(test)]
    pub(crate) fn available_requests(&self) -> usize {
        self.shared.requests.available_permits()
    }

    /// Peers with a dial in progress or a live connection.
    #[cfg(test)]
    pub(crate) fn peers(&self) -> std::collections::BTreeSet<PeerId> {
        let table = self.shared.table.lock().unwrap();
        let connected = table.connections.values().map(|entry| entry.state.peer);
        table.dials.keys().copied().chain(connected).collect()
    }

    /// The current connection to `peer`, dialling one if there is none.
    /// Concurrent callers for one peer share a single dial.
    pub async fn connect(&self, peer: PeerId) -> anyhow::Result<Connection<T::Conn>> {
        if let Some(connection) = self.current(peer) {
            return Ok(connection);
        }
        let mut waiter = DialWaiter {
            shared: &self.shared,
            peer,
            dial: Some(self.shared.table.lock().unwrap().dial(peer)),
        };
        let dial = waiter.dial.as_ref().unwrap();
        let result = dial
            .result
            .get_or_init(|| self.shared.dial(peer))
            .await
            .clone();
        // The connection now lives in the table; later callers find it there.
        let dial = waiter.dial.take().unwrap();
        let finished = self.shared.table.lock().unwrap().finish(peer, &dial);
        drop((dial, finished));
        // Each caller holds its own handle, not the one the dial produced.
        result
            .map(|connection| {
                let state = connection.state().clone();
                Connection::new(connection.conn, state)
            })
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    /// Take an inbound connection. It serves at once; it can be chosen for
    /// opening streams once its opening `recon/1` frame arrives.
    pub fn accept(&self, conn: T::Conn) -> tokio::task::JoinHandle<()> {
        let peer = conn.remote_id();
        let state = self.shared.state(peer, false);
        self.shared.register(conn, state)
    }

    /// Close `connection` after a request on it failed, unless the table has
    /// already let go of it or the failure stayed on the request's stream: a
    /// stream opened through this handle was reset or stopped by the peer, or
    /// lost with the connection. Other requests and the peer's own streams
    /// share the connection, so it closes only for a peer that broke a
    /// request's protocol. Callers do not invalidate after a deadline.
    pub fn invalidate(&self, connection: &Connection<T::Conn>) {
        if connection.handle.aborted.load(Ordering::SeqCst) {
            return;
        }
        let removed = self.shared.table.lock().unwrap().remove(connection.state());
        if removed {
            connection
                .conn
                .close(CLOSE_NORMAL, b"connection invalidated");
        }
    }
}

/// Owns one caller's share of a dial until it hands off the result. The last
/// cancelled waiter removes a dial nobody completed; the others keep its
/// cell and can take over its cancelled initializer.
struct DialWaiter<'a, T: Transport, S> {
    shared: &'a Shared<T, S>,
    peer: PeerId,
    dial: Option<Arc<Dial<T::Conn>>>,
}

impl<T: Transport, S> Drop for DialWaiter<'_, T, S> {
    fn drop(&mut self) {
        if let Some(dial) = self.dial.take() {
            let released = self.shared.table.lock().unwrap().release(self.peer, dial);
            drop(released);
        }
    }
}

impl<C: Conn> Table<C> {
    fn current(&self, peer: PeerId) -> Option<Connection<C>> {
        let entry = self.connections.get(self.current.get(&peer)?)?;
        Some(Connection::new(entry.conn.clone(), entry.state.clone()))
    }

    fn dial(&mut self, peer: PeerId) -> Arc<Dial<C>> {
        self.dials
            .entry(peer)
            .or_insert_with(|| {
                Arc::new(Dial {
                    result: tokio::sync::OnceCell::new(),
                })
            })
            .clone()
    }

    /// Retire a completed dial. Returns it so its last reference drops
    /// outside the lock.
    fn finish(&mut self, peer: PeerId, dial: &Arc<Dial<C>>) -> Option<Arc<Dial<C>>> {
        if self
            .dials
            .get(&peer)
            .is_some_and(|current| Arc::ptr_eq(current, dial))
        {
            self.dials.remove(&peer)
        } else {
            None
        }
    }

    fn release(&mut self, peer: PeerId, dial: Arc<Dial<C>>) -> Option<Arc<Dial<C>>> {
        if !self
            .dials
            .get(&peer)
            .is_some_and(|current| Arc::ptr_eq(current, &dial))
        {
            return Some(dial);
        }
        // The map still owns this dial, so dropping the waiter's reference
        // destroys nothing. Drop it before deciding: concurrent cancellations
        // must not each see the other's departing reference.
        drop(dial);
        let current = self.dials.get(&peer).unwrap();
        if current.result.get().is_none() && Arc::strong_count(current) == 1 {
            self.dials.remove(&peer)
        } else {
            None
        }
    }

    /// Decide between `state`'s connection and its peer's current one, now
    /// that its sequence number is known. The loser is retired.
    fn rank(&mut self, state: &Arc<State>) {
        if state.retired.load(Ordering::SeqCst) || !self.connections.contains_key(&state.id) {
            return;
        }
        let present = self
            .current
            .get(&state.peer)
            .and_then(|id| self.connections.get(id));
        match present {
            Some(present) if present.state.id == state.id => {}
            Some(present) if !state.outranks(&present.state) => state.retire(),
            present => {
                if let Some(present) = present {
                    present.state.retire();
                }
                self.current.insert(state.peer, state.id);
            }
        }
    }

    /// Forget a connection. Returns whether it was still held.
    fn remove(&mut self, state: &State) -> bool {
        if self.current.get(&state.peer) == Some(&state.id) {
            self.current.remove(&state.peer);
        }
        self.connections.remove(&state.id).is_some()
    }

    /// Above the cap in `state`'s direction, pick the connection to close:
    /// least recently used, preferring draining ones and ones nobody uses,
    /// never a neighbour and never the newcomer itself.
    fn evict(&mut self, state: &State) -> Option<C> {
        let candidates = || {
            self.connections.values().filter(|entry| {
                entry.state.dialled == state.dialled
                    && !entry.state.neighbour.load(Ordering::SeqCst)
            })
        };
        if candidates().count() <= MAX_CONNECTIONS {
            return None;
        }
        let victim = candidates()
            .filter(|entry| entry.state.id != state.id)
            .min_by_key(|entry| {
                (
                    !entry.state.retired.load(Ordering::SeqCst),
                    entry.state.in_use(),
                    entry.state.last_frame(),
                    entry.state.id,
                )
            })?
            .clone();
        self.remove(&victim.state);
        Some(victim.conn)
    }
}

impl<T: Transport, S: Service> Shared<T, S> {
    fn state(&self, peer: PeerId, dialled: bool) -> Arc<State> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        State::new(id, peer, self.transport.local_id(), dialled)
    }

    async fn dial(
        self: &Arc<Self>,
        peer: PeerId,
    ) -> Result<Connection<T::Conn>, Arc<anyhow::Error>> {
        let opened = tokio::time::timeout(DIAL_DEADLINE, async {
            let conn = self.transport.dial(peer, PILE_SYNC_ALPN).await?;
            if conn.remote_id() != peer {
                anyhow::bail!("dialed endpoint identity does not match requested peer");
            }
            let state = self.state(peer, true);
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
            state.sequence.set(sequence).unwrap();
            // The dialler's first recon frame carries its sequence number.
            let (send, recv) = conn.open_bi().await?;
            let mut send = Tracked::new(send, &state, None);
            send_u8(&mut send, TAG_RECON).await?;
            write_frame(&mut send, FRAME_OPEN, &sequence.to_be_bytes()).await?;
            let recv = Tracked::new(recv, &state, None);
            Ok((conn, state, send, recv))
        })
        .await
        .map_err(|_| anyhow::anyhow!("connection setup deadline exceeded"))
        .and_then(|opened| opened)
        .map_err(Arc::new)?;
        let (conn, state, send, recv) = opened;
        // The dialler's own stream is its connection's only `recon/1`.
        tokio::spawn(recon(
            Arc::downgrade(self),
            conn.clone(),
            state.clone(),
            None,
            send,
            recv,
        ));
        self.register(conn.clone(), state.clone());
        // Another connection may already outrank this one.
        Ok(self
            .table
            .lock()
            .unwrap()
            .current(peer)
            .unwrap_or_else(|| Connection::new(conn, state)))
    }

    /// Hold a connection and start its accept loop.
    fn register(self: &Arc<Self>, conn: T::Conn, state: Arc<State>) -> tokio::task::JoinHandle<()> {
        let evicted = {
            let mut table = self.table.lock().unwrap();
            table.connections.insert(
                state.id,
                Entry {
                    conn: conn.clone(),
                    state: state.clone(),
                },
            );
            if state.sequence.get().is_some() {
                table.rank(&state);
            }
            table.evict(&state)
        };
        if let Some(evicted) = evicted {
            debug!(target: "triblespace_net::handoff", "connection limit reached; evicting the least recently used");
            evicted.close(CLOSE_NORMAL, b"connection evicted");
        }
        let span = info_span!("connection", peer = %hex::encode(&state.peer[..4]));
        tokio::spawn(accept_loop(Arc::downgrade(self), conn, state).instrument(span))
    }
}

impl<T: Transport, S> Drop for Shared<T, S> {
    fn drop(&mut self) {
        let table = self
            .table
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for entry in table.connections.values() {
            entry.conn.close(CLOSE_NORMAL, b"connection table dropped");
        }
    }
}

/// One connection's accept loop and idle check, for either direction.
async fn accept_loop<T: Transport, S: Service>(
    shared: Weak<Shared<T, S>>,
    conn: T::Conn,
    state: Arc<State>,
) {
    debug!(target: "triblespace_net::handoff", dialled = state.dialled, "connection accept loop started");
    // Streams are accepted in the order the peer opened them, which their
    // tasks may not keep: a replacement `recon/1` is the later-opened one.
    let mut accepted_streams = 0;
    let closing = loop {
        let changed = state.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let deadline = state.deadline();
        tokio::select! {
            accepted = conn.accept_bi() => {
                let Some((send, recv)) = accepted else {
                    debug!(target: "triblespace_net::handoff", "connection accept ended");
                    break None;
                };
                let Some(table) = shared.upgrade() else {
                    break None;
                };
                let (service, requests) = (table.service.clone(), table.requests.clone());
                drop(table);
                accepted_streams += 1;
                let accepted = Accepted {
                    order: accepted_streams,
                    send: Tracked::new(send, &state, None),
                    recv: Tracked::new(recv, &state, None),
                };
                tokio::spawn(
                    stream(shared.clone(), conn.clone(), state.clone(), service, requests, accepted)
                        .instrument(debug_span!("stream", tag = tracing::field::Empty).or_current()),
                );
            }
            () = tokio::time::sleep_until(deadline) => {
                if Instant::now() >= state.deadline() {
                    break Some(if state.retired.load(Ordering::SeqCst) {
                        "connection drained"
                    } else {
                        "connection idle timeout"
                    });
                }
            }
            () = &mut changed => {}
        }
    };
    if let Some(reason) = closing {
        debug!(target: "triblespace_net::handoff", reason, "closing connection");
        conn.close(CLOSE_NORMAL, reason.as_bytes());
    }
    if let Some(table) = shared.upgrade() {
        table.table.lock().unwrap().remove(&state);
    }
}

/// A stream the peer opened, numbered in accept order.
struct Accepted<C: Conn> {
    order: u64,
    send: Tracked<C::SendHalf>,
    recv: Tracked<C::RecvHalf>,
}

/// Dispatch one accepted stream on its tag.
async fn stream<T: Transport, S: Service>(
    shared: Weak<Shared<T, S>>,
    conn: T::Conn,
    state: Arc<State>,
    service: S,
    requests: Arc<Semaphore>,
    accepted: Accepted<T::Conn>,
) {
    let Accepted {
        order,
        mut send,
        mut recv,
    } = accepted;
    let tag = match tokio::time::timeout(TAG_DEADLINE, recv_u8(&mut recv)).await {
        Ok(Ok(tag)) => tag,
        Ok(Err(error)) => return debug!(%error, "stream ended before its tag"),
        Err(_) => return debug!("stream tag deadline exceeded"),
    };
    tracing::Span::current().record("tag", tag_name(tag));
    match tag {
        TAG_RECON => recon(shared, conn, state, Some(order), send, recv).await,
        TAG_DHT | TAG_BLOB | TAG_REPAIR => {
            // A held stream keeps the opener's stream credit even after the
            // opener gave up on it, so the connection holds a bounded number
            // and resets the rest. Within the bound, a burst waits for its
            // permit instead: other streams may be serving independent
            // requests on the connection.
            let Ok(_held) = state.held.clone().try_acquire_owned() else {
                debug!("resetting a request stream beyond the connection's bound");
                send.reset(RESET_BUSY);
                recv.stop(RESET_BUSY);
                return;
            };
            let _request = InFlight::new(&state, None, None);
            let Ok(_global) = requests.acquire_owned().await else {
                return;
            };
            let served = tokio::time::timeout(
                REQUEST_DEADLINE,
                service.serve(state.peer, tag, &mut send, &mut recv),
            )
            .await;
            match served {
                Ok(Ok(())) => {}
                Ok(Err(error)) => debug!(%error, "request stream failed"),
                Err(_) => warn!("request stream deadline exceeded"),
            }
            let _ = send.shutdown().await;
        }
        unknown => {
            debug!(tag = unknown, "resetting a stream with an unknown tag");
            send.reset(RESET_UNKNOWN);
            recv.stop(RESET_UNKNOWN);
        }
    }
}

fn tag_name(tag: u8) -> &'static str {
    match tag {
        TAG_RECON => "recon/1",
        TAG_DHT => "dht/1",
        TAG_BLOB => "blob/1",
        TAG_REPAIR => "repair/0",
        _ => "unknown",
    }
}

/// Run one `recon/1` stream after its tag: the dialler's own stream, or one
/// the peer opened, with its accept order. On the accepting side the first
/// frame names the dialler's sequence number, which decides between this
/// connection and any other to the same peer. A `recon/1` stream the peer
/// opened later on the connection replaces this one.
async fn recon<T: Transport, S: Service>(
    shared: Weak<Shared<T, S>>,
    conn: T::Conn,
    state: Arc<State>,
    accepted: Option<u64>,
    mut send: Tracked<<T::Conn as Conn>::SendHalf>,
    mut recv: Tracked<<T::Conn as Conn>::RecvHalf>,
) {
    let outcome = if accepted.is_some() && state.dialled {
        Err(FrameError::Violation(
            "recon/1 opened by the side that did not dial",
        ))
    } else {
        let order = accepted.unwrap_or(0);
        state.recon.fetch_max(order, Ordering::SeqCst);
        state.changed.notify_waiters();
        let frames = async {
            if accepted.is_some() {
                let sequence = match read_frame(&mut recv).await? {
                    Some((FRAME_OPEN, payload)) => u64::from_be_bytes(
                        payload
                            .try_into()
                            .map_err(|_| FrameError::Violation("malformed opening frame"))?,
                    ),
                    Some(_) => return Err(FrameError::Violation("recon/1 must open first")),
                    None => return Ok(()),
                };
                match state.sequence.set(sequence) {
                    Ok(()) => {
                        if let Some(table) = shared.upgrade() {
                            table.table.lock().unwrap().rank(&state);
                        }
                    }
                    // A reopened `recon/1` repeats the connection's sequence.
                    Err(_) if state.sequence.get() == Some(&sequence) => {}
                    Err(_) => {
                        return Err(FrameError::Violation(
                            "recon/1 reopened with another sequence",
                        ));
                    }
                }
            }
            while let Some((kind, _payload)) = read_frame(&mut recv).await? {
                if kind == FRAME_OPEN {
                    return Err(FrameError::Violation("recon/1 opened twice"));
                }
            }
            Ok(())
        };
        let superseded = async {
            loop {
                let changed = state.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if state.recon.load(Ordering::SeqCst) != order {
                    return;
                }
                changed.await;
            }
        };
        // A stream already replaced reads none of its frames.
        tokio::select! {
            biased;
            () = superseded => {
                send.reset(RESET_REPLACED);
                recv.stop(RESET_REPLACED);
                Ok(())
            }
            outcome = frames => outcome,
        }
    };
    match outcome {
        Ok(()) => {}
        Err(FrameError::Violation(violation)) => {
            warn!(
                violation,
                "recon/1 protocol violation; closing the connection"
            );
            conn.close(CLOSE_VIOLATION, violation.as_bytes());
        }
        Err(FrameError::Transport(error)) => debug!(%error, "recon/1 stream ended"),
    }
}

/// A `recon/1` framing failure.
#[derive(Debug)]
enum FrameError {
    /// The peer broke the framing; the connection closes.
    Violation(&'static str),
    /// The stream or its connection ended under the reader.
    Transport(io::Error),
}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Violation("truncated frame")
        } else {
            FrameError::Transport(error)
        }
    }
}

/// Read one frame, or `None` when the stream ends between frames.
async fn read_frame<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<Option<(u8, Vec<u8>)>, FrameError> {
    let mut kind = [0; 1];
    if recv.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    let length = recv.read_u32().await?;
    if length > MAX_RECON_FRAME_BYTES {
        return Err(FrameError::Violation("oversized frame"));
    }
    let mut payload = vec![0; length as usize];
    recv.read_exact(&mut payload).await?;
    Ok(Some((kind[0], payload)))
}

/// Write one frame.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    send: &mut W,
    kind: u8,
    payload: &[u8],
) -> anyhow::Result<()> {
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|length| *length <= MAX_RECON_FRAME_BYTES)
        .ok_or_else(|| anyhow::anyhow!("recon/1 frame payload too large"))?;
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(kind);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    send.write_all(&frame)
        .await
        .map_err(|error| anyhow::anyhow!("send recon/1 frame: {error}"))
}

#[cfg(all(test, feature = "sim"))]
mod tests {
    use super::*;
    use crate::transport::sim::SimConn;

    #[test]
    fn a_cancelled_old_waiter_cannot_remove_a_replacement_dial() {
        let mut table = Table::<SimConn> {
            connections: HashMap::new(),
            current: HashMap::new(),
            dials: HashMap::new(),
        };
        let peer = [1; 32];
        let old = table.dial(peer);
        // The old dial finished and left; a new one took its place.
        drop(table.finish(peer, &old));
        let replacement = table.dial(peer);
        assert!(!Arc::ptr_eq(&old, &replacement));
        assert!(table.release(peer, old).is_some());
        assert!(
            table
                .dials
                .get(&peer)
                .is_some_and(|current| Arc::ptr_eq(current, &replacement))
        );
        // The replacement's last cancelled waiter removes it.
        assert!(table.release(peer, replacement).is_some());
        assert!(table.dials.is_empty());
    }
}
