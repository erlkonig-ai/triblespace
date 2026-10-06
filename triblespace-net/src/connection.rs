//! One connection per peer pair, carrying typed streams.
//!
//! A [`ConnectionTable`] holds the connections of both directions, keyed by
//! the remote's TLS-authenticated [`PeerId`]. Every connection, dialled or
//! accepted, runs one accept loop. The first byte of each stream is its type
//! tag ([`TAG_RECON`], [`TAG_DHT`] or [`TAG_BLOB`]). The loop reads the tag
//! before it takes any permit: `recon/1` takes none, a request stream takes
//! one of its connection's (or is reset when none is left) and waits for one
//! of the table's within its connection's share, and an unknown tag resets
//! only its own stream.
//!
//! The dialler opens `recon/1`, and its first frame carries the dialler's
//! sequence number. When a pair holds two connections, both sides keep the
//! same one: of crossed dials, the one dialled by the lower key; of two dials
//! by one side, the higher sequence number. The loser drains: nothing new is
//! opened on it, and it closes once no request stream is in flight on it and
//! no frame has crossed it for [`DRAIN_GRACE`], or like any other connection
//! when it goes idle.
//!
//! Every connection carries one `recon/1` stream at a time, and its frames
//! go both ways at once: the peer's frames reach the service as
//! [`ReconEvent`]s, and the frames queued on the connection's [`Link`] are
//! written in order on whichever `recon/1` stream it holds. The queue, like
//! the peerings it carries, belongs to the connection and outlives a
//! replaced stream.
//!
//! A writer that waits [`RECON_CREDIT_DEADLINE`] for stream credit resets
//! `recon/1`: the peer stopped reading. The service hears that the stream
//! ended, and the dialler opens a new one at once, though no sooner than
//! [`RECON_REOPEN_INTERVAL`] after it opened the last.
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
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::Instant;
use tracing::{Instrument as _, debug, debug_span, info_span, warn};

use crate::protocol::{PILE_SYNC_ALPN, TAG_BLOB, TAG_DHT, TAG_RECON, recv_u8, send_u8};
pub(crate) use crate::recon::{FRAME_OPEN, MAX_RECON_FRAME_BYTES};
use crate::recon::{Frame, Malformed};
use crate::transport::{Conn, PeerId, RecvStream, SendStream, Transport};

/// Bound on a dial, including its opening `recon/1` frame.
const DIAL_DEADLINE: Duration = Duration::from_secs(10);
/// A connection closes after this long without a frame on any stream.
pub(crate) const CONNECTION_IDLE_DEADLINE: Duration = Duration::from_secs(120);
/// A `recon/1` writer that waited this long for stream credit resets the
/// stream: the peer stopped reading it.
pub(crate) const RECON_CREDIT_DEADLINE: Duration = Duration::from_secs(60);
/// The dialler opens `recon/1` at most once per this interval, so a peer
/// that ends each one at once costs a stream per interval, not a loop.
pub(crate) const RECON_REOPEN_INTERVAL: Duration = Duration::from_secs(1);
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
/// Request streams served at once on one connection: half the table's, so
/// a peer that holds its requests open until their deadline leaves the
/// other half to the rest.
pub(crate) const MAX_SERVED_PER_CONNECTION: usize = MAX_REQUESTS_GLOBAL / 2;

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
/// Stream reset code: the peer granted `recon/1` no credit for
/// [`RECON_CREDIT_DEADLINE`].
pub const RESET_STALLED: u32 = 4;

/// What streams mean. The table decides which request streams reach the
/// service and holds their permits; the service answers them, and hears what
/// happens on each connection's `recon/1`.
pub trait Service: Clone + Send + Sync + 'static {
    /// Serve one `dht/1` or `blob/1` stream after its tag.
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

    /// Hear one connection event. The `recon/1` reader waits for this, so a
    /// slow service holds back that connection's later frames.
    fn recon(&self, event: ReconEvent) -> impl Future<Output = ()> + Send {
        drop(event);
        async {}
    }
}

/// What happens on one connection: `Opened` comes before its frames, and
/// `Closed` after them, though it can overtake `Opened` when the connection
/// closes at once. [`Link::closed`] says which.
#[derive(Debug)]
pub enum ReconEvent {
    /// A connection can carry frames: this node dialled it, or the peer's
    /// opening frame arrived on it.
    Opened(Link),
    /// A frame arrived on the connection's `recon/1`.
    Frame(Link, Frame),
    /// The connection's `recon/1` stream ended while the connection stays
    /// open, and whatever ran on it with it. The connection's peerings and
    /// queued frames outlive it: the dialler opens a new stream at once. On
    /// the accepting side a stream the dialler replaced before this side saw
    /// it end also counts, reported before the new stream's first frame.
    Ended(Link),
    /// The connection closed; frames queued on it go nowhere.
    Closed(Link),
}

/// One connection's `recon/1`, as a service sees it. Frames sent through it
/// are written in order on whichever `recon/1` stream the connection holds.
/// A stream that ends or is replaced loses what it wrote that the peer had
/// not read; a frame still queued goes out on the next stream.
#[derive(Clone)]
pub struct Link {
    state: Arc<State>,
}

impl Link {
    /// The connection's local id, unique within its table.
    pub fn id(&self) -> u64 {
        self.state.id
    }

    pub fn peer(&self) -> PeerId {
        self.state.peer
    }

    /// Whether this node dialled the connection.
    pub(crate) fn dialled(&self) -> bool {
        self.state.dialled
    }

    /// Queue one frame. It is dropped if the connection has closed. On a
    /// connection this node dialled whose `recon/1` ended, it also asks for
    /// a new stream.
    pub fn send(&self, frame: Frame) {
        let _ = self.state.outbox.try_send(frame);
        if self.state.dialled && !self.state.recon_live.load(Ordering::SeqCst) {
            self.state.reopen.store(true, Ordering::SeqCst);
            self.state.changed.notify_waiters();
        }
    }

    /// Mark or unmark this as a neighbour connection, which eviction spares.
    pub fn set_neighbour(&self, neighbour: bool) {
        self.state.neighbour.store(neighbour, Ordering::SeqCst);
    }

    /// Frames queued and not yet taken by a `recon/1` writer.
    pub(crate) fn queued(&self) -> usize {
        self.state.outbox.max_capacity() - self.state.outbox.capacity()
    }

    /// Whether the tie-break retired the connection: it drains and closes.
    pub fn retired(&self) -> bool {
        self.state.retired.load(Ordering::SeqCst)
    }

    /// Whether the connection has closed.
    pub fn closed(&self) -> bool {
        self.state.closed.load(Ordering::SeqCst)
    }

    /// A link to no connection, whose queued frames the test reads back.
    #[cfg(test)]
    pub(crate) fn detached(id: u64, peer: PeerId) -> (Self, mpsc::Receiver<Frame>) {
        let state = State::new(id, peer, [0; 32], true);
        let (outbox, frames) = outbox();
        let state = Arc::new(State {
            outbox,
            ..Arc::into_inner(state).unwrap()
        });
        (Self { state }, frames)
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Link")
            .field("id", &self.state.id)
            .field("peer", &hex::encode(&self.state.peer[..4]))
            .finish()
    }
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
    /// Nanoseconds after `epoch` at which the dialler last opened `recon/1`.
    recon_opened: AtomicU64,
    /// Request streams open on the connection, in either direction.
    in_flight: AtomicUsize,
    /// Callers holding a [`Connection`] handle to it.
    handles: AtomicUsize,
    retired: AtomicBool,
    neighbour: AtomicBool,
    /// The order of the newest `recon/1` stream (accept order, or the
    /// dialler's opening order); a stream that is no longer the newest
    /// yields to its replacement.
    recon: AtomicU64,
    /// A `recon/1` stream carries the connection's frames, or is being
    /// opened. A dialled connection opens one as it connects.
    recon_live: AtomicBool,
    /// The dialler's `recon/1` ended, or a frame was queued while no stream
    /// was live: the accept loop opens a new one.
    reopen: AtomicBool,
    /// Woken on retirement, on the last in-flight stream, on a new `recon/1`
    /// stream, and on a frame that asks for one.
    changed: Notify,
    opened: Arc<Semaphore>,
    held: Arc<Semaphore>,
    /// Request streams served at once on the connection.
    served: Semaphore,
    /// Frames waiting for the connection's `recon/1` writer. The current
    /// stream's writer holds the receiver; its replacement takes it over.
    outbox: mpsc::Sender<Frame>,
    outbox_frames: tokio::sync::Mutex<mpsc::Receiver<Frame>>,
    /// The service heard `ReconEvent::Opened` for this connection.
    announced: AtomicBool,
    /// The accept loop ended.
    closed: AtomicBool,
}

impl State {
    fn new(id: u64, peer: PeerId, local: PeerId, dialled: bool) -> Arc<Self> {
        let (outbox, outbox_frames) = outbox();
        Arc::new(Self {
            id,
            peer,
            dialled,
            dialler: if dialled { local } else { peer },
            sequence: OnceLock::new(),
            epoch: Instant::now(),
            last_frame: AtomicU64::new(0),
            recon_opened: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            handles: AtomicUsize::new(0),
            retired: AtomicBool::new(false),
            neighbour: AtomicBool::new(false),
            recon: AtomicU64::new(0),
            recon_live: AtomicBool::new(dialled),
            reopen: AtomicBool::new(false),
            changed: Notify::new(),
            opened: Arc::new(Semaphore::new(MAX_REQUESTS_PER_CONNECTION)),
            held: Arc::new(Semaphore::new(MAX_HELD_REQUESTS_PER_CONNECTION)),
            served: Semaphore::new(MAX_SERVED_PER_CONNECTION),
            outbox,
            outbox_frames: tokio::sync::Mutex::new(outbox_frames),
            announced: AtomicBool::new(false),
            closed: AtomicBool::new(false),
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

/// A connection's frame queue. It refuses no frame: its capacity is the
/// most a channel counts, so that what it holds can be read off it.
fn outbox() -> (mpsc::Sender<Frame>, mpsc::Receiver<Frame>) {
    mpsc::channel(Semaphore::MAX_PERMITS)
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

    /// The connection's `recon/1`, as its service sees it.
    pub fn link(&self) -> Link {
        Link {
            state: self.state().clone(),
        }
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

    /// Open a new `recon/1` stream on a connection this node dialled. It
    /// replaces the current one on both sides; the connection's queued
    /// frames and its peerings carry over.
    pub async fn reopen_recon(&self, connection: &Connection<T::Conn>) -> anyhow::Result<()> {
        let state = connection.state();
        if !state.dialled {
            anyhow::bail!("only the dialler opens recon/1");
        }
        let (send, recv) = open_recon(&connection.conn, state).await?;
        let order = state.recon.load(Ordering::SeqCst) + 1;
        tokio::spawn(recon(
            Arc::downgrade(&self.shared),
            connection.conn.clone(),
            state.clone(),
            ReconStream::Dialled(order),
            send,
            recv,
        ));
        Ok(())
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
            let (send, recv) = open_recon(&conn, &state).await?;
            Ok((conn, state, send, recv))
        })
        .await
        .map_err(|_| anyhow::anyhow!("connection setup deadline exceeded"))
        .and_then(|opened| opened)
        .map_err(Arc::new)?;
        let (conn, state, send, recv) = opened;
        // The service hears of the connection before its accept loop can
        // close it and before any of its frames.
        state.announced.store(true, Ordering::SeqCst);
        let link = Link {
            state: state.clone(),
        };
        self.service.recon(ReconEvent::Opened(link)).await;
        tokio::spawn(recon(
            Arc::downgrade(self),
            conn.clone(),
            state.clone(),
            ReconStream::Dialled(0),
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
        let opened = Duration::from_nanos(state.recon_opened.load(Ordering::SeqCst));
        let reopen_at = state.epoch + opened + RECON_REOPEN_INTERVAL;
        if Instant::now() >= reopen_at
            && state.reopen.swap(false, Ordering::SeqCst)
            && !state.retired.load(Ordering::SeqCst)
            && !state.recon_live.swap(true, Ordering::SeqCst)
        {
            let now = state.epoch.elapsed().as_nanos() as u64;
            state.recon_opened.store(now, Ordering::SeqCst);
            tokio::spawn(reopen(shared.clone(), conn.clone(), state.clone()));
        }
        let deadline = state.deadline();
        let reopening = state.reopen.load(Ordering::SeqCst);
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
            () = tokio::time::sleep_until(reopen_at), if reopening => {}
            () = &mut changed => {}
        }
    };
    if let Some(reason) = closing {
        debug!(target: "triblespace_net::handoff", reason, "closing connection");
        conn.close(CLOSE_NORMAL, reason.as_bytes());
    }
    state.closed.store(true, Ordering::SeqCst);
    if let Some(table) = shared.upgrade() {
        table.table.lock().unwrap().remove(&state);
        if state.announced.load(Ordering::SeqCst) {
            let service = table.service.clone();
            drop(table);
            service.recon(ReconEvent::Closed(Link { state })).await;
        }
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
        TAG_RECON => {
            recon(
                shared,
                conn,
                state,
                ReconStream::Accepted(order),
                send,
                recv,
            )
            .await
        }
        TAG_DHT | TAG_BLOB => {
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
            let Ok(_share) = state.served.acquire().await else {
                return;
            };
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
        _ => "unknown",
    }
}

/// Open a `recon/1` stream on a connection this node dialled, with the
/// opening frame that carries its sequence number.
async fn open_recon<C: Conn>(
    conn: &C,
    state: &Arc<State>,
) -> anyhow::Result<(Tracked<C::SendHalf>, Tracked<C::RecvHalf>)> {
    let sequence = *state
        .sequence
        .get()
        .expect("a dialled connection knows its sequence");
    let (send, recv) = conn.open_bi().await?;
    let mut send = Tracked::new(send, state, None);
    send_u8(&mut send, TAG_RECON).await?;
    write_frame(&mut send, FRAME_OPEN, &sequence.to_be_bytes()).await?;
    Ok((send, Tracked::new(recv, state, None)))
}

/// Open a new `recon/1` stream after the last one ended; the frames queued
/// since go out on it.
async fn reopen<T: Transport, S: Service>(
    shared: Weak<Shared<T, S>>,
    conn: T::Conn,
    state: Arc<State>,
) {
    match open_recon(&conn, &state).await {
        Ok((send, recv)) => {
            let order = state.recon.load(Ordering::SeqCst) + 1;
            recon(shared, conn, state, ReconStream::Dialled(order), send, recv).await;
        }
        Err(error) => {
            debug!(%error, "reopening recon/1 failed");
            state.recon_live.store(false, Ordering::SeqCst);
        }
    }
}

/// Which side opened a `recon/1` stream, and its order there: the dialler
/// numbers its own streams, the accepting side numbers streams as accepted.
#[derive(Clone, Copy)]
enum ReconStream {
    Dialled(u64),
    Accepted(u64),
}

/// Run one `recon/1` stream after its tag. On the accepting side the first
/// frame names the dialler's sequence number, which decides between this
/// connection and any other to the same peer. A newer `recon/1` stream on the
/// connection replaces this one.
///
/// Both directions run at once: each frame read goes to the service as it
/// arrives, and the connection's queued frames are written as they come. A
/// frame that waits [`RECON_CREDIT_DEADLINE`] for credit resets the stream.
async fn recon<T: Transport, S: Service>(
    shared: Weak<Shared<T, S>>,
    conn: T::Conn,
    state: Arc<State>,
    stream: ReconStream,
    mut send: Tracked<<T::Conn as Conn>::SendHalf>,
    mut recv: Tracked<<T::Conn as Conn>::RecvHalf>,
) {
    let Some(service) = shared.upgrade().map(|table| table.service.clone()) else {
        return;
    };
    let link = Link {
        state: state.clone(),
    };
    let (order, accepted) = match stream {
        ReconStream::Dialled(order) => (order, false),
        ReconStream::Accepted(order) => (order, true),
    };
    let mut ended_here = false;
    let outcome = if accepted && state.dialled {
        Err(FrameError::Violation(
            "recon/1 opened by the side that did not dial",
        ))
    } else {
        state.recon.fetch_max(order, Ordering::SeqCst);
        // On the accepting side nothing else sets this flag, so a stream
        // that finds it already set replaces one that never saw its end.
        let replaces_live = state.recon_live.swap(true, Ordering::SeqCst);
        state.changed.notify_waiters();
        let ended = {
            let frames = async {
                if accepted {
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
                            state.announced.store(true, Ordering::SeqCst);
                            service.recon(ReconEvent::Opened(link.clone())).await;
                        }
                        // A reopened `recon/1` repeats the connection's sequence.
                        // If it replaced a stream still live here, that stream
                        // ended unseen: say so before this one's first frame.
                        Err(_) if state.sequence.get() == Some(&sequence) => {
                            if replaces_live && state.announced.load(Ordering::SeqCst) {
                                service.recon(ReconEvent::Ended(link.clone())).await;
                            }
                        }
                        Err(_) => {
                            return Err(FrameError::Violation(
                                "recon/1 reopened with another sequence",
                            ));
                        }
                    }
                }
                while let Some((kind, payload)) = read_frame(&mut recv).await? {
                    if kind == FRAME_OPEN {
                        return Err(FrameError::Violation("recon/1 opened twice"));
                    }
                    match Frame::decode(kind, &payload) {
                        Ok(Some(frame)) => {
                            service.recon(ReconEvent::Frame(link.clone(), frame)).await
                        }
                        Ok(None) => {}
                        Err(Malformed(violation)) => return Err(FrameError::Violation(violation)),
                    }
                }
                Ok(())
            };
            let writer = async {
                let mut outbox = state.outbox_frames.lock().await;
                // The connection's state holds the sender, so this ends only
                // when a write fails.
                while let Some(frame) = outbox.recv().await {
                    let (kind, payload) = frame.encode();
                    let written = write_frame(&mut send, kind, &payload);
                    match tokio::time::timeout(RECON_CREDIT_DEADLINE, written).await {
                        Ok(written) => written
                            .map_err(|error| FrameError::Transport(io::Error::other(error)))?,
                        Err(_) => return Err(FrameError::Stalled),
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
            // A stream already replaced reads and writes none of its frames.
            tokio::select! {
                biased;
                () = superseded => None,
                outcome = frames => Some(outcome),
                written = writer => Some(written),
            }
        };
        match ended {
            Some(outcome) => {
                if let Err(FrameError::Stalled) = outcome {
                    send.reset(RESET_STALLED);
                    recv.stop(RESET_STALLED);
                }
                // The newest stream ended, and none replaces it yet. The
                // dialler opens the next one at once: the acceptor cannot,
                // and may have frames queued for it.
                if state.recon.load(Ordering::SeqCst) == order {
                    state.recon_live.store(false, Ordering::SeqCst);
                    ended_here = true;
                    if state.dialled {
                        state.reopen.store(true, Ordering::SeqCst);
                        state.changed.notify_waiters();
                    }
                }
                outcome
            }
            None => {
                send.reset(RESET_REPLACED);
                recv.stop(RESET_REPLACED);
                Ok(())
            }
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
        Err(FrameError::Stalled) => debug!("recon/1 got no credit; reset"),
    }
    if ended_here && state.announced.load(Ordering::SeqCst) {
        service.recon(ReconEvent::Ended(link)).await;
    }
}

/// A `recon/1` framing failure.
#[derive(Debug)]
enum FrameError {
    /// The peer broke the framing; the connection closes.
    Violation(&'static str),
    /// The stream or its connection ended under the reader.
    Transport(io::Error),
    /// The peer granted no credit for [`RECON_CREDIT_DEADLINE`].
    Stalled,
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
