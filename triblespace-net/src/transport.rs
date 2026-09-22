//! The transport seam — everything the sync protocol needs from a
//! network, as traits.
//!
//! This module exists so the *entire* protocol stack above it — the
//! host loop, collection-authorized repair, and bearer DHT/provider operations
//! — can run
//! unmodified against either:
//!
//! - [`crate::transport::iroh`]: the production iroh QUIC adapter, or
//! - a deterministic in-memory simulator (discrete-event router with
//!   seeded delays, partitions, and crashes) for
//!   FoundationDB/TigerBeetle-style simulation testing.
//!
//! Design rule: the seam carries network capabilities, not protocol. Anything
//! that decides what bytes mean (ALPN dispatch targets, frame layouts,
//! request admission) lives above; anything that decides how
//! bytes move (QUIC, relays, and NAT traversal) lives below.
//! The week-of-2026-06-04 bug hunt found every
//! protocol bug *above* this line (snapshot ordering and authentication
//! subject binding), which is why the
//! host loop must run inside the simulator rather than being mocked
//! out at the latest serving-observation / authenticated evidence boundary.
//!
//! Stream IO is plain `tokio::io::{AsyncRead, AsyncWrite}` — iroh's
//! QUIC streams already implement both, and an in-memory duplex pipe
//! trivially does. `SendStream::finish()` maps to
//! `AsyncWriteExt::shutdown()`.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// A 32-byte node identity — the ed25519 pubkey bytes that double as
/// the iroh endpoint id in production and as the node address in the
/// simulator.
pub type PeerId = [u8; 32];

/// Application-layer protocol identifier for a connection. The protocol's
/// ALPN is a `'static` const ([`crate::protocol::PILE_SYNC_ALPN`]), so a
/// borrowed static slice suffices and keeps dispatch alloc-free.
pub type Alpn = &'static [u8];

/// A bidirectional connection to one remote peer on one ALPN.
///
/// Mirrors the slice of iroh's `Connection` the protocol actually
/// uses: open/accept bidirectional byte streams, learn the remote's
/// TLS-verified identity, close with a code. Clone is shallow
/// (`Arc`-like) — the pool and concurrent stream users share one
/// connection.
pub trait Conn: Clone + Send + Sync + 'static {
    type SendHalf: AsyncWrite + Unpin + Send + 'static;
    type RecvHalf: AsyncRead + Unpin + Send + 'static;

    /// The remote peer's verified identity. In production this is
    /// iroh's TLS-level `remote_id` — the subject checked by pinned local
    /// READ(C) admission and by every cold-bootstrap proof leaf.
    /// The simulator forges nothing: it returns the actual id of the
    /// node that dialed, so identity-dependent protocol logic is
    /// exercised honestly.
    fn remote_id(&self) -> PeerId;

    /// Open an outgoing bidirectional stream.
    fn open_bi(
        &self,
    ) -> impl std::future::Future<Output = anyhow::Result<(Self::SendHalf, Self::RecvHalf)>> + Send;

    /// Accept the next incoming bidirectional stream on this
    /// connection, or `None` when the connection is closed.
    fn accept_bi(
        &self,
    ) -> impl std::future::Future<Output = Option<(Self::SendHalf, Self::RecvHalf)>> + Send;

    /// Close the connection (best-effort, fire-and-forget).
    fn close(&self, code: u32, reason: &[u8]);
}

/// The network capabilities the protocol consumes. One instance per
/// node; `Clone` is shallow.
///
/// Deliberately *not* part of the trait: endpoint construction,
/// relay/discovery configuration, and protocol (ALPN) registration. Those are
/// adapter-construction concerns —
/// see [`Harness`] for the bundle a constructor hands to the host
/// loop.
pub trait Transport: Clone + Send + Sync + 'static {
    type Conn: Conn;
    type WakePlane: crate::wake::CollectionWakeNetwork;

    /// Our own identity (= the pubkey of the signing key the node
    /// runs as).
    fn local_id(&self) -> PeerId;

    /// Dial `peer` on `alpn`. Address resolution is the transport's
    /// problem (iroh: relay + pkarr + mDNS; sim: direct
    /// table lookup, subject to simulated partitions).
    fn dial(
        &self,
        peer: PeerId,
        alpn: Alpn,
    ) -> impl std::future::Future<Output = anyhow::Result<Self::Conn>> + Send;

    /// Gracefully stop the underlying endpoint after the host command loop
    /// loses every owner. Production QUIC needs an awaited close so peers do
    /// not mistake a clean daemon stop for a failed connection.
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send;

    /// Collection wake plane used to discover exact per-collection
    /// participants. It is transport state, never collection authority.
    fn collection_wake_plane(&self) -> Self::WakePlane;
}

/// An accepted inbound connection, tagged with the ALPN it arrived on.
pub struct Incoming<C> {
    pub alpn: Alpn,
    pub conn: C,
}

/// Everything a transport constructor hands the host loop: the
/// dial/discovery capabilities and inbound-connection stream.
///
/// Both halves of every channel are owned here rather than living in
/// trait methods so that adapter construction — which for iroh has to
/// register ALPN handlers before the router spawns — happens in one place, and
/// the host loop receives a ready-to-run bundle.
pub struct Harness<T: Transport> {
    pub transport: T,
    pub incoming: mpsc::Receiver<Incoming<T::Conn>>,
}

pub mod iroh;

#[cfg(feature = "sim")]
pub mod sim;
