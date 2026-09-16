//! Collection-scoped anti-entropy for triblespace.
//!
//! [`Peer<S>`](peer::Peer) wraps one store. Periodic per-request authorized
//! PATCH walks converge one explicitly active collection's records and
//! collection-scoped native evidence for descriptor-declared capabilities. A separate
//! stock-gossip wake plane carries only a signed endpoint origin and opaque
//! per-collection anti-entropy root; knowing the collection handle is its
//! discovery capability, while every useful collection byte remains
//! capability-gated.
//! Exact content reads are independent: every served resident blob may publish
//! a full-width opaque locator derived from its bearer handle H. The selected
//! endpoint proves H before the requester proves H, both proofs bind their
//! authenticated endpoint identities, and returned bytes must hash to H.
//!
//! Semantic snapshots and local writes remain synchronous. Explicit exact-blob
//! reads through [`PeerSnapshot`](peer::PeerSnapshot) await acquisition while
//! keeping the captured collection and authorization observation unchanged.
//! [`Leech<S>`](peer::Leech) provides the same local store and exact-acquisition
//! operations without constructing or advertising a serving inventory.

pub(crate) mod bearer;
mod channel;
pub mod collection_activation;
pub mod collection_delta;
pub(crate) mod collection_session;
pub(crate) mod collection_wire;

/// Base backoff for failed WANT fulfillment in [`reconcile::Reconciler`];
/// doubles per attempt up to
/// [`RETRY_BACKOFF_CAP`]. Values chosen so a transient fault (peer
/// restarting, partition healing) is retried promptly while a
/// persistently-dead source costs at most one attempt per cap period.
pub(crate) const RETRY_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);
/// Upper bound the exponential retry backoff saturates at.
pub(crate) const RETRY_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(60);
pub mod clock;
pub mod dashboard;
pub mod health;
pub mod health_record;
pub mod host;
pub mod identity;
pub mod inventory;
pub mod patch_repair;
pub mod peer;
pub mod protocol;
pub mod provider;
pub mod reconcile;
pub(crate) mod routing;
pub mod transport;
pub mod wake;
