//! Collection-scoped anti-entropy for triblespace.
//!
//! [`Peer<S>`](peer::Peer) wraps one store. Authorized pushes of PATCH trees
//! converge one explicitly active collection's records and collection-scoped
//! native evidence for descriptor-declared capabilities. Neighbours that peer
//! for a selected collection on the one `recon/1` stream of their connection
//! each push it the part of their trees it has not confirmed, on `walk/1`
//! streams of their own. Policy roots, scoped AUTH keys and ordinary
//! descriptor-blob providers supply candidate contacts, never authority;
//! every useful collection byte remains capability-gated.
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
pub mod clock;
pub mod collection_activation;
pub mod collection_delta;
pub(crate) mod collection_wire;
pub mod connection;
pub mod dashboard;
pub(crate) mod grants;
pub mod health;
pub mod health_record;
pub mod host;
pub mod identity;
pub(crate) mod landing;
pub mod patch_repair;
pub mod peer;
pub(crate) mod peering;
pub mod protocol;
pub mod provider;
pub(crate) mod push;
pub(crate) mod receive;
pub mod recon;
pub mod reconcile;
pub(crate) mod routing;
pub(crate) mod schedule;
pub mod telemetry;
pub mod transport;
mod wake_schedule;
pub mod walk;
pub mod walk_stream;
