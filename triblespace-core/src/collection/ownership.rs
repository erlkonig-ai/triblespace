//! Who produced a foundation: "you own what you signed".
//!
//! Ownership decides neither merging nor whether a foundation is derived. A
//! collection's carry merges every node the store holds, whoever signed the
//! foundations beneath it, into the host's own merges: join is
//! associative, commutative and idempotent, so whose tree covers a
//! foundation does not matter. A derived collection derives a foundation
//! when no admitted leaf for it is usable, whoever owns it. Ownership only
//! orders that work and scopes the per-write pass: `ensure` derives the
//! foundations its key owns, the key's own payloads are fetched while
//! another owner's are used only when here, and what the mapping cannot do
//! with another owner's foundation is not the key's failure. Those
//! decisions ask [`owns`], and nothing else, so a later notion of ownership
//! (claims, transfer) replaces this function rather than a scatter of
//! signer comparisons.
//!
//! Ownership of a node is read from the coverage index's `owners` relation:
//! the signers of the believed COMMITs and DERIVEs that produced it. A node
//! two signers produced -- the same payload committed by both -- is owned by
//! both. A join records no owner: every join the index believes is the
//! host's.

use ed25519_dalek::VerifyingKey;

use crate::inline::Inline;

use super::coverage::Coverage;
use super::{CollectionData, CollectionHandle};

/// Whether `key` owns `node` of `collection` in this coverage observation.
pub fn owns(
    coverage: &Coverage,
    collection: CollectionHandle,
    node: CollectionData,
    key: &VerifyingKey,
) -> bool {
    coverage.owned_by(collection, node, Inline::new(key.to_bytes()))
}
