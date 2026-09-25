//! Who may merge or derive a node: "you own what you signed".
//!
//! Maintenance never merges or derives a node it does not own. A root's
//! carry takes only its own frontier nodes; a derived collection derives the
//! source foundations its maintainer owns and mirrors the source merges that
//! produce nodes its maintainer owns. Every one of those decisions asks
//! [`owns`], and nothing else, so a later notion of ownership (claims,
//! transfer) replaces this one function rather than a scatter of signer
//! comparisons.
//!
//! For now ownership is read from the coverage index's `owners` relation:
//! the signers of the believed records that produced the node. A node two
//! signers produced -- the same payload committed by both, or one join both
//! happened to sign -- is owned by both, and either may build on it.

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
