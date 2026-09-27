//! Who produced a foundation: "you own what you signed".
//!
//! Ownership decides derivation, not merging. A root's carry merges every
//! node the store holds, whoever signed the foundations beneath it, into the
//! host's own merges: join is associative, commutative and idempotent, so
//! whose tree covers a foundation does not matter. A derived collection
//! still derives the source foundations its maintainer owns first, and
//! mirrors the source merges its maintainer signed; those decisions ask
//! [`owns`] or [`owns_merge`], and nothing else, so a later notion of
//! ownership (claims, transfer) replaces these two functions rather than a
//! scatter of signer comparisons.
//!
//! Ownership of a node is read from the coverage index's `owners` relation:
//! the signers of the believed COMMITs and DERIVEs that produced it. A node
//! two signers produced -- the same payload committed by both -- is owned by
//! both. A join records no owner: every join the index believes is the
//! host's. Ownership of a MERGE record is its signer.

use ed25519_dalek::VerifyingKey;

use crate::inline::Inline;

use super::coverage::Coverage;
use super::{CollectionData, CollectionHandle, CollectionMerge};

/// Whether `key` owns `node` of `collection` in this coverage observation.
pub fn owns(
    coverage: &Coverage,
    collection: CollectionHandle,
    node: CollectionData,
    key: &VerifyingKey,
) -> bool {
    coverage.owned_by(collection, node, Inline::new(key.to_bytes()))
}

/// Whether `key` owns one MERGE record: it signed it.
///
/// This is what a derived collection mirrors: the source merges its
/// maintainer owns, never somebody else's claim about the maintainer's
/// nodes. Whether the merge is believed at all is a separate question the
/// caller asks the coverage index.
pub fn owns_merge(merge: &CollectionMerge, key: &VerifyingKey) -> bool {
    merge.public_key() == Inline::new(key.to_bytes())
}
