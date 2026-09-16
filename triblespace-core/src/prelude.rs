//! This module re-exports the most commonly used types and traits from the `triblespace` crate.
//! It is intended to be glob imported as `use triblespace::prelude::*;`.
//!
//! # Introduction
//!
//! The `triblespace` crate is a Rust library for working with graph data.
//! It is designed to be simple, fast, and flexible.
//!
//! # Deletion and Forgetting
//!
//! On the surface, deletion and forgetting may seem identical.
//! However, there is a subtle but crucial difference: Deletion removes
//! a statement from existence, making it no longer valid, whereas forgetting removes your knowledge
//! of it, without affecting its validity. This distinction is particularly
//! important in contexts where data is shared among multiple parties, or where
//! derived statements are based on the original data.
//! Forgetting does not propagate to other parties,
//! is reversible should the forgotten information be rediscovered,
//! and does not invalidate any derived statements or facts.
//!
//! The property that distinguishes forgetting from deletion is called _monotonicity_,
//! and it has a deep relationship with _consistency_, as laid out by the [CALM theorem](https://arxiv.org/abs/1901.01930)
//! (Consistency as Logical Monotonicity). The CALM theorem states that a distributed
//! system is consistent if and only if it is logically monotonic. This means that
//! if you want to build a consistent distributed system, you need to
//! ensure that it is logically monotonic. This is where forgetting comes
//! in: _By allowing you to forget things, but preventing you from deleting
//! things, `triblespace` allows you to build consistent distributed systems.
//!

/// Re-exports of blob encoding types.
pub mod blobencodings;
/// Re-exports of inline encoding types.
pub mod inlineencodings;

pub use crate::attribute::Attribute;
pub use crate::blob::Blob;
pub use crate::blob::BlobEncoding;
pub use crate::blob::IntoBlob;
pub use crate::blob::MemoryBlobStore;
pub use crate::blob::TryFromBlob;
pub use crate::collection::{
    Collection, CollectionDerivation, CollectionEncoding, CollectionMapping, CollectionRead,
    CollectionSnapshot, CollectionSnapshotExt, CollectionStore, CollectionStoreExt, Cover, Support,
    TryFromCover, TryFromCoverError, VerifyingKey,
};
pub use crate::id::fucid;
pub use crate::id::genid;
pub use crate::id::local_ids;
pub use crate::id::rngid;
pub use crate::id::ufoid;
pub use crate::id::ExclusiveId;
pub use crate::id::Id;
pub use crate::id::IdOwner;
pub use crate::id::RawId;
pub use crate::inline::encodings::UnknownInline;
pub use crate::inline::Encoded;
pub use crate::inline::Inline;
pub use crate::inline::InlineEncoding;
pub use crate::inline::IntoInline;
pub use crate::inline::ToEncoded;
pub use crate::inline::TryFromInline;
pub use crate::inline::TryToInline;
pub use crate::metadata::{Describe, MetaDescribe};
pub use crate::or;
pub use crate::query::exists;
pub use crate::query::find;
pub use crate::query::frontier::latest;
pub use crate::query::intersectionconstraint::and;
pub use crate::query::intersectionconstraint::IntersectionConstraint;
pub use crate::query::rangeconstraint::{value_range, InlineRange};
pub use crate::query::register::{
    maximal, resolve, sole, End, Maximal, ObservationOrder, RegisterOrder, StatedOrder, Unordered,
};
pub use crate::query::sortedsliceconstraint::SortedSlice;
pub use crate::query::temp;
pub use crate::query::unionconstraint::UnionConstraint;
pub use crate::query::ContainsConstraint;
pub use crate::query::Term;
pub use crate::query::TriblePattern;
pub use crate::query::Variable;
pub use crate::repo::memoryrepo::MemoryRepo;
pub use crate::repo::pile::{Pile, PileSnapshot};
pub use crate::repo::BlobChildren;
pub use crate::repo::BlobStore;
pub use crate::repo::BlobStoreGet;
pub use crate::repo::BlobStorePut;
pub use crate::repo::CommitHandle;
pub use crate::repo::SnapshotErrorOf;
pub use crate::repo::SnapshotOf;
pub use crate::repo::SnapshotSource;
pub use crate::repo::StorageFlush;
pub use crate::repo::Store;
pub use crate::repo::StoreChanges;
pub use crate::repo::StoreRead;
pub use crate::repo::StoreSnapshot;
pub use crate::repo::WantRead;
pub use crate::repo::WantRequest;
pub use crate::repo::WantRequestDecodeError;
pub use crate::repo::WantStore;
pub use crate::repo::WANT_REQUEST_BYTES_LEN;
pub use crate::repo::{BlobInfo, BlobStoreList};
pub use crate::trible::Fragment;
pub use crate::trible::Spread;
pub use crate::trible::Trible;
pub use crate::trible::TribleSet;
pub use crate::trible::TribleSetFingerprint;
pub use anybytes::View;
// Re-export the pattern/entity procedural macros into the prelude so they can
// be imported with `use triblespace::prelude::*;` and called as `pattern!(...)`.
// After migrating away from namespace-local wrapper macros, this makes the
// new global proc-macros ergonomically available.
pub use crate::macros::attributes;
pub use crate::macros::entity;
pub use crate::macros::id_hex;
pub use crate::macros::pattern;
pub use crate::macros::pattern_changes;
