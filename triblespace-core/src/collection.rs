//! Canonical records, discovery, and semantic resolution for typed collections.
//!
//! Wire decoding and strict self-signature checks remain structural. Production
//! [resolution](crate::collection::resolution) admits only authorized,
//! representation-validated claims. The larger generic oracle remains
//! test-only: it exercises algebraic laws rather than serving as another
//! runtime implementation.

use crate::blob::{encodings::simplearchive::SimpleArchive, IntoBlob};
use crate::capability::CapabilityHandle;
use crate::id::{id_hex, Id};
use std::sync::OnceLock;

/// The exact action required to contribute a signed commit to a collection.
///
/// Minted with `trible genid` on 2026-08-22. Capability policies pair this
/// stable action with one exact collection descriptor handle.
pub const ACTION_WRITE: Id = id_hex!("66B660A5481E04E552A1FA96AA9ECC48");

/// The exact action required to receive or inspect one collection.
///
/// Minted with `trible genid` on 2026-08-30. Capability policies pair this
/// stable action with one exact collection descriptor handle.
pub const ACTION_READ: Id = id_hex!("76583A671BBD61A6A8E66405DE75873F");

/// Exact definition handle of collection READ; descriptor builders attach it.
pub fn read_capability() -> CapabilityHandle {
    static HANDLE: OnceLock<CapabilityHandle> = OnceLock::new();
    *HANDLE.get_or_init(|| {
        IntoBlob::<SimpleArchive>::to_blob(policy::read_definition().facts().clone()).get_handle()
    })
}

/// Exact definition handle of collection WRITE; descriptor builders attach it.
pub fn write_capability() -> CapabilityHandle {
    static HANDLE: OnceLock<CapabilityHandle> = OnceLock::new();
    *HANDLE.get_or_init(|| {
        IntoBlob::<SimpleArchive>::to_blob(policy::write_definition().facts().clone()).get_handle()
    })
}

/// Narrow write facade for a scoped fact collection.
pub mod api;
/// Reading one collection descriptor's facts.
pub mod descriptor;
pub mod discovery;
/// Canonical collection encodings and join-preserving mappings.
pub mod encoding;
/// Exact realization over invariant foundational support.
mod exact_derived;
/// Deterministic size-tiered maintenance behind exact derived collections.
mod exact_target_compaction;
/// Maintained positive latest states and historical supersession evidence.
pub mod latest;
/// Maintained stated last-write-wins registers over exact source covers.
pub mod lww_register;
mod operation_snapshot;
/// Immutable collection-local READ and WRITE authorization ceilings.
pub mod policy;
pub mod records;
/// Unionable summaries of complete producer-side referenced-blob closures.
pub mod reference_summary;
/// Stateless semantic admission, closure, provenance, and physical-cover view.
pub mod resolution;
/// Canonical `SimpleArchive` set-union collection kind.
pub mod simplearchive_union;
/// Native grow-only storage for collection-calculus records.
pub mod store;
/// Canonical raw `SuccinctArchiveBlob` set-union collection kind.
pub mod succinctarchive_union;
/// Logical values reconstructed from typed physical covers.
pub mod view;

/// Ed25519 public key, re-exported for collection admission policies.
///
/// Each action policy may name one or more capability trust roots. Downstream
/// crates should not need a direct `ed25519-dalek` dependency merely to state
/// those roots.
pub use ed25519_dalek::VerifyingKey;

pub use api::*;
pub use discovery::*;
pub use encoding::*;
pub use exact_derived::CollectionRealizationError;
pub use policy::*;
pub use records::*;
pub use resolution::*;
pub use simplearchive_union::{PreparedCollectionCommit, StagedCollectionCommit};
pub use store::*;
pub use view::*;

#[cfg(test)]
mod oracle;

#[cfg(test)]
mod equation_admission_tests;
