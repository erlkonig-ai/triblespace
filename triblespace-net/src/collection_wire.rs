//! Bounds and summaries of one collection's repair evidence.
//!
//! The repair session that pinned one manifest per stream is gone: pushes
//! on `walk/1` streams ([`crate::walk`]) carry the evidence now. What stays
//! is the leaf bound a walk frame enforces and the manifest that health
//! reports as a collection's frontier.

use triblespace_core::capability::MAX_CAPABILITY_PROOF_BYTES;

use crate::collection_activation::CollectionRepairOverlay;
use crate::patch_repair::PatchSummary;

/// Largest value transported by one authenticated PATCH leaf.
pub(crate) const MAX_COLLECTION_LEAF_BYTES: usize = MAX_CAPABILITY_PROOF_BYTES;

/// One collection observation's evidence summaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CollectionRepairManifest {
    pub(crate) wake_root: [u8; 32],
    pub(crate) commits: PatchSummary,
    pub(crate) derives: PatchSummary,
    pub(crate) authorization_evidence: PatchSummary,
}

pub(crate) fn manifest(overlay: &CollectionRepairOverlay) -> CollectionRepairManifest {
    CollectionRepairManifest {
        wake_root: overlay.wake_root(),
        commits: overlay.records().summaries()[0],
        derives: overlay.records().summaries()[1],
        authorization_evidence: overlay.authorization_evidence().summary(),
    }
}
