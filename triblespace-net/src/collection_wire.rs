//! Bounds and summaries of one collection's repair evidence.
//!
//! The repair session that pinned one manifest per stream is gone: pull
//! walks on `recon/1` ([`crate::walk`]) carry the evidence now. What stays is
//! the leaf bound a walk frame enforces and the manifest that health reports
//! as a collection's frontier.

use triblespace_core::capability::MAX_CAPABILITY_PROOF_BYTES;

use crate::collection_activation::CollectionRepairOverlay;
use crate::patch_repair::PatchSummary;

/// Largest value transported by one authenticated PATCH leaf.
pub(crate) const MAX_COLLECTION_LEAF_BYTES: usize = MAX_CAPABILITY_PROOF_BYTES;

/// One collection observation's evidence summaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CollectionRepairManifest {
    pub(crate) wake_root: [u8; 32],
    pub(crate) records: PatchSummary,
    pub(crate) authorization_evidence: PatchSummary,
    pub(crate) resident_blobs: PatchSummary,
}

pub(crate) fn manifest(overlay: &CollectionRepairOverlay) -> CollectionRepairManifest {
    CollectionRepairManifest {
        wake_root: overlay.wake_root(),
        records: overlay.records().summary(),
        authorization_evidence: overlay.authorization_evidence().summary(),
        resident_blobs: PatchSummary::from_patch(overlay.blob_inventory()),
    }
}
