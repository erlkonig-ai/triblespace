//! Per-stream one-way Prefix offer receipts. No private inventory lives here.
//!
//! HAVE repeats an exact offered commitment. Its eligibility is decided by the
//! exchange from explicit leaf possession or already shared G, never equality
//! with a complete private prefix. Final LANDED remains independent.

use std::collections::VecDeque;
use triblespace_core::patch::{Entry, IdentitySchema, PATCH};

use super::{FLOOD_LOCATORS, Failure, KEY_BYTES, locator_key};
use crate::patch_repair::PatchSummary;

pub(super) const WINDOW: usize = 64;

#[derive(Default)]
pub(super) struct Offers {
    /// Exact stream offers, retained to validate duplicate/late receipts too.
    offered: PATCH<33, IdentitySchema, PatchSummary>,
    acknowledged: PATCH<33, IdentitySchema>,
    /// At most WINDOW explicit leaves await possession/landing receipts.
    outstanding: PATCH<32, IdentitySchema>,
    eager: VecDeque<[u8; KEY_BYTES]>,
    /// Receiver-side receipt suppression and admitted eager body identities.
    pub(super) sent: PATCH<33, IdentitySchema>,
    pub(super) values: PATCH<32, IdentitySchema>,
    /// Matches the landing task's ordered per-event acknowledgement counts.
    pub(super) landings: VecDeque<Option<[u8; KEY_BYTES]>>,
}

impl Offers {
    pub(super) fn full(&self) -> bool {
        self.outstanding.len() >= WINDOW as u64
    }
    pub(super) fn awaits(&self) -> bool {
        !self.outstanding.is_empty()
    }
    pub(super) fn pending(&self, key: &[u8; KEY_BYTES]) -> bool {
        self.outstanding.get(key).is_some()
    }

    pub(super) fn offer(
        &mut self,
        prefix: &[u8],
        summary: PatchSummary,
        body: bool,
    ) -> Result<(), Failure> {
        if summary.root().is_none() {
            return Ok(());
        }
        if self.offered.len() >= FLOOD_LOCATORS as u64 {
            return Err(Failure::ResourceLimit);
        }
        self.offered
            .insert(&Entry::with_value(&locator_key(prefix), summary));
        if prefix.len() == KEY_BYTES {
            if self.full() {
                return Err(Failure::ResourceLimit);
            }
            let key = prefix.try_into().expect("full-width offered leaf");
            self.outstanding.insert(&Entry::new(&key));
            if body {
                self.eager.push_back(key);
            }
        }
        Ok(())
    }

    pub(super) fn have(&mut self, prefix: &[u8], summary: PatchSummary) -> Result<(), Failure> {
        if prefix.len() > KEY_BYTES {
            return Err(Failure::Protocol);
        }
        let locator = locator_key(prefix);
        if summary.root().is_none() || self.offered.get(&locator) != Some(&summary) {
            return Err(Failure::Protocol);
        }
        if self.acknowledged.get(&locator).is_some() {
            return Ok(());
        }
        self.acknowledged.insert(&Entry::new(&locator));
        // Ephemeral scratch, bounded by WINDOW, not a retained source index.
        let released: Vec<_> = self
            .outstanding
            .iter()
            .filter(|key| key.starts_with(prefix))
            .copied()
            .collect();
        for key in released {
            self.outstanding.remove(&key);
        }
        self.eager.retain(|key| !key.starts_with(prefix));
        Ok(())
    }

    pub(super) fn next_body(&mut self) -> Option<[u8; KEY_BYTES]> {
        while let Some(key) = self.eager.pop_front() {
            if self.pending(&key) {
                return Some(key);
            }
        }
        None
    }
}
