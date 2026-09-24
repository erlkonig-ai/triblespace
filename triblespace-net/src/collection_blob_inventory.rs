//! Bounded, positive-only local blob closure for one active collection.
//!
//! Seeds are exact direct references supplied by the collection observation,
//! including the collection descriptor itself. Descendants use the existing
//! conservative `BlobChildren` semantics: an aligned 32-byte word is a child
//! only when a passive local snapshot can actually read that exact handle.
//! This does not infer semantic references, decrypt ciphertext, establish READ
//! authority, or promise completeness. An absent word is never retained as a
//! speculative WANT and never causes network I/O here.

use anybytes::Bytes;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::patch::{Blake3Merkle, Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::repo::BlobStoreGet;

#[cfg(test)]
use crate::protocol::RawHash;

pub(crate) type ResidentBlobPatch = PATCH<32, IdentitySchema, (), Blake3Merkle>;

/// Change to the snapshot's *readable* blob membership since the last observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobInventoryChange {
    Unchanged,
    /// Every previously readable handle remains readable with the same bytes.
    Additions,
    /// Removal, newly unreadable bytes, or an unknown/reset observation.
    MayRemove,
}

/// Bounds point reads and scanning, not the store's cost of each passive read.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ScanBudget {
    pub(crate) words: usize,
    pub(crate) sources: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ScanStats {
    pub(crate) words: usize,
    pub(crate) sources: usize,
    pub(crate) added: usize,
    /// A previously positive handle became unreadable without a removal notice.
    pub(crate) invalidated: bool,
}

const SOURCE_WORD_QUANTUM: usize = 64;

#[derive(Clone, Copy)]
struct SourceProgress {
    offset: usize,
    generation: u64,
}

/// Incremental traversal state, not a catalogue of speculative references.
///
/// PATCH clones share structure. Each source gets at most 64 words before
/// yielding to other sources in the round; only positive handles retain an
/// offset. No body is pinned between calls. Each round freezes its finite work
/// set. Additions request a revisit without resetting unfinished offsets, so
/// neither a huge body nor constant arrivals can starve other existing work.
/// Without external changes, newly found children do not rescan ancestors.
#[derive(Clone, Default)]
pub(crate) struct CollectionBlobInventory {
    seeds: ResidentBlobPatch,
    resident: ResidentBlobPatch,
    round: ResidentBlobPatch,
    next: ResidentBlobPatch,
    progress: PATCH<32, IdentitySchema, SourceProgress>,
    generation: u64,
    revisit: bool,
}

impl CollectionBlobInventory {
    /// Observe exact direct seeds and a coherent passive snapshot transition.
    ///
    /// Call before `advance` against a changed snapshot. Adding seeds preserves
    /// progress. Removing any seed or readable blob resets the closure: merely
    /// intersecting old results with resident handles would retain descendants
    /// whose only path from this collection has disappeared.
    pub(crate) fn observe_patch(
        &mut self,
        observed: ResidentBlobPatch,
        change: BlobInventoryChange,
    ) {
        let changed = self.seeds != observed;
        let removed = changed && !(self.seeds <= observed);
        if changed && !removed {
            self.next.union(observed.difference(&self.seeds));
        }
        self.seeds = observed;
        if removed || change == BlobInventoryChange::MayRemove {
            self.reset();
        } else if change == BlobInventoryChange::Additions {
            if let Some(generation) = self.generation.checked_add(1) {
                self.generation = generation;
            } else {
                // A full rebuild is safe even at this practically unreachable
                // wrap boundary; no old cursor can appear current again.
                self.generation = 0;
                self.reset();
            }
            self.revisit = !self.seeds.is_empty();
        }
    }

    #[cfg(test)]
    fn observe(&mut self, seeds: impl IntoIterator<Item = RawHash>, change: BlobInventoryChange) {
        let mut observed = ResidentBlobPatch::default();
        for handle in seeds {
            observed.insert(&PatchEntry::new(&handle));
        }
        self.observe_patch(observed, change);
    }

    fn reset(&mut self) {
        self.resident = ResidentBlobPatch::default();
        self.round = ResidentBlobPatch::default();
        self.next = ResidentBlobPatch::default();
        self.progress = PATCH::new();
        self.revisit = !self.seeds.is_empty();
    }

    /// Scan one bounded synchronous quantum against a passive local reader.
    ///
    /// The reader must neither acquire missing blobs nor record demand. At most
    /// `sources + words` point reads occur; no body is pinned between calls.
    /// Bytes are immutable and the caller's change classification must
    /// cover readable membership, not merely unvalidated physical index rows.
    /// Zero in either budget dimension leaves traversal unchanged.
    pub(crate) fn advance<R: BlobStoreGet>(
        &mut self,
        snapshot: &R,
        budget: ScanBudget,
    ) -> ScanStats {
        let mut stats = ScanStats::default();
        if budget.words == 0 || budget.sources == 0 {
            return stats;
        }
        loop {
            if stats.sources == budget.sources || stats.words == budget.words {
                break;
            }
            if self.round.is_empty() {
                self.round = std::mem::take(&mut self.next);
                if self.revisit {
                    self.round.union(self.seeds.clone());
                    self.round.union(self.resident.clone());
                    self.revisit = false;
                }
            }
            let Some(handle) = self.round.iter_ordered().next().copied() else {
                break;
            };
            self.round.remove(&handle);
            // A newly discovered child may also be a source already waiting
            // in this round; do not scan it twice without a snapshot change.
            self.next.remove(&handle);
            stats.sources += 1;
            let body = match snapshot
                .get::<Bytes, UnknownBlob>(Inline::<Handle<UnknownBlob>>::new(handle))
            {
                Ok(bytes) => {
                    if !self.resident.has_prefix(&handle) {
                        self.resident.insert(&PatchEntry::new(&handle));
                        stats.added += 1;
                    }
                    bytes
                }
                Err(_) if self.resident.has_prefix(&handle) => {
                    // Fail closed if a caller misclassified a membership
                    // change. Disconnected descendants cannot remain offered.
                    self.reset();
                    stats.invalidated = true;
                    break;
                }
                Err(_) => continue,
            };
            let bytes: &[u8] = body.as_ref();
            let mut progress = self
                .progress
                .get(&handle)
                .copied()
                .unwrap_or(SourceProgress {
                    offset: 0,
                    generation: self.generation,
                });
            let limit = SOURCE_WORD_QUANTUM.min(budget.words - stats.words);
            let mut words = 0;
            while bytes.len() - progress.offset >= 32 && words < limit {
                let mut child = [0; 32];
                child.copy_from_slice(&bytes[progress.offset..progress.offset + 32]);
                progress.offset += 32;
                words += 1;
                if !self.resident.has_prefix(&child)
                    && snapshot
                        .get::<Bytes, UnknownBlob>(Inline::<Handle<UnknownBlob>>::new(child))
                        .is_ok()
                {
                    self.resident.insert(&PatchEntry::new(&child));
                    self.next.insert(&PatchEntry::new(&child));
                    stats.added += 1;
                }
            }
            stats.words += words;
            if bytes.len() - progress.offset >= 32 {
                self.progress
                    .replace(&PatchEntry::with_value(&handle, progress));
                self.next.insert(&PatchEntry::new(&handle));
            } else if progress.generation != self.generation {
                // A child missed near the beginning may have arrived while
                // this body was in flight. Finish first, then revisit once.
                self.progress.replace(&PatchEntry::with_value(
                    &handle,
                    SourceProgress {
                        offset: 0,
                        generation: self.generation,
                    },
                ));
                self.next.insert(&PatchEntry::new(&handle));
            } else {
                self.progress.remove(&handle);
            }
        }
        stats
    }

    /// Positive partial inventory only; absence is not evidence of unavailability.
    pub(crate) fn patch(&self) -> &ResidentBlobPatch {
        &self.resident
    }

    /// Work pending for the last observation, not a completeness assertion.
    pub(crate) fn has_pending_work(&self) -> bool {
        self.revisit || !self.round.is_empty() || !self.next.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::error::Error;

    use triblespace_core::blob::{Blob, BlobEncoding, MemoryStoreGetError, TryFromBlob};

    use super::*;

    // The passive test reader uses arbitrary keys to exercise cycles. It is not
    // a content-hash implementation; production stores own that invariant.
    #[derive(Default)]
    struct Snapshot {
        blobs: BTreeMap<RawHash, Bytes>,
        reads: Cell<usize>,
    }

    impl Snapshot {
        fn put(&mut self, handle: RawHash, words: &[RawHash]) {
            self.blobs.insert(
                handle,
                Bytes::from_source(words.iter().flatten().copied().collect::<Vec<_>>()),
            );
        }
    }

    impl BlobStoreGet for Snapshot {
        type GetError<E: Error + Send + Sync + 'static> = MemoryStoreGetError<E>;

        fn get<T, S>(
            &self,
            handle: Inline<Handle<S>>,
        ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
        where
            S: BlobEncoding,
            T: TryFromBlob<S>,
        {
            self.reads.set(self.reads.get() + 1);
            let bytes = self
                .blobs
                .get(&handle.raw)
                .cloned()
                .ok_or(MemoryStoreGetError::NotFound())?;
            T::try_from_blob(Blob::with_handle(bytes, handle))
                .map_err(MemoryStoreGetError::ConversionFailed)
        }
    }

    fn finish(scan: &mut CollectionBlobInventory, snapshot: &Snapshot) {
        for _ in 0..256 {
            if !scan.has_pending_work() {
                return;
            }
            scan.advance(
                snapshot,
                ScanBudget {
                    words: 64,
                    sources: 16,
                },
            );
        }
        panic!("finite unchanged inventory did not finish");
    }

    fn keys(scan: &CollectionBlobInventory) -> Vec<RawHash> {
        scan.patch().iter_ordered().copied().collect()
    }

    #[test]
    fn inventory_excludes_absent_unrelated_and_unaligned_words() {
        let mut snapshot = Snapshot::default();
        let mut bytes = Vec::<u8>::new();
        bytes.extend_from_slice(&[2; 32]);
        bytes.extend_from_slice(&[9; 32]); // Absent, not retained as speculative work.
        bytes.extend_from_slice(&[3; 31]); // Partial words are not handles.
        snapshot.blobs.insert([1; 32], Bytes::from_source(bytes));
        snapshot.put([2; 32], &[]);
        snapshot.put([3; 32], &[]);
        snapshot.put([4; 32], &[]); // Resident, but outside this collection's closure.
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn cycles_and_shared_children_finish_without_duplicate_work() {
        let mut snapshot = Snapshot::default();
        snapshot.put([1; 32], &[[2; 32], [3; 32]]);
        snapshot.put([2; 32], &[[1; 32], [3; 32]]);
        snapshot.put([3; 32], &[[3; 32]]);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32], [2; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32], [2; 32], [3; 32]]);
        // Three source reads plus the first positive lookup of each child.
        assert_eq!(snapshot.reads.get(), 5);
    }

    #[test]
    fn blob_only_arrivals_revisit_misses_without_a_negative_backlog() {
        let mut snapshot = Snapshot::default();
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        assert!(scan.patch().is_empty());
        snapshot.put([1; 32], &[[2; 32]]);
        scan.observe([[1; 32]], BlobInventoryChange::Additions);
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32]]);
        snapshot.put([2; 32], &[[3; 32]]);
        snapshot.put([3; 32], &[]);
        scan.observe([[1; 32]], BlobInventoryChange::Additions);
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32], [2; 32], [3; 32]]);
        let reads = snapshot.reads.get();
        scan.observe([[1; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        assert_eq!(snapshot.reads.get(), reads);
    }

    #[test]
    fn removals_drop_disconnected_descendants_and_seed_removal_resets() {
        let mut snapshot = Snapshot::default();
        snapshot.put([1; 32], &[[2; 32]]);
        snapshot.put([2; 32], &[[3; 32]]);
        snapshot.put([3; 32], &[]);
        snapshot.put([4; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32], [4; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        assert_eq!(scan.patch().len(), 4);
        snapshot.blobs.remove(&[2; 32]);
        scan.observe([[1; 32], [4; 32]], BlobInventoryChange::MayRemove);
        assert!(scan.patch().is_empty());
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32], [4; 32]]);
        assert!(snapshot.blobs.contains_key(&[3; 32]));
        scan.observe([[4; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[4; 32]]);
        scan.observe([], BlobInventoryChange::Unchanged);
        assert!(scan.patch().is_empty());
        assert!(!scan.has_pending_work());
    }

    #[test]
    fn budget_and_cloned_cursor_preserve_bounded_progress() {
        let mut snapshot = Snapshot::default();
        snapshot.put([1; 32], &[[9; 32], [9; 32], [9; 32], [2; 32]]);
        snapshot.put([2; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32]], BlobInventoryChange::Unchanged);
        let zero = scan.advance(
            &snapshot,
            ScanBudget {
                words: 0,
                sources: 1,
            },
        );
        assert_eq!(zero, ScanStats::default());
        assert_eq!(snapshot.reads.get(), 0);
        for _ in 0..2 {
            let before = snapshot.reads.get();
            let stats = scan.advance(
                &snapshot,
                ScanBudget {
                    words: 1,
                    sources: 1,
                },
            );
            assert_eq!(stats.words, 1);
            assert!(stats.sources <= 1);
            assert!(snapshot.reads.get() - before <= 2);
        }
        let mut clone = scan.clone();
        finish(&mut scan, &snapshot);
        finish(&mut clone, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32], [2; 32]]);
        assert_eq!(scan.patch(), clone.patch());
        let before = snapshot.reads.get();
        drop(clone);
        assert_eq!(snapshot.reads.get(), before);
    }

    #[test]
    fn steady_additions_do_not_restart_a_large_body() {
        let mut snapshot = Snapshot::default();
        let mut words = vec![[255; 32]; 64];
        words.push([2; 32]);
        snapshot.put([1; 32], &words);
        snapshot.put([2; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        for i in 0..65 {
            // Unrelated arrivals keep requesting revisits, but must not reset
            // the current source's offset or displace its remaining work.
            snapshot.put([100 + i; 32], &[]);
            scan.observe([[1; 32]], BlobInventoryChange::Additions);
            let stats = scan.advance(
                &snapshot,
                ScanBudget {
                    words: 1,
                    sources: 1,
                },
            );
            assert_eq!(stats.words, 1);
        }
        assert!(scan.patch().has_prefix(&[2; 32]));
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn steady_seed_additions_preserve_the_current_source_cursor() {
        let mut snapshot = Snapshot::default();
        snapshot.put([1; 32], &[[255; 32], [255; 32], [255; 32], [2; 32]]);
        snapshot.put([2; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        let mut seeds = vec![[1; 32]];
        let mut previous_offset = 0;
        for i in 0..4 {
            seeds.push([100 + i; 32]);
            snapshot.put([100 + i; 32], &[]);
            scan.observe(seeds.iter().copied(), BlobInventoryChange::Additions);
            scan.advance(
                &snapshot,
                ScanBudget {
                    words: 1,
                    sources: 1,
                },
            );
            let offset = scan.progress.get(&[1; 32]).unwrap().offset;
            assert!(offset >= previous_offset);
            previous_offset = offset;
        }
        finish(&mut scan, &snapshot);
        assert!(scan.patch().has_prefix(&[2; 32]));
        assert_eq!(scan.patch().len(), 6);
    }

    #[test]
    fn a_large_source_yields_to_later_seeds_and_new_descendants() {
        let mut snapshot = Snapshot::default();
        let mut large = vec![[255; 32]; 4096];
        large[0] = [3; 32];
        snapshot.put([1; 32], &large);
        snapshot.put([2; 32], &[[4; 32]]);
        snapshot.put([3; 32], &[[5; 32]]);
        snapshot.put([4; 32], &[]);
        snapshot.put([5; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32], [2; 32]], BlobInventoryChange::Unchanged);
        let budget = ScanBudget {
            words: 1024,
            sources: 1,
        };
        assert_eq!(scan.advance(&snapshot, budget).words, SOURCE_WORD_QUANTUM);
        assert!(scan.patch().has_prefix(&[3; 32]));
        assert!(!scan.patch().has_prefix(&[2; 32]));
        scan.advance(&snapshot, budget);
        assert!(scan.patch().has_prefix(&[4; 32]));
        for _ in 0..4 {
            scan.advance(&snapshot, budget);
        }
        assert!(scan.patch().has_prefix(&[5; 32]));
        assert!(scan.progress.get(&[1; 32]).unwrap().offset < 4096 * 32);
    }

    #[test]
    fn arrival_during_a_partial_source_revisits_its_previously_scanned_prefix() {
        let mut snapshot = Snapshot::default();
        let mut words = vec![[255; 32]; 128];
        words[0] = [2; 32];
        snapshot.put([1; 32], &words);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32]], BlobInventoryChange::Unchanged);
        scan.advance(
            &snapshot,
            ScanBudget {
                words: 1,
                sources: 1,
            },
        );
        assert!(!scan.patch().has_prefix(&[2; 32]));
        assert_eq!(scan.progress.get(&[1; 32]).unwrap().offset, 32);
        snapshot.put([2; 32], &[]);
        scan.observe([[1; 32]], BlobInventoryChange::Additions);
        assert_eq!(scan.progress.get(&[1; 32]).unwrap().offset, 32);
        finish(&mut scan, &snapshot);
        assert!(scan.patch().has_prefix(&[2; 32]));
    }

    #[test]
    fn a_deep_chain_does_not_revisit_already_scanned_ancestors() {
        let mut snapshot = Snapshot::default();
        for i in 1..20 {
            snapshot.put([i; 32], &[[i + 1; 32]]);
        }
        snapshot.put([20; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        assert_eq!(scan.patch().len(), 20);
        // One source read per node plus one positive lookup per edge.
        assert_eq!(snapshot.reads.get(), 39);
    }

    #[test]
    fn missing_and_empty_sources_still_obey_the_source_budget() {
        let mut snapshot = Snapshot::default();
        snapshot.put([1; 32], &[]);
        snapshot.put([2; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32], [2; 32], [3; 32]], BlobInventoryChange::Unchanged);
        let stats = scan.advance(
            &snapshot,
            ScanBudget {
                words: 8,
                sources: 2,
            },
        );
        assert_eq!(stats.sources, 2);
        assert_eq!(stats.words, 0);
        assert_eq!(snapshot.reads.get(), 2);
        assert!(scan.has_pending_work());
        finish(&mut scan, &snapshot);
        assert_eq!(keys(&scan), vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn misclassified_removal_cannot_keep_positive_descendants() {
        let mut snapshot = Snapshot::default();
        snapshot.put([1; 32], &[[2; 32]]);
        snapshot.put([2; 32], &[]);
        let mut scan = CollectionBlobInventory::default();
        scan.observe([[1; 32]], BlobInventoryChange::Unchanged);
        finish(&mut scan, &snapshot);
        snapshot.blobs.remove(&[1; 32]);
        scan.observe([[1; 32]], BlobInventoryChange::Additions);
        let stats = scan.advance(
            &snapshot,
            ScanBudget {
                words: 8,
                sources: 8,
            },
        );
        assert!(stats.invalidated);
        assert!(scan.patch().is_empty());
        finish(&mut scan, &snapshot);
        assert!(scan.patch().is_empty());
    }
}
