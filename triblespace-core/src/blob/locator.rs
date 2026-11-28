//! Opaque discovery names for bearer-addressed blobs.
//!
//! A content handle is also the capability to read its exact bytes. A locator
//! is only a one-way image of that handle: it can be disclosed for discovery
//! and reference summaries without disclosing the bearer capability itself.

use std::sync::{Arc, Mutex};

use crate::patch::{Entry, IdentitySchema, PATCH};
use crate::repo::{BlobStoreList, StoreChanges};

/// A local, snapshot-coherent association from opaque locator to resident handle.
///
/// Values are bearer capabilities and must not be published as a remote resolver.
/// This index describes storage presence, not collection admission or validated
/// payload bytes. A known but nonresident handle need not occur in it.
pub type BlobLocatorIndex = PATCH<32, IdentitySchema, [u8; 32]>;

/// Build an association for a backend without a native shared index.
pub(crate) fn index<R: BlobStoreList + ?Sized>(snapshot: &R) -> Result<BlobLocatorIndex, R::Err> {
    let mut index = BlobLocatorIndex::new();
    for info in snapshot.blobs() {
        let handle = info?.handle.raw;
        index.insert(&Entry::with_value(&blob_locator(handle), handle));
    }
    Ok(index)
}

fn update<R: BlobStoreList>(
    now: &R,
    previous: &R,
    index: &BlobLocatorIndex,
) -> Result<BlobLocatorIndex, R::Err> {
    let mut next = index.clone();
    // Remove before adding: list-only backends conservatively offer both whole
    // inventories. Native Pile/Yard differences skip shared PATCH subtrees.
    for info in previous.blobs_diff(now) {
        next.remove(&blob_locator(info?.handle.raw));
    }
    for info in now.blobs_diff(previous) {
        let handle = info?.handle.raw;
        next.replace(&Entry::with_value(&blob_locator(handle), handle));
    }
    Ok(next)
}

#[derive(Debug)]
enum LocatorState<R> {
    Cold,
    // At most one warm baseline, never a chain of deferred snapshot deltas.
    Delta(R, BlobLocatorIndex),
    Ready(BlobLocatorIndex),
}

/// Lazy association owned by one snapshot family. Failed enumeration leaves the
/// state unchanged. Clones and observations with unchanged blob inventories share
/// the same cell; a changed observation only forks a baseline, doing no scan.
#[derive(Debug)]
pub(crate) struct LocatorCache<R>(Mutex<LocatorState<R>>);

impl<R> Default for LocatorCache<R> {
    fn default() -> Self {
        Self(Mutex::new(LocatorState::Cold))
    }
}

impl<R: Clone> LocatorCache<R> {
    pub(crate) fn advance(self: &Arc<Self>, previous: &R, changes: StoreChanges) -> Arc<Self> {
        if !changes.contains(StoreChanges::BLOBS) {
            return self.clone();
        }
        // Snapshot capture may hold the writer's lock. Never wait here for a
        // reader's cold inventory or delta walk. A changed snapshot can start
        // cold instead; unchanged inventories already shared the cell above.
        let state = match self.0.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Arc::default(),
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("locator cache is poisoned"),
        };
        let next = match &*state {
            LocatorState::Cold => LocatorState::Cold,
            LocatorState::Delta(baseline, index) => {
                LocatorState::Delta(baseline.clone(), index.clone())
            }
            LocatorState::Ready(index) => LocatorState::Delta(previous.clone(), index.clone()),
        };
        Arc::new(Self(Mutex::new(next)))
    }
}

impl<R: BlobStoreList> LocatorCache<R> {
    pub(crate) fn get(&self, now: &R) -> Result<BlobLocatorIndex, R::Err> {
        let mut state = self.0.lock().expect("locator cache is not poisoned");
        let ready = match &*state {
            LocatorState::Ready(index) => return Ok(index.clone()),
            LocatorState::Cold => index(now)?,
            LocatorState::Delta(previous, index) => update(now, previous, index)?,
        };
        *state = LocatorState::Ready(ready.clone());
        Ok(ready)
    }
}

/// Random 32-byte context key that separates locators from every other
/// BLAKE3 input. Generated from the OS random source on 2026-09-24.
///
/// `LOCATOR_CONTEXT || H` is exactly one 64-byte BLAKE3 block, so a locator
/// costs one compression. The previous `derive_key` string context cost two:
/// one for the context string and one for the handle.
pub const LOCATOR_CONTEXT: [u8; 32] =
    hex_literal::hex!("224DFBA2A0DE0FEC0A2073D78B8DCFEE91A037BC7749639A0D5E83DF307BA93A");

/// Derive an opaque discovery locator without disclosing the bearer handle.
///
/// `L = BLAKE3(LOCATOR_CONTEXT || H)`. Possession of this locator does not
/// authorize an exact blob read.
pub fn blob_locator(handle: [u8; 32]) -> [u8; 32] {
    let mut block = [0; 64];
    block[..32].copy_from_slice(&LOCATOR_CONTEXT);
    block[32..].copy_from_slice(&handle);
    *blake3::hash(&block).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline::Inline;
    use crate::repo::BlobInfo;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct Inventory {
        handles: Vec<[u8; 32]>,
        counts: Arc<[AtomicUsize; 2]>,
        fail: bool,
    }

    impl BlobStoreList for Inventory {
        type Err = std::io::Error;
        type Iter<'a> = std::vec::IntoIter<Result<BlobInfo, Self::Err>>;
        fn blobs(&self) -> Self::Iter<'_> {
            self.counts[0].fetch_add(1, Ordering::Relaxed);
            if self.fail {
                return vec![Err(std::io::Error::other("inventory failed"))].into_iter();
            }
            self.handles
                .iter()
                .map(|raw| {
                    Ok(BlobInfo {
                        handle: Inline::new(*raw),
                        length: 1,
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
        }
        fn blobs_diff<'a>(&'a self, old: &Self) -> Self::Iter<'a> {
            self.counts[1].fetch_add(1, Ordering::Relaxed);
            self.handles
                .iter()
                .filter(|raw| !old.handles.contains(raw))
                .map(|raw| {
                    Ok(BlobInfo {
                        handle: Inline::new(*raw),
                        length: 1,
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
        }
    }

    #[test]
    fn locator_cache_is_lazy_shared_and_keeps_old_residency() {
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let old = Inventory {
            handles: vec![[1; 32], [2; 32]],
            counts: counts.clone(),
            fail: false,
        };
        let cache: Arc<LocatorCache<Inventory>> = Arc::default();
        let equal = cache.advance(&old, StoreChanges::COLLECTION_RECORDS);
        assert!(Arc::ptr_eq(&cache, &equal));
        assert_eq!(counts[0].load(Ordering::Relaxed), 0);
        let old_index = equal.get(&old).unwrap();
        assert!(old_index.shares_root(&cache.get(&old).unwrap()));
        assert_eq!(counts[0].load(Ordering::Relaxed), 1);
        let next = Inventory {
            handles: vec![[2; 32], [3; 32]],
            ..old.clone()
        };
        let next_cache = cache.advance(&old, StoreChanges::BLOBS);
        // Several unconsumed snapshots retain one warm baseline, not a chain.
        let last = Inventory {
            handles: vec![[3; 32], [4; 32]],
            ..old.clone()
        };
        let last_cache = next_cache.advance(&next, StoreChanges::BLOBS);
        assert_eq!(counts[1].load(Ordering::Relaxed), 0);
        let latest = last_cache.get(&last).unwrap();
        assert_eq!(counts[0].load(Ordering::Relaxed), 1);
        assert_eq!(counts[1].load(Ordering::Relaxed), 2);
        assert_eq!(latest.len(), 2);
        assert_eq!(latest.get(&blob_locator([4; 32])), Some(&[4; 32]));
        assert!(latest.get(&blob_locator([1; 32])).is_none());
        assert_eq!(
            cache.get(&old).unwrap().get(&blob_locator([1; 32])),
            Some(&[1; 32])
        );
        assert!(cache
            .get(&old)
            .unwrap()
            .get(&blob_locator([4; 32]))
            .is_none());
    }

    #[test]
    fn batch_lookup_records_hits_and_misses_without_tracking_the_whole_inventory() {
        let snapshot = Inventory {
            handles: vec![[1; 32], [2; 32]],
            counts: Arc::default(),
            fail: false,
        };
        let counts = snapshot.counts.clone();
        let observed = crate::repo::ObservedStore::new(snapshot);
        let wanted = [
            blob_locator([1; 32]),
            blob_locator([3; 32]),
            blob_locator([2; 32]),
        ];
        assert_eq!(
            observed.find_blobs(&wanted).unwrap(),
            vec![Some([1; 32]), None, Some([2; 32])]
        );
        assert_eq!(counts[0].load(Ordering::Relaxed), 1);
        let dependencies = observed.dependencies();
        assert_eq!(dependencies.locators.len(), 3);
        assert!(!dependencies.all_blobs);
        assert!(dependencies.blobs.is_empty());
        for locator in wanted {
            assert!(dependencies
                .locators
                .contains(&crate::collection::SourceLocator::from_raw(locator)));
        }
        assert!(observed.find_blobs(&[]).unwrap().is_empty());
        assert_eq!(counts[0].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn conservative_inventory_delta_removes_before_adding() {
        #[derive(Clone)]
        struct ListOnly(Inventory);
        impl BlobStoreList for ListOnly {
            type Err = std::io::Error;
            type Iter<'a> = std::vec::IntoIter<Result<BlobInfo, Self::Err>>;
            fn blobs(&self) -> Self::Iter<'_> {
                self.0.blobs()
            }
        }
        let before = ListOnly(Inventory {
            handles: vec![[1; 32], [2; 32]],
            counts: Arc::default(),
            fail: false,
        });
        let after = ListOnly(Inventory {
            handles: vec![[2; 32], [3; 32]],
            ..before.0.clone()
        });
        let cache: Arc<LocatorCache<ListOnly>> = Arc::default();
        let old = cache.get(&before).unwrap();
        let new = cache
            .advance(&before, StoreChanges::BLOBS)
            .get(&after)
            .unwrap();
        assert_eq!(new.len(), 2);
        assert!(new.get(&blob_locator([1; 32])).is_none());
        assert_eq!(new.get(&blob_locator([2; 32])), Some(&[2; 32]));
        assert_eq!(new.get(&blob_locator([3; 32])), Some(&[3; 32]));
        assert_eq!(old.get(&blob_locator([1; 32])), Some(&[1; 32]));
    }

    #[test]
    fn snapshot_advance_does_not_wait_for_a_locator_build() {
        let snapshot = Inventory {
            handles: vec![],
            counts: Arc::default(),
            fail: false,
        };
        let cache: Arc<LocatorCache<Inventory>> = Arc::default();
        let _held_build = cache.0.lock().unwrap();
        // The previous implementation's blocking lock would deadlock here.
        let changed = cache.advance(&snapshot, StoreChanges::BLOBS);
        assert!(!Arc::ptr_eq(&cache, &changed));
        assert!(changed.get(&snapshot).unwrap().is_empty());
        assert!(Arc::ptr_eq(
            &cache,
            &cache.advance(&snapshot, StoreChanges::NONE)
        ));
    }

    #[test]
    fn failed_locator_inventory_does_not_publish_an_empty_index() {
        let mut snapshot = Inventory {
            handles: vec![[7; 32]],
            counts: Arc::default(),
            fail: true,
        };
        let cache = LocatorCache::default();
        assert!(cache.get(&snapshot).is_err());
        snapshot.fail = false;
        assert_eq!(
            cache.get(&snapshot).unwrap().get(&blob_locator([7; 32])),
            Some(&[7; 32])
        );
    }

    #[test]
    fn locator_matches_its_known_answer() {
        // Computed independently with the reference blake3 crate as
        // blake3::hash(LOCATOR_CONTEXT || [1; 32]). The bytes are wire
        // format: every peer must derive the same DHT key.
        assert_eq!(
            blob_locator([1; 32]),
            hex_literal::hex!("501F0C513B16AB49D80B1C440F848C18A3DDE215F802026B8CEE5C71515CCC51")
        );
    }

    #[test]
    fn locator_is_not_the_handle() {
        for handle in [[0; 32], [1; 32], [255; 32]] {
            assert_ne!(blob_locator(handle), handle);
        }
    }
}
