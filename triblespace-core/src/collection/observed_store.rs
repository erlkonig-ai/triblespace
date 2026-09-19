//! A transparent reader or active store which records its raw lookup interests.
//!
//! Misses and errors are dependencies too: a later exact record or physical
//! blob occurrence can change their answers. The tracker retains no payloads,
//! decoded values, or admission results. Clones share it so reads performed
//! while interpreting an already attached view remain part of that observation.
//! Snapshots and acquisitions of an observed active store share the same tracker.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::blob::encodings::UnknownBlob;
use crate::blob::{BlobEncoding, IntoBlob, TryFromBlob};
use crate::capability::{CapabilityProof, CapabilityProofId};
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::repo::async_store::AsyncBlobStoreAcquire;
use crate::repo::{
    BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList, BlobStoreMeta, BlobStorePut,
    CapabilityProofRead, CapabilityProofStore, SnapshotSource, StoreChanges, StoreDependencies,
    StoreSnapshot, WantRead,
};

use super::coverage::Coverage;
use super::{
    CollectionRead, CollectionRecord, CollectionRecordFingerprint, CollectionRecordSelector,
    CollectionStore,
};

pub(crate) type DependencyTracker = Arc<Mutex<StoreDependencies>>;

/// Opt-in raw read-set observation without retaining interpreted results.
///
/// Reads, including misses and errors, accumulate across clones and snapshots.
/// Active writes forward unchanged; acquisitions record their exact handle
/// before forwarding. Drop the observer after an operation to bound this set,
/// and compare later snapshots with [`StoreSnapshot::changes_for`].
///
/// Provider availability and deadlines are not stored dependencies. A network
/// caller still owns its retry policy; this adapter performs no retries or WANT
/// publication of its own.
#[derive(Clone)]
pub struct ObservedStore<R> {
    inner: R,
    tracker: DependencyTracker,
}

impl<R> ObservedStore<R> {
    /// Start a fresh observation around a reader or an active store.
    pub fn new(inner: R) -> Self {
        Self::with_tracker(inner, Arc::new(Mutex::new(StoreDependencies::default())))
    }

    pub(crate) fn with_tracker(inner: R, tracker: DependencyTracker) -> Self {
        Self { inner, tracker }
    }

    pub(crate) fn inner(&self) -> &R {
        &self.inner
    }

    /// Copy the raw interests collected so far, including failed lookups.
    pub fn dependencies(&self) -> StoreDependencies {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .clone()
    }

    /// Recover the wrapped reader or store without changing it.
    pub fn into_inner(self) -> R {
        self.inner
    }

    pub(crate) fn tracker(&self) -> DependencyTracker {
        Arc::clone(&self.tracker)
    }

    fn observe_blob<S>(&self, handle: Inline<Handle<S>>)
    where
        S: BlobEncoding,
        Handle<S>: InlineEncoding,
    {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .blobs
            .insert(Handle::<S>::to_hash(handle));
    }
}

impl<S: SnapshotSource> SnapshotSource for ObservedStore<S> {
    type Snapshot = ObservedStore<S::Snapshot>;
    type SnapshotError = S::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        let snapshot = self.inner.snapshot()?;
        Ok(Self::Snapshot::with_tracker(snapshot, self.tracker()))
    }
}

impl<S: BlobStorePut> BlobStorePut for ObservedStore<S> {
    type PutError = S::PutError;

    fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
    where
        E: BlobEncoding + 'static,
        T: IntoBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.inner.put(item)
    }
}

impl<S: CollectionStore> CollectionStore for ObservedStore<S> {
    type InsertError = S::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.inner.insert(record)
    }
}

impl<S: CapabilityProofStore> CapabilityProofStore for ObservedStore<S> {
    type InsertError = S::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.inner.insert_proof(proof)
    }
}

impl<S: AsyncBlobStoreAcquire> AsyncBlobStoreAcquire for ObservedStore<S> {
    type AcquireError = S::AcquireError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl std::future::Future<Output = Result<Option<anybytes::Bytes>, Self::AcquireError>> + Send
    {
        self.observe_blob(handle);
        self.inner.acquire(handle)
    }
}

impl<R: StoreSnapshot> StoreSnapshot for ObservedStore<R> {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }

    fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
        self.inner.changes_for(&previous.inner, dependencies)
    }
}

impl<R: BlobStoreGet> BlobStoreGet for ObservedStore<R> {
    type GetError<E: std::error::Error + Send + Sync + 'static> = R::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.observe_blob(handle);
        self.inner.get(handle)
    }
}

impl<R: BlobStoreList> BlobStoreList for ObservedStore<R> {
    type Iter<'a>
        = R::Iter<'a>
    where
        Self: 'a;
    type Err = R::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .all_blobs = true;
        self.inner.blobs()
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.observe_blob(handle);
        self.inner.contains_blob(handle)
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.observe_blob(handle);
        self.inner.blob_info(handle)
    }

    fn blobs_diff<'a>(&'a self, old: &Self) -> Self::Iter<'a> {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .all_blobs = true;
        self.inner.blobs_diff(&old.inner)
    }
}

impl<R: BlobStoreMeta> BlobStoreMeta for ObservedStore<R> {
    type MetaError = R::MetaError;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.observe_blob(handle);
        self.inner.metadata(handle)
    }
}

impl<R: CollectionRead + BlobStoreGet + CapabilityProofRead> CollectionRead
    for ObservedStore<R>
{
    type RecordsError = R::RecordsError;
    type RecordIter<'a>
        = R::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .all_records = true;
        self.inner.records()
    }

    fn record(
        &self,
        fingerprint: CollectionRecordFingerprint,
    ) -> Result<Option<CollectionRecord>, Self::RecordsError> {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .records
            .insert(CollectionRecordSelector::Fingerprint(fingerprint));
        self.inner.record(fingerprint)
    }

    /// Hand out the inner store's coverage instead of refolding it.
    ///
    /// Without this override the trait default applies, and that default folds
    /// one full enumeration of [`Self::records`] -- ignoring the index a pile
    /// already maintains across appends and paying for it again per read.
    ///
    /// The dependency is still every record, and deliberately so. This hands
    /// the caller the whole index, so it may look up any row; the honest read
    /// set of "I took the coverage" is therefore everything that could change
    /// a row. Narrowing it to the rows actually consulted needs a row-wise
    /// coverage read, not a snapshot-wide one, and dropping it without that
    /// makes an observation miss the arrival that completes its own support
    /// (`observation::tests::pile_observation_tracks_only_consulted_ancestry_and_target_changes`
    /// catches exactly this). Not refolding and not depending are separable
    /// wins; only the first is taken here.
    fn coverage(&self) -> Result<Coverage, Self::RecordsError>
    where
        Self: Sized + BlobStoreGet + CapabilityProofRead,
    {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .all_records = true;
        self.inner.coverage()
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .records
            .extend(selectors.iter().copied());
        self.inner.select_records(selectors)
    }
}

impl<R: CapabilityProofRead> CapabilityProofRead for ObservedStore<R> {
    type ProofsError = R::ProofsError;
    type ProofIter<'a>
        = R::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .capability_proofs = true;
        self.inner.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.tracker
            .lock()
            .expect("store dependency tracker is not poisoned")
            .capability_proofs = true;
        self.inner.proof(id)
    }
}

// WANT is not an input to passive collection interpretation. Forward it
// without expanding the observation's blob, record, or authority interests.
impl<R: WantRead> WantRead for ObservedStore<R> {
    type WantsError = R::WantsError;
    type WantIter<'a>
        = R::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.inner.wants()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::encodings::UnknownBlob;
    use crate::blob::Blob;
    use crate::capability::CapabilityResource;
    use crate::collection::{
        empty_metadata_handle, read_capability, AdmissionPolicy, CollectionCommit,
        CollectionPolicy, CollectionStoreExt,
    };
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::{BlobStorePut, SnapshotSource};

    fn blob(text: &str) -> Blob<UnknownBlob> {
        Blob::new(Bytes::from_source(text.as_bytes().to_vec()))
    }

    #[test]
    fn missing_blob_reads_retain_every_exact_interest() {
        let mut store = MemoryRepo::default();
        let observed = ObservedStore::new(store.snapshot().unwrap());
        let handles = ["get", "contains", "info", "metadata"].map(|text| blob(text).get_handle());

        assert!(observed.get::<Blob<UnknownBlob>, _>(handles[0]).is_err());
        assert!(!observed.contains_blob(handles[1]).unwrap());
        assert!(observed.blob_info(handles[2]).unwrap().is_none());
        assert!(observed.metadata(handles[3]).unwrap().is_none());
        assert_eq!(
            observed.dependencies(),
            StoreDependencies {
                blobs: handles
                    .into_iter()
                    .map(Handle::<UnknownBlob>::to_hash)
                    .collect(),
                ..StoreDependencies::default()
            }
        );
    }

    #[test]
    fn clones_and_rebound_readers_share_interests_not_payloads() {
        let mut store = MemoryRepo::default();
        let resident = store.put(blob("resident")).unwrap();
        let absent = blob("absent").get_handle();
        let observed = ObservedStore::new(store.snapshot().unwrap());
        let cloned = observed.clone();
        let rebound = ObservedStore::with_tracker(observed.inner().clone(), observed.tracker());
        assert!(Arc::ptr_eq(&observed.tracker(), &cloned.tracker()));
        assert!(Arc::ptr_eq(&observed.tracker(), &rebound.tracker()));

        let bytes: Bytes = cloned.get(resident).unwrap();
        assert_eq!(bytes.as_ref(), b"resident");
        assert!(!rebound.contains_blob(absent).unwrap());
        let expected = StoreDependencies {
            blobs: [resident, absent]
                .into_iter()
                .map(Handle::<UnknownBlob>::to_hash)
                .collect(),
            ..StoreDependencies::default()
        };
        assert_eq!(observed.dependencies(), expected);
        assert_eq!(cloned.dependencies(), expected);
        assert_eq!(rebound.dependencies(), expected);
        assert!(ObservedStore::new(observed.inner().clone())
            .dependencies()
            .is_empty());
    }

    #[test]
    fn active_writes_forward_and_fresh_snapshots_share_only_read_interests() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "observed active store",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(key.verifying_key()),
                    AdmissionPolicy::direct(key.verifying_key()),
                ),
            )
            .unwrap();
        let mut observed = ObservedStore::new(&mut store);
        let before = observed.snapshot().unwrap();
        let handle = observed.put(blob("active member")).unwrap();
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            collection.handle(),
            Handle::<UnknownBlob>::to_hash(handle),
            empty_metadata_handle(),
        ));
        observed.insert(record).unwrap();
        let proof = CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &key,
            read_capability(),
            SigningKey::from_bytes(&[12; 32]).verifying_key(),
        );
        observed.insert_proof(proof.clone()).unwrap();
        let after = observed.snapshot().unwrap();
        assert!(observed.dependencies().is_empty(), "writes are not reads");
        assert!(!before.contains_blob(handle).unwrap());
        assert_eq!(
            after.get::<Bytes, _>(handle).unwrap().as_ref(),
            b"active member"
        );
        assert!(before.record(record.fingerprint()).unwrap().is_none());
        assert_eq!(after.record(record.fingerprint()).unwrap(), Some(record));
        assert!(before.proof(proof.id()).unwrap().is_none());
        assert_eq!(after.proof(proof.id()).unwrap(), Some(proof));
        let expected = StoreDependencies {
            blobs: BTreeSet::from([Handle::<UnknownBlob>::to_hash(handle)]),
            records: BTreeSet::from([CollectionRecordSelector::Fingerprint(record.fingerprint())]),
            capability_proofs: true,
            ..StoreDependencies::default()
        };
        assert_eq!(observed.dependencies(), expected);
        assert_eq!(before.dependencies(), expected);
        assert_eq!(after.dependencies(), expected);
        let native = after.into_inner();
        assert_eq!(native.record(record.fingerprint()).unwrap(), Some(record));
        assert_eq!(
            observed
                .into_inner()
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn acquisition_misses_errors_and_cancelled_futures_retain_exact_interest() {
        struct Acquirer {
            tracker: DependencyTracker,
            calls: Arc<AtomicUsize>,
            fail: bool,
        }

        impl AsyncBlobStoreAcquire for Acquirer {
            type AcquireError = std::io::Error;

            fn acquire(
                &mut self,
                handle: Inline<Handle<UnknownBlob>>,
            ) -> impl std::future::Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send
            {
                let interests = self
                    .tracker
                    .try_lock()
                    .expect("forward without holding lock");
                assert!(interests
                    .blobs
                    .contains(&Handle::<UnknownBlob>::to_hash(handle)));
                self.calls.fetch_add(1, Ordering::Relaxed);
                std::future::ready(if self.fail {
                    Err(std::io::Error::other("provider failed"))
                } else {
                    Ok(None)
                })
            }
        }

        for fail in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let tracker = Arc::new(Mutex::new(StoreDependencies::default()));
            let mut observed = ObservedStore::with_tracker(
                Acquirer {
                    tracker: Arc::clone(&tracker),
                    calls: Arc::clone(&calls),
                    fail,
                },
                tracker,
            );
            let handle = blob("absent acquisition").get_handle();
            let result = futures::executor::block_on(observed.acquire(handle));
            if fail {
                assert_eq!(result.unwrap_err().to_string(), "provider failed");
            } else {
                assert!(result.unwrap().is_none());
            }
            let cancelled_handle = blob("cancelled acquisition").get_handle();
            drop(observed.acquire(cancelled_handle));
            assert_eq!(
                calls.load(Ordering::Relaxed),
                2,
                "one forwarding call per request"
            );
            assert_eq!(
                observed.dependencies(),
                StoreDependencies {
                    blobs: [handle, cancelled_handle]
                        .into_iter()
                        .map(Handle::<UnknownBlob>::to_hash)
                        .collect(),
                    ..StoreDependencies::default()
                }
            );
        }
    }

    #[test]
    fn missing_record_and_selected_routes_do_not_become_whole_record_reads() {
        let mut store = MemoryRepo::default();
        let key = SigningKey::from_bytes(&[7; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(key.verifying_key()),
            AdmissionPolicy::direct(key.verifying_key()),
        );
        let collection = store.collection("observed missing record", policy).unwrap();
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            collection.handle(),
            Handle::<UnknownBlob>::to_hash(blob("unpublished member").get_handle()),
            empty_metadata_handle(),
        ));
        let observed = ObservedStore::new(store.snapshot().unwrap());
        let selectors = BTreeSet::from([CollectionRecordSelector::Collection(collection.handle())]);

        assert!(observed.record(record.fingerprint()).unwrap().is_none());
        assert!(observed.select_records(&selectors).unwrap().is_empty());
        assert!(observed
            .select_records(&BTreeSet::new())
            .unwrap()
            .is_empty());
        assert_eq!(
            observed.dependencies(),
            StoreDependencies {
                records: BTreeSet::from([
                    CollectionRecordSelector::Collection(collection.handle()),
                    CollectionRecordSelector::Fingerprint(record.fingerprint()),
                ]),
                ..StoreDependencies::default()
            }
        );

        let proof = CapabilityProof::new(
            CapabilityResource::from(collection.handle()),
            &key,
            read_capability(),
            SigningKey::from_bytes(&[8; 32]).verifying_key(),
        );
        assert!(observed.proof(proof.id()).unwrap().is_none());
        assert!(observed.dependencies().capability_proofs);
        assert!(!observed.dependencies().all_records);
    }

    #[test]
    fn enumerations_mark_whole_components_but_wants_do_not() {
        let mut store = MemoryRepo::default();
        let before = store.snapshot().unwrap();
        let handle = store.put(blob("new member")).unwrap();
        let after = store.snapshot().unwrap();

        let listed = ObservedStore::new(after.clone());
        assert_eq!(listed.blobs().count(), 1);
        assert_eq!(
            listed.dependencies(),
            StoreDependencies {
                all_blobs: true,
                ..StoreDependencies::default()
            }
        );

        let delta = ObservedStore::new(after.clone());
        let old = ObservedStore::new(before);
        let new: Vec<_> = delta.blobs_diff(&old).map(Result::unwrap).collect();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].handle, handle);
        assert!(delta.dependencies().all_blobs);
        assert!(old.dependencies().is_empty());

        let records = ObservedStore::new(after.clone());
        assert_eq!(records.records().unwrap().count(), 0);
        assert_eq!(
            records.dependencies(),
            StoreDependencies {
                all_records: true,
                ..StoreDependencies::default()
            }
        );

        let proofs = ObservedStore::new(after.clone());
        assert_eq!(proofs.proofs().unwrap().count(), 0);
        assert_eq!(
            proofs.dependencies(),
            StoreDependencies {
                capability_proofs: true,
                ..StoreDependencies::default()
            }
        );

        let wants = ObservedStore::new(after);
        assert_eq!(wants.wants().unwrap().count(), 0);
        assert!(wants.dependencies().is_empty());
    }

    #[test]
    fn dependency_lock_is_released_before_backend_calls() {
        struct InspectLock(DependencyTracker);

        impl BlobStoreMeta for InspectLock {
            type MetaError = Infallible;

            fn metadata<S>(
                &self,
                _handle: Inline<Handle<S>>,
            ) -> Result<Option<BlobMetadata>, Self::MetaError>
            where
                S: BlobEncoding + 'static,
                Handle<S>: InlineEncoding,
            {
                assert!(
                    self.0.try_lock().is_ok(),
                    "read must not retain the tracker lock"
                );
                Ok(None)
            }
        }

        let tracker = Arc::new(Mutex::new(StoreDependencies::default()));
        let observed = ObservedStore::with_tracker(InspectLock(Arc::clone(&tracker)), tracker);
        let handle = blob("missing metadata").get_handle();
        assert!(observed.metadata(handle).unwrap().is_none());
        assert!(observed
            .dependencies()
            .blobs
            .contains(&Handle::<UnknownBlob>::to_hash(handle)));
    }

    #[test]
    fn snapshot_comparisons_delegate_without_recording_reads() {
        #[derive(Clone)]
        struct ScopedSnapshot(Arc<AtomicUsize>);

        impl StoreSnapshot for ScopedSnapshot {
            fn changes_since(&self, _previous: &Self) -> StoreChanges {
                StoreChanges::ALL
            }

            fn changes_for(
                &self,
                _previous: &Self,
                dependencies: &StoreDependencies,
            ) -> StoreChanges {
                assert!(dependencies.all_records);
                self.0.fetch_add(1, Ordering::Relaxed);
                StoreChanges::NONE
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let before = ObservedStore::new(ScopedSnapshot(Arc::clone(&calls)));
        let after = before.clone();
        let dependencies = StoreDependencies {
            all_records: true,
            ..StoreDependencies::default()
        };
        assert_eq!(after.changes_since(&before), StoreChanges::ALL);
        assert_eq!(
            after.changes_for(&before, &dependencies),
            StoreChanges::NONE
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(after.dependencies().is_empty());
    }
}
