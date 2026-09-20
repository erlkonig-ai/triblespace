//! Frozen semantic observation with live, exact-handle blob reads.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::ops::Deref;
use std::sync::{Arc, Mutex, Weak};

use triblespace_core::patch::{IdentitySchema, PATCH};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{BlobEncoding, TryFromBlob};
use triblespace_core::capability::{CapabilityProof, CapabilityProofId};
use triblespace_core::collection::{CollectionRead, CollectionRecord, CollectionRecordSelector};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{Inline, InlineEncoding};
use triblespace_core::repo::async_store::AsyncBlobStoreGet;
use triblespace_core::repo::{
    BlobChildren, BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreList, BlobStoreMeta, BlobStorePut,
    CapabilityProofRead, MissingBlob, SnapshotSource, StoreChanges, StoreDependencies,
    StoreSnapshot, WantRead,
};

use super::{PeerAcquireError, SharedHost};
use crate::host::INTERACTIVE_FETCH_DEADLINE;

/// A peer's frozen records, proofs, and residency index.
///
/// Explicit [`get`](Self::get) reads may fetch and cache exact immutable bytes
/// without a mutable borrow of the peer. Such reads do not replace this
/// observation or publish WANTs. Synchronous [`BlobStoreGet`] remains a passive
/// read of the captured resident prefix, as used by collection observation.
/// Closing the peer closes live acquisition; already captured bytes remain
/// readable for the lifetime of this snapshot.
pub struct PeerSnapshot<S: SnapshotSource> {
    pub(super) frozen: S::Snapshot,
    pub(super) store: Arc<Mutex<Option<S>>>,
    pub(super) host: Weak<Mutex<SharedHost>>,
}

impl<S: SnapshotSource> Clone for PeerSnapshot<S> {
    fn clone(&self) -> Self {
        Self {
            frozen: self.frozen.clone(),
            store: self.store.clone(),
            host: self.host.clone(),
        }
    }
}

impl<S: SnapshotSource> fmt::Debug for PeerSnapshot<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerSnapshot").finish_non_exhaustive()
    }
}

impl<S: SnapshotSource> Deref for PeerSnapshot<S> {
    type Target = S::Snapshot;

    fn deref(&self) -> &Self::Target {
        &self.frozen
    }
}

/// Failure to acquire or decode an exact blob through a peer snapshot.
#[derive(Debug)]
pub enum PeerGetError<E> {
    /// The live backend or endpoint could not satisfy the read.
    Acquire(PeerAcquireError),
    /// No provider supplied the requested content.
    Missing(MissingBlob),
    /// Resident bytes failed validation or decoding.
    Read(E),
}

impl<E: fmt::Display> fmt::Display for PeerGetError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquire(error) => error.fmt(f),
            Self::Missing(_) => f.write_str("no provider supplied the requested blob"),
            Self::Read(error) => error.fmt(f),
        }
    }
}

impl<E: Error + 'static> Error for PeerGetError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::Acquire(error) => error,
            Self::Missing(error) => error,
            Self::Read(error) => error,
        })
    }
}

impl<S> PeerSnapshot<S>
where
    S: SnapshotSource + BlobStorePut + Send,
    S::Snapshot: BlobStoreGet + BlobStoreList,
{
    /// Read the exact immutable content named by `handle`, fetching it if
    /// necessary. The snapshot's semantic observation remains unchanged.
    pub fn get<T, E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> impl Future<Output = Result<T, <Self as AsyncBlobStoreGet>::GetError<T::Error>>> + Send
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        AsyncBlobStoreGet::get(self, handle)
    }

    // Only the blob read below consumes this reader. Never expose its later
    // records as part of `self`: the original semantic observation is frozen.
    pub(super) async fn acquire_reader(
        &self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> Result<Option<S::Snapshot>, PeerAcquireError> {
        let contains = |reader: &S::Snapshot| {
            reader
                .contains_blob(handle)
                .map_err(|error| PeerAcquireError(format!("cannot check blob residency: {error}")))
        };
        if contains(&self.frozen)? {
            return Ok(Some(self.frozen.clone()));
        }
        {
            let mut guard = self.store.lock().expect("store mutex");
            let store = guard
                .as_mut()
                .ok_or_else(|| PeerAcquireError("peer is closed".into()))?;
            let reader = store
                .snapshot()
                .map_err(|error| PeerAcquireError(format!("cannot observe blob cache: {error}")))?;
            if contains(&reader)? {
                return Ok(Some(reader));
            }
        }
        let sender = {
            let host = self
                .host
                .upgrade()
                .ok_or_else(|| PeerAcquireError("peer is closed".into()))?;
            let mut host = host.lock().expect("host mutex");
            host.start()
                .map_err(|error| PeerAcquireError(error.to_string()))?;
            host.sender.clone()
        };
        // No store/host lock is held across network I/O. Writers and other
        // snapshot readers remain free to make progress (or close the peer).
        let Some(verified) = sender
            .fetch_blob(handle.raw, INTERACTIVE_FETCH_DEADLINE)
            .await
        else {
            return Ok(None);
        };
        let mut guard = self.store.lock().expect("store mutex");
        let store = guard
            .as_mut()
            .ok_or_else(|| PeerAcquireError("peer closed during blob acquisition".into()))?;
        // The wire handshake verified these bytes against `handle`; they land
        // under it without a second hash.
        store
            .put::<UnknownBlob, _>(verified)
            .map_err(|error| PeerAcquireError(format!("cannot cache acquired blob: {error}")))?;
        store
            .snapshot()
            .map(Some)
            .map_err(|error| PeerAcquireError(format!("cannot observe acquired blob: {error}")))
    }
}

impl<S> AsyncBlobStoreGet for PeerSnapshot<S>
where
    S: SnapshotSource + BlobStorePut + Send,
    S::Snapshot: BlobStoreGet + BlobStoreList,
{
    type GetError<E: Error + Send + Sync + 'static> =
        PeerGetError<<S::Snapshot as BlobStoreGet>::GetError<E>>;

    fn get<T, E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> impl Future<Output = Result<T, Self::GetError<T::Error>>> + Send
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        let raw = handle.raw;
        async move {
            let reader = self
                .acquire_reader(Inline::new(raw))
                .await
                .map_err(PeerGetError::Acquire)?
                .ok_or_else(|| {
                    PeerGetError::Missing(MissingBlob {
                        handle: Inline::new(raw),
                    })
                })?;
            reader.get(Inline::new(raw)).map_err(PeerGetError::Read)
        }
    }
}

impl<S: SnapshotSource + Send + 'static> StoreSnapshot for PeerSnapshot<S> {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.frozen.changes_since(&previous.frozen)
    }

    fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
        self.frozen.changes_for(&previous.frozen, dependencies)
    }
}

impl<S: SnapshotSource> BlobStoreGet for PeerSnapshot<S>
where
    S::Snapshot: BlobStoreGet,
{
    type GetError<E: Error + Send + Sync + 'static> = <S::Snapshot as BlobStoreGet>::GetError<E>;

    fn get<T, E>(&self, handle: Inline<Handle<E>>) -> Result<T, Self::GetError<T::Error>>
    where
        E: BlobEncoding + 'static,
        T: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.frozen.get(handle)
    }
}

impl<S: SnapshotSource> BlobStoreList for PeerSnapshot<S>
where
    S::Snapshot: BlobStoreList,
{
    type Err = <S::Snapshot as BlobStoreList>::Err;
    type Iter<'a>
        = <S::Snapshot as BlobStoreList>::Iter<'a>
    where
        Self: 'a;

    fn blobs(&self) -> Self::Iter<'_> {
        self.frozen.blobs()
    }

    fn contains_blob<E>(&self, handle: Inline<Handle<E>>) -> Result<bool, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.frozen.contains_blob(handle)
    }

    fn blob_info<E>(&self, handle: Inline<Handle<E>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.frozen.blob_info(handle)
    }

    fn blobs_diff<'a>(&'a self, previous: &Self) -> Self::Iter<'a> {
        self.frozen.blobs_diff(&previous.frozen)
    }
}

impl<S: SnapshotSource> BlobStoreMeta for PeerSnapshot<S>
where
    S::Snapshot: BlobStoreMeta,
{
    type MetaError = <S::Snapshot as BlobStoreMeta>::MetaError;

    fn metadata<E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.frozen.metadata(handle)
    }

    fn resident(
        &self,
        handles: &PATCH<32, IdentitySchema, ()>,
    ) -> Result<PATCH<32, IdentitySchema, ()>, Self::MetaError> {
        self.frozen.resident(handles)
    }
}

/// The frozen inner snapshot's index. Until this delegate existed the trait
/// default applied here, and every `maintain` a faculty ran through a peer
/// snapshot refolded the whole record set with an admission query per record
/// the store did not admit -- in production, on every pass, unmeasured.
impl<S: SnapshotSource> triblespace_core::collection::CoverageRead for PeerSnapshot<S>
where
    S::Snapshot: triblespace_core::collection::CoverageRead,
{
    fn index(
        &self,
        lineage: &std::collections::BTreeSet<triblespace_core::collection::CollectionHandle>,
    ) -> Result<triblespace_core::collection::coverage::CoverageIndex, Self::RecordsError> {
        self.frozen.index(lineage)
    }
}

impl<S: SnapshotSource> CollectionRead for PeerSnapshot<S>
where
    S::Snapshot: CollectionRead,
{
    type RecordsError = <S::Snapshot as CollectionRead>::RecordsError;
    type RecordIter<'a>
        = <S::Snapshot as CollectionRead>::RecordIter<'a>
    where
        Self: 'a;

    fn records(&self) -> Result<Self::RecordIter<'_>, Self::RecordsError> {
        self.frozen.records()
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.frozen.select_records(selectors)
    }
}

impl<S: SnapshotSource> CapabilityProofRead for PeerSnapshot<S>
where
    S::Snapshot: CapabilityProofRead,
{
    type ProofsError = <S::Snapshot as CapabilityProofRead>::ProofsError;
    type ProofIter<'a>
        = <S::Snapshot as CapabilityProofRead>::ProofIter<'a>
    where
        Self: 'a;

    fn proofs(&self) -> Result<Self::ProofIter<'_>, Self::ProofsError> {
        self.frozen.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.frozen.proof(id)
    }
}

impl<S: SnapshotSource> WantRead for PeerSnapshot<S>
where
    S::Snapshot: WantRead,
{
    type WantsError = <S::Snapshot as WantRead>::WantsError;
    type WantIter<'a>
        = <S::Snapshot as WantRead>::WantIter<'a>
    where
        Self: 'a;

    fn wants(&self) -> Result<Self::WantIter<'_>, Self::WantsError> {
        self.frozen.wants()
    }
}

impl<S: SnapshotSource> BlobChildren for PeerSnapshot<S>
where
    S::Snapshot: BlobChildren,
{
    fn children(&self, handle: Inline<Handle<UnknownBlob>>) -> Vec<Inline<Handle<UnknownBlob>>> {
        self.frozen.children(handle)
    }
}

#[cfg(test)]
mod tests {
    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;
    use triblespace_core::blob::Blob;
    use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
    use triblespace_core::repo::pile::Pile;
    use triblespace_core::trible::Fragment;

    use super::*;

    #[test]
    fn pile_scoped_changes_survive_peer_snapshot_wrapping() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let mut pile = Pile::open(path.path()).unwrap();
        let signer = SigningKey::from_bytes(&[19; 32]);
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let target = pile.collection("observed target", policy.clone()).unwrap();
        let other = pile.collection("unrelated target", policy).unwrap();
        let missing = Blob::<UnknownBlob>::new(Bytes::from_source(b"arrives later".to_vec()));
        let missing_handle = missing.get_handle();
        let dependencies = StoreDependencies {
            records: BTreeSet::from([CollectionRecordSelector::Collection(target.handle())]),
            blobs: BTreeSet::from([Handle::<UnknownBlob>::to_hash(missing_handle)]),
            ..StoreDependencies::default()
        };
        // No peer host or live store is installed: these snapshots can only
        // observe their captured local pile prefixes, never start networking.
        let freeze = |pile: &mut Pile| PeerSnapshot::<Pile> {
            frozen: pile.snapshot().unwrap(),
            store: Arc::new(Mutex::new(None)),
            host: Weak::new(),
        };
        let before = freeze(&mut pile);
        assert!(!before.contains_blob(missing_handle).unwrap());
        assert!(
            before
                .select_records(&dependencies.records)
                .unwrap()
                .is_empty()
        );

        pile.put::<UnknownBlob, _>(Bytes::from_source(b"unrelated blob".to_vec()))
            .unwrap();
        pile.commit(other, &signer, Fragment::empty()).unwrap();
        let unrelated = freeze(&mut pile);
        assert!(
            unrelated
                .changes_since(&before)
                .contains(StoreChanges::BLOBS)
        );
        assert!(
            unrelated
                .changes_since(&before)
                .contains(StoreChanges::COLLECTION_RECORDS)
        );
        assert_eq!(
            unrelated.changes_for(&before, &dependencies),
            StoreChanges::NONE,
            "unrelated physical appends must not broaden the scoped observation",
        );

        pile.put::<UnknownBlob, _>(missing).unwrap();
        let arrived = freeze(&mut pile);
        assert!(arrived.contains_blob(missing_handle).unwrap());
        assert_eq!(
            arrived.changes_for(&unrelated, &dependencies),
            StoreChanges::BLOBS,
            "an exact earlier miss is still a dependency",
        );

        pile.commit(target, &signer, Fragment::empty()).unwrap();
        let published = freeze(&mut pile);
        assert_eq!(
            published
                .select_records(&dependencies.records)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            published.changes_for(&arrived, &dependencies),
            StoreChanges::COLLECTION_RECORDS,
            "the selected collection's first record activates the observation",
        );
        assert_eq!(
            published.changes_for(&before, &dependencies),
            StoreChanges::BLOBS.union(StoreChanges::COLLECTION_RECORDS),
        );
        assert!(!before.contains_blob(missing_handle).unwrap());
        assert!(
            before
                .select_records(&dependencies.records)
                .unwrap()
                .is_empty()
        );

        drop((before, unrelated, arrived, published));
        pile.close().unwrap();
    }
}
