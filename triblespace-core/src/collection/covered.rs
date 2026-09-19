//! The coverage index over any store, fed by the difference between
//! consecutive snapshots.
//!
//! Every store used to keep this index itself: a pile parked each record as
//! replay decoded it, noted each blob and proof as an arrival, and settled the
//! backlog at the end of a refresh; a memory repo did the same on insert, put
//! and proof, and settled when a snapshot was taken; a hybrid could do neither
//! and refolded on every read. The bookkeeping was the same in each place and
//! belonged to none of them. Here it is written once, over the one thing every
//! store can do: say what its snapshot holds that the previous one did not.
//!
//! No write is intercepted. Writes reach the inner store directly, and the
//! index catches up when a snapshot is taken -- the moment a reader could
//! first observe them. Order within one catch-up does not matter: a record
//! parked in this pass is decided against the snapshot it came from, where its
//! descriptor is already resident if it arrived in the same pass; the arrivals
//! list only wakes records an *earlier* pass parked.

use std::collections::BTreeSet;
use std::ops::{Deref, DerefMut};

use crate::blob::encodings::UnknownBlob;
use crate::blob::{BlobEncoding, IntoBlob, TryFromBlob};
use crate::capability::{CapabilityProof, CapabilityProofId};
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::repo::async_store::AsyncBlobStoreAcquire;
use crate::repo::{
    BlobChildren, BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreKeep, BlobStoreList,
    BlobStoreMeta, BlobStorePut, CapabilityProofRead, CapabilityProofStore, PinSnapshot,
    PinSnapshotSource, SnapshotSource, StorageClose, StorageFlush, StoreChanges, StoreDependencies, StoreSnapshot, WantRead,
    WantRequest, WantStore,
};

use super::coverage::{Coverage, CoverageIndex, StoreWriters};
use super::{
    CollectionHandle, CollectionRead, CollectionRecord,
    CollectionRecordSelector, CollectionStore, CoverageRead,
};

/// What a snapshot exposes so the index can be fed by difference.
pub trait RecordDelta {
    /// Offer every collection record `self` holds that `since` did not -- all
    /// of them for `None` -- in a deterministic order. Cheap where the record
    /// index is persistent: shared subtrees are skipped, so the walk is
    /// proportional to the delta rather than to the store.
    fn for_each_record_since(&self, since: Option<&Self>, each: &mut dyn FnMut(&CollectionRecord));
}

/// A store whose snapshots carry the coverage index, maintained here.
///
/// Every trait the inner store implements is forwarded unchanged, and its
/// inherent methods are reachable through `Deref`; only [`SnapshotSource`] is
/// this type's own, so that the index catches up exactly when a snapshot is
/// taken.
pub struct Covered<S: SnapshotSource> {
    inner: S,
    /// The last snapshot handed out and the memo it settles into, so the
    /// next snapshot starts from what readers have already decided and pays
    /// only for what arrived since, and only for lineages someone reads.
    last: Option<(S::Snapshot, std::sync::Arc<std::sync::Mutex<Memo>>)>,
}

/// What a snapshot has decided so far: the index, and the collections whose
/// records have all been offered to it -- for those, a later snapshot needs
/// only the records that arrived since; for the rest, the first reader that
/// asks selects them wholesale from the store's own by-collection index.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Memo {
    index: CoverageIndex,
    settled: BTreeSet<CollectionHandle>,
}

impl<S: SnapshotSource> Covered<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, last: None }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: SnapshotSource + Default> Default for Covered<S> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

impl<S> Clone for Covered<S>
where
    S: SnapshotSource + Clone,
    S::Snapshot: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            last: self.last.clone(),
        }
    }
}

impl<S: SnapshotSource + std::fmt::Debug> std::fmt::Debug for Covered<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Covered")
            .field("inner", &self.inner)
            .field("last", &self.last.is_some())
            .finish()
    }
}

impl<S: SnapshotSource> Deref for Covered<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.inner
    }
}

impl<S: SnapshotSource> DerefMut for Covered<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S> Covered<S>
where
    S: SnapshotSource,
    S::Snapshot: RecordDelta + BlobStoreList + BlobStoreGet + CapabilityProofRead + Clone,
{
    /// Feed the index everything `now` holds that the last fed snapshot did
    /// not, then decide what that could have changed.
    /// Start the next snapshot's memo from the last one and feed it only what
    /// arrived since -- and only for collections some reader already had
    /// decided. Nothing is decided here, and nothing is parked for a
    /// collection nobody has asked about: the first reader to ask selects its
    /// records from the store's own index. A first snapshot therefore costs
    /// exactly replay.
    fn carry_forward(&mut self, now: &S::Snapshot) -> std::sync::Arc<std::sync::Mutex<Memo>> {
        let Some((fed, last)) = &self.last else {
            return std::sync::Arc::default();
        };
        let mut memo = last.lock().expect("coverage memo is not poisoned").clone();
        // A blob matters only as the descriptor some parked record is waiting
        // on; when nothing waits, the blob walk is skipped entirely.
        if memo.index.parked_on_lineages() > 0 {
            for handle in now.blobs_diff(fed).flatten() {
                let descriptor: CollectionHandle = Inline::new(handle.handle.raw);
                if memo.index.blob_arrived(descriptor) {
                    memo.index.wake_descriptor(descriptor);
                }
            }
        }
        if !memo.settled.is_empty() {
            now.for_each_record_since(Some(fed), &mut |record| {
                if memo.settled.contains(&record.collection()) {
                    memo.index.park_record(record);
                }
            });
        }
        if now
            .changes_since(fed)
            .contains(StoreChanges::CAPABILITY_PROOFS)
        {
            memo.index.wake_proofs();
        }
        std::sync::Arc::new(std::sync::Mutex::new(memo))
    }
}

impl<S> SnapshotSource for Covered<S>
where
    S: SnapshotSource,
    S::Snapshot: RecordDelta + BlobStoreList + BlobStoreGet + CapabilityProofRead + Clone,
{
    type Snapshot = CoveredSnapshot<S::Snapshot>;
    type SnapshotError = S::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        let now = self.inner.snapshot()?;
        let memo = self.carry_forward(&now);
        self.last = Some((now.clone(), std::sync::Arc::clone(&memo)));
        Ok(CoveredSnapshot { inner: now, memo })
    }
}

impl<S: SnapshotSource + BlobStorePut> BlobStorePut for Covered<S> {
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

impl<S: SnapshotSource + BlobStoreKeep> BlobStoreKeep for Covered<S> {
    fn keep<I>(&mut self, handles: I)
    where
        I: IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
    {
        self.inner.keep(handles)
    }
}

impl<S: SnapshotSource + CollectionStore> CollectionStore for Covered<S> {
    type InsertError = S::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.inner.insert(record)
    }
}

impl<S: SnapshotSource + CapabilityProofStore> CapabilityProofStore for Covered<S> {
    type InsertError = S::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.inner.insert_proof(proof)
    }
}

impl<S: SnapshotSource + WantStore> WantStore for Covered<S> {
    type WantError = S::WantError;

    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
        self.inner.want(request)
    }
}

impl<S: SnapshotSource + StorageFlush> StorageFlush for Covered<S> {
    type Error = S::Error;

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}

impl<S: SnapshotSource + AsyncBlobStoreAcquire> AsyncBlobStoreAcquire for Covered<S> {
    type AcquireError = S::AcquireError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl std::future::Future<Output = Result<Option<anybytes::Bytes>, Self::AcquireError>> + Send
    {
        self.inner.acquire(handle)
    }
}

impl<S: SnapshotSource + PinSnapshotSource> PinSnapshotSource for Covered<S> {
    type PinSnapshotError = S::PinSnapshotError;

    fn snapshot_pin_heads(&mut self) -> Result<PinSnapshot, Self::PinSnapshotError> {
        self.inner.snapshot_pin_heads()
    }
}

impl<S: SnapshotSource + StorageClose> StorageClose for Covered<S> {
    type Error = S::Error;

    fn close(self) -> Result<(), Self::Error> {
        self.inner.close()
    }
}

impl<S: SnapshotSource + StorageClose> Covered<S> {
    /// Close the inner store. Inherent as well as via [`StorageClose`]: a
    /// by-value `close` reached through `Deref` would try to move the inner
    /// store out of the wrapper, and the trait method is only found when the
    /// trait is in scope.
    pub fn close(self) -> Result<(), S::Error> {
        self.inner.close()
    }
}

/// One immutable observation of a [`Covered`] store: the inner snapshot and
/// the coverage index for exactly that prefix, decided one lineage at a time
/// as readers ask. The index is a persistent root behind a lock shared by
/// every clone of this snapshot, so a lineage settled through one clone is
/// settled for all of them, and handing it out is a constant-time clone.
#[derive(Clone)]
pub struct CoveredSnapshot<T> {
    inner: T,
    memo: std::sync::Arc<std::sync::Mutex<Memo>>,
}

impl<T: std::fmt::Debug> std::fmt::Debug for CoveredSnapshot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoveredSnapshot")
            .field("inner", &self.inner)
            .field("memo", &*self.memo.lock().expect("coverage memo is not poisoned"))
            .finish()
    }
}

impl<T: PartialEq> PartialEq for CoveredSnapshot<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.inner != other.inner {
            return false;
        }
        // Clones share the memo; locking it twice would wait on ourselves.
        if std::sync::Arc::ptr_eq(&self.memo, &other.memo) {
            return true;
        }
        *self.memo.lock().expect("coverage memo is not poisoned")
            == *other.memo.lock().expect("coverage memo is not poisoned")
    }
}

impl<T: Eq> Eq for CoveredSnapshot<T> {}

impl<T> CoveredSnapshot<T> {
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T: CollectionRead + BlobStoreGet + CapabilityProofRead> CoveredSnapshot<T> {
    /// Offer every record of `collections` this memo has not seen to the
    /// index, selected from the store's own by-collection index, then decide
    /// everything fresh for them. Records of a collection already settled
    /// were parked by [`Covered`] as they arrived, so only those are new.
    fn settle_lineage(
        &self,
        memo: &mut Memo,
        collections: &BTreeSet<CollectionHandle>,
    ) -> Result<(), T::RecordsError> {
        let unseen: BTreeSet<_> = collections
            .iter()
            .filter(|collection| !memo.settled.contains(*collection))
            .map(|collection| CollectionRecordSelector::Collection(*collection))
            .collect();
        if !unseen.is_empty() {
            for record in self.inner.select_records(&unseen)? {
                memo.index.park_record(&record);
            }
            memo.settled.extend(collections.iter().copied());
        }
        memo.index
            .settle_collections(&StoreWriters::new(&self.inner), collections);
        Ok(())
    }

    /// The whole index for this prefix, every collection decided -- the eager
    /// form, for inspection and for readers that really do want everything.
    /// [`CoverageRead::index`] is the lazy one. (Named apart from it: an
    /// inherent `index()` would shadow the trait method at every concrete
    /// call site.)
    pub fn coverage_index(&self) -> CoverageIndex {
        let mut memo = self.memo.lock().expect("coverage memo is not poisoned");
        let mut all = BTreeSet::new();
        if let Ok(records) = self.inner.records() {
            for record in records.flatten() {
                if !memo.settled.contains(&record.collection()) {
                    memo.index.park_record(&record);
                }
                all.insert(record.collection());
            }
        }
        memo.settled.extend(all.iter().copied());
        memo.index
            .settle(&StoreWriters::new(&self.inner), std::iter::empty(), false);
        memo.index.clone()
    }

    /// The published half of the whole index: which foundation commits each
    /// lattice node stands for, every lineage decided for exactly this prefix.
    pub fn coverage(&self) -> Coverage {
        self.coverage_index().published().clone()
    }
}

impl<T> Deref for CoveredSnapshot<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for CoveredSnapshot<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: CollectionRead + BlobStoreGet + CapabilityProofRead> CoverageRead for CoveredSnapshot<T> {
    /// Decide this lineage's records if nobody has yet, against this prefix,
    /// and hand out the index as it stands: a persistent-root clone whose
    /// rows for the lineage are complete and whose other lineages may still
    /// be parked, which a reader asking for its own lineage never sees.
    fn index(&self, lineage: &BTreeSet<CollectionHandle>) -> Result<CoverageIndex, Self::RecordsError> {
        let mut memo = self.memo.lock().expect("coverage memo is not poisoned");
        self.settle_lineage(&mut memo, lineage)?;
        Ok(memo.index.clone())
    }
}

impl<T: RecordDelta> RecordDelta for CoveredSnapshot<T> {
    fn for_each_record_since(&self, since: Option<&Self>, each: &mut dyn FnMut(&CollectionRecord)) {
        self.inner
            .for_each_record_since(since.map(|since| &since.inner), each)
    }
}

impl<T: StoreSnapshot> StoreSnapshot for CoveredSnapshot<T> {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }

    fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
        self.inner.changes_for(&previous.inner, dependencies)
    }
}

impl<T: BlobStoreGet> BlobStoreGet for CoveredSnapshot<T> {
    type GetError<E: std::error::Error + Send + Sync + 'static> = T::GetError<E>;

    fn get<V, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<V, Self::GetError<<V as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        V: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.inner.get(handle)
    }
}

impl<T: BlobStoreList> BlobStoreList for CoveredSnapshot<T> {
    type Iter<'a>
        = T::Iter<'a>
    where
        Self: 'a;
    type Err = T::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.inner.blobs()
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.contains_blob(handle)
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.blob_info(handle)
    }

    fn blobs_diff<'a>(&'a self, old: &Self) -> Self::Iter<'a> {
        self.inner.blobs_diff(&old.inner)
    }
}

impl<T: BlobStoreMeta> BlobStoreMeta for CoveredSnapshot<T> {
    type MetaError = T::MetaError;

    fn metadata<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.inner.metadata(handle)
    }
}

impl<T: BlobChildren> BlobChildren for CoveredSnapshot<T> {
    fn children(&self, handle: Inline<Handle<UnknownBlob>>) -> Vec<Inline<Handle<UnknownBlob>>> {
        self.inner.children(handle)
    }
}

impl<T: CollectionRead> CollectionRead for CoveredSnapshot<T> {
    type RecordsError = T::RecordsError;
    type RecordIter<'a>
        = T::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.inner.records()
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.inner.select_records(selectors)
    }
}

impl<T: CapabilityProofRead> CapabilityProofRead for CoveredSnapshot<T> {
    type ProofsError = T::ProofsError;
    type ProofIter<'a>
        = T::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.inner.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.inner.proof(id)
    }
}

impl<T: WantRead> WantRead for CoveredSnapshot<T> {
    type WantsError = T::WantsError;
    type WantIter<'a>
        = T::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.inner.wants()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::encodings::utf8string::UTF8String;
    use crate::blob::Blob;
    use crate::capability::CapabilityResource;
    use crate::prelude::entity;
    use crate::collection::{
        write_capability, AdmissionPolicy, Collection, CollectionPolicy, CollectionStoreExt,
    };
    use crate::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};

    fn policy(root: &SigningKey) -> CollectionPolicy {
        CollectionPolicy::new(
            AdmissionPolicy::direct(root.verifying_key()),
            AdmissionPolicy::direct(root.verifying_key()),
        )
    }

    /// The wrapper's index and the level below's, over the same snapshot,
    /// both in the eager form so every lineage is decided.
    fn agree(snapshot: &CoveredSnapshot<MemoryRepoSnapshot>, step: &str) -> CoverageIndex {
        let ours = snapshot.coverage_index();
        let theirs = snapshot.inner().coverage_index();
        assert_eq!(ours, theirs, "after {step}");
        ours
    }

    /// Asking for one lineage decides that lineage and leaves the other
    /// parked; asking for the other afterwards decides it too, on the same
    /// snapshot, without touching the first again.
    #[test]
    fn a_reader_pays_for_the_lineage_it_asks_for_and_no_other() {
        let root = SigningKey::from_bytes(&[73; 32]);
        let mut store = Covered::new(MemoryRepo::default());
        let first: Collection<SimpleArchive> = store.collection("first", policy(&root)).unwrap();
        let second: Collection<SimpleArchive> = store.collection("second", policy(&root)).unwrap();
        for (collection, text) in [(first, "one"), (second, "two")] {
            let child = store.put::<UTF8String, _>(text.to_owned()).unwrap();
            store
                .commit(collection, &root, entity! { crate::metadata::name: child })
                .unwrap();
        }
        let snapshot = store.snapshot().unwrap();

        let only_first = snapshot.index(&BTreeSet::from([first.handle()])).unwrap();
        assert_eq!(only_first.published().len(), 1);
        assert_eq!(only_first.parked(), 0, "the other lineage was never even offered");

        let both = snapshot.index(&BTreeSet::from([second.handle()])).unwrap();
        assert_eq!(both.published().len(), 2);
        assert_eq!(both.parked(), 0);
        assert_eq!(snapshot.coverage_index(), both, "the eager form has nothing left to decide");

        // A later snapshot starts from what this one decided and pays only
        // for what arrived since, for the collections already settled.
        let child = store.put::<UTF8String, _>("three".to_owned()).unwrap();
        store
            .commit(first, &root, entity! { crate::metadata::name: child })
            .unwrap();
        let later = store.snapshot().unwrap();
        let carried = later.index(&BTreeSet::from([first.handle()])).unwrap();
        assert_eq!(carried.published().len(), 3);
    }

    /// Drive one store through every arrival the index reacts to -- a
    /// descriptor, admitted and not-yet-admitted commits, a proof, a record
    /// ahead of its descriptor, the descriptor itself, and nothing at all --
    /// and require the index fed by snapshot difference to equal the one the
    /// store feeds itself as writes happen.
    #[test]
    fn the_index_fed_by_difference_equals_the_one_fed_by_writes() {
        let root = SigningKey::from_bytes(&[71; 32]);
        let writer = SigningKey::from_bytes(&[72; 32]);
        let mut store = Covered::new(MemoryRepo::default());

        let empty = agree(&store.snapshot().unwrap(), "nothing");
        assert!(empty.is_empty());

        let collection: Collection<SimpleArchive> =
            store.collection("equivalence", policy(&root)).unwrap();
        let child = store.put::<UTF8String, _>("child".to_owned()).unwrap();
        store
            .commit(collection, &root, entity! { crate::metadata::name: child })
            .unwrap();
        let admitted = agree(&store.snapshot().unwrap(), "an admitted commit");
        assert_eq!(admitted.published().len(), 1);

        let other = store.put::<UTF8String, _>("other".to_owned()).unwrap();
        store
            .commit(collection, &writer, entity! { crate::metadata::name: other })
            .unwrap();
        let parked = agree(&store.snapshot().unwrap(), "a commit by an unadmitted writer");
        assert_eq!(parked.parked_on_signers(), 1);
        assert_eq!(parked.published().len(), 1);

        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(collection.handle()),
                &root,
                write_capability(),
                writer.verifying_key(),
            ))
            .unwrap();
        let proven = agree(&store.snapshot().unwrap(), "the proof that admits the writer");
        assert_eq!(proven.parked_on_signers(), 0);
        assert_eq!(proven.published().len(), 2);

        // A record for a collection whose descriptor this store has not seen.
        let mut elsewhere = MemoryRepo::default();
        let later: Collection<SimpleArchive> = elsewhere.collection("later", policy(&root)).unwrap();
        let payload = elsewhere.put::<UTF8String, _>("later".to_owned()).unwrap();
        let ahead = elsewhere
            .commit(later, &root, entity! { crate::metadata::name: payload })
            .unwrap();
        let descriptor: Blob<UnknownBlob> = elsewhere
            .snapshot()
            .unwrap()
            .get(later.handle().transmute())
            .unwrap();
        store.insert(CollectionRecord::Commit(ahead)).unwrap();
        // Nothing is known about who may write a collection whose descriptor
        // is absent, so the commit waits on that descriptor -- an ordinary
        // blob, whose arrival is what re-offers it.
        let waiting = agree(&store.snapshot().unwrap(), "a record ahead of its descriptor");
        assert_eq!(waiting.parked_on_lineages(), 1);
        assert_eq!(waiting.parked_on_signers(), 0);
        assert_eq!(waiting.published().len(), 2);

        store.put::<UnknownBlob, _>(descriptor).unwrap();
        let landed = agree(&store.snapshot().unwrap(), "the descriptor it was waiting on");
        assert_eq!(landed.parked(), 0);
        assert_eq!(landed.published().len(), 3);

        let quiet = agree(&store.snapshot().unwrap(), "no change at all");
        assert_eq!(quiet, landed);
    }
}
