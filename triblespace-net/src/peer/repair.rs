//! A store whose snapshots repair a corrupt copy where the held sets read it.
//!
//! A pile's index answers presence without reading bytes, so a blob can be
//! resident and still fail validation when it is read. [`PeerSnapshot`]'s
//! reader already treats such a copy like an absent one: it fetches the
//! verified bytes and lands them beside it. The held-set scan reads through
//! the store's own snapshots instead, which only validate, so a corrupt blob
//! and everything above it stay out of the held set until the store is
//! reopened. [`Repairing`] gives that read the same rule, without a change to
//! the scan: wrap the store as `Covered<Repairing<S>>` and its snapshots, which
//! the held sets read, repair.
//!
//! The rule, for one read: bytes that fail validation (the blob is resident
//! and its every copy is corrupt) are fetched, verified on the wire against
//! the handle, landed beside the corrupt copy, and read back from the store.
//! A blob that is not resident is never fetched: absence stays absence.
//!
//! Only a peer's held-set thread repairs ([`Peer::set_replication`] installs
//! the repair there). Every other thread reads exactly as the inner store
//! does, because the held sets are also read *inside* taking a snapshot -- the
//! publication barrier and a building collection's first allowance -- with the
//! store mutex held, on the owner's thread or the landing task. Landing a
//! repair there would take that mutex again and block an async runtime on the
//! network. The held-set thread holds neither the store mutex nor the held
//! index while it reads, and nothing waits for it.
//!
//! Each thread tries each handle at most once: a blob no neighbour holds costs
//! one fetch, not one per closure that reaches it.
//!
//! # Known gap: what a snapshot reads first is not repaired
//!
//! Only blobs the held-set thread reads are repaired, and that thread reads
//! only a building collection's first closure, past what a snapshot read of it
//! inline. Two reads run inside a snapshot instead, on a thread that may not
//! repair:
//!
//! - the inline allowance: the snapshot that settles collections reads their
//!   first closures itself, up to 256 scans or 16 MiB shared by all of them
//!   (`INLINE_SCANS`/`INLINE_BYTES` in the core's `held.rs`);
//! - the publication barrier: every extension of a built collection -- a new
//!   record's closure, an arrived pending seed, a peer's report -- runs inline
//!   in a snapshot, for the life of the store.
//!
//! A corrupt blob first read there is marked unknown in its job, and that job
//! does not read it again. It and every ancestor stay out of that
//! collection's held set until a reset or a reopen, even if a later job of
//! another collection repairs the bytes on the held-set thread. Closing this
//! needs a change in the core's held index (hand such a job to the driver
//! rather than marking the blob unknown); it is not made here.
//!
//! [`PeerSnapshot`]: super::PeerSnapshot
//! [`Peer::set_replication`]: super::Peer::set_replication

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ops::{Deref, DerefMut};

use anybytes::Bytes;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::{Blob, BlobEncoding, IntoBlob, TryFromBlob};
use triblespace_core::capability::{CapabilityProof, CapabilityProofId};
use triblespace_core::collection::covered::RecordDelta;
use triblespace_core::collection::{
    CollectionHandle, CollectionRead, CollectionRecord, CollectionRecordSelector,
    CollectionRecordView, CollectionStore, RecordViewChanges,
};
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{Inline, InlineEncoding};
use triblespace_core::patch::{Entry, IdentitySchema, PATCH};
use triblespace_core::repo::{
    BlobChildren, BlobInfo, BlobMetadata, BlobStoreGet, BlobStoreKeep, BlobStoreList,
    BlobStoreMeta, BlobStorePut, CapabilityProofRead, CapabilityProofStore, PinSnapshot,
    PinSnapshotSource, SnapshotSource, StorageClose, StorageFlush, StoreChanges, StoreDependencies,
    StoreSnapshot, WantRead, WantRequest, WantStore,
};

use crate::protocol::RawHash;

/// Fetch a verified copy of a blob, land it, and return its bytes as the
/// store now holds them; `None` when that did not happen.
type Fetch = Box<dyn FnMut(RawHash) -> Option<Bytes>>;

/// The repair one thread may make, and the handles it has tried.
pub(super) struct Repair {
    fetch: Fetch,
    tried: PATCH<32, IdentitySchema, ()>,
}

thread_local! {
    /// Set only on a peer's held-set thread, for the thread's life. Taken
    /// out while a repair runs, so nothing the repair calls repairs again.
    static REPAIR: RefCell<Option<Repair>> = const { RefCell::new(None) };
}

impl Repair {
    /// Let this thread repair through `fetch` from now on.
    pub(super) fn install(fetch: impl FnMut(RawHash) -> Option<Bytes> + 'static) {
        REPAIR.with(|repair| {
            *repair.borrow_mut() = Some(Repair {
                fetch: Box::new(fetch),
                tried: PATCH::new(),
            })
        });
    }
}

/// Whether this thread may repair a read now.
fn may_repair() -> bool {
    REPAIR.with(|repair| repair.borrow().is_some())
}

/// Repair `handle`, unless this thread may not or already tried it.
fn repair(handle: RawHash) -> Option<Bytes> {
    let mut repair = REPAIR.with(|repair| repair.borrow_mut().take())?;
    let bytes = if repair.tried.get(&handle).is_some() {
        None
    } else {
        repair.tried.insert(&Entry::new(&handle));
        (repair.fetch)(handle)
    };
    REPAIR.with(|slot| *slot.borrow_mut() = Some(repair));
    bytes
}

/// A store whose snapshots repair corrupt blobs on a peer's held-set thread
/// (see the [module documentation](self)). Every store operation is the
/// inner store's; so is every snapshot read but a blob read that fails
/// validation there.
#[derive(Debug, Default)]
pub struct Repairing<S>(S);

impl<S> Repairing<S> {
    pub fn new(inner: S) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S> Deref for Repairing<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.0
    }
}

impl<S> DerefMut for Repairing<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.0
    }
}

/// One observation of a [`Repairing`] store: the inner store's.
#[derive(Clone, Debug)]
pub struct RepairingSnapshot<T>(T);

impl<T> RepairingSnapshot<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for RepairingSnapshot<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<S: SnapshotSource> SnapshotSource for Repairing<S> {
    type Snapshot = RepairingSnapshot<S::Snapshot>;
    type SnapshotError = S::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        self.0.snapshot().map(RepairingSnapshot)
    }
}

impl<S: BlobStorePut> BlobStorePut for Repairing<S> {
    type PutError = S::PutError;

    fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
    where
        E: BlobEncoding + 'static,
        T: IntoBlob<E>,
        Handle<E>: InlineEncoding,
    {
        self.0.put(item)
    }
}

impl<S: BlobStoreKeep> BlobStoreKeep for Repairing<S> {
    fn keep<I>(&mut self, handles: I)
    where
        I: IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
    {
        self.0.keep(handles)
    }
}

impl<S: CollectionStore> CollectionStore for Repairing<S> {
    type InsertError = S::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.0.insert(record)
    }
}

impl<S: CapabilityProofStore> CapabilityProofStore for Repairing<S> {
    type InsertError = S::InsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.0.insert_proof(proof)
    }
}

impl<S: WantStore> WantStore for Repairing<S> {
    type WantError = S::WantError;

    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
        self.0.want(request)
    }
}

impl<S: StorageFlush> StorageFlush for Repairing<S> {
    type Error = S::Error;

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush()
    }
}

impl<S: StorageClose> StorageClose for Repairing<S> {
    type Error = S::Error;

    fn close(self) -> Result<(), Self::Error> {
        self.0.close()
    }
}

impl<S: PinSnapshotSource> PinSnapshotSource for Repairing<S> {
    type PinSnapshotError = S::PinSnapshotError;

    fn snapshot_pin_heads(&mut self) -> Result<PinSnapshot, Self::PinSnapshotError> {
        self.0.snapshot_pin_heads()
    }
}

impl<T> RepairingSnapshot<T>
where
    T: BlobStoreList + BlobStoreMeta,
{
    /// Resident, and no copy validates: the rule `PeerSnapshot`'s reader
    /// applies. A blob that reads but fails to decode is not corrupt.
    fn corrupt(&self, handle: Inline<Handle<UnknownBlob>>) -> bool {
        self.0.contains_blob(handle).unwrap_or(false) && matches!(self.0.metadata(handle), Ok(None))
    }
}

impl<T> BlobStoreGet for RepairingSnapshot<T>
where
    T: BlobStoreGet + BlobStoreList + BlobStoreMeta,
{
    type GetError<E: std::error::Error + Send + Sync + 'static> = T::GetError<E>;

    /// The inner read. On the held-set thread, a blob whose every copy fails
    /// validation is repaired instead, and the repaired bytes are decoded.
    /// When repair is not possible, or the repaired bytes do not decode, the
    /// inner read's error stands.
    fn get<V, E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<V, Self::GetError<<V as TryFromBlob<E>>::Error>>
    where
        E: BlobEncoding + 'static,
        V: TryFromBlob<E>,
        Handle<E>: InlineEncoding,
    {
        let error = match self.0.get::<V, E>(handle) {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if !may_repair() || !self.corrupt(Inline::new(handle.raw)) {
            return Err(error);
        }
        let Some(bytes) = repair(handle.raw) else {
            return Err(error);
        };
        // Verified against `handle` on the wire and read back from the store.
        Blob::<E>::with_handle(bytes, handle)
            .try_from_blob()
            .map_err(|_| error)
    }
}

impl<T: StoreSnapshot> StoreSnapshot for RepairingSnapshot<T> {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.0.changes_since(&previous.0)
    }

    fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
        self.0.changes_for(&previous.0, dependencies)
    }
}

impl<T: RecordDelta> RecordDelta for RepairingSnapshot<T> {
    fn for_each_record_since(&self, since: Option<&Self>, each: &mut dyn FnMut(&CollectionRecord)) {
        self.0
            .for_each_record_since(since.map(|since| &since.0), each)
    }
}

impl<T: BlobStoreList> BlobStoreList for RepairingSnapshot<T> {
    type Iter<'a>
        = T::Iter<'a>
    where
        Self: 'a;
    type Err = T::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.0.blobs()
    }

    fn contains_blob<E>(&self, handle: Inline<Handle<E>>) -> Result<bool, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.0.contains_blob(handle)
    }

    fn blob_info<E>(&self, handle: Inline<Handle<E>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.0.blob_info(handle)
    }

    fn blobs_diff<'a>(&'a self, old: &Self) -> Self::Iter<'a> {
        self.0.blobs_diff(&old.0)
    }
}

impl<T: BlobStoreMeta> BlobStoreMeta for RepairingSnapshot<T> {
    type MetaError = T::MetaError;

    fn metadata<E>(
        &self,
        handle: Inline<Handle<E>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        E: BlobEncoding + 'static,
        Handle<E>: InlineEncoding,
    {
        self.0.metadata(handle)
    }

    fn resident(
        &self,
        handles: &PATCH<32, IdentitySchema, ()>,
    ) -> Result<PATCH<32, IdentitySchema, ()>, Self::MetaError> {
        self.0.resident(handles)
    }
}

/// The inner store's children: a walk outside the held sets never repairs.
impl<T> BlobChildren for RepairingSnapshot<T>
where
    T: BlobChildren + BlobStoreList + BlobStoreMeta,
{
    fn children(&self, handle: Inline<Handle<UnknownBlob>>) -> Vec<Inline<Handle<UnknownBlob>>> {
        self.0.children(handle)
    }
}

impl<T: CollectionRead> CollectionRead for RepairingSnapshot<T> {
    type RecordsError = T::RecordsError;
    type RecordIter<'a>
        = T::RecordIter<'a>
    where
        Self: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.0.records()
    }

    fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
        self.0.collections()
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        self.0.select_records(selectors)
    }

    fn select_record_views(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecordView>, Self::RecordsError> {
        self.0.select_record_views(selectors)
    }

    fn select_record_view_changes(
        &self,
        previous: &Self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<RecordViewChanges, Self::RecordsError> {
        self.0.select_record_view_changes(&previous.0, selectors)
    }

    fn select_record_changes(
        &self,
        previous: &Self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<(Vec<CollectionRecord>, Vec<CollectionRecord>), Self::RecordsError> {
        self.0.select_record_changes(&previous.0, selectors)
    }
}

impl<T: CapabilityProofRead> CapabilityProofRead for RepairingSnapshot<T> {
    type ProofsError = T::ProofsError;
    type ProofIter<'a>
        = T::ProofIter<'a>
    where
        Self: 'a;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        self.0.proofs()
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        self.0.proof(id)
    }
}

impl<T: WantRead> WantRead for RepairingSnapshot<T> {
    type WantsError = T::WantsError;
    type WantIter<'a>
        = T::WantIter<'a>
    where
        Self: 'a;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        self.0.wants()
    }
}

#[cfg(test)]
mod tests;
