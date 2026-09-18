//! Async store traits — the honest contract for *remote* backends.
//!
//! The sync [`crate::repo::BlobStore`] family is the right
//! contract for *local* backends: `MemoryBlobStore` and a
//! `Pile`-over-mmap are genuinely synchronous, and a sync `get` that
//! returns a `Result` is the truth. But genuinely *remote* backends —
//! `ObjectStore` (cloud object storage) and a networked `Peer` — are
//! async at their core. Hiding that I/O behind a private tokio runtime and
//! `block_on` on every call would prevent composition with existing async
//! callers. Remote reads instead expose futures, with blocking adaptation
//! reserved for a synchronous application's outer boundary.
//!
//! This module gives those backends an honest home: an async mirror of
//! the blob-store traits, written in the same explicit
//! `-> impl Future<…> + Send` (RPITIT) style as the network
//! [`Transport`](../../../triblespace_net/transport/trait.Transport.html)
//! trait, so the returned futures carry a `Send` bound.
//!
//! [`AsyncBlobStoreAcquire`] is also the uniform live-store capability used by
//! collection construction. Local stores answer it immediately from a frozen
//! resident snapshot; a networked store may fetch and cache the exact handle.
//! The caller therefore awaits one honest API without choosing between a
//! resident-only and a remote variant.
//!
//! Two adapters bridge the worlds:
//! - [`SyncAsAsync`](crate::repo::async_store::SyncAsAsync) lifts any sync store into the async traits via
//!   zero-await futures — so an async consumer can read a local store
//!   for free, with no runtime and no blocking (the futures resolve on
//!   first poll).
//! - [`Blocking`](crate::repo::async_store::Blocking) lowers an async store
//!   behind one `block_on` boundary, so remote backends do not carry private
//!   runtimes or scatter blocking calls through their implementations.

use std::error::Error;
use std::fmt::Debug;
use std::future::Future;

use anybytes::Bytes;

use crate::blob::encodings::UnknownBlob;
use crate::blob::{BlobEncoding, IntoBlob, TryFromBlob};
use crate::collection::{CollectionRead, CollectionRecord, CollectionStore};
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::repo::{
    BlobInfo, BlobMetadata, BlobStoreForget, BlobStoreGet, BlobStoreList, BlobStoreMeta,
    BlobStorePut, SnapshotSource, StoreChanges, StoreSnapshot,
};
// Only used by the `object-store`-gated `Blocking` impls below.
#[cfg(feature = "object-store")]
use crate::repo::{BlobChildren, StorageClose};

/// Async counterpart of [`BlobStoreGet`].
///
/// `get` returns a `Send` future so it can be driven on a multi-thread
/// runtime. The output `T` need not be `Send` — it is produced at
/// completion, not held across an await — so this mirrors the sync
/// signature's bounds exactly. Content-addressed bytes are independent of the
/// snapshot's frozen record and authorization observation. A reader may fetch
/// and cache the exact immutable bytes named by `handle`, including bytes which
/// were not resident when the snapshot was taken. This must not advance the
/// snapshot's records or a previously selected cover,
/// and must not implicitly record durable WANTs.
pub trait AsyncBlobStoreGet {
    /// Error type for get operations, parameterised by the
    /// deserialization error (mirrors the sync GAT).
    type GetError<E: Error + Send + Sync + 'static>: Error + Send + Sync + 'static;

    /// Retrieve a blob by handle, awaiting whatever I/O the backend
    /// needs (a cloud GET, a swarm fetch).
    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> impl Future<Output = Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>> + Send
    where
        // Bounds mirror the sync `BlobStoreGet::get` exactly — notably
        // NO `S: Send`. The phantom-typed handle is `!Send` when the
        // schema is, so impls must extract the raw 32 bytes before any
        // await rather than capturing the typed handle (see
        // `SyncAsAsync`). This keeps the trait a drop-in mirror, which a
        // sync `Blocking` adapter relies on (its sync `get` can't add an
        // `S: Send` bound the sync trait doesn't have).
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding;
}

/// Live exact-handle acquisition into a mutable store.
///
/// Like snapshot [`AsyncBlobStoreGet`], this operation may fetch and cache
/// immutable content-addressed bytes. It must validate fetched bytes through
/// the store's checked insertion path and must not implicitly record a WANT.
/// `Ok(None)` means that no provider supplied the named bytes.
pub trait AsyncBlobStoreAcquire {
    /// Failure while probing, fetching, validating, caching, or refreshing.
    type AcquireError: Error + Send + Sync + 'static;

    /// Ensure the exact blob is locally resident and return its bytes.
    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send;
}

impl<S> AsyncBlobStoreAcquire for &mut S
where
    S: AsyncBlobStoreAcquire + ?Sized,
{
    type AcquireError = S::AcquireError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send {
        (**self).acquire(handle)
    }
}

/// Failure while satisfying live acquisition from a synchronous local store.
#[derive(Debug)]
pub struct ResidentBlobAcquireError {
    operation: &'static str,
    source: Box<dyn Error + Send + Sync>,
}

impl ResidentBlobAcquireError {
    fn new(operation: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            operation,
            source: Box::new(source),
        }
    }
}

impl std::fmt::Display for ResidentBlobAcquireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "failed to {operation} while acquiring a resident blob: {source}",
            operation = self.operation,
            source = self.source
        )
    }
}

impl Error for ResidentBlobAcquireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn acquire_resident<S>(
    store: &mut S,
    handle: Inline<Handle<UnknownBlob>>,
) -> Result<Option<Bytes>, ResidentBlobAcquireError>
where
    S: SnapshotSource,
    S::Snapshot: BlobStoreGet + BlobStoreList,
{
    let snapshot = store
        .snapshot()
        .map_err(|error| ResidentBlobAcquireError::new("freeze a local snapshot", error))?;
    if !snapshot
        .contains_blob(handle)
        .map_err(|error| ResidentBlobAcquireError::new("inspect local residency", error))?
    {
        return Ok(None);
    }
    snapshot
        .get::<Bytes, UnknownBlob>(handle)
        .map(Some)
        .map_err(|error| ResidentBlobAcquireError::new("read validated local bytes", error))
}

macro_rules! impl_resident_blob_acquire {
    ($store:ty) => {
        impl AsyncBlobStoreAcquire for $store {
            type AcquireError = ResidentBlobAcquireError;

            fn acquire(
                &mut self,
                handle: Inline<Handle<UnknownBlob>>,
            ) -> impl Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send {
                std::future::ready(acquire_resident(self, handle))
            }
        }
    };
}

impl_resident_blob_acquire!(crate::repo::memoryrepo::MemoryRepo);
impl_resident_blob_acquire!(crate::repo::pile::Pile);
impl_resident_blob_acquire!(crate::repo::yard::Yard);

impl<B, R> AsyncBlobStoreAcquire for crate::repo::hybridstore::HybridStore<B, R>
where
    B: AsyncBlobStoreAcquire,
{
    type AcquireError = B::AcquireError;

    fn acquire(
        &mut self,
        handle: Inline<Handle<UnknownBlob>>,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::AcquireError>> + Send {
        self.blobs.acquire(handle)
    }
}

/// Async counterpart of [`BlobStorePut`].
///
/// Bounds mirror the sync `put` exactly (no `T: Send`). Impls must
/// serialise `item` to bytes *before* the first await and carry only
/// those `Send` bytes across it — never the phantom-typed value — so
/// the future is `Send` without constraining `T`. That keeps the trait
/// a drop-in mirror the sync `Blocking` adapter can lower through.
pub trait AsyncBlobStorePut {
    /// Error type for put operations.
    type PutError: Error + Send + Sync + 'static;

    /// Serialise `item`, store it (awaiting the backend write), and
    /// return its handle.
    fn put<S, T>(
        &mut self,
        item: T,
    ) -> impl Future<Output = Result<Inline<Handle<S>>, Self::PutError>> + Send
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding;
}

/// Async counterpart of [`BlobStoreList`].
///
/// Returns the listing eagerly as a `Vec` rather than a `Stream` — that
/// keeps the trait dependency-free (only `std::future`) and is fine for
/// blob enumeration, which is metadata-sized. A streaming variant can
/// be added later if a backend's listing is genuinely unbounded.
pub trait AsyncBlobStoreList {
    /// Error type for listing operations.
    type Err: Error + Debug + Send + Sync + 'static;

    /// List lightweight information for every blob in the store.
    fn blobs(&self) -> impl Future<Output = Vec<Result<BlobInfo, Self::Err>>> + Send;
}

/// Async counterpart of [`SnapshotSource`].
///
/// The snapshot value uses the same [`StoreSnapshot`] change contract as a
/// synchronous backend; only freezing it may require asynchronous I/O. Its
/// semantic records, listings, and retrievable blob membership are immutable.
pub trait AsyncSnapshotSource {
    /// Immutable observation returned by this store.
    type Snapshot: StoreSnapshot;
    /// Failure while refreshing and freezing an observation.
    type SnapshotError: Error + Debug + Send + Sync + 'static;

    /// Reobserve external changes and freeze the resulting known prefix.
    fn snapshot(
        &mut self,
    ) -> impl Future<Output = Result<Self::Snapshot, Self::SnapshotError>> + Send;
}

/// Async combined blob storage whose reads come from one shared snapshot.
pub trait AsyncBlobStore:
    AsyncBlobStorePut + AsyncSnapshotSource<Snapshot: AsyncBlobStoreGet + AsyncBlobStoreList>
{
}

impl<S> AsyncBlobStore for S
where
    S: AsyncBlobStorePut + AsyncSnapshotSource,
    S::Snapshot: AsyncBlobStoreGet + AsyncBlobStoreList,
{
}

/// Async immutable read surface for one frozen collection-record observation.
pub trait AsyncCollectionRead {
    /// Failure while enumerating stored records.
    type RecordsError: Error + Debug + Send + Sync + 'static;

    /// Return every record in deterministic fingerprint order.
    fn records(
        &self,
    ) -> impl Future<Output = Result<Vec<CollectionRecord>, Self::RecordsError>> + Send;
}

/// Async counterpart of the insert-only [`CollectionStore`].
///
/// Read access belongs to the immutable snapshot returned by
/// [`AsyncSnapshotSource`].
pub trait AsyncCollectionStore {
    /// Failure while admitting one canonical record.
    type InsertError: Error + Debug + Send + Sync + 'static;

    /// Insert one immutable canonical record.
    ///
    /// Re-inserting the same intrinsic record is an idempotent success.
    fn insert(
        &mut self,
        record: CollectionRecord,
    ) -> impl Future<Output = Result<(), Self::InsertError>> + Send;
}

/// Async counterpart of [`BlobStoreMeta`].
pub trait AsyncBlobStoreMeta {
    /// Error type for metadata calls.
    type MetaError: Error + Send + Sync + 'static;

    /// Metadata for the blob `handle`, or `None` if absent.
    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> impl Future<Output = Result<Option<BlobMetadata>, Self::MetaError>> + Send
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding;
}

/// Async counterpart of [`BlobStoreForget`].
pub trait AsyncBlobStoreForget {
    /// Error type for forget operations.
    type ForgetError: Error + Send + Sync + 'static;

    /// Drop the materialised blob `handle` (monotonic, idempotent).
    fn forget<S>(
        &mut self,
        handle: Inline<Handle<S>>,
    ) -> impl Future<Output = Result<(), Self::ForgetError>> + Send
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding;
}

/// Lift a synchronous store into the async traits via zero-await
/// futures.
///
/// Local backends (`MemoryBlobStore`, `Pile`) are genuinely
/// synchronous; this wrapper lets an async consumer read them without
/// each backend reimplementing the async surface and without spinning
/// up a runtime. The futures contain no `.await`, so they resolve on
/// the first poll — there is no blocking, no executor required, just
/// the sync call wrapped in a future shell. It is the async-side
/// identity for things that were never really async.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncAsAsync<S>(pub S);

impl<S> SyncAsAsync<S> {
    /// Wrap a sync store.
    pub fn new(store: S) -> Self {
        Self(store)
    }

    /// Unwrap back to the sync store.
    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S> StoreSnapshot for SyncAsAsync<S>
where
    S: StoreSnapshot,
{
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.0.changes_since(&previous.0)
    }
}

impl<S> AsyncBlobStoreGet for SyncAsAsync<S>
where
    S: BlobStoreGet + Sync,
{
    type GetError<E: Error + Send + Sync + 'static> = S::GetError<E>;

    fn get<T, Sch>(
        &self,
        handle: Inline<Handle<Sch>>,
    ) -> impl Future<Output = Result<T, Self::GetError<<T as TryFromBlob<Sch>>::Error>>> + Send
    where
        Sch: BlobEncoding + 'static,
        T: TryFromBlob<Sch>,
        Handle<Sch>: InlineEncoding,
    {
        // Extract the raw 32 bytes *before* the async block so the
        // future captures only `[u8; 32]` (Send) and `&self` (Send iff
        // S: Sync) — never the phantom-typed handle, which is `!Send`
        // when `Sch` is. The typed handle is rebuilt inside, used in the
        // same poll with no await in between, so it is never part of the
        // future's held state.
        let raw = handle.raw;
        async move { self.0.get::<T, Sch>(Inline::new(raw)) }
    }
}

impl<S> AsyncBlobStorePut for SyncAsAsync<S>
where
    S: BlobStorePut + Send,
{
    type PutError = S::PutError;

    fn put<Sch, T>(
        &mut self,
        item: T,
    ) -> impl Future<Output = Result<Inline<Handle<Sch>>, Self::PutError>> + Send
    where
        Sch: BlobEncoding + 'static,
        T: IntoBlob<Sch>,
        Handle<Sch>: InlineEncoding,
    {
        // Serialise synchronously and capture only the `Send` bytes +
        // raw handle — never the phantom-typed item/blob/handle — so the
        // future is Send without bounding `T` (mirrors the `get` trick).
        let blob: crate::blob::Blob<Sch> = item.to_blob();
        let raw = blob.get_handle().raw;
        let bytes = blob.bytes;
        async move {
            self.0
                .put::<Sch, crate::blob::Blob<Sch>>(crate::blob::Blob::new(bytes))
                .map(|_| Inline::new(raw))
        }
    }
}

impl<S> AsyncBlobStoreList for SyncAsAsync<S>
where
    S: BlobStoreList + Sync,
{
    type Err = S::Err;

    fn blobs(&self) -> impl Future<Output = Vec<Result<BlobInfo, Self::Err>>> + Send {
        // The borrowed iterator is created and drained inside the
        // future (no await), so only `&self` (Send iff S: Sync) is held.
        async move { self.0.blobs().collect() }
    }
}

impl<S> AsyncSnapshotSource for SyncAsAsync<S>
where
    S: SnapshotSource + Send,
{
    type Snapshot = SyncAsAsync<S::Snapshot>;
    type SnapshotError = S::SnapshotError;

    fn snapshot(
        &mut self,
    ) -> impl Future<Output = Result<Self::Snapshot, Self::SnapshotError>> + Send {
        async move { self.0.snapshot().map(SyncAsAsync) }
    }
}

impl<S> AsyncCollectionRead for SyncAsAsync<S>
where
    S: CollectionRead + Sync,
{
    type RecordsError = S::RecordsError;

    fn records(
        &self,
    ) -> impl Future<Output = Result<Vec<CollectionRecord>, Self::RecordsError>> + Send {
        async move { self.0.records()?.collect() }
    }
}

impl<S> AsyncCollectionStore for SyncAsAsync<S>
where
    S: CollectionStore + Send,
{
    type InsertError = S::InsertError;

    fn insert(
        &mut self,
        record: CollectionRecord,
    ) -> impl Future<Output = Result<(), Self::InsertError>> + Send {
        async move { self.0.insert(record) }
    }
}

impl<S> AsyncBlobStoreMeta for SyncAsAsync<S>
where
    S: BlobStoreMeta + Sync,
{
    type MetaError = S::MetaError;

    fn metadata<Sch>(
        &self,
        handle: Inline<Handle<Sch>>,
    ) -> impl Future<Output = Result<Option<BlobMetadata>, Self::MetaError>> + Send
    where
        Sch: BlobEncoding + 'static,
        Handle<Sch>: InlineEncoding,
    {
        let raw = handle.raw;
        async move { self.0.metadata::<Sch>(Inline::new(raw)) }
    }
}

impl<S> AsyncBlobStoreForget for SyncAsAsync<S>
where
    S: BlobStoreForget + Send,
{
    type ForgetError = S::ForgetError;

    fn forget<Sch>(
        &mut self,
        handle: Inline<Handle<Sch>>,
    ) -> impl Future<Output = Result<(), Self::ForgetError>> + Send
    where
        Sch: BlobEncoding + 'static,
        Handle<Sch>: InlineEncoding,
    {
        let raw = handle.raw;
        async move { self.0.forget::<Sch>(Inline::new(raw)) }
    }
}

/// Drive an async store from synchronous code through a single
/// `block_on` boundary.
///
/// The inverse of [`SyncAsAsync`]: where that lifts a sync store into
/// async with zero-await futures, `Blocking` lowers an async store into
/// the sync traits by owning a tokio runtime and `block_on`-ing each
/// call. It exists so the scattered `block_on`s that backends like
/// `ObjectStore` carry internally collapse into *one* place — and so
/// genuinely-sync call sites (a CLI `main`) can still use an async
/// backend.
///
/// Caveat inherited from `block_on`: calling a `Blocking` method from
/// *within* an existing tokio runtime panics. It is an edge adapter for
/// sync boundaries, not something to thread through async code — async
/// code should depend on the async traits directly.
#[cfg(feature = "object-store")]
pub struct Blocking<A> {
    inner: A,
    rt: std::sync::Arc<tokio::runtime::Runtime>,
}

#[cfg(feature = "object-store")]
impl<A: Clone> Clone for Blocking<A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            rt: self.rt.clone(),
        }
    }
}

#[cfg(feature = "object-store")]
impl<A: std::fmt::Debug> std::fmt::Debug for Blocking<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The runtime is a driver, not state — show only the inner store.
        f.debug_struct("Blocking")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(feature = "object-store")]
impl<A> StoreSnapshot for Blocking<A>
where
    A: StoreSnapshot,
{
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        self.inner.changes_since(&previous.inner)
    }
}

#[cfg(feature = "object-store")]
impl<A> Blocking<A> {
    /// Wrap an async store, owning a fresh current-thread runtime to
    /// drive it. Current-thread (with all drivers enabled) is enough
    /// for sequential `block_on` and far lighter than a multi-thread
    /// runtime per store.
    pub fn new(inner: A) -> std::io::Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(Self {
            inner,
            rt: std::sync::Arc::new(rt),
        })
    }

    /// Wrap an async store, sharing a caller-provided runtime (e.g. a
    /// multi-thread one the cloud SDK wants for its connection pool).
    pub fn with_runtime(inner: A, rt: std::sync::Arc<tokio::runtime::Runtime>) -> Self {
        Self { inner, rt }
    }

    /// Unwrap back to the async store.
    pub fn into_inner(self) -> A {
        self.inner
    }
}

#[cfg(feature = "object-store")]
impl<A> SnapshotSource for Blocking<A>
where
    A: AsyncSnapshotSource,
{
    type Snapshot = Blocking<A::Snapshot>;
    type SnapshotError = A::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        let snapshot = self.rt.block_on(self.inner.snapshot())?;
        Ok(Blocking {
            inner: snapshot,
            rt: self.rt.clone(),
        })
    }
}

#[cfg(feature = "object-store")]
impl<A: AsyncBlobStoreGet> BlobStoreGet for Blocking<A> {
    type GetError<E: Error + Send + Sync + 'static> = A::GetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.rt.block_on(self.inner.get::<T, S>(handle))
    }
}

#[cfg(feature = "object-store")]
impl<A: AsyncBlobStoreList> BlobStoreList for Blocking<A> {
    type Iter<'a>
        = std::vec::IntoIter<Result<BlobInfo, A::Err>>
    where
        A: 'a;
    type Err = A::Err;

    fn blobs<'a>(&'a self) -> Self::Iter<'a> {
        self.rt.block_on(self.inner.blobs()).into_iter()
    }
}

#[cfg(feature = "object-store")]
impl<A: AsyncBlobStorePut> BlobStorePut for Blocking<A> {
    type PutError = A::PutError;

    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.rt.block_on(self.inner.put::<S, T>(item))
    }
}

#[cfg(feature = "object-store")]
impl<A: AsyncCollectionRead> CollectionRead for Blocking<A> {
    type RecordsError = A::RecordsError;
    type RecordIter<'a>
        = std::vec::IntoIter<Result<CollectionRecord, A::RecordsError>>
    where
        A: 'a;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        self.rt
            .block_on(self.inner.records())
            .map(|records| records.into_iter().map(Ok).collect::<Vec<_>>().into_iter())
    }
}

#[cfg(feature = "object-store")]
impl<A: AsyncCollectionStore> CollectionStore for Blocking<A> {
    type InsertError = A::InsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.rt.block_on(self.inner.insert(record))
    }
}

#[cfg(feature = "object-store")]
impl<A: AsyncBlobStoreMeta> BlobStoreMeta for Blocking<A> {
    type MetaError = A::MetaError;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.rt.block_on(self.inner.metadata::<S>(handle))
    }
}

#[cfg(feature = "object-store")]
impl<A: AsyncBlobStoreForget> BlobStoreForget for Blocking<A> {
    type ForgetError = A::ForgetError;

    fn forget<S>(&mut self, handle: Inline<Handle<S>>) -> Result<(), Self::ForgetError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.rt.block_on(self.inner.forget::<S>(handle))
    }
}

// The conservative reference scan rides the sync `BlobStoreGet` delegation,
// so a blocking snapshot gets `children` via the default scan-and-check.
#[cfg(feature = "object-store")]
impl<A: AsyncBlobStoreGet> BlobChildren for Blocking<A> {}

// Lifecycle teardown forwards to the inner store (and drops the
// runtime). `close` is not a storage op, so it stays synchronous.
#[cfg(feature = "object-store")]
impl<A: StorageClose> StorageClose for Blocking<A> {
    type Error = A::Error;

    fn close(self) -> Result<(), Self::Error> {
        self.inner.close()
    }
}

// `ObjectStoreRemote` completes every write before its future resolves, and
// the blocking adapter has no write buffer of its own. There is therefore no
// pending state for the synchronous publication protocol to flush between its
// dependency and record phases.
#[cfg(feature = "object-store")]
impl crate::repo::StorageFlush for Blocking<crate::repo::objectstore::ObjectStoreRemote> {
    type Error = std::convert::Infallible;

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.
    /// An equation names its input PAYLOAD; this used to pair it with a
    /// fingerprint citing a record that produced it.
    use super::*;
    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::Blob;
    use crate::blob::MemoryBlobStore;
    use crate::collection::descriptor::{identity_for_tests, named_for_tests};
    use crate::collection::{CollectionMerge, CollectionRecord, CollectionStore};
    use crate::id::{ExclusiveId, Id};
    use crate::macros::entity;
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::trible::TribleSet;
    use futures::executor::block_on;

    fn blob(tag: u8) -> Blob<SimpleArchive> {
        let e = Id::new([tag; 16]).unwrap();
        let ts: TribleSet = entity! {
            ExclusiveId::force_ref(&e) @
            crate::metadata::tag: Id::new([tag.wrapping_add(3).max(1); 16]).unwrap(),
        }
        .into();
        ts.to_blob()
    }

    fn collection_record(tag: u8) -> CollectionRecord {
        let descriptor = named_for_tests(
            &format!("tagged-{tag}"),
            Id::new([tag.wrapping_add(1).max(1); 16]).unwrap(),
        );
        CollectionRecord::Merge(CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            Inline::new([tag.wrapping_add(3); 32]),
            Inline::new([tag.wrapping_add(4); 32]),
            Inline::new([tag.wrapping_add(5); 32]),
        ))
    }

    #[test]
    fn async_adapter_preserves_snapshot_content_changes() {
        let mut inner = MemoryBlobStore::new();
        let mut store = SyncAsAsync::new(&mut inner);
        let before = block_on(store.snapshot()).unwrap();
        let unchanged = block_on(store.snapshot()).unwrap();
        assert_eq!(before.clone().changes_since(&before), StoreChanges::NONE);
        assert_eq!(unchanged.changes_since(&before), StoreChanges::NONE);

        let handle = block_on(store.put::<SimpleArchive, _>(blob(1))).unwrap();
        let after = block_on(store.snapshot()).unwrap();
        assert_eq!(after.changes_since(&before), StoreChanges::BLOBS);
        assert!(block_on(before.blobs()).is_empty());
        assert_eq!(
            block_on(after.blobs())[0].as_ref().unwrap().handle.raw,
            handle.raw
        );
    }

    #[test]
    fn sync_store_reads_and_writes_through_async_facade() {
        let mut store = SyncAsAsync::new(MemoryBlobStore::new());
        let b = blob(1);

        let handle = block_on(store.put::<SimpleArchive, _>(b.clone())).unwrap();
        let snapshot = block_on(store.snapshot()).unwrap();
        let got: Blob<SimpleArchive> = block_on(snapshot.get(handle)).unwrap();
        assert_eq!(got.bytes, b.bytes);
    }

    #[test]
    fn missing_blob_is_an_error_not_a_hang() {
        let mut store = SyncAsAsync::new(MemoryBlobStore::new());
        let snapshot = block_on(store.snapshot()).unwrap();
        let missing = blob(9).get_handle();
        let got = block_on(snapshot.get::<Blob<SimpleArchive>, SimpleArchive>(missing));
        assert!(got.is_err(), "absent blob resolves to Err, immediately");
    }

    #[test]
    fn async_list_through_facade() {
        let mut store = SyncAsAsync::new(MemoryBlobStore::new());
        let h1 = block_on(store.put::<SimpleArchive, _>(blob(1))).unwrap();
        let h2 = block_on(store.put::<SimpleArchive, _>(blob(2))).unwrap();
        let snapshot = block_on(store.snapshot()).unwrap();
        let listed: Vec<_> = block_on(snapshot.blobs())
            .into_iter()
            .filter_map(Result::ok)
            .map(|info| info.handle.raw)
            .collect();
        assert!(listed.contains(&h1.raw) && listed.contains(&h2.raw));
    }

    #[test]
    fn sync_collection_store_reads_and_writes_through_async_facade() {
        let mut store = SyncAsAsync::new(MemoryRepo::default());
        let first = collection_record(1);
        let second = collection_record(7);

        block_on(AsyncCollectionStore::insert(&mut store, second)).unwrap();
        block_on(AsyncCollectionStore::insert(&mut store, first)).unwrap();
        block_on(AsyncCollectionStore::insert(&mut store, second)).unwrap();

        let snapshot = block_on(store.snapshot()).unwrap();
        let actual = block_on(AsyncCollectionRead::records(&snapshot)).unwrap();
        let mut expected = vec![first, second];
        expected.sort_unstable_by_key(CollectionRecord::fingerprint);
        assert_eq!(actual, expected);
    }

    #[cfg(feature = "object-store")]
    #[test]
    fn blocking_adapter_preserves_snapshot_content_changes() {
        let mut store = Blocking::new(SyncAsAsync::new(MemoryRepo::default())).unwrap();
        let before = SnapshotSource::snapshot(&mut store).unwrap();
        let unchanged = SnapshotSource::snapshot(&mut store).unwrap();
        assert_eq!(before.clone().changes_since(&before), StoreChanges::NONE);
        assert_eq!(unchanged.changes_since(&before), StoreChanges::NONE);

        BlobStorePut::put::<SimpleArchive, _>(&mut store, blob(1)).unwrap();
        let after = SnapshotSource::snapshot(&mut store).unwrap();
        assert_eq!(after.changes_since(&before), StoreChanges::BLOBS);
        assert_eq!(BlobStoreList::blobs(&before).count(), 0);
        assert_eq!(BlobStoreList::blobs(&after).count(), 1);
    }

    #[cfg(feature = "object-store")]
    #[test]
    fn blocking_lowers_async_collection_store_back_to_sync() {
        let mut store = Blocking::new(SyncAsAsync::new(MemoryRepo::default())).unwrap();
        let record = collection_record(13);

        CollectionStore::insert(&mut store, record).unwrap();
        let snapshot = SnapshotSource::snapshot(&mut store).unwrap();
        let actual = CollectionRead::records(&snapshot)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, vec![record]);
    }

    // Blocking and SyncAsAsync are inverses: a sync store wrapped up
    // into async and back down through Blocking behaves as a plain sync
    // store. This is the round-trip that proves Blocking yields a full,
    // working sync `BlobStore` surface over an async backend.
    #[cfg(feature = "object-store")]
    #[test]
    fn blocking_over_async_roundtrips_as_a_sync_store() {
        use crate::repo::{BlobStoreGet, BlobStoreList, BlobStorePut, SnapshotSource};

        let mut store = Blocking::new(SyncAsAsync::new(MemoryBlobStore::new())).unwrap();
        let b = blob(5);
        // Pure sync calls — no `.await`, no visible runtime.
        let h = store.put::<SimpleArchive, _>(b.clone()).unwrap();
        let snapshot = store.snapshot().unwrap();
        let got: Blob<SimpleArchive> = snapshot.get(h).unwrap();
        assert_eq!(got.bytes, b.bytes);
        let listed: Vec<_> = snapshot
            .blobs()
            .filter_map(Result::ok)
            .map(|info| info.handle.raw)
            .collect();
        assert!(listed.contains(&h.raw));
    }

    // Statically assert the futures are `Send` — the whole point of the
    // RPITIT style. If the zero-await blocks ever captured something
    // non-Send, this would stop compiling.
    fn _assert_send<F: Send>(_: F) {}
    #[allow(dead_code)]
    fn _send_proof(store: &mut SyncAsAsync<MemoryBlobStore>) {
        _assert_send(store.put::<SimpleArchive, _>(blob(2)));
        _assert_send(store.snapshot());
    }
}
