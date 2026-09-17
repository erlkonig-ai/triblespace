#![allow(clippy::type_complexity)]
//! Content-addressed blob storage, complete capability proofs, collection
//! records, durable wants, and read-only access to legacy named-pin snapshots.
//!
//! Collections are the mutable-history replacement. Legacy pin and commit
//! encodings remain readable so existing piles can be migrated and retained,
//! but this module deliberately exposes no API for mutating named pins.
pub mod async_store;

pub mod branch;
/// Commit metadata construction and signature verification.
pub mod commit;
/// Storage adapter that delegates blobs and collection records to separate backends.
pub mod hybridstore;
/// Fully in-memory storage implementation for tests and ephemeral use.
pub mod memoryrepo;
#[cfg(feature = "object-store")]
/// Storage backed by an `object_store`-compatible remote (S3, local FS, etc.).
pub mod objectstore;
/// Local file-based pile storage backend.
pub mod pile;
/// Grow-only native storage for complete capability proofs.
pub mod proof;
pub use crate::collection::observed_store::ObservedStore;
pub use proof::{CapabilityProofRead, CapabilityProofStore};
/// Generational collection of piles for lazy-retention blob storage.
pub mod yard;

/// Exact content absent from an immutable blob snapshot.
///
/// A live caller may acquire this handle and retry against a later snapshot;
/// the failing snapshot itself never fetches or records demand. Keep the
/// bearer capability available to code rather than printing it in diagnostics.
#[derive(Clone, Copy)]
pub struct MissingBlob {
    pub handle: Inline<Handle<UnknownBlob>>,
}

impl std::fmt::Display for MissingBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("blob is not resident in this snapshot")
    }
}

impl std::error::Error for MissingBlob {}

impl std::fmt::Debug for MissingBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Trait for storage backends that require explicit close/cleanup.
///
/// Not all storage backends need to implement this; implementations that have
/// nothing to do on close may return Ok(()) or use `Infallible` as the error
/// type.
pub trait StorageClose {
    /// Error type returned by `close`.
    type Error: std::error::Error;

    /// Consume the storage and perform any necessary cleanup.
    fn close(self) -> Result<(), Self::Error>;
}

/// Trait for storage backends that can make pending writes crash-durable.
///
/// Mirrors [`StorageClose`]: backends with buffered/unsynced state
/// ([`pile::Pile`]'s appended records are not durable until
/// [`pile::Pile::flush`]) expose it here so generic code can demand
/// durability at a specific point — most importantly when recording a
/// durable **want** whose writer may exit immediately afterwards (a
/// faculty process recording a demand for a sync daemon to service).
/// Backends with nothing to sync (in-memory stores) return `Ok(())` with
/// `Infallible` as the error type.
pub trait StorageFlush {
    /// Error type returned by `flush`.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Persist all pending writes and markers durably.
    fn flush(&mut self) -> Result<(), Self::Error>;
}

/// Component mask for a changed store snapshot.
///
/// This is deliberately local invalidation evidence, not a portable revision
/// or a promise that a component changed by only one element. It lets a
/// consumer retain already-derived state for components that provably did not
/// change while conservatively rebuilding everything for stores that cannot
/// distinguish them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreChanges(u8);

impl StoreChanges {
    /// No sync-visible component changed.
    pub const NONE: Self = Self(0);
    /// The observable blob view (membership, metadata, or retrievability) may
    /// have changed.
    pub const BLOBS: Self = Self(1 << 0);
    /// Native collection records may have changed.
    pub const COLLECTION_RECORDS: Self = Self(1 << 1);
    /// Complete capability proofs may have changed.
    pub const CAPABILITY_PROOFS: Self = Self(1 << 2);
    /// Durable WANT requests may have changed.
    pub const WANTS: Self = Self(1 << 3);
    /// Every sync-visible component may have changed.
    pub const ALL: Self = Self(
        Self::BLOBS.0 | Self::COLLECTION_RECORDS.0 | Self::CAPABILITY_PROOFS.0 | Self::WANTS.0,
    );

    /// Whether every bit in `change` is present.
    pub const fn contains(self, change: Self) -> bool {
        self.0 & change.0 == change.0
    }

    /// Whether no sync-visible component changed.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Union two conservative change observations.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The raw read-set of one retained immutable-store observation.
///
/// These are lookup interests, including absent records and blobs, rather
/// than copies of their contents or a second catalog. A later matching record
/// or readable replacement of a corrupt blob can invalidate an earlier miss.
/// Whole-component flags cover readers that enumerate rather than perform exact lookups.
/// Query time and external provider availability are not stored dependencies;
/// callers retain their existing deadline and exact-acquisition behavior.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreDependencies {
    /// Raw record selection routes consulted by the observation.
    pub records: BTreeSet<CollectionRecordSelector>,
    /// Exact blob hashes consulted, whether resident, missing, or unreadable.
    pub blobs: BTreeSet<CollectionData>,
    /// Whether complete capability proof evidence was consulted.
    pub capability_proofs: bool,
    /// Whether an unrestricted record enumeration was consulted.
    pub all_records: bool,
    /// Whether an unrestricted blob enumeration was consulted.
    pub all_blobs: bool,
}

impl StoreDependencies {
    /// Whether no store component was consulted.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
            && self.blobs.is_empty()
            && !self.capability_proofs
            && !self.all_records
            && !self.all_blobs
    }
}

/// One immutable observation of a storage backend.
///
/// A snapshot is its own local revision token. It owns every read capability
/// needed to interpret the prefix it observed, and compares directly with an
/// earlier snapshot from the same store lineage. Cloning or reading never
/// advances that observation.
/// Record reads and residency observations are frozen and never perform work.
/// A snapshot may additionally carry an asynchronous blob reader which fetches
/// and caches exact immutable content without advancing these observations or
/// recording durable demand. The default change classification is deliberately
/// conservative for backends that cannot classify changes cheaply.
pub trait StoreSnapshot: Clone + Send + Sync + 'static {
    /// Conservatively classify changes since `previous`.
    ///
    /// False positives only repeat derived work. A false negative can strand
    /// derived state, so implementations must report every component which may
    /// have changed. This compares stored content only. Consumers caching
    /// time-sensitive application queries must separately track their own
    /// clocks and boundaries. Snapshots are local observations, not portable
    /// versions.
    fn changes_since(&self, _previous: &Self) -> StoreChanges {
        StoreChanges::ALL
    }

    /// Conservatively classify changes relevant to a retained raw read-set.
    ///
    /// An unchanged result must cover misses as well as successful reads.
    /// Backends may narrow comparison using shared indexes; this default only
    /// masks [`changes_since`](Self::changes_since) by the components that
    /// were consulted, so wrappers without scoped comparison remain safe.
    /// Blob changes include recovery of a previously unreadable payload under
    /// an existing hash, not just newly observed hashes. A redundant readable
    /// copy need not invalidate an observation. WANT changes
    /// and application clocks are deliberately outside this read-set.
    fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
        if dependencies.is_empty() {
            return StoreChanges::NONE;
        }
        let observed = self.changes_since(previous);
        let mut relevant = StoreChanges::NONE;
        if (dependencies.all_records || !dependencies.records.is_empty())
            && observed.contains(StoreChanges::COLLECTION_RECORDS)
        {
            relevant = relevant.union(StoreChanges::COLLECTION_RECORDS);
        }
        if (dependencies.all_blobs || !dependencies.blobs.is_empty())
            && observed.contains(StoreChanges::BLOBS)
        {
            relevant = relevant.union(StoreChanges::BLOBS);
        }
        if dependencies.capability_proofs && observed.contains(StoreChanges::CAPABILITY_PROOFS) {
            relevant = relevant.union(StoreChanges::CAPABILITY_PROOFS);
        }
        relevant
    }
}

#[cfg(test)]
mod store_dependency_tests {
    use super::*;

    #[derive(Clone)]
    struct UnclassifiedSnapshot;

    impl StoreSnapshot for UnclassifiedSnapshot {}

    #[derive(Clone)]
    struct ClassifiedSnapshot(StoreChanges);

    impl StoreSnapshot for ClassifiedSnapshot {
        fn changes_since(&self, _previous: &Self) -> StoreChanges {
            self.0
        }
    }

    #[test]
    fn scoped_default_keeps_unclassified_wrappers_conservative() {
        let snapshot = UnclassifiedSnapshot;
        let mut dependencies = StoreDependencies::default();
        assert!(dependencies.is_empty());
        assert_eq!(
            snapshot.changes_for(&snapshot, &dependencies),
            StoreChanges::NONE
        );

        dependencies
            .records
            .insert(CollectionRecordSelector::Collection(CollectionHandle::new(
                [1; INLINE_LEN],
            )));
        assert!(!dependencies.is_empty());
        assert_eq!(
            snapshot.changes_for(&snapshot, &dependencies),
            StoreChanges::COLLECTION_RECORDS
        );
        dependencies
            .blobs
            .insert(CollectionData::new([2; INLINE_LEN]));
        dependencies.capability_proofs = true;
        let all_reads = StoreChanges::COLLECTION_RECORDS
            .union(StoreChanges::BLOBS)
            .union(StoreChanges::CAPABILITY_PROOFS);
        assert_eq!(snapshot.changes_for(&snapshot, &dependencies), all_reads);
        assert!(!all_reads.contains(StoreChanges::WANTS));

        dependencies.records.clear();
        dependencies.blobs.clear();
        dependencies.all_records = true;
        dependencies.all_blobs = true;
        assert_eq!(snapshot.changes_for(&snapshot, &dependencies), all_reads);
    }

    #[test]
    fn scoped_default_filters_only_uninterested_components() {
        let before = ClassifiedSnapshot(StoreChanges::NONE);
        let mut dependencies = StoreDependencies {
            all_records: true,
            ..StoreDependencies::default()
        };
        for observed in [StoreChanges::NONE, StoreChanges::BLOBS, StoreChanges::WANTS] {
            assert_eq!(
                ClassifiedSnapshot(observed).changes_for(&before, &dependencies),
                StoreChanges::NONE
            );
        }
        assert_eq!(
            ClassifiedSnapshot(StoreChanges::ALL).changes_for(&before, &dependencies),
            StoreChanges::COLLECTION_RECORDS
        );
        dependencies.capability_proofs = true;
        assert_eq!(
            ClassifiedSnapshot(StoreChanges::CAPABILITY_PROOFS).changes_for(&before, &dependencies),
            StoreChanges::CAPABILITY_PROOFS
        );
        dependencies
            .blobs
            .insert(CollectionData::new([3; INLINE_LEN]));
        assert_eq!(
            ClassifiedSnapshot(StoreChanges::BLOBS).changes_for(&before, &dependencies),
            StoreChanges::BLOBS
        );
    }
}

/// A mutable store which can freeze one immutable read observation.
///
/// Every semantic read capability implemented by a store shares this one
/// associated snapshot. Records and proof evidence are frozen together.
/// An attached asynchronous blob reader may resolve exact
/// immutable handles later; that does not select a newer semantic observation.
pub trait SnapshotSource {
    /// Immutable observation returned by this store.
    type Snapshot: StoreSnapshot;
    /// Failure while refreshing and freezing an observation.
    type SnapshotError: Error + Debug + Send + Sync + 'static;

    /// Reobserve external changes and freeze the resulting known prefix.
    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError>;
}

/// Immutable snapshot type produced by `S`.
pub type SnapshotOf<S> = <S as SnapshotSource>::Snapshot;

/// Failure while freezing a snapshot of `S`.
pub type SnapshotErrorOf<S> = <S as SnapshotSource>::SnapshotError;

impl<S> SnapshotSource for &mut S
where
    S: SnapshotSource + ?Sized,
{
    type Snapshot = S::Snapshot;
    type SnapshotError = S::SnapshotError;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        (**self).snapshot()
    }
}

impl<S> StorageFlush for &mut S
where
    S: StorageFlush + ?Sized,
{
    type Error = S::Error;

    fn flush(&mut self) -> Result<(), Self::Error> {
        (**self).flush()
    }
}

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::fmt::{self};

use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::blob::BlobEncoding;
use crate::blob::IntoBlob;
use crate::collection::{
    CollectionData, CollectionHandle, CollectionRead, CollectionRecordSelector, CollectionStore,
};
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::INLINE_LEN;
use crate::patch::IdentitySchema;
use crate::patch::PATCH;
use crate::prelude::inlineencodings::GenId;
use crate::trible::{TribleSet, V_END, V_START};

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::utf8string::UTF8String;
use crate::inline::encodings::shortstring::ShortString;
use crate::prelude::*;

attributes! {
    /// The actual data of the commit.
    "4DD4DDD05CC31734B03ABB4E43188B1F" unsafe as pub content: Handle<SimpleArchive>;
    /// A commit that this commit is based on.
    "317044B612C690000D798CA660ECFD2A" unsafe as pub parent: Handle<SimpleArchive>;
    /// A (potentially long) message describing the commit.
    "B59D147839100B6ED4B165DF76EDF3BB" unsafe as pub message: Handle<UTF8String>;
    /// A short message describing the commit.
    "12290C0BE0E9207E324F24DDE0D89300" unsafe as pub short_message: ShortString;
    /// The hash of the first commit in the commit chain of the branch.
    "272FBC56108F336C4D2E17289468C35F" unsafe as pub head: Handle<SimpleArchive>;
    /// An id used to track the branch.
    "8694CC73AF96A5E1C7635C677D1B928A" unsafe as pub branch: GenId;
}

/// Handle of a legacy signed commit metadata archive.
pub type CommitHandle = Inline<Handle<SimpleArchive>>;

/// Lightweight information returned while enumerating a blob store.
///
/// `length` is storage-observed metadata, not proof that the bytes decode to
/// the encoding named by a subsequently typed handle. Consumers that accept a
/// blob as data must still retrieve and validate it through [`BlobStoreGet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobInfo {
    /// Content-addressed handle recorded by the store.
    pub handle: Inline<Handle<UnknownBlob>>,
    /// Stored payload length in bytes.
    pub length: u64,
}

/// The `ListBlobs` trait is used to list all blobs in a repository.
pub trait BlobStoreList {
    /// Iterator over lightweight blob information in the store.
    type Iter<'a>: Iterator<Item = Result<BlobInfo, Self::Err>>
    where
        Self: 'a;
    /// Error type for listing operations.
    type Err: Error + Debug + Send + Sync + 'static;

    /// Lists all blobs in the repository.
    fn blobs<'a>(&'a self) -> Self::Iter<'a>;

    /// Test whether one blob is present in this store snapshot without
    /// turning absence into demand.
    ///
    /// The default derives membership from [`blobs`](Self::blobs). Indexed
    /// local readers should override it with their native lookup; wrappers
    /// should delegate to the wrapped snapshot. Unlike [`BlobStoreGet::get`],
    /// this is always an observation and must not record a want or fetch.
    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        for info in self.blobs() {
            if info?.handle.raw == handle.raw {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Return lightweight, unvalidated storage information for one resident
    /// blob without reading or hashing its payload.
    ///
    /// This is an observation of the store index, just like
    /// [`contains_blob`](Self::contains_blob). Consumers that use the payload
    /// must still call [`BlobStoreGet::get`], which validates the recorded
    /// content address. Indexed stores should override this method with their
    /// native lookup; the default remains correct for list-only backends.
    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        for info in self.blobs() {
            let info = info?;
            if info.handle.raw == handle.raw {
                return Ok(Some(info));
            }
        }
        Ok(None)
    }

    /// Lists blobs in `self` that are not in `old`.
    ///
    /// Backends with persistent indexes compute the difference cheaply via
    /// their index's own set-difference operation. Backends without such an
    /// index fall back to the default implementation, which lists all current
    /// blobs — over-eager but always correct.
    ///
    /// Use this for "what blobs are new since I last looked" patterns
    /// (e.g. announcing newly-imported blobs to a DHT) where holding the
    /// previous snapshot as a baseline gives you the delta.
    fn blobs_diff<'a>(&'a self, _old: &Self) -> Self::Iter<'a> {
        self.blobs()
    }
}

/// Metadata about a blob in a repository.
#[derive(Debug, Clone)]
pub struct BlobMetadata {
    /// Timestamp in milliseconds since UNIX epoch when the blob was created/stored.
    pub timestamp: u64,
    /// Length of the blob in bytes.
    pub length: u64,
}

/// Trait exposing metadata lookup for blobs available in a repository reader.
pub trait BlobStoreMeta {
    /// Error type returned by metadata calls.
    type MetaError: std::error::Error + Send + Sync + 'static;

    /// Returns metadata for the blob identified by `handle`, or `None` if
    /// the blob is not present.
    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding;
}

/// Trait exposing a monotonic "forget" operation.
///
/// Forget is idempotent and monotonic: it removes materialization from a
/// particular repository but does not semantically delete derived facts.
pub trait BlobStoreForget {
    /// Error type for forget operations.
    type ForgetError: std::error::Error + Send + Sync + 'static;

    /// Removes the materialized blob identified by `handle` from this store.
    fn forget<S>(&mut self, handle: Inline<Handle<S>>) -> Result<(), Self::ForgetError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding;
}

/// The `GetBlob` trait is used to retrieve blobs from a repository.
///
/// Implementations are a trust boundary: on success, the returned typed value
/// must carry `handle` as its content identity and its bytes must be the bytes
/// validated for that identity. Callers may trust the cached handle and must
/// not need to hash the same bytes again. Stores ingesting untrusted pile,
/// object-store, or network data therefore perform content-address validation
/// before constructing the returned [`Blob`].
pub trait BlobStoreGet {
    /// Error type for get operations, parameterised by the deserialization error.
    type GetError<E: std::error::Error + Send + Sync + 'static>: Error + Send + Sync + 'static;

    /// Retrieves a blob from the repository by its handle.
    /// The handle is a unique identifier for the blob, and is used to retrieve it from the repository.
    /// The blob is returned as a [`Blob`] object, which contains the raw bytes of the blob,
    /// which can be deserialized via the appropriate schema type, which is specified by the `T` type parameter.
    ///
    /// # Errors
    /// Returns an error if the blob could not be found in the repository.
    /// The error type is specified by the `Err` associated type.
    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding;
}

/// The `PutBlob` trait is used to store blobs in a repository.
pub trait BlobStorePut {
    /// Error type for put operations.
    type PutError: Error + Debug + Send + Sync + 'static;

    /// Serialises `item` as a blob, stores it, and returns its handle.
    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding;
}

impl<B> BlobStorePut for &mut B
where
    B: BlobStorePut + ?Sized,
{
    type PutError = B::PutError;

    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        (**self).put(item)
    }
}

/// Combined blob storage whose reads come from the store's one shared
/// immutable snapshot.
///
/// Blob writes remain a property of the mutable store. Blob reads and listings
/// are properties of [`SnapshotSource::Snapshot`], so collection admission,
/// capability verification, and payload decoding can all observe one prefix.
pub trait BlobStore: BlobStorePut + SnapshotSource<Snapshot: BlobStoreGet + BlobStoreList> {}

impl<B> BlobStore for B
where
    B: BlobStorePut + SnapshotSource + ?Sized,
    B::Snapshot: BlobStoreGet + BlobStoreList,
{
}

/// Immutable read surface of a complete repository snapshot.
pub trait StoreRead:
    StoreSnapshot
    + BlobStoreGet
    + BlobStoreList
    + BlobStoreMeta
    + CollectionRead
    + CapabilityProofRead
    + WantRead
{
}

impl<R> StoreRead for R where
    R: StoreSnapshot
        + BlobStoreGet
        + BlobStoreList
        + BlobStoreMeta
        + CollectionRead
        + CapabilityProofRead
        + WantRead
{
}

/// Mutable repository whose semantic reads all share one snapshot.
pub trait Store:
    BlobStore + CollectionStore + CapabilityProofStore + SnapshotSource<Snapshot: StoreRead>
{
}

impl<S> Store for S
where
    S: BlobStore + CollectionStore + CapabilityProofStore + SnapshotSource,
    S::Snapshot: StoreRead,
{
}

/// Trait for blob stores that can retain a supplied set of handles.
pub trait BlobStoreKeep {
    /// Retain only the blobs identified by `handles`.
    fn keep<I>(&mut self, handles: I)
    where
        I: IntoIterator<Item = Inline<Handle<UnknownBlob>>>;
}

/// Explicit roots for one retention pass.
///
/// Retention has two different edge meanings which must not be conflated:
///
/// - **direct** roots retain exactly the named blob and do not inspect its
///   payload; and
/// - **recursive** roots own their resident descendants, discovered through
///   [`reachable`].
///
/// These caller-selected roots supplement native-record ownership. Every
/// retained collection record and WANT owns its resident direct references
/// recursively; backends discover those edges separately from this explicit
/// policy value and without semantic admission. Capability proofs are
/// self-contained and therefore own no blobs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RetentionRoots {
    direct: BTreeSet<[u8; INLINE_LEN]>,
    recursive: BTreeSet<[u8; INLINE_LEN]>,
}

impl RetentionRoots {
    /// Construct an empty retention policy result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Retain exactly `handle`, without interpreting its bytes as ownership
    /// edges.
    pub fn retain_direct<S>(&mut self, handle: Inline<Handle<S>>)
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.direct.insert(handle.raw);
    }

    /// Retain `handle` and every resident descendant reached through the
    /// store's conservative child traversal.
    pub fn retain_recursive<S>(&mut self, handle: Inline<Handle<S>>)
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        self.recursive.insert(handle.raw);
    }

    /// Merge another policy result into this one.
    pub fn union(&mut self, other: Self) {
        self.direct.extend(other.direct);
        self.recursive.extend(other.recursive);
    }

    /// Direct roots in deterministic handle order.
    pub fn direct(&self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> + '_ {
        self.direct
            .iter()
            .copied()
            .map(Inline::<Handle<UnknownBlob>>::new)
    }

    /// Recursive roots in deterministic handle order.
    pub fn recursive(&self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> + '_ {
        self.recursive
            .iter()
            .copied()
            .map(Inline::<Handle<UnknownBlob>>::new)
    }

    /// Expand this policy against a reader into the exact resident keep set.
    ///
    /// Direct roots are inserted without calling [`BlobChildren::children`].
    /// Recursive roots use [`reachable`], whose existing missing-child
    /// behavior remains conservative for the blobs that are locally present.
    pub fn expanded<R>(&self, reader: &R) -> BTreeSet<Inline<Handle<UnknownBlob>>>
    where
        R: BlobChildren,
    {
        let mut keep: BTreeSet<_> = self.direct().collect();
        keep.extend(reachable(reader, self.recursive()));
        keep
    }

    /// Whether neither kind of root is present.
    pub fn is_empty(&self) -> bool {
        self.direct.is_empty() && self.recursive.is_empty()
    }
}

/// Trait for stores that can enumerate a blob's child references.
///
/// "Children" are the 32-byte-aligned values in a blob that correspond
/// to existing blobs in the store — the conservative set of references.
///
/// The default implementation scans the blob's bytes and checks each
/// 32-byte chunk with [`BlobStoreGet::get`]. Backends with batch
/// capabilities (e.g. a network store with a SYNC protocol) can
/// override this for efficiency.
pub trait BlobChildren: BlobStoreGet {
    /// Return handles of blobs referenced by `handle` that exist in this store.
    fn children(&self, handle: Inline<Handle<UnknownBlob>>) -> Vec<Inline<Handle<UnknownBlob>>> {
        let Ok(blob) = self.get::<Blob<UnknownBlob>, UnknownBlob>(handle) else {
            return Vec::new();
        };
        let bytes = blob.bytes.as_ref();
        let mut result = Vec::new();
        let mut offset = 0usize;
        while offset + INLINE_LEN <= bytes.len() {
            let mut raw = [0u8; INLINE_LEN];
            raw.copy_from_slice(&bytes[offset..offset + INLINE_LEN]);
            let candidate = Inline::<Handle<UnknownBlob>>::new(raw);
            if self.get::<anybytes::Bytes, UnknownBlob>(candidate).is_ok() {
                result.push(candidate);
            }
            offset += INLINE_LEN;
        }
        result
    }
}

// No blanket impl — types opt in explicitly so they can provide
// optimized implementations (e.g. network stores with batch protocols).
// Use `impl_blob_children_default!` for the scan-and-check fallback.

/// A point-in-time snapshot of (pin id → head) mappings.
///
/// PATCH keyed by 16-byte pin id, valued by the pinned head's handle.
/// This type exists only for explicit legacy pile migration and diagnosis;
/// current serving paths use collection records directly.
///
/// Returned by [`PinSnapshotSource::snapshot_pin_heads`].
pub type PinSnapshot = PATCH<16, IdentitySchema, Inline<Handle<SimpleArchive>>>;

/// Observational access to one point-in-time snapshot of pin heads.
///
/// Explicit migration and diagnosis tools can inspect legacy pile state
/// without regaining piecemeal access or compare-and-swap mutation. The
/// returned snapshot remains fully inspectable. The mutable receiver permits
/// [`crate::repo::pile::Pile`] to refresh externally appended records before
/// producing the snapshot; the capability itself is read-only and is not
/// forwarded by current storage composition wrappers.
///
/// Implementations must return a complete snapshot or an error. Listing or
/// per-head failures must never be hidden by returning a partial view.
pub trait PinSnapshotSource {
    /// Error returned when a stable pin-head snapshot cannot be produced.
    type PinSnapshotError: Error + Debug + Send + Sync + 'static;

    /// Return a point-in-time snapshot of every `(pin id, head)` mapping.
    fn snapshot_pin_heads(&mut self) -> Result<PinSnapshot, Self::PinSnapshotError>;
}

#[cfg(test)]
mod pin_snapshot_source_tests {
    use super::PinSnapshotSource;
    use crate::repo::pile::Pile;

    fn assert_source<T: PinSnapshotSource>() {}

    #[test]
    fn only_pile_exposes_legacy_pin_inspection() {
        assert_source::<Pile>();
    }
}

/// Exact byte length of a canonical [`WantRequest`].
pub const WANT_REQUEST_BYTES_LEN: usize = 1 + 3 * INLINE_LEN;

/// Versioned tag of a blob request in the canonical [`WantRequest`] codec.
pub const WANT_REQUEST_KIND_BLOB_V1: u8 = 1;
/// Versioned tag of a merge request in the canonical [`WantRequest`] codec.
pub const WANT_REQUEST_KIND_MERGE_V1: u8 = 2;
/// Retired derive tag used only while projecting historical pile WANT logs.
///
/// It encoded `(source, target, input)`; current canonical requests use tag 4
/// and omit the source already named by the target descriptor.
pub(crate) const WANT_REQUEST_KIND_DERIVE_V1: u8 = 3;
/// Derive request naming only its target and input.
///
/// The source is what the target's descriptor says it is, so a want that
/// restated it only offered a way to disagree with the descriptor.
pub const WANT_REQUEST_KIND_DERIVE_V2: u8 = 4;

/// A durable request for absent content or reproducible collection work.
///
/// Requests deliberately name only inputs. A fulfiller may satisfy a blob
/// request by fetching its content, a merge request by publishing an exact
/// [`crate::collection::CollectionMerge`], or a derive request by publishing
/// an exact [`crate::collection::CollectionDerive`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WantRequest {
    /// Obtain and retain one content-addressed blob according to local policy.
    Blob {
        /// Type-erased bearer handle used for local lookup or global discovery.
        handle: Inline<Handle<UnknownBlob>>,
    },
    /// Discover or compute the exact merge of two collection elements.
    Merge {
        /// Collection whose merge operation is requested.
        collection: CollectionHandle,
        /// Canonically lower input digest.
        low: CollectionData,
        /// Canonically higher input digest.
        high: CollectionData,
    },
    /// Discover or compute one collection derivation.
    ///
    /// The source is not named: the target's descriptor says which collection
    /// it derives from, so a want asks for one instance of a mapping the
    /// responder can already identify.
    Derive {
        /// Target collection requested for the derived output.
        target: CollectionHandle,
        /// Source element to derive.
        input: CollectionData,
    },
}

impl WantRequest {
    /// Construct a blob request from any typed content handle.
    pub fn blob<S>(handle: Inline<Handle<S>>) -> Self
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        Self::Blob {
            handle: handle.transmute(),
        }
    }

    /// Return the requested blob handle, if this is an exact-content request.
    pub const fn blob_handle(self) -> Option<Inline<Handle<UnknownBlob>>> {
        match self {
            Self::Blob { handle } => Some(handle),
            Self::Merge { .. } | Self::Derive { .. } => None,
        }
    }

    /// Construct a merge request with its two inputs in canonical order.
    pub fn merge(
        collection: CollectionHandle,
        first: CollectionData,
        second: CollectionData,
    ) -> Self {
        let (low, high) = if first <= second {
            (first, second)
        } else {
            (second, first)
        };
        Self::Merge {
            collection,
            low,
            high,
        }
    }

    /// Construct a derivation request from one exact source element.
    pub const fn derive(target: CollectionHandle, input: CollectionData) -> Self {
        Self::Derive { target, input }
    }

    /// Blob handles named directly by this durable request.
    ///
    /// WANT is an ordinary structural lifetime record: when retained it owns
    /// whichever of these handles are resident, recursively. The method does
    /// not fetch absent bytes or turn them into subordinate wants.
    pub fn blob_references(self) -> impl ExactSizeIterator<Item = Inline<Handle<UnknownBlob>>> {
        let mut references = arrayvec::ArrayVec::<_, 3>::new();
        match self {
            Self::Blob { handle } => references.push(handle),
            Self::Merge {
                collection,
                low,
                high,
            } => references.extend([
                collection.transmute(),
                Handle::<UnknownBlob>::from_hash(low),
                Handle::<UnknownBlob>::from_hash(high),
            ]),
            Self::Derive { target, input } => {
                references.extend([target.transmute(), Handle::<UnknownBlob>::from_hash(input)])
            }
        }
        references.into_iter()
    }

    /// Encode this request into its exact tagged 97-byte representation.
    pub fn to_bytes(self) -> [u8; WANT_REQUEST_BYTES_LEN] {
        let mut bytes = [0; WANT_REQUEST_BYTES_LEN];
        match self {
            Self::Blob { handle } => {
                bytes[0] = WANT_REQUEST_KIND_BLOB_V1;
                write_want_field(&mut bytes, 0, handle.raw);
            }
            Self::Merge {
                collection,
                low,
                high,
            } => {
                bytes[0] = WANT_REQUEST_KIND_MERGE_V1;
                write_want_field(&mut bytes, 0, collection.raw);
                write_want_field(&mut bytes, 1, low.raw);
                write_want_field(&mut bytes, 2, high.raw);
            }
            Self::Derive { target, input } => {
                bytes[0] = WANT_REQUEST_KIND_DERIVE_V2;
                write_want_field(&mut bytes, 0, target.raw);
                write_want_field(&mut bytes, 1, input.raw);
            }
        }
        bytes
    }

    /// Decode one exact canonical 97-byte request.
    pub fn from_bytes(bytes: [u8; WANT_REQUEST_BYTES_LEN]) -> Result<Self, WantRequestDecodeError> {
        match bytes[0] {
            WANT_REQUEST_KIND_BLOB_V1 => {
                if bytes[1 + INLINE_LEN..].iter().any(|byte| *byte != 0) {
                    return Err(WantRequestDecodeError::NonZeroUnusedFields {
                        kind: WANT_REQUEST_KIND_BLOB_V1,
                    });
                }
                Ok(Self::Blob {
                    handle: Inline::new(read_want_field(&bytes, 0)),
                })
            }
            WANT_REQUEST_KIND_MERGE_V1 => {
                let collection = Inline::new(read_want_field(&bytes, 0));
                let low = Inline::new(read_want_field(&bytes, 1));
                let high = Inline::new(read_want_field(&bytes, 2));
                if high < low {
                    return Err(WantRequestDecodeError::NonCanonicalMergeInputs);
                }
                Ok(Self::Merge {
                    collection,
                    low,
                    high,
                })
            }
            WANT_REQUEST_KIND_DERIVE_V2 => {
                if read_want_field(&bytes, 2).iter().any(|byte| *byte != 0) {
                    return Err(WantRequestDecodeError::NonZeroUnusedFields {
                        kind: WANT_REQUEST_KIND_DERIVE_V2,
                    });
                }
                Ok(Self::Derive {
                    target: Inline::new(read_want_field(&bytes, 0)),
                    input: Inline::new(read_want_field(&bytes, 1)),
                })
            }
            unknown => Err(WantRequestDecodeError::UnknownKind(unknown)),
        }
    }
}

/// Structural failure while decoding a canonical [`WantRequest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WantRequestDecodeError {
    /// The versioned variant tag is unknown.
    UnknownKind(u8),
    /// A short variant used non-zero bytes in a reserved field.
    NonZeroUnusedFields { kind: u8 },
    /// A merge encoded its inputs in descending order.
    NonCanonicalMergeInputs,
}

impl fmt::Display for WantRequestDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind(kind) => {
                write!(formatter, "want request has unknown dense kind {kind}")
            }
            Self::NonZeroUnusedFields { kind } => write!(
                formatter,
                "want request kind {kind} has non-zero unused fields"
            ),
            Self::NonCanonicalMergeInputs => {
                formatter.write_str("want request merge inputs are not canonically ordered")
            }
        }
    }
}

impl Error for WantRequestDecodeError {}

fn write_want_field(
    bytes: &mut [u8; WANT_REQUEST_BYTES_LEN],
    index: usize,
    field: [u8; INLINE_LEN],
) {
    let start = 1 + index * INLINE_LEN;
    bytes[start..start + INLINE_LEN].copy_from_slice(&field);
}

fn read_want_field(bytes: &[u8; WANT_REQUEST_BYTES_LEN], index: usize) -> [u8; INLINE_LEN] {
    let start = 1 + index * INLINE_LEN;
    bytes[start..start + INLINE_LEN]
        .try_into()
        .expect("validated fixed-width want request field")
}

/// Immutable enumeration of one frozen durable-WANT observation.
pub trait WantRead {
    /// Error while enumerating the frozen request set.
    type WantsError: Error + Debug + Send + Sync + 'static;

    /// Iterator over the frozen grow-only request set.
    type WantIter<'a>: Iterator<Item = Result<WantRequest, Self::WantsError>>
    where
        Self: 'a;

    /// List the request set captured by this observation.
    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError>;
}

/// Insertion capability for durable typed wants.
///
/// Wants are an idempotent grow-only set, independent of legacy named-pin
/// evidence and native collection records. A backend may support either
/// capability without supporting the other. Repeated [`want`](Self::want)
/// calls for one exact request have no additional effect. Frozen enumeration
/// is exposed separately through [`WantRead`]. Exact-content requests are
/// identified solely by their bearer handle.
///
/// Forgetting is deliberately not a counter-record operation. A physical
/// rewrite may omit a WANT deliberately, but while the record is retained it
/// strongly owns every independently resident direct blob reference. No
/// appended negative fact may retract another replica's demand after pile
/// concatenation.
pub trait WantStore {
    /// Error type for want operations.
    type WantError: Error + Debug + Send + Sync + 'static;

    /// Add durable interest in `request` idempotently.
    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError>;
}

#[cfg(test)]
mod want_request_tests {
    use super::*;

    fn collection(byte: u8) -> CollectionHandle {
        Inline::new([byte; INLINE_LEN])
    }

    fn data(byte: u8) -> CollectionData {
        Inline::new([byte; INLINE_LEN])
    }

    #[test]
    fn typed_blob_request_roundtrips_with_zero_unused_fields() {
        let typed = Inline::<Handle<SimpleArchive>>::new([0x41; INLINE_LEN]);
        let request = WantRequest::blob(typed);
        let bytes = request.to_bytes();

        assert_eq!(bytes.len(), WANT_REQUEST_BYTES_LEN);
        assert_eq!(bytes[0], WANT_REQUEST_KIND_BLOB_V1);
        assert!(bytes[1 + INLINE_LEN..].iter().all(|byte| *byte == 0));
        assert_eq!(WantRequest::from_bytes(bytes), Ok(request));
        assert_eq!(
            request,
            WantRequest::Blob {
                handle: typed.transmute()
            }
        );
    }

    #[test]
    fn merge_constructor_sorts_and_dense_decoder_rejects_reverse_order() {
        let request = WantRequest::merge(collection(1), data(9), data(2));
        assert_eq!(
            request,
            WantRequest::Merge {
                collection: collection(1),
                low: data(2),
                high: data(9),
            }
        );
        assert_eq!(WantRequest::from_bytes(request.to_bytes()), Ok(request));

        let mut reversed = request.to_bytes();
        reversed[1 + INLINE_LEN..1 + 2 * INLINE_LEN].fill(9);
        reversed[1 + 2 * INLINE_LEN..].fill(2);
        assert_eq!(
            WantRequest::from_bytes(reversed),
            Err(WantRequestDecodeError::NonCanonicalMergeInputs)
        );
    }

    #[test]
    fn derive_request_roundtrips() {
        let request = WantRequest::derive(collection(2), data(3));
        let bytes = request.to_bytes();
        assert_eq!(bytes[0], WANT_REQUEST_KIND_DERIVE_V2);
        assert_eq!(WantRequest::from_bytes(bytes), Ok(request));
    }

    #[test]
    fn wants_enumerate_every_direct_blob_reference() {
        let blob = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([1; INLINE_LEN]));
        let merge = WantRequest::merge(collection(2), data(3), data(4));
        let derive = WantRequest::derive(collection(5), data(6));

        assert_eq!(
            blob.blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[1; INLINE_LEN]],
        );
        assert_eq!(
            merge
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[2; INLINE_LEN], [3; INLINE_LEN], [4; INLINE_LEN]],
        );
        assert_eq!(
            derive
                .blob_references()
                .map(|handle| handle.raw)
                .collect::<Vec<_>>(),
            vec![[5; INLINE_LEN], [6; INLINE_LEN]],
        );
    }

    #[test]
    fn dense_decoder_rejects_noncanonical_shapes() {
        let mut unknown = [0; WANT_REQUEST_BYTES_LEN];
        unknown[0] = 99;
        assert_eq!(
            WantRequest::from_bytes(unknown),
            Err(WantRequestDecodeError::UnknownKind(99))
        );

        let mut padded =
            WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([0x51; INLINE_LEN])).to_bytes();
        padded[1 + INLINE_LEN] = 1;
        assert_eq!(
            WantRequest::from_bytes(padded),
            Err(WantRequestDecodeError::NonZeroUnusedFields {
                kind: WANT_REQUEST_KIND_BLOB_V1,
            })
        );
    }
}

/// Error returned by [`transfer`] when copying blobs between stores.
#[derive(Debug)]
pub enum TransferError<ListErr, LoadErr, StoreErr> {
    /// Failed to list handles from the source.
    List(ListErr),
    /// Failed to load a blob from the source.
    Load(LoadErr),
    /// Failed to store a blob in the target.
    Store(StoreErr),
}

impl<ListErr, LoadErr, StoreErr> fmt::Display for TransferError<ListErr, LoadErr, StoreErr> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to transfer blob")
    }
}

impl<ListErr, LoadErr, StoreErr> Error for TransferError<ListErr, LoadErr, StoreErr>
where
    ListErr: Debug + Error + 'static,
    LoadErr: Debug + Error + 'static,
    StoreErr: Debug + Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::List(e) => Some(e),
            Self::Load(e) => Some(e),
            Self::Store(e) => Some(e),
        }
    }
}

/// Copies the specified blob handles from `source` into `target`.
pub fn transfer<'a, BS, BT, Handles>(
    source: &'a BS,
    target: &'a mut BT,
    handles: Handles,
) -> impl Iterator<
    Item = Result<
        (Inline<Handle<UnknownBlob>>, Inline<Handle<UnknownBlob>>),
        TransferError<
            Infallible,
            <BS as BlobStoreGet>::GetError<Infallible>,
            <BT as BlobStorePut>::PutError,
        >,
    >,
> + 'a
where
    BS: BlobStoreGet + 'a,
    BT: BlobStorePut + 'a,
    Handles: IntoIterator<Item = Inline<Handle<UnknownBlob>>> + 'a,
    Handles::IntoIter: 'a,
{
    handles.into_iter().map(move |source_handle| {
        let blob: Blob<UnknownBlob> = source.get(source_handle).map_err(TransferError::Load)?;

        Ok((
            source_handle,
            (target.put(blob).map_err(TransferError::Store)?),
        ))
    })
}

/// Iterator that visits every blob handle reachable from a set of roots.
///
/// Uses [`BlobChildren`] to enumerate references at each level,
/// so backends with batch capabilities get efficient traversal.
pub struct ReachableHandles<'a, BS>
where
    BS: BlobChildren,
{
    source: &'a BS,
    queue: VecDeque<Inline<Handle<UnknownBlob>>>,
    visited: HashSet<[u8; INLINE_LEN]>,
}

impl<'a, BS> ReachableHandles<'a, BS>
where
    BS: BlobChildren,
{
    fn new(source: &'a BS, roots: impl IntoIterator<Item = Inline<Handle<UnknownBlob>>>) -> Self {
        let mut queue = VecDeque::new();
        for handle in roots {
            queue.push_back(handle);
        }

        Self {
            source,
            queue,
            visited: HashSet::new(),
        }
    }
}

impl<'a, BS> Iterator for ReachableHandles<'a, BS>
where
    BS: BlobChildren,
{
    type Item = Inline<Handle<UnknownBlob>>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(handle) = self.queue.pop_front() {
            let raw = handle.raw;

            if !self.visited.insert(raw) {
                continue;
            }

            // Use BlobChildren to get references — backends can override
            // with batch-optimized implementations.
            for child in self.source.children(handle) {
                if !self.visited.contains(&child.raw) {
                    self.queue.push_back(child);
                }
            }

            return Some(handle);
        }

        None
    }
}

/// Create a breadth-first iterator over blob handles reachable from `roots`.
///
/// Uses [`BlobChildren`] for reference enumeration, so network-backed
/// stores can provide optimized batch implementations.
pub fn reachable<'a, BS>(
    source: &'a BS,
    roots: impl IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
) -> ReachableHandles<'a, BS>
where
    BS: BlobChildren,
{
    ReachableHandles::new(source, roots)
}

/// Iterate over every 32-byte candidate in the value column of a [`TribleSet`].
///
/// This is a conservative conversion used when scanning metadata for potential
/// blob handles. Each 32-byte chunk is treated as a `Handle<UnknownBlob>`.
/// Callers can feed the resulting iterator into [`BlobStoreKeep::keep`] or other
/// helpers that accept collections of handles.
pub fn potential_handles<'a>(
    set: &'a TribleSet,
) -> impl Iterator<Item = Inline<Handle<UnknownBlob>>> + 'a {
    set.vae.iter().map(|raw| {
        let mut value = [0u8; INLINE_LEN];
        value.copy_from_slice(&raw[V_START..=V_END]);
        Inline::<Handle<UnknownBlob>>::new(value)
    })
}
