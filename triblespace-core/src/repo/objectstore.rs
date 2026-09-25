use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

use anybytes::Bytes;
use futures::StreamExt;

use object_store::parse_url;
use object_store::path::Path;
use object_store::ObjectStore;
use object_store::PutMode;
use object_store::{self};
use url::Url;

use hex::FromHex;

use super::async_store::{
    AsyncBlobStoreForget, AsyncBlobStoreGet, AsyncBlobStoreList, AsyncBlobStoreMeta,
    AsyncBlobStorePut, AsyncCollectionRead, AsyncCollectionStore, AsyncSnapshotSource,
};
use super::{BlobInfo, BlobMetadata, StoreChanges, StoreSnapshot};
use crate::blob::Blob;
use crate::blob::BlobEncoding;
use crate::blob::IntoBlob;
use crate::blob::TryFromBlob;
use crate::collection::{
    CollectionRecord, CollectionRecordFingerprint, LegacyUnsignedCollectionEquation,
    RecordDecodeError, RetiredCollectionEquation, COLLECTION_RECORD_KIND_DERIVE_V2,
    COLLECTION_RECORD_KIND_MERGE_V2,
};
#[cfg(test)]
use crate::id::Id;
use crate::inline::encodings::hash::{Blake3, Handle, Hash};
use crate::inline::Inline;
use crate::inline::InlineEncoding;
use crate::inline::RawInline;

const BLOB_INFIX: &str = "blobs";
const COLLECTION_RECORD_INFIX: &str = "collection-records";

/// Storage backed by an [`object_store`] compatible backend.
///
/// All data is stored in an external service (e.g. S3, local filesystem)
/// via the `object_store` crate, which is async at its core — so this
/// type is **async-native**: it implements the
/// [`super::async_store::AsyncBlobStore`] family
/// directly, awaiting each operation, with no owned runtime.
///
/// This is a trusted persistence backend, not foreign-record ingress. Typed
/// inserts must already be locally signed or checked at their import boundary.
/// Replay checks canonical structure and the content-addressed object key,
/// without repeating signature verification. Retired unsigned equation objects
/// remain untouched as evidence but are absent from the current record view.
///
/// Synchronous callers wrap it in
/// [`Blocking`](super::async_store::Blocking), which carries the single
/// `block_on` boundary:
///
/// ```no_run
/// # use url::Url;
/// # use triblespace_core::repo::objectstore::ObjectStoreRemote;
/// # use triblespace_core::repo::async_store::Blocking;
/// # fn f(url: &Url) -> Result<(), Box<dyn std::error::Error>> {
/// let remote = ObjectStoreRemote::with_url(url)?;
/// let mut store = Blocking::new(remote)?; // now a plain sync BlobStore
/// # let _ = &mut store;
/// # Ok(())
/// # }
/// ```
pub struct ObjectStoreRemote {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
}

impl fmt::Debug for ObjectStoreRemote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStoreRemote")
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl fmt::Debug for ObjectStoreSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStoreSnapshot")
            .field("prefix", &self.prefix)
            .field("blob_count", &self.blobs.len())
            .field("collection_record_count", &self.collection_records.len())
            .finish()
    }
}

/// One immutable observation of an [`ObjectStoreRemote`].
///
/// Remote object stores generally cannot provide an atomic cross-prefix read
/// transaction. Snapshot construction therefore observes both immutable
/// namespaces once, validates every observed entry, and freezes their
/// membership together. Record enumeration and residency observations stay
/// frozen. An explicit exact-handle GET can retrieve bytes added later without
/// changing those observations.
#[derive(Clone)]
pub struct ObjectStoreSnapshot {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
    blobs: Arc<BTreeMap<RawInline, ObservedBlob>>,
    collection_records: Arc<Vec<CollectionRecord>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedBlob {
    length: u64,
    timestamp: u64,
}

impl StoreSnapshot for ObjectStoreSnapshot {
    fn changes_since(&self, previous: &Self) -> StoreChanges {
        let mut changes = StoreChanges::NONE;
        if self.blobs != previous.blobs {
            changes = changes.union(StoreChanges::BLOBS);
        }
        if self.collection_records != previous.collection_records {
            changes = changes.union(StoreChanges::COLLECTION_RECORDS);
        }
        changes
    }
}

impl ObjectStoreRemote {
    /// Creates storage pointing at the object store described by
    /// `url`. The returned value is async-native — wrap it in
    /// [`Blocking`](super::async_store::Blocking) for synchronous use.
    pub fn with_url(url: &Url) -> Result<ObjectStoreRemote, object_store::Error> {
        let (store, path) = parse_url(url)?;
        Ok(ObjectStoreRemote {
            store: Arc::from(store),
            prefix: path,
        })
    }
}

impl AsyncBlobStorePut for ObjectStoreRemote {
    type PutError = PutBlobErr;

    fn put<S, T>(
        &mut self,
        item: T,
    ) -> impl Future<Output = Result<Inline<Handle<S>>, Self::PutError>> + Send
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        // Serialise + capture only Send primitives before the await (the
        // phantom-typed handle is `!Send` when the schema is).
        let blob = item.to_blob();
        let raw = blob.get_handle().raw;
        let bytes: bytes::Bytes = blob.bytes.into();
        async move {
            let path = self.prefix.child(BLOB_INFIX).child(hex::encode(raw));
            let result = self
                .store
                .put_opts(&path, bytes.clone().into(), PutMode::Create.into())
                .await;
            match result {
                Ok(_) => Ok(Inline::new(raw)),
                Err(object_store::Error::AlreadyExists { .. }) => {
                    // A content-addressed retry is idempotent only when the
                    // occupied key contains the exact staged bytes. Merely
                    // trusting the filename could publish an authoritative
                    // collection record over a corrupt dependency.
                    let object = self
                        .store
                        .get(&path)
                        .await
                        .map_err(PutBlobErr::ReadExisting)?;
                    let actual = object.bytes().await.map_err(PutBlobErr::ReadExisting)?;
                    if actual == bytes {
                        Ok(Inline::new(raw))
                    } else {
                        Err(PutBlobErr::ExistingMismatch {
                            handle: Inline::new(raw),
                        })
                    }
                }
                Err(error) => Err(PutBlobErr::Store(error)),
            }
        }
    }
}

impl AsyncSnapshotSource for ObjectStoreRemote {
    type Snapshot = ObjectStoreSnapshot;
    type SnapshotError = ObjectStoreSnapshotError;

    fn snapshot(
        &mut self,
    ) -> impl Future<Output = Result<Self::Snapshot, Self::SnapshotError>> + Send {
        async move {
            // Observe semantic records before blobs. Under the normal
            // dependency-first, naming-record-last publication order, this
            // biases a concurrent observation toward harmless extra blobs
            // rather than a newly observed record whose preceding blob write
            // was missed by an earlier listing. Explicit forgets can still
            // make a snapshotted payload unavailable; GET reports that I/O
            // failure without changing the frozen membership.
            let record_prefix = self.prefix.child(COLLECTION_RECORD_INFIX);
            let mut collection_records = BTreeMap::new();
            let mut listed_records = self.store.list(Some(&record_prefix));
            while let Some(item) = listed_records.next().await {
                let meta = item.map_err(ListCollectionRecordsErr::List)?;
                if let Some(record) =
                    read_collection_record(&*self.store, &record_prefix, meta.location).await?
                {
                    collection_records.insert(record.fingerprint(), record);
                }
            }
            let collection_records = collection_records.into_values().collect();

            let blob_prefix = self.prefix.child(BLOB_INFIX);
            let mut blobs = BTreeMap::new();
            let mut listed_blobs = self.store.list(Some(&blob_prefix));
            while let Some(item) = listed_blobs.next().await {
                let meta = item.map_err(ListBlobsErr::List)?;
                let raw = blob_handle_from_path(&blob_prefix, &meta.location)?;
                let timestamp = u64::try_from(meta.last_modified.timestamp_millis()).unwrap_or(0);
                blobs.insert(
                    raw,
                    ObservedBlob {
                        length: meta.size,
                        timestamp,
                    },
                );
            }

            Ok(ObjectStoreSnapshot {
                store: self.store.clone(),
                prefix: self.prefix.clone(),
                blobs: Arc::new(blobs),
                collection_records: Arc::new(collection_records),
            })
        }
    }
}

impl AsyncCollectionStore for ObjectStoreRemote {
    type InsertError = InsertCollectionRecordErr;

    fn insert(
        &mut self,
        record: CollectionRecord,
    ) -> impl Future<Output = Result<(), Self::InsertError>> + Send {
        let fingerprint = record.fingerprint();
        let path = self
            .prefix
            .child(COLLECTION_RECORD_INFIX)
            .child(hex::encode(fingerprint.raw()));
        let expected: bytes::Bytes = record.to_bytes().into();

        async move {
            match self
                .store
                .put_opts(&path, expected.clone().into(), PutMode::Create.into())
                .await
            {
                Ok(_) => Ok(()),
                Err(object_store::Error::AlreadyExists { .. }) => {
                    // The namespace is immutable. A replay is success only
                    // when the already-present canonical bytes are identical;
                    // never turn insertion into a mutable CAS update.
                    let object = self
                        .store
                        .get(&path)
                        .await
                        .map_err(InsertCollectionRecordErr::ReadExisting)?;
                    let actual = object
                        .bytes()
                        .await
                        .map_err(InsertCollectionRecordErr::ReadExisting)?;
                    if actual == expected {
                        Ok(())
                    } else {
                        Err(InsertCollectionRecordErr::ExistingMismatch { fingerprint })
                    }
                }
                Err(error) => Err(InsertCollectionRecordErr::Store(error)),
            }
        }
    }
}

impl AsyncBlobStoreForget for ObjectStoreRemote {
    type ForgetError = object_store::Error;

    fn forget<S>(
        &mut self,
        handle: Inline<Handle<S>>,
    ) -> impl Future<Output = Result<(), Self::ForgetError>> + Send
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        let raw = handle.raw;
        async move {
            let path = self.prefix.child(BLOB_INFIX).child(hex::encode(raw));
            match self.store.delete(&path).await {
                Ok(_) => Ok(()),
                Err(object_store::Error::NotFound { .. }) => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}

impl crate::repo::StorageClose for ObjectStoreRemote {
    type Error = Infallible;

    fn close(self) -> Result<(), Self::Error> {
        // No explicit close necessary for the remote object store adapter.
        Ok(())
    }
}

impl ObjectStoreSnapshot {
    fn blob_path(&self, handle_hex: String) -> Path {
        self.prefix.child(BLOB_INFIX).child(handle_hex)
    }
}

impl AsyncBlobStoreGet for ObjectStoreSnapshot {
    type GetError<E: Error + Send + Sync + 'static> = GetBlobErr<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> impl Future<Output = Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>> + Send
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let raw = handle.raw;
        async move {
            let path = self.blob_path(hex::encode(raw));
            let object = self.store.get(&path).await?;
            let bytes = object.bytes().await?;
            let bytes: Bytes = bytes.into();
            let blob: Blob<S> = Blob::new(bytes);
            let expected = Inline::<Hash<Blake3>>::new(raw);
            let actual = blob.get_handle().into();
            if actual != expected {
                return Err(GetBlobErr::HashMismatch { expected, actual });
            }
            blob.try_from_blob().map_err(GetBlobErr::Conversion)
        }
    }
}

impl AsyncBlobStoreList for ObjectStoreSnapshot {
    type Err = Infallible;

    fn blobs(&self) -> impl Future<Output = Vec<Result<BlobInfo, Self::Err>>> + Send {
        let blobs = self
            .blobs
            .iter()
            .map(|(raw, observed)| {
                Ok(BlobInfo {
                    handle: Inline::new(*raw),
                    length: observed.length,
                })
            })
            .collect();
        async move { blobs }
    }
}

impl AsyncBlobStoreMeta for ObjectStoreSnapshot {
    type MetaError = Infallible;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> impl Future<Output = Result<Option<BlobMetadata>, Self::MetaError>> + Send
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        let raw = handle.raw;
        let metadata = self.blobs.get(&raw).map(|observed| BlobMetadata {
            timestamp: observed.timestamp,
            length: observed.length,
        });
        async move { Ok(metadata) }
    }
}

impl AsyncCollectionRead for ObjectStoreSnapshot {
    type RecordsError = Infallible;

    fn records(
        &self,
    ) -> impl Future<Output = Result<Vec<CollectionRecord>, Self::RecordsError>> + Send {
        let records = self.collection_records.as_ref().clone();
        async move { Ok(records) }
    }

    fn collections(
        &self,
    ) -> impl Future<Output = Result<Vec<crate::collection::CollectionHandle>, Self::RecordsError>> + Send
    {
        // The listing that produced this snapshot already read every record.
        let collections =
            crate::collection::distinct_collections(self.collection_records.iter().copied());
        async move { Ok(collections) }
    }
}

fn blob_handle_from_path(prefix: &Path, location: &Path) -> Result<RawInline, ListBlobsErr> {
    let name = location
        .filename()
        .ok_or(ListBlobsErr::NotAFile("no filename"))?;
    if location != &prefix.child(name) {
        return Err(ListBlobsErr::NotDirectChild(location.to_string()));
    }
    RawInline::from_hex(name).map_err(ListBlobsErr::BadNameHex)
}

fn collection_record_fingerprint_from_path(
    prefix: &Path,
    location: &Path,
) -> Result<CollectionRecordFingerprint, ListCollectionRecordsErr> {
    let name = location
        .filename()
        .ok_or(ListCollectionRecordsErr::NotAFile("no filename"))?;
    if location != &prefix.child(name) {
        return Err(ListCollectionRecordsErr::NotDirectChild(
            location.to_string(),
        ));
    }
    let raw = RawInline::from_hex(name).map_err(ListCollectionRecordsErr::BadFingerprintHex)?;
    Ok(CollectionRecordFingerprint::from_raw(raw))
}

async fn read_collection_record(
    store: &dyn ObjectStore,
    prefix: &Path,
    location: Path,
) -> Result<Option<CollectionRecord>, ListCollectionRecordsErr> {
    let path_fingerprint = collection_record_fingerprint_from_path(prefix, &location)?;
    let object = store
        .get(&location)
        .await
        .map_err(ListCollectionRecordsErr::Get)?;
    let bytes = object
        .bytes()
        .await
        .map_err(ListCollectionRecordsErr::Get)?;
    let (record, record_fingerprint) = if matches!(bytes.first(), Some(2 | 3)) {
        let legacy = LegacyUnsignedCollectionEquation::from_bytes(&bytes)
            .map_err(ListCollectionRecordsErr::Decode)?;
        (None, legacy.fingerprint())
    } else if matches!(
        bytes.first(),
        Some(&COLLECTION_RECORD_KIND_MERGE_V2 | &COLLECTION_RECORD_KIND_DERIVE_V2)
    ) {
        // The live MERGE and DERIVE until lattice v2. Skipped rather than
        // failing the snapshot, so a namespace written before the cutover
        // still opens; their fingerprint is still checked against the path.
        let retired = RetiredCollectionEquation::from_bytes(&bytes)
            .map_err(ListCollectionRecordsErr::Decode)?;
        (None, retired.fingerprint())
    } else {
        let record = CollectionRecord::from_bytes_trusted(&bytes)
            .map_err(ListCollectionRecordsErr::Decode)?;
        (Some(record), record.fingerprint())
    };
    if record_fingerprint != path_fingerprint {
        return Err(ListCollectionRecordsErr::FingerprintMismatch {
            path: path_fingerprint,
            record: record_fingerprint,
        });
    }
    Ok(record)
}

/// Failure while freezing one object-store observation.
///
/// Snapshot construction is all-or-nothing: a malformed or unavailable
/// object in either immutable namespace prevents publication of a partial
/// authority view.
#[derive(Debug)]
pub enum ObjectStoreSnapshotError {
    /// Blob membership could not be observed and validated.
    Blobs(ListBlobsErr),
    /// Collection-record membership could not be observed and validated.
    CollectionRecords(ListCollectionRecordsErr),
}

impl From<ListBlobsErr> for ObjectStoreSnapshotError {
    fn from(error: ListBlobsErr) -> Self {
        Self::Blobs(error)
    }
}

impl From<ListCollectionRecordsErr> for ObjectStoreSnapshotError {
    fn from(error: ListCollectionRecordsErr) -> Self {
        Self::CollectionRecords(error)
    }
}

impl fmt::Display for ObjectStoreSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blobs(error) => write!(formatter, "failed to snapshot blobs: {error}"),
            Self::CollectionRecords(error) => {
                write!(formatter, "failed to snapshot collection records: {error}")
            }
        }
    }
}

impl Error for ObjectStoreSnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Blobs(error) => Some(error),
            Self::CollectionRecords(error) => Some(error),
        }
    }
}

/// Error returned while enumerating native collection records.
#[derive(Debug)]
pub enum ListCollectionRecordsErr {
    /// The object-store LIST operation failed.
    List(object_store::Error),
    /// A listed object had no filename component.
    NotAFile(&'static str),
    /// A listed object was nested below the one-fingerprint-per-object namespace.
    NotDirectChild(String),
    /// A listed filename was not a hexadecimal full-width fingerprint.
    BadFingerprintHex(<RawInline as FromHex>::Error),
    /// A listed record object could not be fetched.
    Get(object_store::Error),
    /// The stored bytes were not a canonical dense collection record.
    Decode(RecordDecodeError),
    /// The record's canonical-byte fingerprint did not match its object path.
    FingerprintMismatch {
        path: CollectionRecordFingerprint,
        record: CollectionRecordFingerprint,
    },
}

impl fmt::Display for ListCollectionRecordsErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List(error) => write!(f, "collection-record list failed: {error}"),
            Self::NotAFile(error) => write!(f, "collection-record list failed: {error}"),
            Self::NotDirectChild(path) => {
                write!(f, "collection-record object is not a direct child: {path}")
            }
            Self::BadFingerprintHex(error) => {
                write!(f, "collection-record filename is not hexadecimal: {error}")
            }
            Self::Get(error) => write!(f, "collection-record fetch failed: {error}"),
            Self::Decode(error) => write!(f, "collection-record decode failed: {error}"),
            Self::FingerprintMismatch { path, record } => write!(
                f,
                "collection-record path fingerprint {path:X} does not match decoded fingerprint {record:X}"
            ),
        }
    }
}

impl Error for ListCollectionRecordsErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::List(error) | Self::Get(error) => Some(error),
            Self::BadFingerprintHex(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::NotAFile(_) | Self::NotDirectChild(_) | Self::FingerprintMismatch { .. } => None,
        }
    }
}

/// Error returned while inserting one immutable collection record.
#[derive(Debug)]
pub enum InsertCollectionRecordErr {
    /// Creating the immutable record object failed.
    Store(object_store::Error),
    /// An existing object could not be fetched for idempotency validation.
    ReadExisting(object_store::Error),
    /// The fingerprint path already contained different bytes.
    ExistingMismatch {
        fingerprint: CollectionRecordFingerprint,
    },
}

impl fmt::Display for InsertCollectionRecordErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "collection-record insert failed: {error}"),
            Self::ReadExisting(error) => {
                write!(f, "failed to validate existing collection record: {error}")
            }
            Self::ExistingMismatch { fingerprint } => write!(
                f,
                "collection-record fingerprint {fingerprint:X} already contains different bytes"
            ),
        }
    }
}

impl Error for InsertCollectionRecordErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) | Self::ReadExisting(error) => Some(error),
            Self::ExistingMismatch { .. } => None,
        }
    }
}

/// Error returned while inserting one immutable content-addressed blob.
#[derive(Debug)]
pub enum PutBlobErr {
    /// Creating the immutable blob object failed.
    Store(object_store::Error),
    /// An existing object could not be fetched for idempotency validation.
    ReadExisting(object_store::Error),
    /// The content-addressed path already contained different bytes.
    ExistingMismatch {
        /// Handle encoded by the occupied object path.
        handle: Inline<Hash<Blake3>>,
    },
}

impl fmt::Display for PutBlobErr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "blob insert failed: {error}"),
            Self::ReadExisting(error) => {
                write!(formatter, "failed to validate existing blob: {error}")
            }
            Self::ExistingMismatch { handle } => write!(
                formatter,
                "blob handle {} already contains different bytes",
                Hash::<Blake3>::to_hex(handle)
            ),
        }
    }
}

impl Error for PutBlobErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) | Self::ReadExisting(error) => Some(error),
            Self::ExistingMismatch { .. } => None,
        }
    }
}

/// Error returned when retrieving a blob from the object store.
#[derive(Debug)]
pub enum GetBlobErr<E: Error> {
    /// The underlying object store operation failed.
    Store(object_store::Error),
    /// The fetched object's bytes did not hash to the requested content address.
    HashMismatch {
        /// Digest encoded by the requested object path.
        expected: Inline<Hash<Blake3>>,
        /// Digest computed from the fetched bytes.
        actual: Inline<Hash<Blake3>>,
    },
    /// The blob bytes could not be converted to the requested type.
    Conversion(E),
}

impl<E: Error> fmt::Display for GetBlobErr<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "object store error: {e}"),
            Self::HashMismatch { expected, actual } => write!(
                f,
                "object content hash mismatch: expected {}, got {}",
                Hash::<Blake3>::to_hex(expected),
                Hash::<Blake3>::to_hex(actual)
            ),
            Self::Conversion(e) => write!(f, "conversion error: {e}"),
        }
    }
}

impl<E: Error> Error for GetBlobErr<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            Self::HashMismatch { .. } | Self::Conversion(_) => None,
        }
    }
}

impl<E: Error> From<object_store::Error> for GetBlobErr<E> {
    fn from(e: object_store::Error) -> Self {
        Self::Store(e)
    }
}

/// Error returned when listing blobs from the object store.
#[derive(Debug)]
pub enum ListBlobsErr {
    /// The underlying list operation failed.
    List(object_store::Error),
    /// A listed object had no filename component.
    NotAFile(&'static str),
    /// A listed object was nested below the one-handle-per-object namespace.
    NotDirectChild(String),
    /// A listed object's filename was not valid hexadecimal.
    BadNameHex(<RawInline as FromHex>::Error),
}

impl fmt::Display for ListBlobsErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::List(e) => write!(f, "list failed: {e}"),
            Self::NotAFile(e) => write!(f, "list failed: {e}"),
            Self::NotDirectChild(path) => {
                write!(f, "blob object is not a direct child: {path}")
            }
            Self::BadNameHex(e) => write!(f, "list failed: {e}"),
        }
    }
}
impl Error for ListBlobsErr {}

#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.
    /// An equation names its input PAYLOAD; this used to pair it with a
    /// fingerprint citing a record that produced it.
    use super::*;

    use futures::executor::block_on;
    use object_store::memory::InMemory;

    use crate::blob::encodings::rawbytes::RawBytes;
    use crate::collection::descriptor::{identity_for_tests, named_for_tests};
    use crate::collection::{
        collection_merge_bytes_len, CollectionMerge, CollectionRead, CollectionStore,
        COLLECTION_RECORD_KIND_MERGE_V4,
    };
    use crate::repo::async_store::{
        AsyncBlobStoreGet, AsyncBlobStoreList, AsyncBlobStorePut, AsyncCollectionRead,
        AsyncSnapshotSource, Blocking,
    };
    use crate::repo::{SnapshotSource, StorageFlush};

    fn remote() -> ObjectStoreRemote {
        ObjectStoreRemote {
            store: Arc::new(InMemory::new()),
            prefix: Path::from("test-repository"),
        }
    }

    fn record(tag: u8) -> CollectionRecord {
        let descriptor = named_for_tests(
            &format!("tagged-{tag}"),
            Id::new([tag.wrapping_add(1).max(1); 16]).unwrap(),
        );
        CollectionRecord::Merge(
            CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                identity_for_tests(&descriptor),
                [
                    Inline::new([tag.wrapping_add(3); 32]),
                    Inline::new([tag.wrapping_add(4); 32]),
                ],
                Inline::new([tag.wrapping_add(5); 32]),
            )
            .unwrap(),
        )
    }

    #[test]
    fn native_collection_records_are_sorted_and_idempotent() {
        block_on(async {
            let mut store = remote();
            let first = record(1);
            let second = record(9);
            let before = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();

            AsyncCollectionStore::insert(&mut store, second)
                .await
                .unwrap();
            AsyncCollectionStore::insert(&mut store, first)
                .await
                .unwrap();
            AsyncCollectionStore::insert(&mut store, second)
                .await
                .unwrap();

            let first_path = store
                .prefix
                .child(COLLECTION_RECORD_INFIX)
                .child(hex::encode(first.fingerprint().raw()));
            let stored = store
                .store
                .get(&first_path)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            assert_eq!(stored.len(), 1 + collection_merge_bytes_len(2));
            assert_eq!(stored[0], COLLECTION_RECORD_KIND_MERGE_V4);

            let snapshot = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();
            assert!(AsyncCollectionRead::records(&before)
                .await
                .unwrap()
                .is_empty());
            let actual = AsyncCollectionRead::records(&snapshot).await.unwrap();
            let mut expected = vec![first, second];
            expected.sort_unstable_by_key(CollectionRecord::fingerprint);
            assert_eq!(actual, expected);
            let changes = snapshot.changes_since(&before);
            assert!(changes.contains(StoreChanges::COLLECTION_RECORDS));
            assert!(!changes.contains(StoreChanges::BLOBS));
        });
    }

    #[test]
    fn trusted_object_replay_does_not_reverify_signatures() {
        block_on(async {
            let mut store = remote();
            let mut bytes = record(1).to_bytes();
            *bytes.last_mut().unwrap() ^= 1;
            assert!(CollectionRecord::from_bytes(&bytes).is_err());
            let evidence = CollectionRecord::from_bytes_trusted(&bytes).unwrap();
            AsyncCollectionStore::insert(&mut store, evidence)
                .await
                .unwrap();
            let snapshot = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();
            assert_eq!(
                AsyncCollectionRead::records(&snapshot).await.unwrap(),
                vec![evidence]
            );
            assert!(evidence.verify_strict().is_err());
        });
    }

    #[test]
    fn retired_dense_equation_objects_stay_present_but_semantically_inert() {
        block_on(async {
            let mut store = remote();
            let current = record(1);
            AsyncCollectionStore::insert(&mut store, current)
                .await
                .unwrap();
            for (tag, fields) in [
                (2, vec![[1; 32], [2; 32], [3; 32], [4; 32]]),
                (3, vec![[1; 32], [2; 32], [4; 32]]),
            ] {
                let mut bytes = vec![tag];
                bytes.extend(fields.into_iter().flatten());
                let legacy = LegacyUnsignedCollectionEquation::from_bytes(&bytes).unwrap();
                let path = store
                    .prefix
                    .child(COLLECTION_RECORD_INFIX)
                    .child(hex::encode(legacy.fingerprint().raw()));
                store.store.put(&path, bytes.clone().into()).await.unwrap();
                let snapshot = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();
                assert_eq!(
                    AsyncCollectionRead::records(&snapshot).await.unwrap(),
                    vec![current]
                );
                assert_eq!(
                    store
                        .store
                        .get(&path)
                        .await
                        .unwrap()
                        .bytes()
                        .await
                        .unwrap()
                        .as_ref(),
                    bytes
                );
            }
        });
    }

    /// The live MERGE and DERIVE until lattice v2 (tags 4 and 5) are skipped
    /// by a snapshot, never a reason to refuse the namespace.
    #[test]
    fn retired_live_equation_objects_are_skipped_not_fatal() {
        block_on(async {
            let mut store = remote();
            let current = record(1);
            AsyncCollectionStore::insert(&mut store, current)
                .await
                .unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            for retired in [
                RetiredCollectionEquation::sign_merge_v8(
                    &key,
                    Inline::new([1; 32]),
                    Inline::new([2; 32]),
                    Inline::new([3; 32]),
                    Inline::new([4; 32]),
                ),
                RetiredCollectionEquation::sign_derive_v9(
                    &key,
                    Inline::new([1; 32]),
                    Inline::new([2; 32]),
                    Inline::new([4; 32]),
                ),
            ] {
                let bytes = retired.to_bytes();
                assert!(matches!(bytes[0], 4 | 5));
                let path = store
                    .prefix
                    .child(COLLECTION_RECORD_INFIX)
                    .child(hex::encode(retired.fingerprint().raw()));
                store.store.put(&path, bytes.clone().into()).await.unwrap();
                let snapshot = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();
                assert_eq!(
                    AsyncCollectionRead::records(&snapshot).await.unwrap(),
                    vec![current]
                );
            }
        });
    }

    #[test]
    fn collection_record_path_must_match_decoded_fingerprint() {
        block_on(async {
            let mut store = remote();
            let path_record = record(1);
            let stored_record = record(2);
            let path = store
                .prefix
                .child(COLLECTION_RECORD_INFIX)
                .child(hex::encode(path_record.fingerprint().raw()));
            let bytes: bytes::Bytes = stored_record.to_bytes().into();
            store.store.put(&path, bytes.into()).await.unwrap();

            assert!(matches!(
                AsyncCollectionStore::insert(&mut store, path_record).await,
                Err(InsertCollectionRecordErr::ExistingMismatch { fingerprint })
                    if fingerprint == path_record.fingerprint()
            ));

            assert!(matches!(
                AsyncSnapshotSource::snapshot(&mut store).await,
                Err(ObjectStoreSnapshotError::CollectionRecords(
                    ListCollectionRecordsErr::FingerprintMismatch { path, record }
                )) if path == path_record.fingerprint()
                    && record == stored_record.fingerprint()
            ));
        });
    }

    #[test]
    fn blob_get_can_fetch_later_bytes_without_advancing_the_snapshot() {
        block_on(async {
            let mut store = remote();
            let before = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();
            let unchanged = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();
            assert_eq!(before.clone().changes_since(&before), StoreChanges::NONE);
            assert_eq!(unchanged.changes_since(&before), StoreChanges::NONE);
            let bytes = Bytes::from_source(b"arrived after snapshot".to_vec());
            let handle = AsyncBlobStorePut::put::<RawBytes, _>(&mut store, bytes.clone())
                .await
                .unwrap();
            AsyncCollectionStore::insert(&mut store, record(1))
                .await
                .unwrap();

            assert!(AsyncBlobStoreList::blobs(&before).await.is_empty());
            let fetched: Blob<RawBytes> = AsyncBlobStoreGet::get(&before, handle).await.unwrap();
            assert_eq!(fetched.bytes, bytes);
            assert_eq!(fetched.get_handle(), handle);
            assert!(AsyncCollectionRead::records(&before)
                .await
                .unwrap()
                .is_empty());
            assert!(AsyncBlobStoreList::blobs(&before).await.is_empty());

            let after = AsyncSnapshotSource::snapshot(&mut store).await.unwrap();
            let fetched: Blob<RawBytes> = AsyncBlobStoreGet::get(&after, handle).await.unwrap();
            assert_eq!(fetched.bytes, bytes);
            assert_eq!(AsyncBlobStoreList::blobs(&after).await.len(), 1);
            let changes = after.changes_since(&before);
            assert!(changes.contains(StoreChanges::BLOBS));
            assert!(changes.contains(StoreChanges::COLLECTION_RECORDS));
        });
    }

    #[test]
    fn blob_retry_requires_exact_existing_bytes() {
        block_on(async {
            let mut store = remote();
            let expected = Bytes::from_source(b"canonical blob".to_vec());
            let handle = Blob::<RawBytes>::new(expected.clone()).get_handle();
            let path = store
                .prefix
                .child(BLOB_INFIX)
                .child(hex::encode(handle.raw));
            store
                .store
                .put(&path, bytes::Bytes::from_static(b"wrong bytes").into())
                .await
                .unwrap();

            assert!(matches!(
                AsyncBlobStorePut::put::<RawBytes, _>(&mut store, expected).await,
                Err(PutBlobErr::ExistingMismatch { handle: actual })
                    if actual.raw == handle.raw
            ));
        });
    }

    #[test]
    fn blob_retry_accepts_exact_existing_bytes() {
        block_on(async {
            let mut store = remote();
            let bytes = Bytes::from_source(b"canonical blob".to_vec());

            let first = AsyncBlobStorePut::put::<RawBytes, _>(&mut store, bytes.clone())
                .await
                .unwrap();
            let repeated = AsyncBlobStorePut::put::<RawBytes, _>(&mut store, bytes)
                .await
                .unwrap();

            assert_eq!(repeated, first);
        });
    }

    #[test]
    fn blocking_object_store_supports_collection_publication_flush() {
        let mut store = Blocking::new(remote()).unwrap();
        let record = record(17);

        CollectionStore::insert(&mut store, record).unwrap();
        StorageFlush::flush(&mut store).unwrap();
        let snapshot = SnapshotSource::snapshot(&mut store).unwrap();
        let actual = CollectionRead::records(&snapshot)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, vec![record]);
    }
}
