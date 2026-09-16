use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::blob::BlobEncoding;
use crate::blob::IntoBlob;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::inline::INLINE_LEN;
use crate::patch::{Entry, IdentitySchema, XorSip128, PATCH};
use crate::repo::BlobInfo;
use crate::repo::BlobStoreGet;
use crate::repo::BlobStoreKeep;
use crate::repo::BlobStoreList;
use crate::repo::BlobStorePut;
use crate::repo::{SnapshotSource, StoreSnapshot};

use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::fmt::{self};
use std::iter::FromIterator;

use super::TryFromBlob;

type BlobIndex = PATCH<INLINE_LEN, IdentitySchema, Blob<UnknownBlob>, XorSip128>;

/// In-memory blob storage keyed by content-hash handle.
///
/// Internally a [`PATCH`] mapping the 32-byte raw handle to a
/// [`Blob<UnknownBlob>`]. Writes go through `&mut self` (the
/// type system enforces single-writer);
/// [`snapshot`](SnapshotSource::snapshot) hands out owned snapshots that are
/// independent of the original
/// store. PATCH's structural sharing makes those snapshots
/// O(1) clones — the writer keeps mutating the canonical
/// PATCH; snapshots each hold a pinned Arc-clone.
///
pub struct MemoryBlobStore {
    blobs: BlobIndex,
}

impl Debug for MemoryBlobStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryBlobStore")
    }
}

#[derive(Debug)]
/// Snapshot view into a [`MemoryBlobStore`]. Independent from
/// the source store — subsequent writes to the store are not
/// visible to a snapshot produced earlier; call
/// [`snapshot`](SnapshotSource::snapshot) again
/// to pick them up.
///
/// `Clone` is O(1) (PATCH structural sharing). The snapshot is
/// `Send + Sync` and freely composes through `find!` /
/// `pattern!` / `and!` / `or!`.
///
pub struct MemoryBlobStoreSnapshot {
    blobs: BlobIndex,
}

impl Clone for MemoryBlobStoreSnapshot {
    fn clone(&self) -> Self {
        MemoryBlobStoreSnapshot {
            blobs: self.blobs.clone(),
        }
    }
}

impl PartialEq for MemoryBlobStoreSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.blobs == other.blobs
    }
}

impl Eq for MemoryBlobStoreSnapshot {}

impl MemoryBlobStoreSnapshot {
    fn new(blobs: BlobIndex) -> Self {
        MemoryBlobStoreSnapshot { blobs }
    }

    /// Number of blobs in this snapshot.
    pub fn len(&self) -> usize {
        self.blobs.len() as usize
    }

    /// True iff the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterator over `(handle, blob)` pairs in this snapshot.
    /// Iteration order is unspecified.
    pub fn iter(&self) -> MemoryBlobStoreIter {
        let for_iter = self.blobs.clone();
        let lookup = for_iter.clone();
        MemoryBlobStoreIter {
            keys: for_iter.into_iter(),
            lookup,
        }
    }
}

impl Clone for MemoryBlobStore {
    fn clone(&self) -> Self {
        MemoryBlobStore {
            blobs: self.blobs.clone(),
        }
    }
}

impl PartialEq for MemoryBlobStore {
    fn eq(&self, other: &Self) -> bool {
        self.blobs == other.blobs
    }
}

impl Eq for MemoryBlobStore {}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBlobStore {
    /// Creates a new [`MemoryBlobStore`] with no blobs.
    pub fn new() -> MemoryBlobStore {
        MemoryBlobStore {
            blobs: PATCH::new(),
        }
    }

    /// Inserts `blob` into the store and returns its handle.
    ///
    /// O(1) over the handle computation — the handle was hashed once
    /// at `Blob::new` and cached in the blob; this method reuses it.
    /// Idempotent at the PATCH level: re-inserting the same handle is
    /// a no-op, which matches the content-addressed semantics
    /// (same handle ⇒ same bytes).
    pub fn insert<S>(&mut self, blob: Blob<S>) -> Inline<Handle<S>>
    where
        S: BlobEncoding,
        Handle<S>: crate::inline::InlineEncoding,
    {
        let handle: Inline<Handle<S>> = blob.get_handle();
        let unknown_handle: Inline<Handle<UnknownBlob>> = handle.transmute();
        let blob: Blob<UnknownBlob> = blob.transmute::<UnknownBlob>();
        let entry = Entry::with_value(&unknown_handle.raw, blob);
        self.blobs.insert(&entry);
        handle
    }

    /// Number of distinct blobs in the store.
    pub fn len(&self) -> usize {
        self.blobs.len() as usize
    }

    /// True iff the store contains no blobs.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Structurally merge `other` into this store, consuming `other`.
    ///
    /// Handle bytes match by content-addressing — duplicate keys
    /// collapse via PATCH's union semantics (idempotent). Faster
    /// than per-blob `BlobStorePut::put`: PATCH's `union` is a
    /// structural merge — cost is bounded by the size of the
    /// non-overlapping subtrees, not the total blob count.
    pub fn union(&mut self, other: Self) {
        self.blobs.union(other.blobs);
    }

    /// Drops any blobs that are not referenced by one of the provided tribles.
    pub fn keep<I>(&mut self, handles: I)
    where
        I: IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
    {
        let mut surviving = PATCH::new();
        for handle in handles {
            if let Some(blob) = self.blobs.get(&handle.raw) {
                let entry = Entry::with_value(&handle.raw, blob.clone());
                surviving.insert(&entry);
            }
        }
        self.blobs = surviving;
    }
}

impl BlobStoreKeep for MemoryBlobStore {
    fn keep<I>(&mut self, handles: I)
    where
        I: IntoIterator<Item = Inline<Handle<UnknownBlob>>>,
    {
        MemoryBlobStore::keep(self, handles);
    }
}

impl FromIterator<(Inline<Handle<UnknownBlob>>, Blob<UnknownBlob>)> for MemoryBlobStore {
    fn from_iter<I: IntoIterator<Item = (Inline<Handle<UnknownBlob>>, Blob<UnknownBlob>)>>(
        iter: I,
    ) -> Self {
        let mut store = MemoryBlobStore::new();
        for (handle, blob) in iter {
            let entry = Entry::with_value(&handle.raw, blob);
            store.blobs.insert(&entry);
        }
        store
    }
}

impl IntoIterator for MemoryBlobStoreSnapshot {
    type Item = (Inline<Handle<UnknownBlob>>, Blob<UnknownBlob>);
    type IntoIter = MemoryBlobStoreIter;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
pub enum MemoryStoreGetError<E: Error> {
    /// This error occurs when a blob is requested that does not exist in the store.
    NotFound(),
    /// This error occurs when a blob is requested that exists, but cannot be converted to the requested type.
    ConversionFailed(E),
}

impl<E: Error> fmt::Display for MemoryStoreGetError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryStoreGetError::NotFound() => write!(f, "Blob not found in memory store"),
            MemoryStoreGetError::ConversionFailed(e) => write!(f, "Blob conversion failed: {e}"),
        }
    }
}

impl<E: Error> Error for MemoryStoreGetError<E> {}

/// Iterator returned by [`MemoryBlobStoreSnapshot::iter`].
///
/// Yields `(Handle, Blob)` pairs. Owned snapshot via PATCH
/// clones — does not borrow from the source snapshot.
pub struct MemoryBlobStoreIter {
    keys: crate::patch::PATCHIntoIterator<INLINE_LEN, IdentitySchema, Blob<UnknownBlob>, XorSip128>,
    lookup: BlobIndex,
}

impl Debug for MemoryBlobStoreIter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryBlobStoreIter").finish()
    }
}

impl Iterator for MemoryBlobStoreIter {
    type Item = (Inline<Handle<UnknownBlob>>, Blob<UnknownBlob>);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.keys.next()?;
        let handle: Inline<Handle<UnknownBlob>> = Inline::new(key);
        let blob = self
            .lookup
            .get(&key)
            .cloned()
            .expect("key from PATCH iterator must resolve in the same snapshot");
        Some((handle, blob))
    }
}

/// Adapter over [`MemoryBlobStoreIter`] that yields blob information.
pub struct MemoryBlobStoreListIter {
    inner: MemoryBlobStoreIter,
}

impl Iterator for MemoryBlobStoreListIter {
    type Item = Result<BlobInfo, Infallible>;

    fn next(&mut self) -> Option<Self::Item> {
        let (handle, blob) = self.inner.next()?;
        Some(Ok(BlobInfo {
            handle,
            length: blob.bytes.len() as u64,
        }))
    }
}

impl BlobStoreList for MemoryBlobStoreSnapshot {
    type Iter<'a> = MemoryBlobStoreListIter;
    type Err = Infallible;

    fn blobs(&self) -> Self::Iter<'static> {
        MemoryBlobStoreListIter { inner: self.iter() }
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: crate::inline::InlineEncoding,
    {
        Ok(self.blobs.get(&handle.raw).is_some())
    }
}

impl crate::repo::BlobStoreMeta for MemoryBlobStoreSnapshot {
    type MetaError = Infallible;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<crate::repo::BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: crate::inline::InlineEncoding,
    {
        Ok(self
            .blobs
            .get(&handle.raw)
            .map(|blob| crate::repo::BlobMetadata {
                timestamp: 0,
                length: blob.bytes.len() as u64,
            }))
    }
}

impl BlobStoreGet for MemoryBlobStoreSnapshot {
    type GetError<E: Error + Send + Sync + 'static> = MemoryStoreGetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding,
        T: TryFromBlob<S>,
    {
        let handle: Inline<Handle<UnknownBlob>> = handle.transmute();
        let Some(blob) = self.blobs.get(&handle.raw) else {
            return Err(MemoryStoreGetError::NotFound());
        };
        let blob: Blob<S> = blob.clone().transmute();
        match blob.try_from_blob() {
            Ok(value) => Ok(value),
            Err(e) => Err(MemoryStoreGetError::ConversionFailed(e)),
        }
    }
}

impl crate::repo::BlobChildren for MemoryBlobStoreSnapshot {}

impl BlobStorePut for MemoryBlobStore {
    type PutError = Infallible;

    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding,
        T: IntoBlob<S>,
    {
        let blob = item.to_blob();
        let handle = blob.get_handle();
        self.insert(blob);
        Ok(handle)
    }
}

impl StoreSnapshot for MemoryBlobStoreSnapshot {
    fn changes_since(&self, previous: &Self) -> crate::repo::StoreChanges {
        if self.blobs == previous.blobs {
            crate::repo::StoreChanges::NONE
        } else {
            crate::repo::StoreChanges::BLOBS
        }
    }
}

impl SnapshotSource for MemoryBlobStore {
    type Snapshot = MemoryBlobStoreSnapshot;
    type SnapshotError = Infallible;

    fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
        Ok(MemoryBlobStoreSnapshot::new(self.blobs.clone()))
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    use super::*;
    use anybytes::Bytes;

    use blobencodings::UTF8String;
    use inlineencodings::Handle;

    attributes! {
        "5AD0FAFB1FECBC197A385EC20166899E" unsafe as description: Handle<UTF8String>;
    }

    #[test]
    fn potential_handles_retain_value_handles() {
        use crate::repo::potential_handles;
        use crate::trible::TribleSet;

        let mut kb = TribleSet::new();
        let mut blobs = MemoryBlobStore::new();
        let retained = blobs
            .put::<UTF8String, _>(Bytes::from_source("retained".to_owned()).view().unwrap())
            .unwrap();
        let discarded = blobs
            .put::<UTF8String, _>(Bytes::from_source("discarded".to_owned()).view().unwrap())
            .unwrap();
        kb += entity! { description: retained };

        let candidates: Vec<_> = potential_handles(&kb).collect();
        assert_eq!(candidates, vec![retained.transmute()]);

        blobs.keep(candidates);
        let reader = blobs.snapshot().unwrap();
        assert!(reader.get::<View<str>, UTF8String>(retained).is_ok());
        assert!(reader.get::<View<str>, UTF8String>(discarded).is_err());
    }

    /// `MemoryBlobStoreSnapshot` must be `Send + Sync` so it composes
    /// through the parallel-iter ready `and!` / `or!` macros.
    #[test]
    fn snapshot_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MemoryBlobStoreSnapshot>();
    }

    /// `snapshot()` returns an independent observation — writes after
    /// it is produced are not visible to that snapshot.
    #[test]
    fn snapshot_is_pinned() {
        let mut store = MemoryBlobStore::new();
        let blob_a: Inline<Handle<UTF8String>> = store
            .put(Bytes::from_source("hello".to_string()).view().unwrap())
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.len(), 1);

        let _blob_b: Inline<Handle<UTF8String>> = store
            .put(Bytes::from_source("world".to_string()).view().unwrap())
            .unwrap();
        // The snapshot still has only the original blob.
        assert_eq!(snapshot.len(), 1);
        use anybytes::View;
        let recovered: View<str> = snapshot.get::<View<str>, UTF8String>(blob_a).unwrap();
        assert_eq!(&*recovered, "hello");

        // A fresh snapshot sees both.
        let fresh = store.snapshot().unwrap();
        assert_eq!(fresh.len(), 2);
    }

    #[test]
    fn snapshot_change_classification_uses_patch_identity() {
        let mut store = MemoryBlobStore::new();
        let before = store.snapshot().unwrap();
        let unchanged = store.snapshot().unwrap();
        assert_eq!(before, before.clone());
        assert_eq!(before, unchanged);
        assert_eq!(
            unchanged.changes_since(&before),
            crate::repo::StoreChanges::NONE
        );

        store
            .put::<UTF8String, _>(Bytes::from_source("new".to_string()).view().unwrap())
            .unwrap();
        let after = store.snapshot().unwrap();
        assert_ne!(after, before);
        assert!(before.is_empty());
        assert_eq!(
            after.changes_since(&before),
            crate::repo::StoreChanges::BLOBS,
        );
    }

    #[test]
    fn listing_reports_stored_lengths() {
        let mut store = MemoryBlobStore::new();
        let handle = store
            .put::<UTF8String, _>(Bytes::from_source("hello".to_string()).view().unwrap())
            .unwrap();

        let listed: Vec<_> = store
            .snapshot()
            .unwrap()
            .blobs()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            listed,
            vec![crate::repo::BlobInfo {
                handle: handle.transmute(),
                length: 5,
            }]
        );
    }

    /// `union` structurally merges two stores; handles round-trip.
    #[test]
    fn union_merges_and_preserves_handles() {
        let mut a = MemoryBlobStore::new();
        let h_hello: Inline<Handle<UTF8String>> = a
            .put(Bytes::from_source("hello".to_string()).view().unwrap())
            .unwrap();
        let mut b = MemoryBlobStore::new();
        let h_world: Inline<Handle<UTF8String>> = b
            .put(Bytes::from_source("world".to_string()).view().unwrap())
            .unwrap();
        // Idempotent overlap: putting "hello" in b too — union should
        // collapse the duplicate, not double-count.
        let _h_hello_b: Inline<Handle<UTF8String>> = b
            .put(Bytes::from_source("hello".to_string()).view().unwrap())
            .unwrap();

        a.union(b);
        assert_eq!(
            a.snapshot().unwrap().len(),
            2,
            "duplicates collapse via union"
        );

        use anybytes::View;
        let recovered_hello: View<str> = a
            .snapshot()
            .unwrap()
            .get::<View<str>, UTF8String>(h_hello)
            .unwrap();
        assert_eq!(&*recovered_hello, "hello");
        let recovered_world: View<str> = a
            .snapshot()
            .unwrap()
            .get::<View<str>, UTF8String>(h_world)
            .unwrap();
        assert_eq!(&*recovered_world, "world");
    }
}
