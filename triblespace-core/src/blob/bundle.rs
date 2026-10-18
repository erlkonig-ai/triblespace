use std::fmt;
use std::iter::{once, Once};

use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::trible::{Fragment, Spread, TribleSet};

use super::{Blob, BlobEncoding, MemoryBlobStore};

/// A typed blob root together with explicitly carried blob attachments.
///
/// Unlike a [`Fragment`], a bundle exports a blob handle rather than entity IDs
/// and carries no facts or metafacts. Spreading it into an `entity!` repeated
/// attribute emits that one handle and merges its blobs into the resulting
/// fragment's attachment store:
///
/// ```
/// use triblespace_core::prelude::*;
/// use blobencodings::RawBytes;
/// use inlineencodings::Handle;
///
/// attributes! { body: Handle<RawBytes>; }
///
/// let root: Blob<RawBytes> = b"payload".as_slice().to_blob();
/// let bundle = Bundle::new(root, MemoryBlobStore::new());
/// let handle = bundle.root();
/// let fragment = entity! { body*: bundle };
/// assert_eq!(fragment.facts().len(), 1);
/// let mut blobs = fragment.blobs().clone();
/// let bytes: triblespace_core::blob::Bytes = blobs.snapshot().unwrap().get(handle).unwrap();
/// assert_eq!(&*bytes, b"payload");
/// ```
///
/// Construction includes the root's bytes and keeps all supplied attachments,
/// including ones not referenced by the root. It neither discovers dependencies
/// nor promises a complete transitive closure. A bundle is an in-memory carrier,
/// not an encoding or new stored record: publication copies its carried bytes,
/// while later GC and synchronization reachability still depend on references
/// exposed by the stored blob formats.
pub struct Bundle<S: BlobEncoding> {
    root: Inline<Handle<S>>,
    blobs: MemoryBlobStore,
}

impl<S: BlobEncoding> Bundle<S> {
    /// Includes `root` in the supplied store, reusing its cached handle.
    ///
    /// Equal content deduplicates through the store's ordinary insertion path.
    pub fn new(root: Blob<S>, mut blobs: MemoryBlobStore) -> Self {
        let root = blobs.insert(root);
        Self { root, blobs }
    }

    /// Returns the typed handle of the root blob.
    pub fn root(&self) -> Inline<Handle<S>> {
        self.root
    }

    /// Borrows all carried blobs, including the root.
    pub fn blobs(&self) -> &MemoryBlobStore {
        &self.blobs
    }

    /// Consumes the bundle into its typed root and carried blob store.
    pub fn into_parts(self) -> (Inline<Handle<S>>, MemoryBlobStore) {
        (self.root, self.blobs)
    }
}

impl<S: BlobEncoding> Clone for Bundle<S> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            blobs: self.blobs.clone(),
        }
    }
}

impl<S: BlobEncoding> fmt::Debug for Bundle<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bundle")
            .field("root", &self.root)
            .field("blobs", &self.blobs)
            .finish()
    }
}

impl<S: BlobEncoding> Spread for Bundle<S> {
    type Item = Inline<Handle<S>>;
    type Iter = Once<Self::Item>;

    fn spread(self) -> (Self::Iter, Fragment) {
        let (root, blobs) = self.into_parts();
        let extras = Fragment::from_facts_and_blobs(TribleSet::new(), blobs);
        (once(root), extras)
    }
}
