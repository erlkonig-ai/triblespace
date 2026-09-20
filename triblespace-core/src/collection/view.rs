//! Immutable collection observations and logical views over their realized
//! covers.
//!
//! A [`CollectionSnapshot`] owns the store observation against which its
//! realized target cover is valid. Its support comes with it, read from the
//! coverage index by the same selection. Logical values remain caller-chosen
//! projections reconstructed through [`TryFromCover`].

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::repo::{BlobStoreGet, StoreChanges, StoreRead, StoreSnapshot};
use crate::trible::Fragment;

use super::observed_store::{DependencyTracker, ObservedStore};
use super::{
    CollectionData, CollectionDescriptorError, CollectionEncoding, CollectionHandle,
    CollectionRealizationError, Cover, CoverageRead, RecordDecodeError, Support,
};

/// One immutable collection observation and what it stands on.
///
/// The cover is the target's resident frontier, selected from the coverage
/// index; the support is the union of what those nodes stand for, taken from
/// the same index in the same selection. Reading the value does not require
/// the historical inputs to be present. Logical views are reconstructed on
/// demand with [`Self::view`].
pub struct CollectionSnapshot<R, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    snapshot: R,
    support: Support,
    cover: Cover<E>,
    /// The lineage the support stands on. Charged to the read-set when the
    /// support is asked for, not when the cover is attached: the cover moves
    /// on the target's records, the support on the whole lineage's.
    support_lineage: BTreeSet<CollectionHandle>,
    dependencies: DependencyTracker,
}

impl<R, E> Clone for CollectionSnapshot<R, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    fn clone(&self) -> Self {
        Self {
            snapshot: self.snapshot.clone(),
            support: self.support.clone(),
            cover: self.cover.clone(),
            support_lineage: self.support_lineage.clone(),
            dependencies: self.dependencies.clone(),
        }
    }
}

impl<R, E> CollectionSnapshot<R, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    /// Pair one store observation with a cover and support taken from the
    /// coverage index's frontier. The cover's read-set is already in
    /// `dependencies`; the support's lineage is charged when it is asked for.
    pub(crate) fn from_frontier(
        snapshot: R,
        support: Support,
        cover: Cover<E>,
        lineage: BTreeSet<CollectionHandle>,
        dependencies: DependencyTracker,
    ) -> Self {
        Self {
            snapshot,
            support,
            cover,
            support_lineage: lineage,
            dependencies,
        }
    }

    /// Immutable store observation against which the cover and provenance are valid.
    pub fn snapshot(&self) -> &R {
        &self.snapshot
    }

    /// Whether all consulted store dependencies are unchanged in `snapshot`.
    ///
    /// Missing records and blobs are dependencies too. Unrelated appends do
    /// not invalidate an observation on backends with scoped indexes. A false
    /// result is conservative: a reattachment may still select the same cover.
    /// Application clocks and deadlines are independent of this comparison.
    /// Reading a view or requesting support extends the tracked read-set.
    pub fn is_current(&self, snapshot: &R) -> bool {
        let dependencies = self
            .dependencies
            .lock()
            .expect("dependency tracker poisoned");
        snapshot.changes_for(&self.snapshot, &dependencies) == StoreChanges::NONE
    }

    /// The foundational support this observation stands on.
    ///
    /// The support stands on the whole lineage's records, so asking for it is
    /// what makes them a dependency of this observation; the cover alone
    /// depends only on the target's own. The one storage read this performs
    /// is that charge.
    pub fn support(&self) -> Result<&Support, CollectionRealizationError>
    where
        R: StoreRead,
    {
        let observed =
            ObservedStore::with_tracker(self.snapshot.clone(), self.dependencies.clone());
        observed
            .coverage(&self.support_lineage)
            .map_err(|error| CollectionRealizationError::storage("charge support lineage", error))?;
        Ok(&self.support)
    }

    /// Resident target cover selected from the coverage index.
    pub fn cover(&self) -> &Cover<E> {
        &self.cover
    }

    /// Reconstruct one caller-chosen logical value from the realized cover.
    pub fn view<V>(&self) -> Result<V, TryFromCoverError<R::GetError<Infallible>, V::Error>>
    where
        R: BlobStoreGet,
        V: TryFromCover<E>,
    {
        let observed =
            ObservedStore::with_tracker(self.snapshot.clone(), self.dependencies.clone());
        let descriptor =
            super::api::load_collection_descriptor(&observed, self.cover.collection().handle())
                .map_err(TryFromCoverError::from)?;
        V::try_from_cover(&self.cover, &descriptor.fragment, &observed)
    }

    /// Consume this snapshot into its store observation and exact covers.
    pub fn into_parts(self) -> Result<(R, Support, Cover<E>), CollectionRealizationError>
    where
        R: StoreRead,
    {
        self.support()?;
        Ok((self.snapshot, self.support, self.cover))
    }
}

/// Failure at the generic boundary between a physical cover and its logical
/// interpretation.
#[derive(Debug)]
pub enum TryFromCoverError<GetError, ViewError> {
    /// The cover's canonical collection descriptor could not be fetched.
    DescriptorGet {
        /// Canonical collection identity.
        collection: CollectionHandle,
        /// Backend fetch failure.
        source: GetError,
    },
    /// The fetched descriptor was not a canonical collection descriptor.
    InvalidDescriptor {
        /// Canonical collection identity.
        collection: CollectionHandle,
        /// Structural descriptor decoding failure.
        source: RecordDecodeError,
    },
    /// One exact physical member could not be fetched from the snapshot.
    MemberGet {
        /// Selected physical member.
        member: CollectionData,
        /// Backend fetch failure.
        source: GetError,
    },
    /// Resident member bytes could not form the requested logical value.
    View(ViewError),
}

impl<GetError, ViewError> fmt::Display for TryFromCoverError<GetError, ViewError>
where
    GetError: fmt::Display,
    ViewError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DescriptorGet { collection, source } => write!(
                formatter,
                "failed to fetch collection descriptor {}: {source}",
                hex::encode_upper(collection.raw),
            ),
            Self::InvalidDescriptor { collection, source } => write!(
                formatter,
                "collection descriptor {} is invalid: {source}",
                hex::encode_upper(collection.raw),
            ),
            Self::MemberGet { member, source } => write!(
                formatter,
                "failed to fetch cover member {}: {source}",
                hex::encode_upper(member.raw),
            ),
            Self::View(source) => source.fmt(formatter),
        }
    }
}

impl<GetError, ViewError> Error for TryFromCoverError<GetError, ViewError>
where
    GetError: Error + 'static,
    ViewError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DescriptorGet { source, .. } => Some(source),
            Self::InvalidDescriptor { source, .. } => Some(source),
            Self::MemberGet { source, .. } => Some(source),
            Self::View(source) => Some(source),
        }
    }
}

impl<GetError, ViewError> From<CollectionDescriptorError<GetError>>
    for TryFromCoverError<GetError, ViewError>
{
    fn from(source: CollectionDescriptorError<GetError>) -> Self {
        match source {
            CollectionDescriptorError::Get { collection, source } => {
                Self::DescriptorGet { collection, source }
            }
            CollectionDescriptorError::Invalid { collection, source } => {
                Self::InvalidDescriptor { collection, source }
            }
        }
    }
}

/// Low-level reconstruction hook for one selected typed physical cover.
///
/// This is deliberately cover-aware rather than a blanket blob conversion:
/// some values eagerly join members, while others retain mmap-backed shards
/// and answer queries over the union without constructing one monolith.
pub trait TryFromCover<L: CollectionEncoding>: Sized {
    /// Failure to construct the logical view from the resolved cover.
    type Error: Error + Send + Sync + 'static;

    /// Reconstruct the logical value named by `cover` through `snapshot`.
    ///
    /// Normal callers use [`CollectionSnapshot::view`], which passes the exact
    /// realized cover, its canonical descriptor, and the immutable store
    /// observation that validated it. Encoding-specific parameters belong in
    /// the descriptor rather than in a lifecycle facade around the collection.
    fn try_from_cover<R>(
        cover: &Cover<L>,
        descriptor: &Fragment,
        snapshot: &R,
    ) -> Result<Self, TryFromCoverError<R::GetError<Infallible>, Self::Error>>
    where
        R: BlobStoreGet;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::encodings::succinctarchive::SuccinctArchiveBlob;
    use crate::collection::observed_store::ObservedStore;
    use crate::collection::{Collection, CollectionData, CollectionHandle};
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::SnapshotSource;

    use super::{CollectionSnapshot, Cover, Support};

    #[test]
    fn snapshot_keeps_foundational_support_separate_from_target_cover() {
        let foundation = Collection::<SimpleArchive>::from_handle(CollectionHandle::new([1; 32]));
        let target = Collection::<SuccinctArchiveBlob>::from_handle(CollectionHandle::new([2; 32]));
        let support = Support::from_data(foundation, [CollectionData::new([3; 32])]);
        let cover = Cover::from_data(target, [CollectionData::new([4; 32])]);
        let mut store = MemoryRepo::default();
        let store_snapshot = store.snapshot().unwrap();

        let snapshot = CollectionSnapshot::from_frontier(
            store_snapshot.clone(),
            support.clone(),
            cover.clone(),
            BTreeSet::new(),
            ObservedStore::new(store_snapshot.clone()).tracker(),
        );
        assert!(snapshot.snapshot() == &store_snapshot);
        assert_eq!(snapshot.support().unwrap(), &support);
        assert_eq!(snapshot.cover(), &cover);

        let (actual_store, actual_support, actual_cover) = snapshot.into_parts().unwrap();
        assert!(actual_store == store_snapshot);
        assert_eq!(actual_support, support);
        assert_eq!(actual_cover, cover);
    }
}
