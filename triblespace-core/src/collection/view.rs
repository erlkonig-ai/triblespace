//! Immutable collection observations and logical views over their realized
//! covers.
//!
//! A [`CollectionSnapshot`] owns the store observation against which its
//! realized target cover is valid. Its support comes with it, read from the
//! coverage index by the same selection: a cover of the collection's own
//! foundations. Whether a derived collection has caught up with its source
//! is [`CollectionSnapshot::missing_from`]. Logical values remain
//! caller-chosen projections reconstructed through [`TryFromCover`].

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::inline::encodings::hash::Handle;
use crate::repo::{BlobStoreGet, StoreChanges, StoreRead, StoreSnapshot};
use crate::trible::Fragment;

use super::observed_store::{DependencyTracker, ObservedStore};
use super::{
    CollectionData, CollectionDescriptorError, CollectionEncoding, CollectionHandle,
    CollectionRealizationError, Cover, CoverageRead, MapMapping, RecordDecodeError, SourceLocator,
    Support,
};

/// One immutable collection observation and what it stands on.
///
/// The cover is the target's resident frontier, selected from the coverage
/// index; the support is the union of what those nodes stand for, taken from
/// the same index in the same selection: the target's own foundations.
/// Reading the value does not require the historical inputs to be present.
/// Logical views are reconstructed on demand with [`Self::view`].
pub struct CollectionSnapshot<R, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    snapshot: R,
    support: Support<E>,
    cover: Cover<E>,
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
    /// coverage index's frontier. Both are read from the target's own rows,
    /// whose read-set is already in `dependencies`.
    pub(crate) fn from_frontier(
        snapshot: R,
        support: Support<E>,
        cover: Cover<E>,
        dependencies: DependencyTracker,
    ) -> Self {
        Self {
            snapshot,
            support,
            cover,
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

    /// What this observation stands on: a cover of the collection's own
    /// foundations -- commit payloads for a root, leaf images for a derived
    /// collection.
    ///
    /// It is read from the target's own rows, the same ones the cover came
    /// from, so it adds nothing to the read-set. Two collections' supports
    /// are never comparable; ask [`Self::missing_from`] whether a derived
    /// collection has caught up with its source.
    pub fn support(&self) -> Result<&Support<E>, CollectionRealizationError>
    where
        R: StoreRead,
    {
        Ok(&self.support)
    }

    /// The foundations of `source` this observation does not answer for:
    /// the freshness of a view against a source observation.
    ///
    /// Each source foundation `F` is looked up by its locator `L(F)` in this
    /// collection's leaves, the DERIVE relation read by its own key, and
    /// counts as answered only when one of its outputs is in this
    /// observation's support, which is what [`Self::view`] reads. A leaf whose
    /// image is not here yet, and is under no resident merge, is still
    /// missing: a caller that treated the leaf record as delivery would skip
    /// facts it never saw. Nothing is compared between the two collections'
    /// supports. `source` must be the collection this one's descriptor names
    /// as its source; the two observations may be of different store
    /// snapshots, and the answer is then this view against that source's
    /// foundations.
    pub fn missing_from<RS, S>(
        &self,
        source: &CollectionSnapshot<RS, S>,
    ) -> Result<Cover<S>, CollectionRealizationError>
    where
        R: StoreRead,
        RS: StoreRead,
        S: CollectionEncoding,
    {
        let target = self.cover.collection().handle();
        let observed =
            ObservedStore::with_tracker(self.snapshot.clone(), self.dependencies.clone());
        let descriptor = super::api::load_collection_descriptor(&observed, target)
            .map_err(|error| CollectionRealizationError::storage("read view descriptor", error))?;
        let named = super::descriptor::source(descriptor.fragment.facts()).map_err(|error| {
            CollectionRealizationError::resolution_from("read view source", error)
        })?;
        let source_collection = source.cover().collection();
        if named != Some(source_collection.handle()) {
            return Err(CollectionRealizationError::InvalidCover(format!(
                "collection {} does not derive from {}",
                hex::encode_upper(target.raw),
                hex::encode_upper(source_collection.handle().raw),
            )));
        }
        let coverage = observed
            .coverage(&BTreeSet::from([target]))
            .map_err(|error| CollectionRealizationError::storage("read view leaves", error))?;
        let missing = source.support()?.data_members().filter(|foundation| {
            !coverage
                .leaf_outputs(target, SourceLocator::of(foundation.raw))
                .into_iter()
                .any(|output| {
                    self.support
                        .contains(crate::inline::Inline::new(output.raw))
                })
        });
        Ok(Cover::from_data(source_collection, missing))
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

    /// Consume this snapshot into its store observation, its support and its
    /// cover.
    pub fn into_parts(self) -> Result<(R, Support<E>, Cover<E>), CollectionRealizationError>
    where
        R: StoreRead,
    {
        Ok((self.snapshot, self.support, self.cover))
    }
}

/// One immutable observation of an attached collection: the attached cover
/// over its parent's lattice.
///
/// The cover is a set of attachments, one per parent node taken; the
/// support is the parent foundations those nodes stand for, read from the
/// parent's own rows in the same observation; the residual is the parent
/// foundations no attachment reaches. An attached collection has no support
/// of its own: it stands for its parent's.
pub struct AttachedSnapshot<R, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    snapshot: R,
    cover: Cover<E>,
    support: Support<SimpleArchive>,
    residual: Support<SimpleArchive>,
    dependencies: DependencyTracker,
}

#[cfg(feature = "object-store")]
impl<R, E> AttachedSnapshot<crate::repo::async_store::AcquiringReader<R>, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    /// Remove only the acquisition adapter, retaining this selected cover,
    /// support, residual and read-set. This extracts the exact original frozen
    /// reader; it cannot substitute another snapshot or reselect after a fetch.
    pub fn into_frozen(self) -> AttachedSnapshot<R, E> {
        AttachedSnapshot {
            snapshot: self.snapshot.into_frozen(),
            cover: self.cover,
            support: self.support,
            residual: self.residual,
            dependencies: self.dependencies,
        }
    }
}

impl<R, E> Clone for AttachedSnapshot<R, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    fn clone(&self) -> Self {
        Self {
            snapshot: self.snapshot.clone(),
            cover: self.cover.clone(),
            support: self.support.clone(),
            residual: self.residual.clone(),
            dependencies: self.dependencies.clone(),
        }
    }
}

impl<R, E> AttachedSnapshot<R, E>
where
    R: StoreSnapshot,
    E: CollectionEncoding,
{
    pub(crate) fn new(
        snapshot: R,
        cover: Cover<E>,
        support: Support<SimpleArchive>,
        residual: Support<SimpleArchive>,
        dependencies: DependencyTracker,
    ) -> Self {
        Self {
            snapshot,
            cover,
            support,
            residual,
            dependencies,
        }
    }

    /// Immutable store observation against which the cover is valid.
    pub fn snapshot(&self) -> &R {
        &self.snapshot
    }

    /// Whether everything consulted is unchanged in `snapshot`: the parent's
    /// and the attached collection's records, and the residency of every
    /// attachment and dependency looked at and of every residual foundation.
    /// A MAP, an attachment's bytes or a residual foundation's bytes arriving
    /// moves an observation off current, and so does a new parent node.
    pub fn is_current(&self, snapshot: &R) -> bool {
        let dependencies = self
            .dependencies
            .lock()
            .expect("dependency tracker poisoned");
        snapshot.changes_for(&self.snapshot, &dependencies) == StoreChanges::NONE
    }

    /// The attachments taken, in the attached collection.
    pub fn cover(&self) -> &Cover<E> {
        &self.cover
    }

    /// The parent foundations the taken attachments stand for.
    pub fn support(&self) -> &Support<SimpleArchive> {
        &self.support
    }

    /// The parent foundations no taken attachment reaches: a node whose
    /// attachment is not built yet, cannot be represented, or waits for a
    /// dependency. Attached reads report these as a gap; explicit writer
    /// upkeep can build and publish their images. Membership never implies
    /// that their bytes are here.
    pub fn residual(&self) -> &Support<SimpleArchive> {
        &self.residual
    }

    /// Reconstruct one caller-chosen logical value from the attachments
    /// taken, and nothing else.
    ///
    /// The residual is not part of it. [`Self::read`] uses the same stored
    /// cover and returns the residual alongside the value, so callers can
    /// distinguish a complete attached observation from a partial one.
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

    /// Read only the stored attached cover. Every foundation outside that
    /// cover remains explicitly unread, even when its source bytes are resident.
    /// This never runs a mapping or publishes an attachment.
    pub fn read<V>(
        &self,
    ) -> Result<AttachedRead<V>, AttachedReadError<R::GetError<Infallible>, V::Error>>
    where
        R: StoreRead,
        E: super::CollectionAttachment,
        V: TryFromCover<E>,
    {
        self.read_with::<super::encoding::CanonicalAttachment<E>, V>()
    }

    /// Read the same stored cover through the supplied reader. An acquiring
    /// reader may get selected attachment bytes; residual source bytes are
    /// neither requested nor mapped. Upkeep is an explicit store operation.
    pub fn read_acquiring<V>(
        &self,
    ) -> Result<AttachedRead<V>, AttachedReadError<R::GetError<Infallible>, V::Error>>
    where
        R: StoreRead,
        E: super::CollectionAttachment,
        V: TryFromCover<E>,
    {
        self.read::<V>()
    }

    /// Stored-only read with an explicit mapping, validating its descriptor
    /// without invoking the mapping.
    pub fn read_with_acquiring<M, V>(
        &self,
    ) -> Result<AttachedRead<V>, AttachedReadError<R::GetError<Infallible>, V::Error>>
    where
        R: StoreRead,
        M: MapMapping<Target = E>,
        V: TryFromCover<E>,
    {
        self.read_with::<M, V>()
    }

    /// Wrap only the byte reader of this already-selected observation.
    /// The caller must keep the runtime and network store owner alive and
    /// execute synchronous reads outside an async task (e.g. spawn_blocking).
    #[cfg(feature = "object-store")]
    pub fn acquiring(
        &self,
        runtime: tokio::runtime::Handle,
    ) -> AttachedSnapshot<crate::repo::async_store::AcquiringReader<R>, E> {
        AttachedSnapshot {
            snapshot: crate::repo::async_store::AcquiringReader::with_handle(
                self.snapshot.clone(),
                runtime,
            ),
            cover: self.cover.clone(),
            support: self.support.clone(),
            residual: self.residual.clone(),
            dependencies: self.dependencies.clone(),
        }
    }

    /// Validate the named mapping, then read only persisted attachments.
    /// Use `ensure_attached_within_with` on the owning store for bounded
    /// durable construction, and take a fresh observation after it finishes.
    pub fn read_with<M, V>(
        &self,
    ) -> Result<AttachedRead<V>, AttachedReadError<R::GetError<Infallible>, V::Error>>
    where
        R: StoreRead,
        M: MapMapping<Target = E>,
        V: TryFromCover<E>,
    {
        let observed =
            ObservedStore::with_tracker(self.snapshot.clone(), self.dependencies.clone());
        let descriptor =
            super::api::load_collection_descriptor(&observed, self.cover.collection().handle())
                .map_err(|error| AttachedReadError::View(error.into()))?;
        let parent_descriptor =
            super::api::load_collection_descriptor(&observed, self.support.collection().handle())
                .map_err(|error| AttachedReadError::View(error.into()))?;
        M::bind(&parent_descriptor.fragment, &descriptor.fragment)
            .map_err(AttachedReadError::Mapping)?;
        let value = V::try_from_cover(&self.cover, &descriptor.fragment, &observed)
            .map_err(AttachedReadError::View)?;
        Ok(AttachedRead::new(value, self.residual.clone()))
    }
}

/// The logical value of stored attachments in one observation, and every
/// parent foundation those attachments leave unread.
#[derive(Clone, Debug)]
pub struct AttachedRead<V> {
    value: V,
    unread: Support<SimpleArchive>,
}

impl<V> AttachedRead<V> {
    pub(crate) fn new(value: V, unread: Support<SimpleArchive>) -> Self {
        Self { value, unread }
    }

    /// The value of the stored attachments selected here.
    pub fn value(&self) -> &V {
        &self.value
    }

    /// The value alone.
    pub fn into_value(self) -> V {
        self.value
    }

    /// Parent foundations not covered by the stored attachments. Resident
    /// source bytes do not make a foundation visible through an index.
    pub fn unread(&self) -> &Support<SimpleArchive> {
        &self.unread
    }

    /// The value and what it leaves out.
    pub fn into_parts(self) -> (V, Support<SimpleArchive>) {
        (self.value, self.unread)
    }

    /// The same read with its value transformed.
    pub fn map<W>(self, transform: impl FnOnce(V) -> W) -> AttachedRead<W> {
        AttachedRead {
            value: transform(self.value),
            unread: self.unread,
        }
    }
}

/// Failure to read an attached collection's stored cover
/// ([`AttachedSnapshot::read_with`]).
#[derive(Debug)]
pub enum AttachedReadError<GetError, ViewError> {
    /// A descriptor or an attachment could not be read, or the view could
    /// not be formed from the stored attachments.
    View(TryFromCoverError<GetError, ViewError>),
    /// The attached descriptor does not name the mapping read through.
    Mapping(super::CollectionOperationError),
}

impl<GetError, ViewError> fmt::Display for AttachedReadError<GetError, ViewError>
where
    GetError: fmt::Display,
    ViewError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::View(source) => source.fmt(formatter),
            Self::Mapping(source) => write!(
                formatter,
                "attached descriptor does not bind the mapping read through: {source}"
            ),
        }
    }
}

impl<GetError, ViewError> Error for AttachedReadError<GetError, ViewError>
where
    GetError: Error + 'static,
    ViewError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::View(source) => Some(source),
            Self::Mapping(source) => Some(source),
        }
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
    use crate::blob::encodings::succinctarchive::SuccinctArchiveBlob;
    use crate::collection::observed_store::ObservedStore;
    use crate::collection::{Collection, CollectionData, CollectionHandle};
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::SnapshotSource;

    use super::{CollectionSnapshot, Cover, Support};

    #[test]
    fn snapshot_keeps_its_own_support_beside_its_cover() {
        let target = Collection::<SuccinctArchiveBlob>::from_handle(CollectionHandle::new([2; 32]));
        let support: Support<SuccinctArchiveBlob> =
            Support::from_data(target, [CollectionData::new([3; 32])]);
        let cover = Cover::from_data(target, [CollectionData::new([4; 32])]);
        let mut store = MemoryRepo::default();
        let store_snapshot = store.snapshot().unwrap();

        let snapshot = CollectionSnapshot::from_frontier(
            store_snapshot.clone(),
            support.clone(),
            cover.clone(),
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
