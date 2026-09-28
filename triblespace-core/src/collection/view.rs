//! Immutable collection observations and logical views over their realized
//! covers.
//!
//! A [`CollectionSnapshot`] owns the store observation against which its
//! realized target cover is valid. Its support comes with it, read from the
//! coverage index by the same selection: a cover of the collection's own
//! foundations. Whether a derived collection has caught up with its source
//! is [`CollectionSnapshot::missing_from`]. Logical values remain
//! caller-chosen projections reconstructed through [`TryFromCover`].

use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::{Blob, BlobEncoding, Bytes, TryFromBlob};
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::repo::{BlobStoreGet, BlobStoreMeta, StoreChanges, StoreRead, StoreSnapshot};
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
            CollectionRealizationError::Resolution(format!("read view source: {error}"))
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
                .any(|output| self.support.contains(crate::inline::Inline::new(output.raw)))
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
    /// dependency. Read these raw, build them, or report them as a gap;
    /// membership never implies that their bytes are here.
    pub fn residual(&self) -> &Support<SimpleArchive> {
        &self.residual
    }

    /// Reconstruct one caller-chosen logical value from the attachments
    /// taken, and nothing else.
    ///
    /// The residual is not part of it, so beside a read that does include
    /// the residual -- the facts of the same parent, say -- it answers for
    /// less than they do. [`Self::read`] is the whole read; this is the
    /// cover alone, for a caller that reads the residual some other way or
    /// reports it.
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

    /// Reconstruct one caller-chosen logical value over everything the
    /// parent stands on in this observation, through the canonical mapping
    /// the attached descriptor names: [`Self::read_with`] for
    /// [`CollectionAttachment`](super::CollectionAttachment).
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

    /// Reconstruct one caller-chosen logical value over everything the
    /// parent stands on in this observation: the attachments taken, and an
    /// image of every residual foundation built in memory through `M`.
    ///
    /// This is the reader's half of "read raw, build, or report a gap": a
    /// residual foundation whose bytes are here is mapped the way
    /// maintenance would map it, and the view is formed over the cover and
    /// those images together, so it answers like the view of the parent's
    /// whole support and never less than a fact read of the same
    /// observation. Nothing is stored or published. What cannot be built
    /// here -- bytes not here, a dependency the mapping names not here, a
    /// node the mapping cannot represent or interpret, or any node at all
    /// when the mapping reads sibling attachments -- is named in
    /// [`AttachedRead::unread`], never read as absent. The mapping's reads
    /// join this observation's read-set, so a dependency arriving moves it
    /// off current.
    ///
    /// `M` must be the mapping the attached descriptor names; one it does
    /// not bind is [`AttachedReadError::Mapping`].
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
        let attached = self.cover.collection();
        let parent = self.support.collection();
        let descriptor = super::api::load_collection_descriptor(&observed, attached.handle())
            .map_err(|error| AttachedReadError::View(error.into()))?;
        let parent_descriptor = super::api::load_collection_descriptor(&observed, parent.handle())
            .map_err(|error| AttachedReadError::View(error.into()))?;
        let mapping = M::bind(&parent_descriptor.fragment, &descriptor.fragment)
            .map_err(AttachedReadError::Mapping)?;
        // A sibling's attachment of a residual node is not built here: the
        // sibling's own mapping is not known to this read.
        let builds = mapping.siblings().is_empty();
        let mut images: HashMap<[u8; 32], Bytes> = HashMap::new();
        let mut unread = Vec::new();
        for foundation in self.residual.members() {
            let member = Handle::<SimpleArchive>::to_hash(foundation);
            if !builds {
                unread.push(member);
                continue;
            }
            let failed = |reason: String| AttachedReadError::Residual { member, reason };
            if observed
                .metadata(foundation)
                .map_err(|error| failed(error.to_string()))?
                .is_none()
            {
                unread.push(member);
                continue;
            }
            let node: Blob<SimpleArchive> = observed
                .get(foundation)
                .map_err(|error| failed(error.to_string()))?;
            match mapping.map(&node, &[], &observed) {
                Ok(image) => {
                    images.insert(image.get_handle().raw, image.bytes);
                }
                Err(_) => unread.push(member),
            }
        }
        let cover = Cover::from_members(
            attached,
            self.cover
                .members()
                .chain(images.keys().map(|raw| Inline::new(*raw))),
        );
        let reader = WithImages {
            base: &observed,
            images: &images,
        };
        let value = V::try_from_cover(&cover, &descriptor.fragment, &reader)
            .map_err(|error| AttachedReadError::View(error.into_base()))?;
        Ok(AttachedRead::new(value, Support::from_data(parent, unread)))
    }
}

/// A logical value an attached collection gives over its parent's whole
/// support in one observation ([`AttachedSnapshot::read`]), and the residual
/// foundations it could not include.
#[derive(Clone, Debug)]
pub struct AttachedRead<V> {
    value: V,
    unread: Support<SimpleArchive>,
}

impl<V> AttachedRead<V> {
    pub(crate) fn new(value: V, unread: Support<SimpleArchive>) -> Self {
        Self { value, unread }
    }

    /// The value, over the attachments taken and every residual foundation
    /// read here.
    pub fn value(&self) -> &V {
        &self.value
    }

    /// The value alone.
    pub fn into_value(self) -> V {
        self.value
    }

    /// The residual foundations the value leaves out, each a gap: its bytes
    /// are not here, a dependency its mapping names is not here, or the
    /// mapping cannot represent or interpret it here. The rest of the
    /// residual is in the value. Empty when the value answers for
    /// everything the parent stands on in this observation.
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

/// Failure to read an attached collection with its residual
/// ([`AttachedSnapshot::read_with`]).
#[derive(Debug)]
pub enum AttachedReadError<GetError, ViewError> {
    /// A descriptor or an attachment could not be read, or the view could
    /// not be formed from the attachments and the images built.
    View(TryFromCoverError<GetError, ViewError>),
    /// The attached descriptor does not name the mapping read through.
    Mapping(super::CollectionOperationError),
    /// The store could not read a residual foundation whose bytes are here.
    Residual {
        /// The parent foundation.
        member: CollectionData,
        /// What went wrong.
        reason: String,
    },
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
            Self::Residual { member, reason } => write!(
                formatter,
                "read residual foundation {}: {reason}",
                hex::encode_upper(member.raw),
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
            Self::Residual { .. } => None,
        }
    }
}

/// A store read with images built in memory beside it: a get of one of the
/// images answers from memory, every other get from the store.
struct WithImages<'a, R> {
    base: &'a R,
    images: &'a HashMap<[u8; 32], Bytes>,
}

/// A get through [`WithImages`]: an in-memory image that did not decode as
/// asked, or the store's own failure.
#[derive(Debug)]
enum WithImagesGetError<Decode, Base> {
    Decode(Decode),
    Base(Base),
}

impl<Decode: fmt::Display, Base: fmt::Display> fmt::Display for WithImagesGetError<Decode, Base> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(source) => write!(formatter, "decode an image built in memory: {source}"),
            Self::Base(source) => source.fmt(formatter),
        }
    }
}

impl<Decode, Base> Error for WithImagesGetError<Decode, Base>
where
    Decode: Error + 'static,
    Base: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(source) => Some(source),
            Self::Base(source) => Some(source),
        }
    }
}

impl<R: BlobStoreGet> BlobStoreGet for WithImages<'_, R> {
    type GetError<E: Error + Send + Sync + 'static> = WithImagesGetError<E, R::GetError<E>>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        match self.images.get(&handle.raw) {
            Some(bytes) => T::try_from_blob(Blob::with_handle(bytes.clone(), handle))
                .map_err(WithImagesGetError::Decode),
            None => self.base.get(handle).map_err(WithImagesGetError::Base),
        }
    }
}

impl<Base, ViewError> TryFromCoverError<WithImagesGetError<Infallible, Base>, ViewError> {
    /// The same failure, as the store's own: an in-memory image never fails
    /// to be read as the blob it is.
    fn into_base(self) -> TryFromCoverError<Base, ViewError> {
        let base = |source: WithImagesGetError<Infallible, Base>| match source {
            WithImagesGetError::Decode(never) => match never {},
            WithImagesGetError::Base(source) => source,
        };
        match self {
            Self::DescriptorGet { collection, source } => TryFromCoverError::DescriptorGet {
                collection,
                source: base(source),
            },
            Self::InvalidDescriptor { collection, source } => {
                TryFromCoverError::InvalidDescriptor { collection, source }
            }
            Self::MemberGet { member, source } => TryFromCoverError::MemberGet {
                member,
                source: base(source),
            },
            Self::View(source) => TryFromCoverError::View(source),
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
