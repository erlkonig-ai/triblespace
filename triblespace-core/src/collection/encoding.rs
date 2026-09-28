//! Canonical encodings and mappings for typed collections.
//!
//! Durable collection records carry representation-neutral content hashes.
//! This module restores their physical meaning at the API boundary without
//! inventing a second runtime planner:
//!
//! - a [`CollectionEncoding`] owns the canonical bytes, validation, and join
//!   within one collection;
//! - a [`CollectionDerivation`] lets one target encoding own its canonical,
//!   parameterized, join-preserving conversion from one source encoding;
//! - a [`DeriveMapping`] is an explicit mapping whose images are derived into
//!   a collection of their own, and a [`MapMapping`] (or the target-owned
//!   [`CollectionAttachment`]) indexes another collection's nodes instead,
//!   into an attached collection;
//! - [`Collection`] binds an encoding to one exact, content-addressed
//!   descriptor.
//!
//! Logical interpretation is deliberately separate in
//! [`TryFromCover`](crate::collection::TryFromCover). Maintained-index views
//! retain their mmap-backed shards and check only the framing, bounds and
//! alignment needed to access them safely. Attachment does not re-prove
//! canonical contents, serialize a logical union, or construct an accelerator.
//! Query preparation may derive scratch data the encoding does not persist;
//! that work belongs to the requested query, not to attaching the index.

use std::error::Error;
use std::fmt;
use std::marker::PhantomData;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::{Blob, BlobEncoding};
use crate::metadata::{self, MetaDescribe};
use crate::prelude::{exists, pattern};
use crate::repo::{BlobStoreGet, BlobStoreMeta, StoreRead};
use crate::trible::Fragment;

use super::{
    collection_representation, CollectionData, CollectionHandle, KIND_COLLECTION_DESCRIPTOR,
};

/// Failure of one exact canonical collection operation.
///
/// `Capacity` is reserved for deterministic geometry limits of the chosen
/// encoding. It must not describe transient allocation, I/O, or accelerator
/// failures. Malformed or noncanonical bytes are always `Fatal`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionOperationError {
    /// The operation or supplied bytes are invalid and another cover cannot
    /// repair it.
    Fatal(String),
    /// This exact encoding cannot hold the result, but a finer physical cover
    /// may still represent the same logical value.
    Capacity(String),
    /// The canonical result names an immutable dependency which is not present
    /// in the current snapshot. Storage may materialize or fetch it and retry
    /// the otherwise pure operation.
    MissingDependency(CollectionData),
}

impl fmt::Display for CollectionOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fatal(reason) | Self::Capacity(reason) => formatter.write_str(reason),
            Self::MissingDependency(member) => write!(
                formatter,
                "collection operation requires resident blob {}",
                hex::encode_upper(member.raw),
            ),
        }
    }
}

impl Error for CollectionOperationError {}

/// One canonical physical shape carried by a blob encoding.
///
/// Collection members are always ordinary typed [`Blob`] values. An encoding
/// validates its own bytes and owns one canonical intra-shape join. Derived
/// collections are ordinary lattices connected to their source by a
/// join-preserving [`CollectionDerivation`], not a weaker kind of collection.
/// The logical join remains total at the [`Cover`](super::Cover) level: when
/// one physical member cannot represent the result, `Capacity` retains a finer
/// cover of members with the same value.
///
/// This is intentionally stronger than [`BlobEncoding`]: not every blob format
/// is a collection member, while every `CollectionEncoding` has an exact
/// validation boundary.
pub trait CollectionEncoding: BlobEncoding + MetaDescribe + Sized + 'static {
    /// Validate encoding-specific context carried by one descriptor.
    ///
    /// Most encodings need no context. An encoding whose canonical bytes are
    /// parameterized (for example a path summary over one automaton) validates
    /// only the shape information it needs here; the source-to-target mapping
    /// still owns the parameterized conversion itself.
    fn validate_descriptor(_descriptor: &Fragment) -> Result<(), CollectionOperationError> {
        Ok(())
    }

    /// Explicitly validate one member independently of its provenance.
    ///
    /// The root bytes have already passed the blob store's content-address
    /// boundary. A Merkle encoding may inspect children through `reader`; a
    /// monolithic encoding normally ignores it. Warm collection resolution
    /// does not invoke this hook; it is available to producers, untrusted
    /// ingress, and offline audits. It is not part of ordinary typed-view
    /// construction, nor a requirement to check locally produced output again.
    fn validate_member<R>(
        descriptor: &Fragment,
        member: &Blob<Self>,
        reader: &R,
    ) -> Result<(), CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta;

    /// Return immutable representation dependencies missing from a resident
    /// member root in this snapshot.
    ///
    /// Self-contained encodings need no extra work. Merkle encodings override
    /// this narrow availability query so cover resolution can ignore an
    /// incomplete compacted root and fall back to a finer support-equivalent
    /// cover. Returned handles are only the blobs required to interpret this
    /// representation, not optional attachments or semantic provenance.
    ///
    /// This is not semantic validation: it neither recomputes the member nor
    /// proves its canonical bytes. It may read the named resident root, but
    /// must not request missing dependencies, persist, or otherwise change
    /// storage.
    fn missing_representation_dependencies<R>(
        _member: CollectionData,
        _reader: &R,
    ) -> Result<Vec<CollectionData>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        Ok(Vec::new())
    }

    /// Compute the exact canonical join of two members.
    ///
    /// The implementation owns decoding and rejecting malformed inputs while
    /// it performs this new work; warm resolution never calls this method.
    ///
    /// `reader` resolves immutable content-addressed dependencies named by the
    /// inputs or by their canonical result. Availability may delay publication
    /// but cannot alter the result bytes. Other resident content is not an
    /// input to the join.
    ///
    fn join_members<R>(
        descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta;

    /// Compute the exact canonical join of one or more members: the k-way
    /// join an n-ary MERGE states.
    ///
    /// The default folds [`Self::join_members`] left to right, which is the
    /// same canonical result by associativity; an encoding with a cheaper
    /// k-way join overrides it. The same availability rules apply.
    fn join_many<R>(
        descriptor: &Fragment,
        members: &[Blob<Self>],
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        let (first, rest) = members.split_first().ok_or_else(|| {
            CollectionOperationError::Fatal("a join needs at least one member".to_owned())
        })?;
        let mut joined = first.clone();
        for member in rest {
            joined = Self::join_members(descriptor, &joined, member, reader)?;
        }
        Ok(joined)
    }
}

/// The canonical incoming derivation owned by one target encoding.
///
/// The target names its one source encoding and the runtime argument carried
/// by the mapping fragment embedded in its descriptor. Canonical builders
/// normally derive the mapping entity id, but binding validates its algorithm
/// and argument rather than its minting history. Implementations must be a
/// join homomorphism:
///
/// `map(a join b) = map(a) join map(b)`.
pub trait CollectionDerivation: CollectionEncoding {
    /// Canonical source encoding.
    type Source: CollectionEncoding;

    /// Runtime argument which distinguishes concrete mappings of this
    /// canonical source-to-target relation.
    type Argument;

    /// Canonical concrete mapping fragment embedded in a target descriptor.
    ///
    /// Parameterized derivations carry their argument in this fragment;
    /// parameter-free derivations use `()`.
    fn fragment(argument: &Self::Argument) -> Fragment;

    /// Bind and validate the concrete mapping named by the target descriptor.
    fn bind(
        source: &Fragment,
        target: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError>;

    /// Compute the canonical target image of one source member.
    ///
    /// `reader` is the same frozen store observation from which the
    /// source was loaded. The mapping owns decoding and rejecting malformed
    /// input while it performs new work. It may use `reader` only to resolve
    /// dependencies named by `source` or its concrete argument. An explicit
    /// collection reference is resolved using this observation's records and
    /// capability evidence; unrelated store contents are not semantic input.
    fn map<R>(
        argument: &Self::Argument,
        source: &Blob<Self::Source>,
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: StoreRead;

    /// Join two target images.
    ///
    /// A returned blob is the same canonical target join as
    /// [`CollectionEncoding::join_members`]; only the computation differs, so
    /// a mapping may route it through its own backend. `Ok(None)` declines
    /// this route without claiming capacity failure or naming an unknown
    /// dependency.
    fn join_images<R>(
        _argument: &Self::Argument,
        target_descriptor: &Fragment,
        low: &Blob<Self>,
        high: &Blob<Self>,
        reader: &R,
    ) -> Result<Option<Blob<Self>>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        Self::join_members(target_descriptor, low, high, reader).map(Some)
    }
}

/// One explicit parameterized mapping between collection encodings, whose
/// images are derived into a collection of their own.
///
/// Its images are published as `DERIVE` leaves of the derived collection and
/// replicate with it. An index that every reader of a node can compute for
/// itself is a [`MapMapping`] instead.
///
/// This is the coherence-safe extension point for mappings whose source and
/// target encodings are both owned elsewhere. Prefer [`CollectionDerivation`]
/// when a target encoding owns one canonical incoming derivation; explicit
/// mappings are selected through the `*_with` collection-store methods.
/// Implementations must be a join homomorphism:
///
/// `map(a join b) = map(a) join map(b)`.
pub trait DeriveMapping: Sized {
    /// Canonical source encoding.
    type Source: CollectionEncoding;

    /// Whether maintenance maps source foundations another key owns.
    ///
    /// It decides two things, both in `maintain` only. With `true`, after the
    /// maintaining key's own foundations it derives every foundation of
    /// another owner that has no leaf at all, when the view admits the
    /// maintaining key and the payload is already here; and it mirrors a
    /// source merge of its own by mapping the merged node's bytes, whoever
    /// signed the foundations inside it. With `false` it does neither: each
    /// such foundation waits for a leaf from its owner, and a source merge
    /// holding one is not mirrored, so the view keeps the finer images
    /// beneath it. `ensure` never derives another owner's foundation.
    ///
    /// Temporary: it stands in until derivation is scheduled by leaf rather
    /// than by owner (a foundation with any admitted leaf is done, whoever
    /// signed it) and derived collections carry their own leaf images rather
    /// than mirroring their source's merges. A mapping only some hosts can
    /// compute then says so through a hook of its own, and this constant
    /// goes.
    const FOREIGN_DERIVABLE: bool = true;
    /// Canonical target encoding.
    type Target: CollectionEncoding;

    /// Canonical concrete mapping fragment embedded in a target descriptor.
    fn fragment(&self) -> Fragment;

    /// Bind and validate the concrete mapping named by the target descriptor.
    fn bind(source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError>;

    /// Compute the canonical target image of one source member.
    ///
    /// The reader freezes the source and any explicitly named dependencies
    /// together, including collection records and authorization. A mapping may
    /// resolve references carried by its descriptor or input, but must not
    /// discover ambient inputs or advance the control-plane observation.
    fn map<R>(
        &self,
        source: &Blob<Self::Source>,
        reader: &R,
    ) -> Result<Blob<Self::Target>, CollectionOperationError>
    where
        R: StoreRead;

    /// Join two target images.
    ///
    /// Any returned blob must be the canonical target join, without
    /// constructing upstream members or changing storage; a mapping may
    /// compute it through its own backend. `Ok(None)` declines this route
    /// without claiming capacity failure or naming an unknown dependency.
    fn join_images<R>(
        &self,
        target_descriptor: &Fragment,
        low: &Blob<Self::Target>,
        high: &Blob<Self::Target>,
        reader: &R,
    ) -> Result<Option<Blob<Self::Target>>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        Self::Target::join_members(target_descriptor, low, high, reader).map(Some)
    }
}

/// Internal adapter from a target-owned derivation to the explicit mapping
/// engine. Keeping this wrapper private leaves downstream coherence open.
pub(crate) struct CanonicalDerivation<T: CollectionDerivation> {
    argument: T::Argument,
}

impl<T: CollectionDerivation> CanonicalDerivation<T> {
    pub(crate) fn new(argument: T::Argument) -> Self {
        Self { argument }
    }
}

impl<T: CollectionDerivation> DeriveMapping for CanonicalDerivation<T> {
    type Source = T::Source;
    type Target = T;

    fn fragment(&self) -> Fragment {
        T::fragment(&self.argument)
    }

    fn bind(source: &Fragment, target: &Fragment) -> Result<Self, CollectionOperationError> {
        T::bind(source, target).map(Self::new)
    }

    fn map<R>(
        &self,
        source: &Blob<Self::Source>,
        reader: &R,
    ) -> Result<Blob<Self::Target>, CollectionOperationError>
    where
        R: StoreRead,
    {
        T::map(&self.argument, source, reader)
    }

    fn join_images<R>(
        &self,
        target_descriptor: &Fragment,
        low: &Blob<Self::Target>,
        high: &Blob<Self::Target>,
        reader: &R,
    ) -> Result<Option<Blob<Self::Target>>, CollectionOperationError>
    where
        R: BlobStoreGet + BlobStoreMeta,
    {
        T::join_images(&self.argument, target_descriptor, low, high, reader)
    }
}

/// A mapping attached to another collection's nodes: an index of each node,
/// not a collection of its own.
///
/// An attached collection's descriptor names its parent collection and one
/// concrete mapping, and no policy: its records are `MAP(node ->
/// attachment)` signed by the host, which no other host believes: one that
/// reaches another store stays inert there. The contract an implementor
/// takes on:
///
/// - It maps any node of its parent's lattice, a merge result as well as a
///   foundation. The parent is a root collection: its nodes are
///   `SimpleArchive`s.
/// - It is deterministic. Its inputs are the node, immutable dependencies the
///   node or the mapping names, and optionally the attachments of the same
///   node in other attached collections of the same parent, named by
///   [`Self::siblings`]. A dependency that is not resident is reported as
///   [`CollectionOperationError::MissingDependency`], never read as absent.
/// - Every host that can read the node can compute it: it is not pinned to a
///   model, an accelerator class or any other property of a host. A mapping
///   that is pinned cannot implement this trait, so it cannot be attached by
///   mistake; it stays a [`DeriveMapping`].
/// - Its images need no join. `Capacity` means this node's attachment cannot
///   be represented; a reader then descends to finer nodes.
///
/// Its law is cover-query equivalence. A reader answers a query over a cover
/// of attachments at mixed granularity -- one node's image beside the images
/// of finer nodes, possibly overlapping -- and the answer must equal the
/// query over the image of the union the cover stands for:
///
/// `view(cover { map(a_1), ..., map(a_n) }) = view(map(a_1 join ... join a_n))`.
///
/// Because the `a_i` may overlap, a view combines its per-node answers
/// idempotently: a last-writer-wins register pairs partial rows across the
/// cover, a text index takes each entity's maximum score, and a count or any
/// other non-idempotent aggregate is never summed over overlapping supports.
/// Every implementor is tested against this law over random covers.
///
/// The law holds for every cover when an image is built from single facts,
/// as every implementor in this crate's is. A mapping whose image aggregates
/// facts of several entities cannot tell from one node that an entity has
/// more facts elsewhere, and then no combination of per-node images is
/// exact once a cover splits that entity; nothing refuses such a node, so
/// the answer can be wrong with an empty residual and nothing unread. For
/// such a mapping the law is a premise about its input, which the
/// implementor states. The one known is the Archive block BM25 mapping in
/// faculties (`ArchiveBlockTextBm25Mapping`), whose document is a block and
/// whose term frequency sums over the block's parts: it answers like the
/// union for every cover whose nodes hold whole source units (a block with
/// all its parts and their facts); a node holding part of a block scores
/// that block from the part it holds, with no refusal and no residual to
/// show it, so a cover that splits a block undercounts it. Faculties' own
/// Archive importer commits whole source units, and a test there pins it:
/// that is the premise for data it writes, not for another writer's commits
/// or historical input, and the writer keeps the fragments it is given
/// whole without checking that they hold whole blocks. The ignored
/// faculties tests `a_block_whose_parts_sit_in_two_nodes_scores_like_their_union`,
/// `a_block_extended_by_a_node_without_its_tag_scores_like_their_union` and
/// `archive_block_covers_answer_like_the_union_when_parts_spread_over_nodes`
/// are the acceptance tests of the structural fix: a per-fact text index
/// over the content fact's payload, with blocks ranked at query time.
pub trait MapMapping: Sized {
    /// Encoding of the attachments.
    type Target: CollectionEncoding;

    /// Canonical concrete mapping fragment embedded in an attached
    /// descriptor.
    fn fragment(&self) -> Fragment;

    /// Bind and validate the concrete mapping an attached descriptor names.
    fn bind(parent: &Fragment, attached: &Fragment) -> Result<Self, CollectionOperationError>;

    /// The attached collections of the same parent whose attachment of a
    /// node this mapping reads, in the order [`Self::map`] receives them.
    /// Their handles are named by the mapping's own descriptor, never
    /// recomputed.
    fn siblings(&self) -> Vec<CollectionHandle> {
        Vec::new()
    }

    /// Compute the attachment of one node.
    ///
    /// `siblings` holds one usable attachment of this node in each collection
    /// [`Self::siblings`] names. `reader` resolves immutable dependencies
    /// named by the node, the siblings or the mapping; nothing else in the
    /// store is an input.
    fn map<R>(
        &self,
        node: &Blob<SimpleArchive>,
        siblings: &[CollectionData],
        reader: &R,
    ) -> Result<Blob<Self::Target>, CollectionOperationError>
    where
        R: StoreRead;
}

/// The canonical attachment owned by one target encoding: the
/// [`MapMapping`] counterpart of [`CollectionDerivation`], with the same
/// contract and law.
///
/// The target names the runtime argument its mapping fragment carries;
/// attaching it is [`crate::collection::CollectionStoreExt::attach`].
pub trait CollectionAttachment: CollectionEncoding {
    /// Runtime argument which distinguishes concrete mappings of this
    /// canonical relation.
    type Argument;

    /// Canonical concrete mapping fragment embedded in an attached
    /// descriptor.
    fn fragment(argument: &Self::Argument) -> Fragment;

    /// Bind and validate the concrete mapping an attached descriptor names.
    fn bind(
        parent: &Fragment,
        attached: &Fragment,
    ) -> Result<Self::Argument, CollectionOperationError>;

    /// See [`MapMapping::siblings`].
    fn siblings(_argument: &Self::Argument) -> Vec<CollectionHandle> {
        Vec::new()
    }

    /// See [`MapMapping::map`].
    fn map<R>(
        argument: &Self::Argument,
        node: &Blob<SimpleArchive>,
        siblings: &[CollectionData],
        reader: &R,
    ) -> Result<Blob<Self>, CollectionOperationError>
    where
        R: StoreRead;
}

/// Internal adapter from a target-owned attachment to the explicit mapping
/// engine, the counterpart of [`CanonicalDerivation`].
pub(crate) struct CanonicalAttachment<T: CollectionAttachment> {
    argument: T::Argument,
}

impl<T: CollectionAttachment> CanonicalAttachment<T> {
    pub(crate) fn new(argument: T::Argument) -> Self {
        Self { argument }
    }
}

impl<T: CollectionAttachment> MapMapping for CanonicalAttachment<T> {
    type Target = T;

    fn fragment(&self) -> Fragment {
        T::fragment(&self.argument)
    }

    fn bind(parent: &Fragment, attached: &Fragment) -> Result<Self, CollectionOperationError> {
        T::bind(parent, attached).map(Self::new)
    }

    fn siblings(&self) -> Vec<CollectionHandle> {
        T::siblings(&self.argument)
    }

    fn map<R>(
        &self,
        node: &Blob<SimpleArchive>,
        siblings: &[CollectionData],
        reader: &R,
    ) -> Result<Blob<Self::Target>, CollectionOperationError>
    where
        R: StoreRead,
    {
        T::map(&self.argument, node, siblings, reader)
    }
}

/// A descriptor does not denote the encoding requested by its Rust type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionTypeError {
    /// No tagged descriptor entity names the requested encoding.
    WrongEncoding {
        /// Encoding required by the Rust type.
        expected: crate::id::Id,
    },
    /// The descriptor names the right encoding but supplies invalid context.
    InvalidDescriptor(CollectionOperationError),
}

impl fmt::Display for CollectionTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongEncoding { expected } => write!(
                formatter,
                "no collection descriptor names encoding {expected:X}",
            ),
            Self::InvalidDescriptor(source) => {
                write!(formatter, "invalid collection encoding context: {source}")
            }
        }
    }
}

impl Error for CollectionTypeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidDescriptor(source) => Some(source),
            Self::WrongEncoding { .. } => None,
        }
    }
}

/// Recognize the descriptor facts needed to interpret members as `E`.
///
/// A matching encoding fact is sufficient; other representations, annotations,
/// and legacy fields do not invalidate it. Policy and lineage are separate
/// queries at their respective consumers, not encoding prerequisites.
pub(crate) fn validate_descriptor_type<E>(
    descriptor_fragment: &Fragment,
) -> Result<(), CollectionTypeError>
where
    E: CollectionEncoding,
{
    let expected = E::id();
    if !exists!(pattern!(descriptor_fragment.facts(), [{ _?descriptor @
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_representation: expected,
    }])) {
        return Err(CollectionTypeError::WrongEncoding { expected });
    }
    E::validate_descriptor(descriptor_fragment).map_err(CollectionTypeError::InvalidDescriptor)
}

/// One exact collection descriptor, typed by its canonical member encoding.
///
/// The store owns the descriptor bytes. This is only its cheap, cloneable
/// content address plus compile-time meaning; constructing it is restricted to
/// descriptor-validation boundaries.
pub struct Collection<E: CollectionEncoding> {
    handle: CollectionHandle,
    encoding: PhantomData<fn() -> E>,
}

impl<E: CollectionEncoding> Collection<E> {
    pub(crate) const fn from_handle(handle: CollectionHandle) -> Self {
        Self {
            handle,
            encoding: PhantomData,
        }
    }

    /// Representation-neutral descriptor handle stored in dense records.
    pub const fn handle(self) -> CollectionHandle {
        self.handle
    }
}

impl<E: CollectionEncoding> Clone for Collection<E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: CollectionEncoding> Copy for Collection<E> {}

impl<E: CollectionEncoding> fmt::Debug for Collection<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Collection")
            .field(&hex::encode_upper(self.handle.raw))
            .finish()
    }
}

impl<E: CollectionEncoding> PartialEq for Collection<E> {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl<E: CollectionEncoding> Eq for Collection<E> {}

impl<E: CollectionEncoding> PartialOrd for Collection<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: CollectionEncoding> Ord for Collection<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.handle.cmp(&other.handle)
    }
}

impl<E: CollectionEncoding> std::hash::Hash for Collection<E> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl<E: CollectionEncoding> From<Collection<E>> for CollectionHandle {
    fn from(collection: Collection<E>) -> Self {
        collection.handle
    }
}
