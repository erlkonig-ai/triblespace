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

/// One explicit parameterized mapping between collection encodings.
///
/// This is the coherence-safe extension point for mappings whose source and
/// target encodings are both owned elsewhere. Prefer [`CollectionDerivation`]
/// when a target encoding owns one canonical incoming derivation; explicit
/// mappings are selected through the `*_with` collection-store methods.
/// Implementations must be a join homomorphism:
///
/// `map(a join b) = map(a) join map(b)`.
pub trait CollectionMapping: Sized {
    /// Canonical source encoding.
    type Source: CollectionEncoding;
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

impl<T: CollectionDerivation> CollectionMapping for CanonicalDerivation<T> {
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
