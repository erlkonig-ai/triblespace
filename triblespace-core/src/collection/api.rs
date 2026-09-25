//! Store-centric publication and immutable reads for canonical collections.
//!
//! A collection is its descriptor handle. Registering a descriptor through
//! [`CollectionStoreExt::register_collection`] stores its complete attachment
//! closure, while later operations take only that handle. The
//! descriptor's mandatory policy is therefore part of the collection's
//! identity rather than a caller-supplied policy which could disagree with it.
//!
//! Local publication is deliberately unconditional: a store may record any
//! structurally valid, strictly signed commit. Authority is enforced when a
//! an admitted cover or logical value is constructed. The descriptor policy
//! independently governs READ and WRITE admission.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::Blob;
use crate::capability::{
    capability_quorum_authorized_subjects, capability_quorum_decide, CapabilityHandle,
    CapabilityProof, CapabilityRequest, CapabilityResource, QuorumOutcome,
};
use crate::id::Id;
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding};
use crate::patch::{Blake3Merkle, IdentitySchema, PATCH};
use crate::repo::async_store::AsyncBlobStoreAcquire;
use crate::repo::{BlobStoreGet, BlobStorePut, CapabilityProofRead};
use crate::repo::{CapabilityProofStore, SnapshotSource, Store, StoreRead, StoreSnapshot};
use crate::trible::{Fragment, TribleSet};

use super::exact_derived::CollectionRealizationError;
use super::simplearchive_union::PreparedCollectionCommit;
use super::{
    descriptor, read_capability, write_capability, Collection, CollectionCommit, CollectionData,
    CollectionEncoding, CollectionHandle, CollectionSnapshot, CollectionStore, CollectionTypeError,
    RecordDecodeError, TryFromCover, TryFromCoverError,
};
use super::{
    AdmissionPolicy, CanonicalDerivation, CollectionDerivation, CollectionMapping, CollectionPolicy,
};

/// Failure to discover the resident capability evidence used for collection
/// admission.
///
/// Individual candidate proofs are untrusted evidence: an invalid signature,
/// wrong action, or unavailable definition merely grants nothing. This
/// error is reserved for failure of the proof-store observation itself, where
/// silently returning a smaller cover would confuse unavailable evidence with
/// negative authorization.
#[derive(Debug)]
pub enum CollectionEvidenceDiscoveryError<ProofsError> {
    /// The store could not enumerate its resident proof snapshot.
    Proofs(ProofsError),
}

impl<ProofsError> fmt::Display for CollectionEvidenceDiscoveryError<ProofsError>
where
    ProofsError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proofs(source) => {
                write!(
                    formatter,
                    "failed to enumerate resident capability proofs: {source}"
                )
            }
        }
    }
}

impl<ProofsError> Error for CollectionEvidenceDiscoveryError<ProofsError>
where
    ProofsError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Proofs(source) => Some(source),
        }
    }
}

/// Failure while reading a collection descriptor and its local policy by
/// content identity.
#[derive(Debug)]
pub enum CollectionDescriptorError<GetError> {
    /// The descriptor blob could not be fetched.
    Get {
        /// Requested collection identity.
        collection: CollectionHandle,
        /// Backend fetch failure.
        source: GetError,
    },
    /// The archive could not be decoded or its singular policy could not be read.
    Invalid {
        /// Requested collection identity.
        collection: CollectionHandle,
        /// Exact structural failure.
        source: RecordDecodeError,
    },
}

impl<GetError> fmt::Display for CollectionDescriptorError<GetError>
where
    GetError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get { collection, source } => write!(
                formatter,
                "failed to fetch collection descriptor {}: {source}",
                hex::encode_upper(collection.raw),
            ),
            Self::Invalid { collection, source } => write!(
                formatter,
                "collection descriptor {} is invalid: {source}",
                hex::encode_upper(collection.raw),
            ),
        }
    }
}

impl<GetError> Error for CollectionDescriptorError<GetError>
where
    GetError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Get { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
        }
    }
}

/// Failure to open an existing collection as one concrete member encoding.
///
/// Opening is a read-only validation boundary. It neither registers the
/// descriptor nor writes any of its attachment closure into the store.
#[derive(Debug)]
pub enum CollectionOpenError<GetError> {
    /// The descriptor could not be fetched or decoded generically.
    Descriptor(CollectionDescriptorError<GetError>),
    /// The descriptor does not denote the requested member encoding.
    WrongType(CollectionTypeError),
}

impl<GetError> fmt::Display for CollectionOpenError<GetError>
where
    GetError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(source) => source.fmt(formatter),
            Self::WrongType(source) => write!(formatter, "wrong collection type: {source}"),
        }
    }
}

impl<GetError> Error for CollectionOpenError<GetError>
where
    GetError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(source) => Some(source),
            Self::WrongType(source) => Some(source),
        }
    }
}

/// Failure to persist one root-issued, unbounded collection grant.
///
/// The operation validates the descriptor and the exact action roots before
/// writing one self-contained native proof record.
#[derive(Debug)]
pub enum CollectionGrantError<SnapshotError, GetError, InsertError> {
    /// The store could not freeze the read boundary used to validate policy.
    Snapshot(SnapshotError),
    /// The collection descriptor was unavailable or malformed.
    Descriptor(CollectionDescriptorError<GetError>),
    /// The collection action is already open and therefore needs no proof.
    OpenPolicy {
        /// Exact action whose policy is open.
        capability: CapabilityHandle,
        /// Exact collection whose action policy is open.
        collection: CollectionHandle,
    },
    /// The supplied signing key is not one of this collection action's roots.
    RootNotAuthorized {
        /// Exact action whose policy rejected the signer.
        capability: CapabilityHandle,
        /// Exact collection whose policy rejected the signer.
        collection: CollectionHandle,
        /// Public half of the supplied root signing key.
        root: VerifyingKey,
    },
    /// The native proof record could not be inserted.
    ProofInsert(InsertError),
}

impl<SnapshotError, GetError, InsertError> fmt::Display
    for CollectionGrantError<SnapshotError, GetError, InsertError>
where
    SnapshotError: fmt::Display,
    GetError: fmt::Display,
    InsertError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(source) => {
                write!(formatter, "failed to freeze store snapshot: {source}")
            }
            Self::Descriptor(source) => source.fmt(formatter),
            Self::OpenPolicy {
                capability,
                collection,
            } => write!(
                formatter,
                "collection {} has an open {} policy; no proof is required",
                hex::encode_upper(collection.raw),
                collection_capability_label(*capability),
            ),
            Self::RootNotAuthorized {
                capability,
                collection,
                root,
            } => write!(
                formatter,
                "key {} is not a {} root of collection {}",
                hex::encode_upper(root.to_bytes()),
                collection_capability_label(*capability),
                hex::encode_upper(collection.raw),
            ),
            Self::ProofInsert(source) => {
                write!(formatter, "failed to insert capability proof: {source}")
            }
        }
    }
}

impl<SnapshotError, GetError, InsertError> Error
    for CollectionGrantError<SnapshotError, GetError, InsertError>
where
    SnapshotError: Error + 'static,
    GetError: Error + 'static,
    InsertError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Snapshot(source) => Some(source),
            Self::Descriptor(source) => Some(source),
            Self::OpenPolicy { .. } | Self::RootNotAuthorized { .. } => None,
            Self::ProofInsert(source) => Some(source),
        }
    }
}

/// Error returned by [`grant_collection_read`].
pub type CollectionReadGrantError<SnapshotError, GetError, InsertError> =
    CollectionGrantError<SnapshotError, GetError, InsertError>;

/// Error returned by [`grant_collection_write`].
pub type CollectionWriteGrantError<SnapshotError, GetError, InsertError> =
    CollectionGrantError<SnapshotError, GetError, InsertError>;

fn collection_capability_label(capability: CapabilityHandle) -> String {
    if capability == read_capability() {
        "READ".to_owned()
    } else if capability == write_capability() {
        "WRITE".to_owned()
    } else {
        hex::encode_upper(capability.raw)
    }
}

/// Failure to decide whether one subject is currently admitted to a collection.
///
/// Descriptor failures mean that the collection's admission policy could not
/// be established. Evidence failures mean that the resident capability-proof
/// observation itself was unavailable; invalid or irrelevant individual
/// proofs merely fail to admit their subjects and are not errors.
#[derive(Debug)]
pub enum CollectionAdmissionError<ProofsError, GetError> {
    /// The collection descriptor was unavailable or malformed.
    Descriptor(CollectionDescriptorError<GetError>),
    /// The resident capability-proof observation could not be completed.
    Evidence(CollectionEvidenceDiscoveryError<ProofsError>),
}

/// The Invoke audience derivable for one capability and proof snapshot.
///
/// The existing name remains the READ convenience surface; generic consumers
/// receive the same explicit finite-or-open result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionReadAudience {
    /// Every principal is admitted; no finite principal list is complete.
    Open,
    /// Exact finite audience of the restricted policy in public-key order.
    Restricted(Vec<VerifyingKey>),
}

impl<ProofsError, GetError> fmt::Display for CollectionAdmissionError<ProofsError, GetError>
where
    ProofsError: fmt::Display,
    GetError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(source) => source.fmt(formatter),
            Self::Evidence(source) => source.fmt(formatter),
        }
    }
}

impl<ProofsError, GetError> Error for CollectionAdmissionError<ProofsError, GetError>
where
    ProofsError: Error + 'static,
    GetError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(source) => Some(source),
            Self::Evidence(source) => Some(source),
        }
    }
}

/// Failure to register a self-contained collection descriptor.
#[derive(Debug)]
pub enum CollectionRegistrationError<PutError> {
    /// The descriptor names another encoding or invalid encoding context.
    WrongType(CollectionTypeError),
    /// One attachment or the canonical descriptor archive could not be stored.
    DependencyPut(PutError),
}

impl<PutError> fmt::Display for CollectionRegistrationError<PutError>
where
    PutError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongType(source) => write!(formatter, "wrong collection type: {source}"),
            Self::DependencyPut(source) => {
                write!(
                    formatter,
                    "failed to store collection descriptor closure: {source}"
                )
            }
        }
    }
}

impl<PutError> Error for CollectionRegistrationError<PutError>
where
    PutError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::WrongType(source) => Some(source),
            Self::DependencyPut(source) => Some(source),
        }
    }
}

/// One exact point in a collection lattice.
///
/// Members are content identities, not signatures. Several commits may attest
/// the same member with different authors or metadata without changing this
/// value. A caller may name an exact typed coordinate through
/// [`Collection::cover`]; admission, resolution, and materialization still
/// decide independently whether that coordinate is authorized, evidenced, and
/// resident in a particular immutable store snapshot.
pub struct Cover<L: CollectionEncoding> {
    collection: Collection<L>,
    members: PATCH<32, IdentitySchema, (), Blake3Merkle>,
}

impl<L: CollectionEncoding> Cover<L> {
    pub(crate) fn from_members(
        collection: Collection<L>,
        members: impl IntoIterator<Item = Inline<Handle<L>>>,
    ) -> Self {
        Self {
            collection,
            members: PATCH::from_keys(members.into_iter().map(|member| member.raw)),
        }
    }

    pub(crate) fn from_data(
        collection: Collection<L>,
        members: impl IntoIterator<Item = CollectionData>,
    ) -> Self {
        Self {
            collection,
            members: PATCH::from_keys(members.into_iter().map(|member| member.raw)),
        }
    }

    pub(crate) fn from_patch(
        collection: Collection<L>,
        members: PATCH<32, IdentitySchema, (), Blake3Merkle>,
    ) -> Self {
        Self {
            collection,
            members,
        }
    }

    /// Exact descriptor whose lattice contains these members.
    pub const fn collection(&self) -> Collection<L> {
        self.collection
    }

    /// Canonical member identities in ascending byte order.
    pub fn members(&self) -> impl ExactSizeIterator<Item = Inline<Handle<L>>> + '_ {
        self.members
            .iter_ordered()
            .map(|member| Inline::new(*member))
    }

    /// Whether this cover contains one exact member identity.
    pub fn contains(&self, member: Inline<Handle<L>>) -> bool {
        self.members.get(&member.raw).is_some()
    }

    pub(crate) fn data_members(&self) -> impl ExactSizeIterator<Item = CollectionData> + '_ {
        self.members
            .iter_ordered()
            .map(|member| Inline::new(*member))
    }

    /// Number of distinct collection members.
    pub fn len(&self) -> usize {
        self.members.len().min(usize::MAX as u64) as usize
    }

    /// Whether this is the lattice bottom.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    fn ensure_same_collection(&self, other: &Self) -> Result<(), CoverAlgebraError> {
        if self.collection == other.collection {
            Ok(())
        } else {
            Err(CoverAlgebraError::DifferentCollection {
                left: self.collection.handle(),
                right: other.collection.handle(),
            })
        }
    }

    /// Return the set union of two points in the same collection lattice.
    pub fn union(&self, other: &Self) -> Result<Self, CoverAlgebraError> {
        self.ensure_same_collection(other)?;
        let mut members = self.members.clone();
        members.union(other.members.clone());
        Ok(Self::from_patch(self.collection, members))
    }

    /// Return the set intersection of two points in the same collection lattice.
    pub fn intersection(&self, other: &Self) -> Result<Self, CoverAlgebraError> {
        self.ensure_same_collection(other)?;
        Ok(Self::from_patch(
            self.collection,
            self.members.intersect(&other.members),
        ))
    }

    /// Return the members of `self` absent from `other`.
    pub fn difference(&self, other: &Self) -> Result<Self, CoverAlgebraError> {
        self.ensure_same_collection(other)?;
        Ok(Self::from_patch(
            self.collection,
            self.members.difference(&other.members),
        ))
    }

    /// Whether every member of `self` is present in `other`.
    pub fn is_subset(&self, other: &Self) -> Result<bool, CoverAlgebraError> {
        self.ensure_same_collection(other)?;
        Ok(self.members <= other.members)
    }

    /// Return the members added since an earlier observation.
    ///
    /// This is PATCH set difference over payload identities. A new signature
    /// or metadata archive for an existing member is provenance, not a data
    /// delta. Shrinking observations fail because additions-only maintenance
    /// would no longer be sound.
    pub fn additions_since(&self, previous: &Self) -> Result<Self, CoverAdvanceError> {
        if self.collection != previous.collection {
            return Err(CoverAdvanceError::DifferentCollection {
                previous: previous.collection.handle(),
                current: self.collection.handle(),
            });
        }
        let missing = previous.members.difference(&self.members);
        if let Some(member) = missing.iter_ordered().next() {
            return Err(CoverAdvanceError::ResetRequired {
                missing: Inline::new(*member),
            });
        }
        Ok(Self::from_patch(
            self.collection,
            self.members.difference(&previous.members),
        ))
    }
}

impl<L: CollectionEncoding> Clone for Cover<L> {
    fn clone(&self) -> Self {
        Self {
            collection: self.collection,
            members: self.members.clone(),
        }
    }
}

impl<L: CollectionEncoding> fmt::Debug for Cover<L> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cover")
            .field("collection", &self.collection)
            .field("members", &self.data_members().collect::<Vec<_>>())
            .finish()
    }
}

impl<L: CollectionEncoding> PartialEq for Cover<L> {
    fn eq(&self, other: &Self) -> bool {
        self.collection == other.collection && self.members == other.members
    }
}

impl<L: CollectionEncoding> Eq for Cover<L> {}

/// What a collection stands on: a cover of its OWN foundations.
///
/// A root's foundations are its distinct admitted `COMMIT.data` payloads; a
/// derived collection's are the images its believed leaves (`DERIVE`s) name.
/// `MERGE` changes the physical cover, never this value, and several
/// authorized records attesting one payload are one member. Supports of two
/// collections are never compared: whether a view has caught up with its
/// source is [`CollectionSnapshot::missing_from`], which asks the view's
/// leaves for each source foundation's locator.
///
/// The parameter is the collection's own encoding; it defaults to a root's.
pub type Support<E = SimpleArchive> = Cover<E>;

/// Failure to combine covers from distinct collection lattices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverAlgebraError {
    /// The operands carry different canonical collection descriptors.
    DifferentCollection {
        /// Descriptor carried by the left operand.
        left: CollectionHandle,
        /// Descriptor carried by the right operand.
        right: CollectionHandle,
    },
}

impl fmt::Display for CoverAlgebraError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifferentCollection { left, right } => write!(
                formatter,
                "cover collection {} differs from {}",
                hex::encode_upper(left.raw),
                hex::encode_upper(right.raw),
            ),
        }
    }
}

impl Error for CoverAlgebraError {}

/// Failure to treat two covers as one additions-only continuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverAdvanceError {
    /// The two covers belong to different collection lattices.
    DifferentCollection {
        /// Earlier collection descriptor.
        previous: CollectionHandle,
        /// Current collection descriptor.
        current: CollectionHandle,
    },
    /// A member of the earlier cover is absent from the current cover.
    ResetRequired {
        /// First missing member in canonical content order.
        missing: CollectionData,
    },
}

impl fmt::Display for CoverAdvanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifferentCollection { previous, current } => write!(
                formatter,
                "cover collection {} differs from {}",
                hex::encode_upper(current.raw),
                hex::encode_upper(previous.raw),
            ),
            Self::ResetRequired { missing } => write!(
                formatter,
                "previous cover member {} is absent from the current observation; additions-only processing requires a reset",
                hex::encode_upper(missing.raw),
            ),
        }
    }
}

impl Error for CoverAdvanceError {}

/// Failure to publish one collection element into local storage.
#[derive(Debug)]
pub enum CollectionCommitError<PutError, InsertError> {
    /// A described attachment, member, or metadata archive could not be stored.
    DependencyPut(PutError),
    /// The signed visibility record could not be inserted after its dependencies.
    RecordInsert(InsertError),
}

impl<PutError, InsertError> fmt::Display for CollectionCommitError<PutError, InsertError>
where
    PutError: fmt::Display,
    InsertError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DependencyPut(source) => {
                write!(formatter, "failed to store collection dependency: {source}")
            }
            Self::RecordInsert(source) => {
                write!(formatter, "failed to insert collection commit: {source}")
            }
        }
    }
}

impl<PutError, InsertError> Error for CollectionCommitError<PutError, InsertError>
where
    PutError: Error + 'static,
    InsertError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DependencyPut(source) => Some(source),
            Self::RecordInsert(source) => Some(source),
        }
    }
}

/// Failure to read one logical value through a snapshot.
#[derive(Debug)]
pub enum CollectionReadError<GetError, ViewError> {
    /// The snapshot could not attach the collection.
    Realization(CollectionRealizationError),
    /// The attached cover could not form the requested logical view.
    View(TryFromCoverError<GetError, ViewError>),
}

impl<GetError, ViewError> fmt::Display for CollectionReadError<GetError, ViewError>
where
    GetError: fmt::Display,
    ViewError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Realization(source) => source.fmt(formatter),
            Self::View(source) => source.fmt(formatter),
        }
    }
}

impl<GetError, ViewError> Error for CollectionReadError<GetError, ViewError>
where
    GetError: Error + 'static,
    ViewError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Realization(source) => Some(source),
            Self::View(source) => Some(source),
        }
    }
}

pub(crate) struct LoadedCollectionDescriptor {
    pub(crate) fragment: Fragment,
}

pub(crate) fn load_collection_descriptor<R>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<LoadedCollectionDescriptor, CollectionDescriptorError<R::GetError<Infallible>>>
where
    R: BlobStoreGet,
{
    let descriptor_blob: Blob<SimpleArchive> = snapshot
        .get(collection)
        .map_err(|source| CollectionDescriptorError::Get { collection, source })?;
    let facts =
        <TribleSet as crate::blob::TryFromBlob<SimpleArchive>>::try_from_blob(descriptor_blob)
            .map_err(|source| CollectionDescriptorError::Invalid {
                collection,
                source: RecordDecodeError::from(source),
            })?;
    Ok(LoadedCollectionDescriptor {
        fragment: Fragment::from(facts),
    })
}

pub(crate) enum AdmissionEvidence {
    Open,
    Alternatives(Vec<AdmissionEvidence>),
    Quorum {
        roots: Vec<VerifyingKey>,
        invoke_threshold: NonZeroUsize,
        request: CapabilityRequest,
        proofs: Arc<[CapabilityProof]>,
    },
}

impl AdmissionEvidence {
    pub(crate) fn authorizes<R: BlobStoreGet>(&self, reader: &R, subject: VerifyingKey) -> bool {
        matches!(self.decide(reader, subject), QuorumOutcome::Met)
    }

    /// Decide one subject, and say which arrival could change the decision:
    /// a proof, or the capability definitions a proof for the subject named
    /// and this reader could not read.
    pub(crate) fn decide<R: BlobStoreGet>(
        &self,
        reader: &R,
        subject: VerifyingKey,
    ) -> QuorumOutcome {
        match self {
            Self::Open => QuorumOutcome::Met,
            Self::Alternatives(alternatives) => {
                let mut undefined = Vec::new();
                for evidence in alternatives {
                    match evidence.decide(reader, subject) {
                        QuorumOutcome::Met => return QuorumOutcome::Met,
                        QuorumOutcome::Unmet => {}
                        QuorumOutcome::Undefined(handles) => undefined.extend(handles),
                    }
                }
                if undefined.is_empty() {
                    QuorumOutcome::Unmet
                } else {
                    QuorumOutcome::Undefined(undefined)
                }
            }
            Self::Quorum {
                roots,
                invoke_threshold,
                request,
                proofs,
            } => capability_quorum_decide(
                reader,
                proofs.iter(),
                roots.iter().copied(),
                subject,
                *request,
                *invoke_threshold,
            ),
        }
    }

    fn authorized_subjects<R: BlobStoreGet>(&self, reader: &R) -> CollectionReadAudience {
        match self {
            Self::Open => CollectionReadAudience::Open,
            Self::Alternatives(alternatives) => {
                let mut subjects = BTreeMap::new();
                for alternative in alternatives {
                    match alternative.authorized_subjects(reader) {
                        CollectionReadAudience::Open => return CollectionReadAudience::Open,
                        CollectionReadAudience::Restricted(audience) => {
                            subjects.extend(
                                audience
                                    .into_iter()
                                    .map(|subject| (subject.to_bytes(), subject)),
                            );
                        }
                    }
                }
                CollectionReadAudience::Restricted(subjects.into_values().collect())
            }
            Self::Quorum {
                roots,
                invoke_threshold,
                request,
                proofs,
            } => CollectionReadAudience::Restricted(capability_quorum_authorized_subjects(
                reader,
                proofs.iter(),
                roots.iter().copied(),
                *request,
                *invoke_threshold,
            )),
        }
    }
}

pub(crate) fn admission_evidence_from_proofs(
    policy: &AdmissionPolicy,
    action: Id,
    collection: CollectionHandle,
    proofs: Arc<[CapabilityProof]>,
) -> AdmissionEvidence {
    let AdmissionPolicy::Quorum(quorum) = policy else {
        return AdmissionEvidence::Open;
    };
    let request = CapabilityRequest::new(CapabilityResource::from(collection), action);
    AdmissionEvidence::Quorum {
        roots: quorum.roots().to_vec(),
        invoke_threshold: NonZeroUsize::new(quorum.invoke_threshold() as usize)
            .expect("validated collection policy has a nonzero invoke threshold"),
        request,
        proofs,
    }
}

pub(super) fn discover_admission_evidence<S>(
    snapshot: &S,
    policies: impl IntoIterator<Item = AdmissionPolicy>,
    action: Id,
    collection: CollectionHandle,
) -> Result<AdmissionEvidence, CollectionEvidenceDiscoveryError<S::ProofsError>>
where
    S: CapabilityProofRead,
{
    let policies: Vec<_> = policies.into_iter().collect();
    if policies
        .iter()
        .any(|policy| matches!(policy, AdmissionPolicy::Open))
    {
        return Ok(AdmissionEvidence::Open);
    }
    if policies.is_empty() {
        return Ok(AdmissionEvidence::Alternatives(Vec::new()));
    }
    let proofs = snapshot
        .proofs()
        .map_err(CollectionEvidenceDiscoveryError::Proofs)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(CollectionEvidenceDiscoveryError::Proofs)?;
    let proofs: Arc<[CapabilityProof]> = proofs.into();
    Ok(AdmissionEvidence::Alternatives(
        policies
            .iter()
            .map(|policy| {
                admission_evidence_from_proofs(policy, action, collection, Arc::clone(&proofs))
            })
            .collect(),
    ))
}

/// Persist one deterministic root-issued READ/Invoke proof for `recipient`.
///
/// This is deliberately representation-neutral: READ authority concerns the
/// exact descriptor handle, not the collection member encoding. The
/// descriptor policy is first read through one coherent
/// store snapshot. `root` must be named by its READ quorum; an open READ policy
/// needs no grant and is rejected as a redundant operation.
///
/// Repeating the same call with the same collection, root, and recipient
/// reproduces the same self-contained proof bytes and is idempotent on a
/// conforming store.
pub fn grant_collection_read<S>(
    store: &mut S,
    collection: CollectionHandle,
    root: &SigningKey,
    recipient: VerifyingKey,
) -> Result<
    CapabilityProof,
    CollectionReadGrantError<
        <S as SnapshotSource>::SnapshotError,
        <<S as SnapshotSource>::Snapshot as BlobStoreGet>::GetError<Infallible>,
        <S as CapabilityProofStore>::InsertError,
    >,
>
where
    S: SnapshotSource + CapabilityProofStore,
    <S as SnapshotSource>::Snapshot: BlobStoreGet,
{
    grant_collection_capability(store, collection, read_capability(), root, recipient)
}

/// Persist one deterministic root-issued WRITE/Invoke proof for `recipient`.
///
/// This is the WRITE counterpart of [`grant_collection_read`]. The descriptor
/// is validated from one coherent snapshot, `root` must be named by its WRITE
/// quorum. The resulting proof activates matching COMMITs by `recipient` when
/// a later collection snapshot performs WRITE admission; local publication
/// itself remains unconditional.
pub fn grant_collection_write<S>(
    store: &mut S,
    collection: CollectionHandle,
    root: &SigningKey,
    recipient: VerifyingKey,
) -> Result<
    CapabilityProof,
    CollectionWriteGrantError<
        <S as SnapshotSource>::SnapshotError,
        <<S as SnapshotSource>::Snapshot as BlobStoreGet>::GetError<Infallible>,
        <S as CapabilityProofStore>::InsertError,
    >,
>
where
    S: SnapshotSource + CapabilityProofStore,
    <S as SnapshotSource>::Snapshot: BlobStoreGet,
{
    grant_collection_capability(store, collection, write_capability(), root, recipient)
}

/// Persist a root-issued grant described by an already stored definition.
///
/// The definition may combine invocation and delegation actions. Authority is
/// still checked per requested action, against that action's configured roots;
/// a broad grant cannot borrow an unrelated action's roots. An open action may
/// accompany a grant for a restricted action; an entirely open grant is
/// redundant. One root contributes its share, not an entire multi-root quorum.
pub fn grant_collection_capability<S>(
    store: &mut S,
    collection: CollectionHandle,
    capability: CapabilityHandle,
    root: &SigningKey,
    recipient: VerifyingKey,
) -> Result<
    CapabilityProof,
    CollectionGrantError<
        <S as SnapshotSource>::SnapshotError,
        <<S as SnapshotSource>::Snapshot as BlobStoreGet>::GetError<Infallible>,
        <S as CapabilityProofStore>::InsertError,
    >,
>
where
    S: SnapshotSource + CapabilityProofStore,
    <S as SnapshotSource>::Snapshot: BlobStoreGet,
{
    let snapshot = store.snapshot().map_err(CollectionGrantError::Snapshot)?;
    let descriptor = load_collection_descriptor(&snapshot, collection)
        .map_err(CollectionGrantError::Descriptor)?;
    let definition = load_collection_descriptor(&snapshot, capability)
        .map_err(CollectionGrantError::Descriptor)?;
    let actions = crate::prelude::find!(
        action: Id,
        crate::prelude::temp!(
            (grant),
            crate::prelude::or!(
                crate::prelude::pattern!(definition.fragment.facts(), [{ ?grant @ crate::capability::capability_action: ?action }]),
                crate::prelude::pattern!(definition.fragment.facts(), [{ ?grant @ crate::capability::capability_delegate_action: ?action }]),
            )
        )
    );
    let root_key = root.verifying_key();
    let mut has_action = false;
    let mut needs_grant = false;
    for action in actions {
        has_action = true;
        let mut open = false;
        let mut root_is_authorized = false;
        for policy in
            descriptor::admission_policies(&snapshot, descriptor.fragment.facts(), action, None)
        {
            open |= matches!(policy, AdmissionPolicy::Open);
            root_is_authorized |= policy
                .roots()
                .is_some_and(|roots| roots.contains(&root_key));
        }
        if open {
            continue;
        }
        if !root_is_authorized {
            return Err(CollectionGrantError::RootNotAuthorized {
                capability,
                collection,
                root: root_key,
            });
        }
        needs_grant = true;
    }
    if !has_action {
        return Err(CollectionGrantError::RootNotAuthorized {
            capability,
            collection,
            root: root_key,
        });
    }
    if !needs_grant {
        return Err(CollectionGrantError::OpenPolicy {
            capability,
            collection,
        });
    }
    drop(snapshot);

    let proof = CapabilityProof::new(
        CapabilityResource::from(collection),
        root,
        capability,
        recipient,
    );
    store
        .insert_proof(proof.clone())
        .map_err(CollectionGrantError::ProofInsert)?;
    Ok(proof)
}

/// Decide READ admission for an untyped collection handle from explicitly
/// supplied portable proofs.
///
/// Network discovery starts from the descriptor handle carried on the wire,
/// before its member encoding is known. This boundary therefore queries the
/// descriptor's READ policy without manufacturing a typed
/// [`Collection`]. It neither enumerates nor persists ambient proof state.
pub fn collection_reader_is_admitted_by<S>(
    snapshot: &S,
    collection: CollectionHandle,
    subject: VerifyingKey,
    proofs: &[CapabilityProof],
) -> Result<bool, CollectionDescriptorError<S::GetError<Infallible>>>
where
    S: StoreSnapshot + BlobStoreGet,
{
    let loaded = load_collection_descriptor(snapshot, collection)?;
    let admitted =
        descriptor::admission_policies(snapshot, loaded.fragment.facts(), super::ACTION_READ, None)
            .any(|policy| {
                collection_reader_is_admitted_by_policy(
                    snapshot, collection, &policy, subject, proofs,
                )
            });
    Ok(admitted)
}

/// Decide READ admission against one already validated collection policy.
///
/// This is the pure seam for a network host which pinned the descriptor policy
/// while constructing its immutable per-collection repair overlay. It
/// reads reusable capability definitions, with no proof discovery, persistence,
/// network acquisition, or clock sampling.
pub fn collection_reader_is_admitted_by_policy<R: BlobStoreGet>(
    reader: &R,
    collection: CollectionHandle,
    policy: &AdmissionPolicy,
    subject: VerifyingKey,
    proofs: &[CapabilityProof],
) -> bool {
    let evidence = admission_evidence_from_proofs(
        policy,
        super::ACTION_READ,
        collection,
        proofs.to_vec().into(),
    );
    evidence.authorizes(reader, subject)
}

/// Enumerate the READ audience from an already validated collection policy.
///
/// Restricted admission is evaluated over independent root paths in the
/// supplied self-contained proofs. Configured roots plus every independently
/// valid signed prefix participate, so a principal authorized by a proof prefix
/// is included even when that prefix is not separately stored. Invalid,
/// unrelated proofs are inert. Collection authority does not expire.
/// Open admission remains explicit because it cannot be finitely enumerated.
pub fn collection_read_audience_by_policy<R: BlobStoreGet>(
    reader: &R,
    collection: CollectionHandle,
    policy: &AdmissionPolicy,
    proofs: &[CapabilityProof],
) -> CollectionReadAudience {
    admission_evidence_from_proofs(
        policy,
        super::ACTION_READ,
        collection,
        proofs.to_vec().into(),
    )
    .authorized_subjects(reader)
}

/// Discover and enumerate the READ audience from one coherent store snapshot.
///
/// A failed proof-store observation is reported rather than confused with an
/// empty audience. Invalid or unrelated proofs simply grant nothing.
pub fn collection_read_audience<S>(
    snapshot: &S,
    collection: CollectionHandle,
) -> Result<CollectionReadAudience, CollectionAdmissionError<S::ProofsError, S::GetError<Infallible>>>
where
    S: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
{
    collection_action_audience(snapshot, collection, super::ACTION_READ)
}

/// Discover the finite invocation audience for one action.
///
/// This generic collection-resource seam is also used by consumers such as
/// key delivery. It never substitutes READ or WRITE for an absent binding.
pub fn collection_action_audience<S>(
    snapshot: &S,
    collection: CollectionHandle,
    action: Id,
) -> Result<CollectionReadAudience, CollectionAdmissionError<S::ProofsError, S::GetError<Infallible>>>
where
    S: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
{
    let loaded = load_collection_descriptor(snapshot, collection)
        .map_err(CollectionAdmissionError::Descriptor)?;
    let evidence = discover_admission_evidence(
        snapshot,
        descriptor::admission_policies(snapshot, loaded.fragment.facts(), action, None),
        action,
        collection,
    )
    .map_err(CollectionAdmissionError::Evidence)?;
    Ok(evidence.authorized_subjects(snapshot))
}

/// Decide WRITE admission against one already validated collection policy and
/// an explicitly supplied portable proof forest.
///
/// This pure seam lets a network repair client discard inert records before
/// they cross the local admission boundary. It performs no store access,
/// persistence, or clock sampling.
pub fn collection_writer_is_admitted_by_policy<R: BlobStoreGet>(
    reader: &R,
    collection: CollectionHandle,
    policy: &AdmissionPolicy,
    subject: VerifyingKey,
    proofs: &[CapabilityProof],
) -> bool {
    let evidence = admission_evidence_from_proofs(
        policy,
        super::ACTION_WRITE,
        collection,
        proofs.to_vec().into(),
    );
    evidence.authorizes(reader, subject)
}

impl<L: CollectionEncoding> Collection<L> {
    /// Name one exact typed coordinate in this collection lattice.
    ///
    /// This performs no store access and makes no claim that the members are
    /// admitted, related by stored equations, or physically resident. It is
    /// the construction boundary for durable exact-cover manifests; pass the
    /// result to snapshot resolution before reading it as a value.
    pub fn cover(self, members: impl IntoIterator<Item = Inline<Handle<L>>>) -> Cover<L> {
        Cover::from_members(self, members)
    }

    /// Open an existing descriptor as a typed collection without mutating the
    /// backing store.
    ///
    /// `snapshot` should be the caller's coherent immutable read boundary. The
    /// descriptor is fetched by `handle`, its local policy is read, and the
    /// encoding facts needed by `L` are recognized before the cheap typed
    /// handle is returned.
    pub fn open<S>(
        snapshot: &S,
        handle: CollectionHandle,
    ) -> Result<Self, CollectionOpenError<S::GetError<Infallible>>>
    where
        S: BlobStoreGet,
    {
        let descriptor = load_collection_descriptor(snapshot, handle)
            .map_err(CollectionOpenError::Descriptor)?;
        super::encoding::validate_descriptor_type::<L>(&descriptor.fragment)
            .map_err(CollectionOpenError::WrongType)?;
        Ok(Self::from_handle(handle))
    }

    /// Read this collection's immutable admission policy from `snapshot`.
    ///
    /// The descriptor is fetched and queried for its local READ and WRITE
    /// policies. This does not enumerate capability
    /// proofs or make an admission decision.
    pub fn policy<S>(
        self,
        snapshot: &S,
    ) -> Result<CollectionPolicy, CollectionDescriptorError<S::GetError<Infallible>>>
    where
        S: BlobStoreGet,
    {
        let loaded = load_collection_descriptor(snapshot, self.handle())?;
        descriptor::policy(loaded.fragment.facts()).map_err(|source| {
            CollectionDescriptorError::Invalid {
                collection: self.handle(),
                source,
            }
        })
    }

    /// Decide whether `subject` is admitted as a writer in this snapshot.
    ///
    /// Open policy admits every subject. A quorum admits the subject only when
    /// independently rooted exact-action proofs carry support from enough
    /// distinct configured roots.
    pub fn writer_is_admitted<S>(
        self,
        snapshot: &S,
        subject: VerifyingKey,
    ) -> Result<bool, CollectionAdmissionError<S::ProofsError, S::GetError<Infallible>>>
    where
        S: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
    {
        let loaded = load_collection_descriptor(snapshot, self.handle())
            .map_err(CollectionAdmissionError::Descriptor)?;
        let evidence = discover_admission_evidence(
            snapshot,
            descriptor::admission_policies(
                snapshot,
                loaded.fragment.facts(),
                super::ACTION_WRITE,
                Some(L::id()),
            ),
            super::ACTION_WRITE,
            self.handle(),
        )
        .map_err(CollectionAdmissionError::Evidence)?;
        Ok(evidence.authorizes(snapshot, subject))
    }

    /// Decide whether `subject` is admitted as a reader in this snapshot.
    ///
    /// This is the disclosure boundary corresponding to the descriptor's READ
    /// ceiling. Local materialization remains caller-controlled because a
    /// local store cannot infer which external principal will receive bytes.
    pub fn reader_is_admitted<S>(
        self,
        snapshot: &S,
        subject: VerifyingKey,
    ) -> Result<bool, CollectionAdmissionError<S::ProofsError, S::GetError<Infallible>>>
    where
        S: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
    {
        let loaded = load_collection_descriptor(snapshot, self.handle())
            .map_err(CollectionAdmissionError::Descriptor)?;
        let evidence = discover_admission_evidence(
            snapshot,
            descriptor::admission_policies(
                snapshot,
                loaded.fragment.facts(),
                super::ACTION_READ,
                Some(L::id()),
            ),
            super::ACTION_READ,
            self.handle(),
        )
        .map_err(CollectionAdmissionError::Evidence)?;
        Ok(evidence.authorizes(snapshot, subject))
    }

    /// Decide READ admission from one explicitly supplied portable proof set.
    ///
    /// This is the network-facing counterpart of [`Self::reader_is_admitted`].
    /// It loads only the immutable collection descriptor from `snapshot`; it
    /// neither enumerates nor persists ambient proof-store state. An open READ
    /// policy therefore succeeds with an empty proof slice, while a quorum is
    /// evaluated over the independently rooted supplied paths.
    pub fn reader_is_admitted_by<S>(
        self,
        snapshot: &S,
        subject: VerifyingKey,
        proofs: &[CapabilityProof],
    ) -> Result<bool, CollectionDescriptorError<S::GetError<Infallible>>>
    where
        S: StoreSnapshot + BlobStoreGet,
    {
        let loaded = load_collection_descriptor(snapshot, self.handle())?;
        let admitted = descriptor::admission_policies(
            snapshot,
            loaded.fragment.facts(),
            super::ACTION_READ,
            Some(L::id()),
        )
        .any(|policy| {
            collection_reader_is_admitted_by_policy(
                snapshot,
                self.handle(),
                &policy,
                subject,
                proofs,
            )
        });
        Ok(admitted)
    }

    /// What this collection stands for in this snapshot, from the coverage
    /// index: its own foundations, resident or not.
    ///
    /// For a root these are its admitted COMMIT payloads. For a derived
    /// collection they are the images its believed leaves name. Nothing is
    /// enumerated: the index is settled for this one handle and its
    /// frontier's supports are unioned.
    pub fn admitted<S>(self, snapshot: &S) -> Result<Cover<L>, S::RecordsError>
    where
        S: StoreRead,
    {
        let coverage = snapshot.coverage(&BTreeSet::from([self.handle()]))?;
        let (support, _) = coverage.frontier_support(self.handle());
        Ok(Cover::from_patch(self, support))
    }

    /// Read one logical value through this snapshot's realized collection.
    ///
    /// This is exactly `snapshot.collection(self)?.view()`: it neither fetches
    /// missing blobs nor claims support beyond the snapshot's resident cover.
    pub fn read<V, S>(
        self,
        snapshot: &S,
    ) -> Result<V, CollectionReadError<S::GetError<Infallible>, V::Error>>
    where
        S: StoreRead,
        V: TryFromCover<L>,
    {
        snapshot
            .collection(self)
            .map_err(CollectionReadError::Realization)?
            .view()
            .map_err(CollectionReadError::View)
    }
}

/// Immutable collection observations implemented by every complete store snapshot.
///
/// A snapshot is the temporal boundary. The returned [`CollectionSnapshot`]
/// therefore owns this exact store observation, the physical target cover
/// selected inside it, and the [`Support`] that cover stands on: a cover of
/// the collection's own foundations.
pub trait CollectionSnapshotExt: StoreRead + Sized {
    /// Observe what one collection contains in this immutable snapshot.
    ///
    /// Capability decisions use this snapshot's immutable proof and definition
    /// state, independently of its clock.
    /// Physical target realization is selected entirely from this immutable
    /// store snapshot. Accepted target endorsements do not depend on the
    /// residency of their historical source records or source payloads.
    fn collection<E>(
        &self,
        target: Collection<E>,
    ) -> Result<CollectionSnapshot<Self, E>, CollectionRealizationError>
    where
        E: CollectionEncoding,
        Handle<E>: InlineEncoding,
    {
        super::observation::attach(self, target)
    }
}

impl<R> CollectionSnapshotExt for R where R: StoreRead {}

/// An encoding whose collection can be made resident and maintained by storage.
///
/// Root `SimpleArchive` collections acquire their signed support and carry
/// their maintainer's own nodes. Encodings with a canonical
/// [`CollectionDerivation`] derive their maintainer's own leaves and mirror
/// its own source merges. This operational capability is separate from the
/// pure encoding and mapping laws; no fictitious self-derivation is needed for
/// a root collection. The explicit key is the maintainer: it decides what is
/// owned, and signs only records published by realization; pure mapping and
/// snapshot observation need no signer.
/// Use the four [`CollectionStoreExt`] methods at call sites. Explicit foreign
/// mappings remain available through their `*_with` counterparts.
pub trait CollectionRealization: CollectionEncoding {
    /// A root acquires its admitted commits, whoever wrote them; a derived
    /// collection gets a leaf for every source foundation the key owns.
    fn ensure<'a, S>(
        store: &'a mut S,
        target: Collection<Self>,
        signing_key: &'a SigningKey,
    ) -> impl Future<Output = Result<S::Snapshot, CollectionRealizationError>> + Send + 'a
    where
        S: Store + AsyncBlobStoreAcquire + Send;

    /// A root carries the key's own nodes to their LSM fixed point; a
    /// derived collection gets the key's leaves, a leaf for every foundation
    /// another key owns that has none yet (a derive is a function anyone may
    /// compute), and a mirror of every source merge the key owns.
    fn maintain<'a, S>(
        store: &'a mut S,
        target: Collection<Self>,
        signing_key: &'a SigningKey,
    ) -> impl Future<Output = Result<S::Snapshot, CollectionRealizationError>> + Send + 'a
    where
        S: Store + AsyncBlobStoreAcquire + Send;
}

impl<T: CollectionDerivation> CollectionRealization for T {
    async fn ensure<'a, S>(
        store: &'a mut S,
        target: Collection<Self>,
        signing_key: &'a SigningKey,
    ) -> Result<S::Snapshot, CollectionRealizationError>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        store
            .ensure_with::<CanonicalDerivation<T>>(target, signing_key)
            .await
    }

    async fn maintain<'a, S>(
        store: &'a mut S,
        target: Collection<Self>,
        signing_key: &'a SigningKey,
    ) -> Result<S::Snapshot, CollectionRealizationError>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        store
            .maintain_with::<CanonicalDerivation<T>>(target, signing_key)
            .await
    }
}

impl CollectionRealization for SimpleArchive {
    async fn ensure<'a, S>(
        store: &'a mut S,
        target: Collection<Self>,
        signing_key: &'a SigningKey,
    ) -> Result<S::Snapshot, CollectionRealizationError>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        realize_root(store, target, signing_key, false).await
    }

    async fn maintain<'a, S>(
        store: &'a mut S,
        target: Collection<Self>,
        signing_key: &'a SigningKey,
    ) -> Result<S::Snapshot, CollectionRealizationError>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
    {
        realize_root(store, target, signing_key, true).await
    }
}

async fn realize_root<S>(
    store: &mut S,
    target: Collection<SimpleArchive>,
    signing_key: &SigningKey,
    compact: bool,
) -> Result<S::Snapshot, CollectionRealizationError>
where
    S: Store + AsyncBlobStoreAcquire,
{
    super::exact_derived::acquire_authority(store, target).await?;
    if compact {
        // The carry reads the key's own nodes only; nobody else's absent
        // payload is waited for or fetched.
        super::exact_derived::maintain_root_acquiring(store, target, signing_key).await?;
    } else {
        super::exact_derived::ensure_root(store, target).await?;
    }
    store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("freeze realized root snapshot", error)
    })
}

/// Ergonomic collection operations implemented directly by the backing store.
///
/// The trait carries no state and is blanket-implemented. Its purpose is only
/// method syntax: collections remain plain descriptor handles and stores
/// retain their native ownership, flushing, and closing APIs.
pub trait CollectionStoreExt: BlobStorePut + CollectionStore + Sized {
    /// Register a complete custom descriptor at the raw typed boundary.
    ///
    /// Normal root and derived construction should use [`collection`](Self::collection)
    /// and [`derive`](Self::derive), which make canonical descriptors by
    /// construction.
    ///
    /// Registration recognizes only the encoding facts needed by `L` and
    /// stores the complete fragment. Policy and lineage are queried when a
    /// consumer needs them; unrecognized policy never grants admission.
    fn register_collection<L>(
        &mut self,
        descriptor: Fragment,
    ) -> Result<Collection<L>, CollectionRegistrationError<<Self as BlobStorePut>::PutError>>
    where
        L: CollectionEncoding,
    {
        super::encoding::validate_descriptor_type::<L>(&descriptor)
            .map_err(CollectionRegistrationError::WrongType)?;
        let handle = descriptor::put_closure(self, &descriptor)
            .map_err(CollectionRegistrationError::DependencyPut)?;
        Ok(Collection::from_handle(handle))
    }

    /// Create and register one named root fact collection.
    fn collection(
        &mut self,
        name: &str,
        policy: CollectionPolicy,
    ) -> Result<
        Collection<SimpleArchive>,
        CollectionRegistrationError<<Self as BlobStorePut>::PutError>,
    > {
        let descriptor = descriptor::naming::<SimpleArchive>(name, policy);
        let handle = descriptor::put_closure(self, &descriptor)
            .map_err(CollectionRegistrationError::DependencyPut)?;
        Ok(Collection::from_handle(handle))
    }

    /// Create and register one canonical derived collection.
    ///
    /// The target encoding owns its canonical source relation; `argument`
    /// carries only the runtime values embedded in this concrete mapping.
    fn derive<T>(
        &mut self,
        source: Collection<T::Source>,
        argument: T::Argument,
        policy: CollectionPolicy,
    ) -> Result<Collection<T>, CollectionRegistrationError<<Self as BlobStorePut>::PutError>>
    where
        T: CollectionDerivation,
    {
        self.derive_with::<CanonicalDerivation<T>>(
            source,
            CanonicalDerivation::new(argument),
            policy,
        )
    }

    /// Create and register one collection through an explicit mapping value.
    ///
    /// This lower-level extension point remains available when Rust's orphan
    /// rule prevents either encoding crate from owning the canonical
    /// [`CollectionDerivation`] implementation.
    fn derive_with<M>(
        &mut self,
        source: Collection<M::Source>,
        mapping: M,
        policy: CollectionPolicy,
    ) -> Result<Collection<M::Target>, CollectionRegistrationError<<Self as BlobStorePut>::PutError>>
    where
        M: CollectionMapping,
    {
        let descriptor = descriptor::deriving_with(source.handle(), &mapping, policy);
        // The constructor already supplies the target encoding and both
        // policies. Only target-specific context may still need checking.
        M::Target::validate_descriptor(&descriptor).map_err(|source| {
            CollectionRegistrationError::WrongType(CollectionTypeError::InvalidDescriptor(source))
        })?;
        let handle = descriptor::put_closure(self, &descriptor)
            .map_err(CollectionRegistrationError::DependencyPut)?;
        Ok(Collection::from_handle(handle))
    }

    /// Ensure one collection for the key: "derive what you wrote".
    ///
    /// A root acquires its admitted commits, whoever wrote them. A derived
    /// collection gets a leaf, `DERIVE(target, L(F), f(F))`, for every
    /// foundation `F` of its immediate source the key owns whose locator it
    /// has no leaf for yet; empty images are published too. Other owners'
    /// foundations are theirs to derive here; `maintain` derives those an
    /// owner has left without a leaf. Each publishing operation runs
    /// against one frozen control snapshot; when it names a missing image or
    /// descriptor, acquisition ends the operation and the retry starts from a
    /// fresh snapshot that sees everything that arrived, records and proofs
    /// included. No acquisition emits a durable WANT. Newly published
    /// equations are signed by `signing_key`; a target with nothing owed does
    /// not require that key to hold WRITE authority. The returned store
    /// snapshot observes everything published by this work and by any
    /// concurrent writer before that final observation.
    fn ensure<'a, T>(
        &'a mut self,
        target: Collection<T>,
        signing_key: &'a SigningKey,
    ) -> impl Future<Output = Result<Self::Snapshot, CollectionRealizationError>> + Send + 'a
    where
        T: CollectionRealization,
        Self: Store + AsyncBlobStoreAcquire + Send,
        Handle<T>: InlineEncoding,
    {
        T::ensure(self, target, signing_key)
    }

    /// Ensure one derived collection for the key through one explicit
    /// mapping.
    fn ensure_with<'a, M>(
        &'a mut self,
        target: Collection<M::Target>,
        signing_key: &'a SigningKey,
    ) -> impl Future<Output = Result<Self::Snapshot, CollectionRealizationError>> + Send + 'a
    where
        M: CollectionMapping,
        Self: Store + AsyncBlobStoreAcquire + Send,
        Handle<M::Target>: InlineEncoding,
    {
        async move {
            super::exact_derived::acquire_authority(self, target).await?;
            super::exact_derived::ensure_acquiring_with::<Self, M>(self, target, signing_key)
                .await?;
            self.snapshot().map_err(|error| {
                CollectionRealizationError::storage("freeze post-ensure snapshot", error)
            })
        }
    }

    /// Maintain one collection for the key.
    ///
    /// A root carries the key's own frontier nodes: a node inside another
    /// own node's support is absorbed, and every tier (`floor(log_8
    /// |support|)`) holding eight own nodes is joined by one n-ary `MERGE`,
    /// until none does. Other owners' nodes are neither merged nor read. A
    /// derived collection is ensured, an own leaf whose image is absent is
    /// fetched or mapped again, and every believed source `MERGE` the key
    /// signed is mirrored, bottom-up, as a target `MERGE` over its inputs'
    /// images, the result mapped from the merged source node's bytes. A
    /// derived collection has no carry of its own, and one stored in a
    /// root's encoding is refused rather than carried. There is no
    /// caller-visible budget or tuning knob; every useful result is published
    /// independently. The live store may acquire exact dependencies while
    /// doing so. The supplied key signs each newly published `MERGE` or
    /// `DERIVE`. Without target WRITE authority, optional merging is skipped.
    fn maintain<'a, T>(
        &'a mut self,
        target: Collection<T>,
        signing_key: &'a SigningKey,
    ) -> impl Future<Output = Result<Self::Snapshot, CollectionRealizationError>> + Send + 'a
    where
        T: CollectionRealization,
        Self: Store + AsyncBlobStoreAcquire + Send,
        Handle<T>: InlineEncoding,
    {
        T::maintain(self, target, signing_key)
    }

    /// Maintain one derived collection for the key through one explicit
    /// mapping.
    fn maintain_with<'a, M>(
        &'a mut self,
        target: Collection<M::Target>,
        signing_key: &'a SigningKey,
    ) -> impl Future<Output = Result<Self::Snapshot, CollectionRealizationError>> + Send + 'a
    where
        M: CollectionMapping,
        Self: Store + AsyncBlobStoreAcquire + Send,
        Handle<M::Target>: InlineEncoding,
    {
        async move {
            super::exact_derived::acquire_authority(self, target).await?;
            super::exact_derived::maintain_acquiring_with::<Self, M>(self, target, signing_key)
                .await?;
            self.snapshot().map_err(|error| {
                CollectionRealizationError::storage("freeze post-maintenance snapshot", error)
            })
        }
    }

    /// Publish one signed fragment into an already registered collection.
    ///
    /// This performs no capability or descriptor check. Local storage is a
    /// grow-only claim ledger; authority and descriptor validity are applied
    /// at untrusted read and synchronization boundaries. Fragment attachments,
    /// data, and metadata are stored before the signed record is inserted,
    /// without an implicit durability flush.
    fn commit(
        &mut self,
        collection: Collection<SimpleArchive>,
        signing_key: &SigningKey,
        fragment: Fragment,
    ) -> Result<
        CollectionCommit,
        CollectionCommitError<
            <Self as BlobStorePut>::PutError,
            <Self as CollectionStore>::InsertError,
        >,
    > {
        PreparedCollectionCommit::from_fragment(fragment)
            .stage_for(self, collection, signing_key)?
            .finalize()
    }
}

impl<S> CollectionStoreExt for S where S: BlobStorePut + CollectionStore {}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use crate::capability::{capability_action, capability_delegate_action};
    use crate::collection::{ACTION_READ, ACTION_WRITE};
    use crate::prelude::entity;
    use crate::repo::memoryrepo::MemoryRepo;

    #[test]
    fn compound_grants_require_a_root_for_every_invocation_and_delegation_action() {
        let read_root = SigningKey::from_bytes(&[71; 32]);
        let write_root = SigningKey::from_bytes(&[72; 32]);
        let recipient = SigningKey::from_bytes(&[73; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "split action roots",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(read_root.verifying_key()),
                    AdmissionPolicy::direct(write_root.verifying_key()),
                ),
            )
            .unwrap();
        for definition in [
            entity! { capability_action*: [ACTION_READ, ACTION_WRITE] },
            entity! {
                capability_action: ACTION_READ,
                capability_delegate_action: ACTION_WRITE,
            },
            entity! { capability_delegate_action*: [ACTION_READ, ACTION_WRITE] },
        ] {
            let capability = store
                .put::<SimpleArchive, _>(definition.facts().clone())
                .unwrap();
            for root in [&read_root, &write_root] {
                assert!(matches!(
                    grant_collection_capability(
                        &mut store,
                        collection.handle(),
                        capability,
                        root,
                        recipient,
                    ),
                    Err(CollectionGrantError::RootNotAuthorized { .. })
                ));
            }
        }
        assert_eq!(store.snapshot().unwrap().proofs().unwrap().count(), 0);
    }

    #[test]
    fn an_unknown_action_or_empty_definition_cannot_borrow_a_known_action_root() {
        let root = SigningKey::from_bytes(&[74; 32]);
        let recipient = SigningKey::from_bytes(&[75; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "unknown grant actions",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::direct(root.verifying_key()),
                ),
            )
            .unwrap();
        let unknown = crate::id::genid().id;
        for definition in [
            entity! { capability_action*: [ACTION_READ, unknown] },
            entity! {
                capability_action: ACTION_READ,
                capability_delegate_action: unknown,
            },
            Fragment::empty(),
        ] {
            let capability = store
                .put::<SimpleArchive, _>(definition.facts().clone())
                .unwrap();
            assert!(matches!(
                grant_collection_capability(
                    &mut store,
                    collection.handle(),
                    capability,
                    &root,
                    recipient,
                ),
                Err(CollectionGrantError::RootNotAuthorized { .. })
            ));
        }
        assert_eq!(store.snapshot().unwrap().proofs().unwrap().count(), 0);
    }

    #[test]
    fn compound_grants_preserve_independent_quorum_shares() {
        let first = SigningKey::from_bytes(&[76; 32]);
        let second = SigningKey::from_bytes(&[77; 32]);
        let recipient = SigningKey::from_bytes(&[78; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let quorum =
            AdmissionPolicy::quorum([first.verifying_key(), second.verifying_key()], 2, None)
                .unwrap();
        let collection = store
            .collection(
                "compound quorum shares",
                CollectionPolicy::new(quorum.clone(), quorum),
            )
            .unwrap();
        let capability = store
            .put::<SimpleArchive, _>(
                entity! {
                    capability_action*: [ACTION_READ, ACTION_WRITE],
                    capability_delegate_action: ACTION_READ,
                }
                .facts()
                .clone(),
            )
            .unwrap();
        let first_proof = grant_collection_capability(
            &mut store,
            collection.handle(),
            capability,
            &first,
            recipient,
        )
        .unwrap();
        let one_share = store.snapshot().unwrap();
        assert!(!collection
            .reader_is_admitted(&one_share, recipient)
            .unwrap());
        assert!(!collection
            .writer_is_admitted(&one_share, recipient)
            .unwrap());
        grant_collection_capability(
            &mut store,
            collection.handle(),
            capability,
            &second,
            recipient,
        )
        .unwrap();
        let repeated = grant_collection_capability(
            &mut store,
            collection.handle(),
            capability,
            &first,
            recipient,
        )
        .unwrap();
        assert_eq!(repeated, first_proof);
        let both_shares = store.snapshot().unwrap();
        assert_eq!(both_shares.proofs().unwrap().count(), 2);
        assert!(collection
            .reader_is_admitted(&both_shares, recipient)
            .unwrap());
        assert!(collection
            .writer_is_admitted(&both_shares, recipient)
            .unwrap());
    }

    #[test]
    fn delegate_only_read_grant_can_confer_read_without_invoking_it() {
        let root = SigningKey::from_bytes(&[79; 32]);
        let delegate = SigningKey::from_bytes(&[80; 32]);
        let reader = SigningKey::from_bytes(&[81; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "delegate without invocation",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::direct(root.verifying_key()),
                ),
            )
            .unwrap();
        let capability = store
            .put::<SimpleArchive, _>(
                entity! { capability_delegate_action: ACTION_READ }
                    .facts()
                    .clone(),
            )
            .unwrap();
        let proof = grant_collection_capability(
            &mut store,
            collection.handle(),
            capability,
            &root,
            delegate.verifying_key(),
        )
        .unwrap();
        let child = proof
            .delegate(&delegate, read_capability(), reader)
            .unwrap();
        store.insert_proof(child).unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(!collection
            .reader_is_admitted(&snapshot, delegate.verifying_key())
            .unwrap());
        assert!(!collection
            .writer_is_admitted(&snapshot, delegate.verifying_key())
            .unwrap());
        assert!(collection.reader_is_admitted(&snapshot, reader).unwrap());
        assert!(!collection.writer_is_admitted(&snapshot, reader).unwrap());
    }

    #[test]
    fn open_actions_can_accompany_a_restricted_grant_but_cannot_authorize_it() {
        let root = SigningKey::from_bytes(&[82; 32]);
        let outsider = SigningKey::from_bytes(&[83; 32]);
        let recipient = SigningKey::from_bytes(&[84; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "public reads private writes",
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(root.verifying_key()),
                ),
            )
            .unwrap();
        let capability = store
            .put::<SimpleArchive, _>(
                entity! {
                    capability_action*: [ACTION_READ, ACTION_WRITE],
                    capability_delegate_action: ACTION_READ,
                }
                .facts()
                .clone(),
            )
            .unwrap();
        assert!(matches!(
            grant_collection_capability(
                &mut store,
                collection.handle(),
                capability,
                &outsider,
                recipient,
            ),
            Err(CollectionGrantError::RootNotAuthorized { .. })
        ));
        grant_collection_capability(
            &mut store,
            collection.handle(),
            capability,
            &root,
            recipient,
        )
        .unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(collection.reader_is_admitted(&snapshot, recipient).unwrap());
        assert!(collection.writer_is_admitted(&snapshot, recipient).unwrap());
        assert!(matches!(
            grant_collection_read(&mut store, collection.handle(), &root, recipient),
            Err(CollectionGrantError::OpenPolicy { .. })
        ));
        let open = store
            .collection(
                "both actions open",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        assert!(matches!(
            grant_collection_capability(&mut store, open.handle(), capability, &root, recipient),
            Err(CollectionGrantError::OpenPolicy { .. })
        ));
        assert_eq!(store.snapshot().unwrap().proofs().unwrap().count(), 1);
    }
}
