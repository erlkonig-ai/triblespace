//! Exact per-collection semantic repair state.
//!
//! Collection records and authorization proofs are independent grow-only
//! sets. A newly arrived proof may activate an old COMMIT or admit a new reader
//! without changing the record PATCH. A collection wake commits to both and to
//! its pinned positive resident-blob inventory, without disclosing those handles.
//! The authorization projection contains byte-valid proofs for exact C and its
//! configured roots. Definition residency determines authority, not membership.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, TryFromBlob};
use triblespace_core::capability::policy::{resource_collection, resource_policies};
use triblespace_core::capability::{
    CapabilityHandle, CapabilityProof, CapabilityProofError, CapabilityProofId, CapabilityRequest,
    CapabilityResource,
};
use triblespace_core::collection::{
    collection_read_audience_by_policy, collection_reader_is_admitted_by_policy, descriptor,
    AdmissionPolicy, CollectionDescriptorError, CollectionHandle, CollectionPolicy, CollectionRead,
    CollectionReadAudience, RecordDecodeError, ACTION_READ, ACTION_WRITE,
};
use triblespace_core::id::Id;
use triblespace_core::patch::{Blake3Merkle, Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::prelude::{find, pattern};
use triblespace_core::repo::{BlobStoreGet, CapabilityProofRead};
use triblespace_core::trible::TribleSet;

use crate::collection_delta::{
    collection_record_patch, CollectionRecordPatch, CollectionRecordPatchError,
};
use crate::host::ResidentBlobReader;
use crate::patch_repair::PatchSummary;

const COLLECTION_REPAIR_ROOT_DOMAIN: &[u8] = b"triblespace.collection.repair-overlay\0";
const COLLECTION_REPAIR_ROOT_VERSION: u32 = 2;

type AuthorizationEvidencePatch = PATCH<64, IdentitySchema, CapabilityProof, Blake3Merkle>;

fn evidence_key(collection: CollectionHandle, id: CapabilityProofId) -> [u8; 64] {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&collection.raw);
    key[32..].copy_from_slice(&id.raw);
    key
}

/// Canonical collection-scoped set of structurally relevant authorization proofs.
///
/// Keys are repair audience C | proof hash, not proof resource | proof hash.
/// The proof's own resource remains part of its signed bytes. Values share ownership of the raw proof
/// bytes; this validated membership index does not copy proof bodies. The
/// public observation and repair protocol expose only the selected resource
/// prefix, never the enclosing index. This is currently a per-overlay index,
/// not a shared global host inventory.
#[derive(Clone, Debug)]
pub struct CollectionAuthorizationEvidencePatch {
    collection: CollectionHandle,
    descriptor: TribleSet,
    proofs: AuthorizationEvidencePatch,
    reader: ResidentBlobReader,
}

impl CollectionAuthorizationEvidencePatch {
    /// Exact collection whose declared capabilities shaped this evidence set.
    pub const fn collection(&self) -> CollectionHandle {
        self.collection
    }

    /// Inspect one unambiguous scalar policy for diagnostics.
    /// Ordinary admission queries the capability-specific alternatives instead.
    pub fn policy(&self) -> Result<CollectionPolicy, RecordDecodeError> {
        descriptor::policy(&self.descriptor)
    }

    /// Explicitly recognized READ policies from the pinned descriptor facts.
    pub fn read_policies(&self) -> impl Iterator<Item = AdmissionPolicy> + '_ {
        descriptor::admission_policies(&self.reader, &self.descriptor, ACTION_READ, None)
    }

    /// Explicitly recognized WRITE policies from the pinned descriptor facts.
    pub fn write_policies(&self) -> impl Iterator<Item = AdmissionPolicy> + '_ {
        descriptor::admission_policies(&self.reader, &self.descriptor, ACTION_WRITE, None)
    }

    /// Every supported capability-policy binding declared by the descriptor.
    pub fn capability_policies(
        &self,
    ) -> impl Iterator<Item = (CapabilityHandle, AdmissionPolicy)> + '_ {
        descriptor::capability_policies(&self.descriptor, None)
    }

    /// Plausible endpoint keys named by this collection's authority evidence.
    ///
    /// Descriptor-declared policy roots are followed by the root and every
    /// delegate of each retained proof, including intermediate issuers. This
    /// uses only recognized policy geometry and signature-valid evidence;
    /// missing capability definitions or READ admission do not hide candidates.
    /// Subordinate-resource proofs contribute only after their immutable
    /// same-entity route and own policy roots selected them into this PATCH.
    ///
    /// These are routing hints, not authorization or evidence that an endpoint
    /// is online, serves this collection, or has any payloads. Duplicates and
    /// the caller's own key are retained. Callers deduplicate, exclude self,
    /// and schedule attempts without truncating this evidence projection.
    pub fn discovery_candidates(&self) -> impl Iterator<Item = VerifyingKey> + '_ {
        let roots = self
            .capability_policies()
            .filter_map(|(_, policy)| match policy {
                AdmissionPolicy::Open => None,
                AdmissionPolicy::Quorum(quorum) => Some(quorum),
            })
            .flat_map(|quorum| (0..quorum.roots().len()).map(move |index| quorum.roots()[index]));
        roots.chain(
            self.proofs()
                .flat_map(|proof| std::iter::once(proof.root_key()).chain(proof.delegated_keys())),
        )
    }

    /// Validate exact resource, configured root, and the signed byte chain.
    /// Capability definitions need not be resident for evidence to be repaired.
    pub fn validate_proof(
        &self,
        proof: &CapabilityProof,
    ) -> Result<(), CollectionAuthorizationEvidenceError> {
        let resource = CollectionHandle::new(proof.resource().into_bytes());
        if resource == self.collection {
            return validate_evidence_for_policies(
                self.collection,
                self.capability_policies().map(|(_, policy)| policy),
                proof,
            );
        }
        let facts: TribleSet = self.reader.get(resource).map_err(|_| {
            CollectionAuthorizationEvidenceError::ResourceDescriptorUnavailable(resource)
        })?;
        let collection = self.collection;
        let policies = find!(
            resource: Id,
            pattern!(&facts, [{ ?resource @ resource_collection: collection }])
        )
        .flat_map(|resource| resource_policies(&facts, resource, None).map(|(_, policy)| policy));
        // Backlink and binding must belong to the same entity in the immutable
        // R blob. A mutable C fact can neither create nor change this route.
        validate_evidence_for_policies(resource, policies, proof)
    }

    pub(crate) fn reader_is_admitted_by(
        &self,
        subject: VerifyingKey,
        proofs: &[CapabilityProof],
    ) -> bool {
        self.read_policies().any(|policy| {
            collection_reader_is_admitted_by_policy(
                &self.reader,
                self.collection,
                &policy,
                subject,
                proofs,
            )
        })
    }

    /// Root and count of the immutable native-proof PATCH.
    pub fn summary(&self) -> PatchSummary {
        self.prefix_summary(&[]).unwrap_or_else(|| {
            PatchSummary::new(None, 0).expect("empty authorization prefix is canonical")
        })
    }

    /// Number of distinct self-contained native proofs.
    pub fn len(&self) -> u64 {
        self.summary().leaf_count()
    }

    /// Whether the projection contains no proof evidence.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up one exact native proof by identity.
    pub fn get(&self, id: CapabilityProofId) -> Option<&CapabilityProof> {
        self.proofs.get(&evidence_key(self.collection, id))
    }

    /// Enumerate every retained native proof in proof-id order.
    pub fn proofs(&self) -> impl Iterator<Item = &CapabilityProof> {
        self.proofs
            .iter_ordered()
            .filter(|key| key.starts_with(&self.collection.raw))
            .map(|key| {
                self.proofs
                    .get(key)
                    .expect("an ordered authorization-evidence key retains its proof")
            })
    }

    pub(crate) const fn patch(&self) -> &AuthorizationEvidencePatch {
        &self.proofs
    }

    pub(crate) fn prefix_summary(&self, prefix: &[u8]) -> Option<PatchSummary> {
        if prefix.len() > 32 {
            return None;
        }
        let mut absolute = self.collection.raw.to_vec();
        absolute.extend_from_slice(prefix);
        self.proofs.merkle_node(&absolute).map(|node| {
            PatchSummary::new(Some(node.digest()), node.leaf_count())
                .expect("a retained authorization prefix is nonempty")
        })
    }

    /// Derive the finite READ(C)-authorized audience from resident definitions.
    ///
    /// Restricted policies return a deterministic, deduplicated list from
    /// independent rooted paths, applying action, delegation, and quorum rules.
    /// Open READ is explicit because no finite list can enumerate its audience.
    pub fn authorized_readers(&self) -> CollectionReadAudience {
        let proofs = self.proofs().cloned().collect::<Vec<_>>();
        let mut readers = BTreeMap::new();
        for policy in self.read_policies() {
            match collection_read_audience_by_policy(
                &self.reader,
                self.collection,
                &policy,
                &proofs,
            ) {
                CollectionReadAudience::Open => return CollectionReadAudience::Open,
                CollectionReadAudience::Restricted(subjects) => {
                    readers.extend(
                        subjects
                            .into_iter()
                            .map(|subject| (subject.to_bytes(), subject)),
                    );
                }
            }
        }
        CollectionReadAudience::Restricted(readers.into_values().collect())
    }

    /// Select the local READ witness from this already constructed evidence.
    /// The caller applies its transport bound after quorum minimization.
    pub(crate) fn read_bootstrap_proofs(&self, subject: VerifyingKey) -> Vec<CapabilityProof> {
        if self
            .read_policies()
            .any(|policy| matches!(policy, AdmissionPolicy::Open))
        {
            return Vec::new();
        }
        let mut selected = self
            .proofs()
            .filter(|proof| {
                proof.resource() == CapabilityResource::from(self.collection)
                    && self
                        .read_policies()
                        .any(|policy| root_is_relevant(&policy, proof.root_key()))
            })
            .filter_map(|proof| {
                proof
                    .prefixes()
                    .filter(|prefix| prefix.subject() == subject)
                    .find_map(|prefix| {
                        let witness = CapabilityProof::from_bytes(prefix.as_bytes())
                            .expect("an exact prefix of a canonical proof is canonical");
                        witness
                            .verify(
                                &self.reader,
                                proof.root_key(),
                                subject,
                                CapabilityRequest::new(
                                    CapabilityResource::from(self.collection),
                                    ACTION_READ,
                                ),
                            )
                            .is_ok()
                            .then_some(witness)
                    })
            })
            .collect::<Vec<_>>();
        if !self.reader_is_admitted_by(subject, &selected) {
            return Vec::new();
        }
        // Each witness ends at the earliest valid READ prefix for this subject;
        // later delegates and their capability handles never enter bootstrap.
        // Delete only proofs not required by the independently rooted quorum.
        let mut index = selected.len();
        while index > 0 {
            index -= 1;
            let removed = selected.remove(index);
            if !self.reader_is_admitted_by(subject, &selected) {
                selected.insert(index, removed);
            }
        }
        selected
    }
}

/// Pinned semantic repair evidence and positive resident-blob inventory.
#[derive(Clone, Debug)]
pub struct CollectionRepairOverlay {
    collection: CollectionHandle,
    records: CollectionRecordPatch,
    authorization_evidence: CollectionAuthorizationEvidencePatch,
    blob_inventory: Arc<PATCH<32, IdentitySchema, (), Blake3Merkle>>,
}

impl CollectionRepairOverlay {
    /// Exact collection represented by this repair observation.
    pub const fn collection(&self) -> CollectionHandle {
        self.collection
    }

    /// Inspect one unambiguous scalar policy for diagnostics.
    /// The pinned evidence retains descriptor facts, not a singular policy gate.
    pub fn policy(&self) -> Result<CollectionPolicy, RecordDecodeError> {
        self.authorization_evidence.policy()
    }

    /// Structurally valid collection records naming this collection.
    ///
    /// WRITE admission is deliberately derived by each receiver from this
    /// component and its local authorization evidence, so records and proofs
    /// may arrive in either order.
    pub const fn records(&self) -> &CollectionRecordPatch {
        &self.records
    }

    /// Structurally relevant proofs for descriptor-declared capabilities over C.
    pub const fn authorization_evidence(&self) -> &CollectionAuthorizationEvidencePatch {
        &self.authorization_evidence
    }

    /// Positive resident handles associated with this collection observation.
    /// Absence is not evidence of deletion or unavailability elsewhere.
    pub fn blob_inventory(&self) -> &PATCH<32, IdentitySchema, (), Blake3Merkle> {
        &self.blob_inventory
    }

    /// Bind inventory from the same immutable observation as the repair evidence.
    /// Its handles are disclosed only inside the READ-authorized pinned session.
    pub fn with_blob_inventory(
        mut self,
        inventory: Arc<PATCH<32, IdentitySchema, (), Blake3Merkle>>,
    ) -> Self {
        self.blob_inventory = inventory;
        self
    }

    /// Route candidates from descriptor roots and structurally relevant AUTH.
    ///
    /// See [`CollectionAuthorizationEvidencePatch::discovery_candidates`] for
    /// the hint-only contract and caller-owned deduplication and scheduling.
    pub fn discovery_candidates(&self) -> impl Iterator<Item = VerifyingKey> + '_ {
        self.authorization_evidence.discovery_candidates()
    }

    /// Opaque digest suitable for the collection gossip wake root.
    ///
    /// Counts participate alongside roots so the digest commits to the same
    /// authenticated component summaries used by PATCH repair. Neither a
    /// proof, record, blob handle, count, nor component root is disclosed by
    /// this value.
    pub fn wake_root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COLLECTION_REPAIR_ROOT_DOMAIN);
        hasher.update(&COLLECTION_REPAIR_ROOT_VERSION.to_be_bytes());
        hasher.update(&self.collection.raw);
        update_summary(&mut hasher, self.records.summary());
        update_summary(&mut hasher, self.authorization_evidence.summary());
        update_summary(&mut hasher, PatchSummary::from_patch(self.blob_inventory()));
        *hasher.finalize().as_bytes()
    }

    /// Keep fixed components whose raw inputs the store certifies unchanged.
    /// Request-dependent authorization always receives this snapshot's reader.
    pub(crate) fn observe<R>(
        snapshot: &R,
        collection: CollectionHandle,
        previous_records: Option<&CollectionRecordPatch>,
        previous_authorization: Option<&CollectionAuthorizationEvidencePatch>,
    ) -> Result<
        Self,
        CollectionRepairOverlayError<R::RecordsError, R::ProofsError, R::GetError<Infallible>>,
    >
    where
        R: BlobStoreGet + CapabilityProofRead + CollectionRead + Clone + Send + 'static,
    {
        let authorization_evidence = match previous_authorization {
            Some(evidence) => CollectionAuthorizationEvidencePatch {
                reader: ResidentBlobReader::new(snapshot),
                ..evidence.clone()
            },
            None => {
                let descriptor = load_collection_descriptor_facts(snapshot, collection)
                    .map_err(CollectionRepairOverlayError::Descriptor)?;
                collection_authorization_evidence_patch_for_descriptor(
                    snapshot, collection, descriptor,
                )
                .map_err(|error| match error {
                    AuthorizationEvidenceBuildError::Proofs(source) => {
                        CollectionRepairOverlayError::Proofs(source)
                    }
                    AuthorizationEvidenceBuildError::Evidence(source) => {
                        CollectionRepairOverlayError::Evidence(source)
                    }
                })?
            }
        };
        let records = match previous_records {
            Some(records) => records.clone(),
            None => collection_record_patch(snapshot, collection)
                .map_err(CollectionRepairOverlayError::Records)?,
        };
        Ok(Self {
            collection,
            records,
            authorization_evidence,
            blob_inventory: Arc::new(PATCH::new()),
        })
    }

    /// Rebind future request-dependent reads without changing fixed evidence.
    /// Existing sessions retain their original reader and immutable PATCHes.
    pub(crate) fn with_reader(mut self, reader: ResidentBlobReader) -> Self {
        self.authorization_evidence.reader = reader;
        self
    }
}

fn update_summary(hasher: &mut blake3::Hasher, summary: PatchSummary) {
    match summary.root() {
        Some(root) => {
            hasher.update(&[1]);
            hasher.update(&root);
        }
        None => {
            hasher.update(&[0]);
            hasher.update(&[0; 32]);
        }
    }
    hasher.update(&summary.leaf_count().to_be_bytes());
}

/// A proof is not collection-scoped authorization evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionAuthorizationEvidenceError {
    /// Both collection policies are open and need no proof evidence.
    OpenPolicies,
    /// The proof names a different opaque resource.
    WrongResource,
    /// The subordinate resource's immutable routing descriptor is not resident.
    ResourceDescriptorUnavailable(CollectionHandle),
    /// The proof starts outside all descriptor-local roots.
    WrongRoot,
    /// A signature in the prefix chain is invalid.
    Invalid(CapabilityProofError),
    /// Cryptographically distinct proof values share one proof identity.
    ProofIdCollision(CapabilityProofId),
}

impl fmt::Display for CollectionAuthorizationEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenPolicies => {
                formatter.write_str("open READ and WRITE policies need no proof evidence")
            }
            Self::WrongRoot => {
                formatter.write_str("capability proof starts outside the collection policy roots")
            }
            Self::WrongResource => {
                formatter.write_str("capability proof names a different resource")
            }
            Self::ResourceDescriptorUnavailable(resource) => write!(
                formatter,
                "capability resource descriptor is unavailable: blake3:{}",
                hex::encode(resource.raw)
            ),
            Self::Invalid(source) => {
                write!(
                    formatter,
                    "invalid collection authorization proof: {source}"
                )
            }
            Self::ProofIdCollision(id) => write!(
                formatter,
                "distinct collection authorization proofs share id {}",
                hex::encode_upper(id.raw),
            ),
        }
    }
}

impl Error for CollectionAuthorizationEvidenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(source) => Some(source),
            _ => None,
        }
    }
}

/// Failure while constructing collection-scoped authorization evidence.
#[derive(Debug)]
pub enum CollectionAuthorizationEvidenceDiscoveryError<ProofsError, GetError> {
    /// The descriptor is absent or structurally invalid.
    Descriptor(CollectionDescriptorError<GetError>),
    /// The coherent proof-store observation failed.
    Proofs(ProofsError),
    /// Canonical evidence construction found a proof-id collision.
    Evidence(CollectionAuthorizationEvidenceError),
}

enum AuthorizationEvidenceBuildError<ProofsError> {
    Proofs(ProofsError),
    Evidence(CollectionAuthorizationEvidenceError),
}

impl<ProofsError, GetError> fmt::Display
    for CollectionAuthorizationEvidenceDiscoveryError<ProofsError, GetError>
where
    ProofsError: fmt::Display,
    GetError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(source) => source.fmt(formatter),
            Self::Proofs(source) => write!(formatter, "enumerate capability proofs: {source}"),
            Self::Evidence(source) => source.fmt(formatter),
        }
    }
}

impl<ProofsError, GetError> Error
    for CollectionAuthorizationEvidenceDiscoveryError<ProofsError, GetError>
where
    ProofsError: Error + 'static,
    GetError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(source) => Some(source),
            Self::Proofs(source) => Some(source),
            Self::Evidence(source) => Some(source),
        }
    }
}

/// Failure while selecting bounded native READ proofs for `C`.
#[derive(Debug)]
pub enum CollectionReadBootstrapError<ProofsError, GetError> {
    /// The descriptor is absent or structurally invalid.
    Descriptor(CollectionDescriptorError<GetError>),
    /// The coherent proof-store observation failed.
    Proofs(ProofsError),
    /// More relevant proofs exist than the caller's transport bound permits.
    TooMany {
        /// Exact number of canonical relevant proofs.
        count: usize,
        /// Caller-supplied maximum.
        limit: usize,
    },
    /// Collection-scoped authorization evidence discovery failed.
    Authorization(CollectionAuthorizationEvidenceError),
}

impl<ProofsError, GetError> fmt::Display for CollectionReadBootstrapError<ProofsError, GetError>
where
    ProofsError: fmt::Display,
    GetError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(source) => source.fmt(formatter),
            Self::Proofs(source) => write!(formatter, "enumerate capability proofs: {source}"),
            Self::TooMany { count, limit } => write!(
                formatter,
                "collection READ bootstrap has {count} proofs; limit is {limit}",
            ),
            Self::Authorization(source) => source.fmt(formatter),
        }
    }
}

impl<ProofsError, GetError> Error for CollectionReadBootstrapError<ProofsError, GetError>
where
    ProofsError: Error + 'static,
    GetError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Descriptor(source) => Some(source),
            Self::Proofs(source) => Some(source),
            Self::TooMany { .. } => None,
            Self::Authorization(source) => Some(source),
        }
    }
}

/// Failure while freezing the repair overlay of one collection.
#[derive(Debug)]
pub enum CollectionRepairOverlayError<RecordsError, ProofsError, GetError> {
    /// Exact collection-record selection failed.
    Records(CollectionRecordPatchError<RecordsError>),
    /// The descriptor is absent or structurally invalid.
    Descriptor(CollectionDescriptorError<GetError>),
    /// The coherent proof-store observation failed.
    Proofs(ProofsError),
    /// Canonical evidence construction found a proof-id collision.
    Evidence(CollectionAuthorizationEvidenceError),
}

impl<RecordsError, ProofsError, GetError> fmt::Display
    for CollectionRepairOverlayError<RecordsError, ProofsError, GetError>
where
    RecordsError: fmt::Display,
    ProofsError: fmt::Display,
    GetError: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Records(source) => source.fmt(formatter),
            Self::Descriptor(source) => source.fmt(formatter),
            Self::Proofs(source) => write!(formatter, "enumerate capability proofs: {source}"),
            Self::Evidence(source) => source.fmt(formatter),
        }
    }
}

impl<RecordsError, ProofsError, GetError> Error
    for CollectionRepairOverlayError<RecordsError, ProofsError, GetError>
where
    RecordsError: Error + 'static,
    ProofsError: Error + 'static,
    GetError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Records(source) => Some(source),
            Self::Descriptor(source) => Some(source),
            Self::Proofs(source) => Some(source),
            Self::Evidence(source) => Some(source),
        }
    }
}

/// Freeze exact collection records and the structurally relevant
/// descriptor-declared capability proof PATCH for `C`.
///
/// Missing descriptor bytes or invalid archives fail closed. Unknown policy
/// rows are inert; no recognized READ alternative means no reader is admitted.
/// Invalid or irrelevant ambient proofs are inert. Record inclusion is independent of
/// WRITE admission and time: a receiver derives its admitted view locally
/// after both grow-only components land in either order. Failure to enumerate
/// the coherent proof snapshot is an error.
pub fn collection_repair_overlay<R>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<
    CollectionRepairOverlay,
    CollectionRepairOverlayError<R::RecordsError, R::ProofsError, R::GetError<Infallible>>,
>
where
    R: BlobStoreGet + CapabilityProofRead + CollectionRead + Clone + Send + 'static,
{
    CollectionRepairOverlay::observe(snapshot, collection, None, None)
}

fn load_collection_descriptor_facts<R>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<TribleSet, CollectionDescriptorError<R::GetError<Infallible>>>
where
    R: BlobStoreGet,
{
    let descriptor_blob: Blob<SimpleArchive> = snapshot
        .get(collection)
        .map_err(|source| CollectionDescriptorError::Get { collection, source })?;
    TribleSet::try_from_blob(descriptor_blob).map_err(|source| CollectionDescriptorError::Invalid {
        collection,
        source: RecordDecodeError::from(source),
    })
}

/// Freeze all structurally relevant proofs for the descriptor's declared
/// roots over exact C, from one coherent store observation. Missing capability
/// definitions remain repairable evidence without granting any authority.
pub fn collection_authorization_evidence<R>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<
    CollectionAuthorizationEvidencePatch,
    CollectionAuthorizationEvidenceDiscoveryError<R::ProofsError, R::GetError<Infallible>>,
>
where
    R: BlobStoreGet + CapabilityProofRead + Clone + Send + 'static,
{
    let descriptor = load_collection_descriptor_facts(snapshot, collection)
        .map_err(CollectionAuthorizationEvidenceDiscoveryError::Descriptor)?;
    collection_authorization_evidence_patch_for_descriptor(snapshot, collection, descriptor)
        .map_err(|error| match error {
            AuthorizationEvidenceBuildError::Proofs(source) => {
                CollectionAuthorizationEvidenceDiscoveryError::Proofs(source)
            }
            AuthorizationEvidenceBuildError::Evidence(source) => {
                CollectionAuthorizationEvidenceDiscoveryError::Evidence(source)
            }
        })
}

/// Select deterministic bounded native proofs for exact READ(C).
///
/// The descriptor's recognized READ alternatives shape the result. Each returned
/// self-contained proof has a valid signature path over the exact resource.
/// Selection and deletion minimization interpret resident definitions for READ;
/// transport membership itself never depends on definition residency.
/// Invalid, irrelevant, and duplicate ambient proofs are inert. The caller
/// chooses `max_proofs`; a larger independent-root witness fails rather than
/// silently dropping paths required by quorum.
pub fn collection_read_bootstrap_proofs<R>(
    snapshot: &R,
    collection: CollectionHandle,
    subject: VerifyingKey,
    max_proofs: usize,
) -> Result<
    Vec<CapabilityProof>,
    CollectionReadBootstrapError<R::ProofsError, R::GetError<Infallible>>,
>
where
    R: BlobStoreGet + CapabilityProofRead + Clone + Send + 'static,
{
    let evidence =
        collection_authorization_evidence(snapshot, collection).map_err(|error| match error {
            CollectionAuthorizationEvidenceDiscoveryError::Descriptor(source) => {
                CollectionReadBootstrapError::Descriptor(source)
            }
            CollectionAuthorizationEvidenceDiscoveryError::Proofs(source) => {
                CollectionReadBootstrapError::Proofs(source)
            }
            CollectionAuthorizationEvidenceDiscoveryError::Evidence(source) => {
                CollectionReadBootstrapError::Authorization(source)
            }
        })?;
    let selected = evidence.read_bootstrap_proofs(subject);
    if selected.len() > max_proofs {
        return Err(CollectionReadBootstrapError::TooMany {
            count: selected.len(),
            limit: max_proofs,
        });
    }
    Ok(selected)
}

fn collection_authorization_evidence_patch_for_descriptor<R>(
    snapshot: &R,
    collection: CollectionHandle,
    descriptor: TribleSet,
) -> Result<CollectionAuthorizationEvidencePatch, AuthorizationEvidenceBuildError<R::ProofsError>>
where
    R: BlobStoreGet + CapabilityProofRead + Clone + Send + 'static,
{
    let proofs = snapshot
        .proofs()
        .map_err(AuthorizationEvidenceBuildError::Proofs)?;
    let mut candidates = Vec::new();
    for proof in proofs {
        let proof = proof.map_err(AuthorizationEvidenceBuildError::Proofs)?;
        candidates.push(proof);
    }
    canonical_authorization_evidence(snapshot, collection, descriptor, candidates)
        .map_err(AuthorizationEvidenceBuildError::Evidence)
}

fn canonical_authorization_evidence<R: BlobStoreGet + Clone + Send + 'static>(
    snapshot: &R,
    collection: CollectionHandle,
    descriptor: TribleSet,
    candidates: impl IntoIterator<Item = CapabilityProof>,
) -> Result<CollectionAuthorizationEvidencePatch, CollectionAuthorizationEvidenceError> {
    let mut evidence = CollectionAuthorizationEvidencePatch {
        collection,
        descriptor,
        proofs: AuthorizationEvidencePatch::new(),
        reader: ResidentBlobReader::new(snapshot),
    };
    for proof in candidates {
        if evidence.validate_proof(&proof).is_err() {
            continue;
        }
        let id = proof.id();
        let key = evidence_key(collection, id);
        if let Some(existing) = evidence.proofs.get(&key) {
            if existing != &proof {
                return Err(CollectionAuthorizationEvidenceError::ProofIdCollision(id));
            }
            continue;
        }
        evidence.proofs.insert(&PatchEntry::with_value(&key, proof));
    }
    Ok(evidence)
}

fn root_is_relevant(policy: &AdmissionPolicy, root: ed25519_dalek::VerifyingKey) -> bool {
    policy.roots().is_some_and(|roots| {
        roots
            .binary_search_by_key(&root.to_bytes(), ed25519_dalek::VerifyingKey::to_bytes)
            .is_ok()
    })
}

/// Validate byte-only proof membership for an exact resource and configured root.
/// This does not establish READ or WRITE authority without its definitions.
pub fn validate_authorization_evidence_proof(
    collection: CollectionHandle,
    policy: &CollectionPolicy,
    proof: &CapabilityProof,
) -> Result<(), CollectionAuthorizationEvidenceError> {
    if matches!(policy.read(), AdmissionPolicy::Open)
        && matches!(policy.write(), AdmissionPolicy::Open)
    {
        return Err(CollectionAuthorizationEvidenceError::OpenPolicies);
    }
    validate_evidence_for_policies(
        collection,
        [policy.read().clone(), policy.write().clone()],
        proof,
    )
}

fn validate_evidence_for_policies(
    collection: CollectionHandle,
    policies: impl IntoIterator<Item = AdmissionPolicy>,
    proof: &CapabilityProof,
) -> Result<(), CollectionAuthorizationEvidenceError> {
    // Header filters are cheap; they assign no authority and acquire no blobs.
    if proof.resource() != CapabilityResource::from(collection) {
        return Err(CollectionAuthorizationEvidenceError::WrongResource);
    }
    if !policies
        .into_iter()
        .any(|policy| root_is_relevant(&policy, proof.root_key()))
    {
        return Err(CollectionAuthorizationEvidenceError::WrongRoot);
    }
    proof
        .verify_signatures()
        .map_err(CollectionAuthorizationEvidenceError::Invalid)
}

#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.

    use std::num::NonZeroUsize;

    use ed25519_dalek::SigningKey;
    use triblespace_core::capability::policy::{capability_handle, resource_policy};
    use triblespace_core::capability::{
        capability_action, capability_delegate_action, capability_quorum_authorizes,
        CapabilityRequest,
    };
    use triblespace_core::collection::{
        empty_metadata_handle, read_capability, write_capability, CollectionCommit, CollectionData,
        CollectionDerive, CollectionMerge, CollectionPolicy, CollectionRecord, CollectionStore,
        CollectionStoreExt, KIND_COLLECTION_DESCRIPTOR,
    };
    use triblespace_core::inline::Inline;
    use triblespace_core::metadata;
    use triblespace_core::prelude::entity;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStorePut, CapabilityProofStore, SnapshotSource};

    use super::*;
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::blob::{MemoryBlobStore, MemoryBlobStoreSnapshot};

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn data(byte: u8) -> CollectionData {
        Inline::new([byte; 32])
    }

    fn policy(roots: &[SigningKey], threshold: u32) -> CollectionPolicy {
        CollectionPolicy::new(
            AdmissionPolicy::Open,
            AdmissionPolicy::quorum(roots.iter().map(SigningKey::verifying_key), threshold, None)
                .unwrap(),
        )
    }

    fn policy_facts(policy: CollectionPolicy) -> TribleSet {
        entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: policy.read().binding(read_capability())
                + policy.write().binding(write_capability()),
        }
        .facts()
        .clone()
    }

    fn scope(
        capability: CapabilityHandle,
        collection: CollectionHandle,
    ) -> (CapabilityHandle, CollectionHandle) {
        (capability, collection)
    }

    fn write_scope(collection: CollectionHandle) -> (CapabilityHandle, CollectionHandle) {
        scope(write_capability(), collection)
    }

    fn definitions() -> MemoryBlobStoreSnapshot {
        let mut store = MemoryBlobStore::new();
        store.insert::<SimpleArchive>(
            entity! { capability_action: ACTION_READ }
                .facts()
                .clone()
                .to_blob(),
        );
        store.insert::<SimpleArchive>(
            entity! { capability_action: ACTION_WRITE }
                .facts()
                .clone()
                .to_blob(),
        );
        store.snapshot().unwrap()
    }

    fn root_proof(
        root: &SigningKey,
        subject: &SigningKey,
        (capability, collection): (CapabilityHandle, CollectionHandle),
    ) -> CapabilityProof {
        CapabilityProof::new(
            CapabilityResource::from(collection),
            root,
            capability,
            subject.verifying_key(),
        )
    }

    fn store_proof(store: &mut MemoryRepo, proof: CapabilityProof) {
        store.insert_proof(proof).unwrap();
    }

    #[test]
    fn discovery_keeps_descriptor_roots_without_definitions_proofs_or_admission() {
        let first = key(110);
        let second = key(111);
        let unbound = key(112);
        let missing_definition = Inline::new([113; 32]);
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::quorum(
                [first.verifying_key(), second.verifying_key()], 2, None,
            ).unwrap().binding(missing_definition)
                + AdmissionPolicy::Open.binding(write_capability()),
        } + AdmissionPolicy::direct(unbound.verifying_key())
            .binding(read_capability());
        let mut store = MemoryRepo::default();
        let collection = store
            .put::<SimpleArchive, _>(descriptor.facts().clone())
            .unwrap();
        let overlay = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
        let evidence = overlay.authorization_evidence();
        assert!(evidence.is_empty());
        assert_eq!(evidence.read_policies().count(), 0);
        assert!(!evidence.reader_is_admitted_by(first.verifying_key(), &[]));
        let mut expected =
            [first.verifying_key(), second.verifying_key()].map(|key| key.to_bytes());
        expected.sort();
        let mut actual = overlay
            .discovery_candidates()
            .map(|key| key.to_bytes())
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(actual, expected, "unbound policy roots are not candidates");
        assert_eq!(
            overlay.discovery_candidates().collect::<Vec<_>>(),
            evidence.discovery_candidates().collect::<Vec<_>>()
        );
    }

    #[test]
    fn discovery_keeps_exact_resource_proof_chain_but_not_unrelated_or_invalid_proofs() {
        let root = key(114);
        let intermediate = key(115);
        let leaf = key(116);
        let unrelated = key(117);
        let unconfigured = key(118);
        let invalid_subject = key(119);
        let collection = Inline::new([120; 32]);
        let missing_definition = Inline::new([121; 32]);
        let chain = root_proof(&root, &intermediate, scope(missing_definition, collection))
            .delegate(&intermediate, missing_definition, leaf.verifying_key())
            .unwrap();
        let wrong_resource = root_proof(
            &root,
            &unrelated,
            scope(missing_definition, Inline::new([122; 32])),
        );
        let wrong_root = root_proof(
            &unconfigured,
            &unrelated,
            scope(missing_definition, collection),
        );
        let mut invalid = root_proof(
            &root,
            &invalid_subject,
            scope(missing_definition, collection),
        )
        .into_bytes();
        *invalid.last_mut().unwrap() ^= 1;
        let invalid = CapabilityProof::from_bytes(&invalid).unwrap();
        let evidence = canonical_authorization_evidence(
            &MemoryBlobStore::new().snapshot().unwrap(),
            collection,
            policy_facts(CollectionPolicy::new(
                AdmissionPolicy::direct(root.verifying_key()),
                AdmissionPolicy::Open,
            )),
            [chain.clone(), wrong_resource, wrong_root, invalid],
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(!evidence.reader_is_admitted_by(leaf.verifying_key(), &[chain]));
        let candidates = evidence.discovery_candidates().collect::<Vec<_>>();
        assert_eq!(
            candidates,
            [
                root.verifying_key(),
                root.verifying_key(),
                intermediate.verifying_key(),
                leaf.verifying_key(),
            ],
            "raw hint projection preserves duplicates and every chain principal"
        );
    }

    #[test]
    fn proof_membership_requires_resource_and_root_but_not_definition_residency() {
        let root = key(60);
        let subject = key(61);
        let custom = Inline::new([62; 32]);
        let collection = Inline::new([63; 32]);
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(custom),
        };
        let proof_for = |issuer: &SigningKey, capability, resource| {
            root_proof(issuer, &subject, scope(capability, resource))
        };
        let bound = proof_for(&root, custom, collection);
        let unknown_definition = proof_for(&root, Inline::new([65; 32]), collection);
        let invalid = [
            proof_for(&root, custom, Inline::new([64; 32])),
            proof_for(&key(66), custom, collection),
        ];
        let evidence = canonical_authorization_evidence(
            &definitions(),
            collection,
            descriptor.facts().clone(),
            [bound.clone(), unknown_definition.clone()]
                .into_iter()
                .chain(invalid.iter().cloned()),
        )
        .unwrap();
        assert_eq!(evidence.len(), 2);
        for proof in [bound, unknown_definition] {
            evidence.validate_proof(&proof).unwrap();
            assert_eq!(evidence.get(proof.id()), Some(&proof));
            assert!(!evidence.reader_is_admitted_by(subject.verifying_key(), &[proof]));
        }
        for proof in invalid {
            assert!(evidence.validate_proof(&proof).is_err());
            assert!(evidence.get(proof.id()).is_none());
        }
    }

    #[test]
    fn generic_inventory_keeps_shares_without_combining_different_actions() {
        let a = key(67);
        let b = key(68);
        let subject = key(69);
        let collection = Inline::new([70; 32]);
        let roots = [a.verifying_key(), b.verifying_key()];
        let quorum = AdmissionPolicy::quorum(roots, 2, None).unwrap();
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: quorum.binding(read_capability()) + quorum.binding(write_capability()),
        };
        let evidence = canonical_authorization_evidence(
            &definitions(),
            collection,
            descriptor.facts().clone(),
            [
                root_proof(&a, &subject, scope(read_capability(), collection)),
                root_proof(&b, &subject, write_scope(collection)),
            ],
        )
        .unwrap();
        assert_eq!(evidence.len(), 2, "incomplete shares remain repairable");
        for action in [ACTION_READ, ACTION_WRITE] {
            assert!(!capability_quorum_authorizes(
                &evidence.reader,
                evidence.proofs(),
                roots,
                subject.verifying_key(),
                CapabilityRequest::new(CapabilityResource::from(collection), action),
                NonZeroUsize::new(2).unwrap(),
            ));
        }
    }

    #[test]
    fn resource_prefix_hides_other_members_and_keeps_its_summary_stable() {
        let root = key(73);
        let subject = key(74);
        let collection = Inline::new([75; 32]);
        let other = Inline::new([76; 32]);
        let valid = root_proof(&root, &subject, write_scope(collection));
        let unrelated = root_proof(&root, &subject, write_scope(other));
        let mut evidence = canonical_authorization_evidence(
            &definitions(),
            collection,
            policy_facts(CollectionPolicy::new(
                AdmissionPolicy::Open,
                AdmissionPolicy::direct(root.verifying_key()),
            )),
            [valid.clone()],
        )
        .unwrap();
        let before = evidence.summary();
        // Exercise a future shared physical index without disclosing its outer root.
        evidence.proofs.insert(&PatchEntry::with_value(
            &evidence_key(other, unrelated.id()),
            unrelated.clone(),
        ));
        assert_eq!(evidence.summary(), before);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence.proofs().collect::<Vec<_>>(), [&valid]);
        assert!(evidence.get(unrelated.id()).is_none());
        let response = crate::patch_repair::patch_node_response(
            evidence.patch(),
            &collection.raw,
            &[],
            |_, proof| Ok(proof.clone()),
        )
        .unwrap();
        let crate::patch_repair::PatchNodeResponse::Found(node) = response else {
            panic!("selected resource exists")
        };
        let request = crate::patch_repair::PatchRepairRequest::new(
            (),
            before,
            32,
            vec![],
            before.root().unwrap(),
        )
        .unwrap();
        crate::patch_repair::validate_patch_node(
            &request,
            64,
            &collection.raw,
            &node,
            |key, proof| {
                assert_eq!(&key[..32], &collection.raw);
                assert_eq!(proof, &valid);
                Ok(())
            },
        )
        .unwrap();
        let crate::patch_repair::PatchNode::Leaf { leaf, .. } = node else {
            panic!("one scoped proof")
        };
        assert_eq!(leaf.key, valid.id().raw);
    }

    #[test]
    fn read_policy_alternatives_shape_evidence_and_bootstrap_independently_of_write() {
        let root_a = key(40);
        let root_b = key(41);
        let reader_a = key(42);
        let reader_b = key(43);
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::direct(root_a.verifying_key()).binding(read_capability())
                + AdmissionPolicy::direct(root_b.verifying_key()).binding(read_capability())
                + entity! {
                    capability_handle: write_capability(),
                    metadata::tag: metadata::KIND_BLOB_ENCODING,
                },
        };
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .put::<SimpleArchive, _>(descriptor.facts().clone())
            .unwrap();
        let proof_a = root_proof(&root_a, &reader_a, scope(read_capability(), collection));
        let proof_b = root_proof(&root_b, &reader_b, scope(read_capability(), collection));
        let wrong_action = root_proof(&root_a, &reader_a, write_scope(collection));
        for proof in [proof_a.clone(), proof_b.clone(), wrong_action] {
            store_proof(&mut store, proof);
        }
        let snapshot = store.snapshot().unwrap();
        let overlay = collection_repair_overlay(&snapshot, collection).unwrap();
        assert!(
            overlay.policy().is_err(),
            "scalar diagnostics remain explicit"
        );
        let evidence = overlay.authorization_evidence();
        assert_eq!(evidence.len(), 3);
        assert_eq!(evidence.write_policies().count(), 0);
        let proofs = evidence.proofs().cloned().collect::<Vec<_>>();
        for reader in [reader_a.verifying_key(), reader_b.verifying_key()] {
            assert!(evidence.reader_is_admitted_by(reader, &proofs));
            assert!(
                triblespace_core::collection::collection_reader_is_admitted_by(
                    &snapshot, collection, reader, &proofs,
                )
                .unwrap()
            );
        }
        assert!(!evidence.reader_is_admitted_by(key(44).verifying_key(), &proofs));
        let CollectionReadAudience::Restricted(audience) = evidence.authorized_readers() else {
            panic!("restricted READ alternatives must not become Open");
        };
        assert!(audience.contains(&reader_a.verifying_key()));
        assert!(audience.contains(&reader_b.verifying_key()));
        assert_eq!(
            collection_read_bootstrap_proofs(&snapshot, collection, reader_b.verifying_key(), 1)
                .unwrap(),
            [proof_b],
        );
    }

    #[test]
    fn absent_or_unknown_read_policy_never_borrows_open_write_or_unrelated_read() {
        let absent = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::Open.binding(write_capability()),
        };
        let unknown = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: entity! {
                    capability_handle: read_capability(),
                    metadata::tag: metadata::KIND_BLOB_ENCODING,
                } + AdmissionPolicy::Open.binding(write_capability()),
        };
        for mut descriptor in [absent, unknown] {
            descriptor += entity! {
                resource_policy*: AdmissionPolicy::Open.binding(read_capability()),
            };
            let mut store = MemoryRepo::default();
            store
                .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
                .unwrap();
            store
                .put::<SimpleArchive, _>(
                    entity! { capability_action: ACTION_WRITE }.facts().clone(),
                )
                .unwrap();
            let collection = store
                .put::<SimpleArchive, _>(descriptor.facts().clone())
                .unwrap();
            let snapshot = store.snapshot().unwrap();
            let overlay = collection_repair_overlay(&snapshot, collection).unwrap();
            let evidence = overlay.authorization_evidence();
            assert_eq!(evidence.read_policies().count(), 0);
            assert!(evidence
                .write_policies()
                .any(|policy| matches!(policy, AdmissionPolicy::Open)));
            assert!(!evidence.reader_is_admitted_by(key(44).verifying_key(), &[]));
            assert_eq!(
                evidence.authorized_readers(),
                CollectionReadAudience::Restricted(Vec::new())
            );
            assert!(
                !triblespace_core::collection::collection_reader_is_admitted_by(
                    &snapshot,
                    collection,
                    key(44).verifying_key(),
                    &[],
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn explicit_open_read_does_not_require_a_write_policy() {
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::Open.binding(read_capability()),
        };
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .put::<SimpleArchive, _>(descriptor.facts().clone())
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let overlay = collection_repair_overlay(&snapshot, collection).unwrap();
        assert!(overlay.policy().is_err());
        let evidence = overlay.authorization_evidence();
        assert!(evidence.is_empty());
        assert_eq!(evidence.write_policies().count(), 0);
        assert!(evidence.reader_is_admitted_by(key(44).verifying_key(), &[]));
        assert_eq!(evidence.authorized_readers(), CollectionReadAudience::Open);
        assert!(collection_read_bootstrap_proofs(
            &snapshot,
            collection,
            key(44).verifying_key(),
            0
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn commit_and_later_write_proof_are_independent_repair_components() {
        let root = key(1);
        let writer = key(2);
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .collection("activation", policy(&[root.clone()], 1))
            .unwrap();
        store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &writer,
                collection.handle(),
                data(3),
                empty_metadata_handle(),
            )))
            .unwrap();

        let before_snapshot = store.snapshot().unwrap();
        let before = collection_repair_overlay(&before_snapshot, collection.handle()).unwrap();
        assert!(!collection
            .writer_is_admitted(&before_snapshot, writer.verifying_key())
            .unwrap());
        let atom = write_scope(collection.handle());
        store_proof(&mut store, root_proof(&root, &writer, atom));
        let after_snapshot = store.snapshot().unwrap();
        let after = collection_repair_overlay(&after_snapshot, collection.handle()).unwrap();
        assert!(collection
            .writer_is_admitted(&after_snapshot, writer.verifying_key())
            .unwrap());

        assert_eq!(before.records().summary().leaf_count(), 1);
        assert_eq!(after.records().summary().leaf_count(), 1);
        assert_eq!(before.records().summary(), after.records().summary());
        assert_ne!(
            before.authorization_evidence().summary(),
            after.authorization_evidence().summary()
        );
        assert_ne!(before.wake_root(), after.wake_root());
    }

    #[test]
    fn record_and_authorization_evidence_converge_in_either_arrival_order() {
        let root = key(32);
        let writer = key(33);
        let policy = policy(&[root.clone()], 1);
        let mut record_first = MemoryRepo::default();
        let first_collection = record_first
            .collection("repair-order", policy.clone())
            .unwrap();
        let mut proof_first = MemoryRepo::default();
        let second_collection = proof_first.collection("repair-order", policy).unwrap();
        assert_eq!(first_collection.handle(), second_collection.handle());

        let commit = CollectionRecord::Commit(CollectionCommit::sign(
            &writer,
            first_collection.handle(),
            data(34),
            empty_metadata_handle(),
        ));
        let grant = root_proof(&root, &writer, write_scope(first_collection.handle()));
        record_first.insert(commit).unwrap();
        store_proof(&mut record_first, grant.clone());
        store_proof(&mut proof_first, grant);
        proof_first.insert(commit).unwrap();

        let first =
            collection_repair_overlay(&record_first.snapshot().unwrap(), first_collection.handle())
                .unwrap();
        let second =
            collection_repair_overlay(&proof_first.snapshot().unwrap(), second_collection.handle())
                .unwrap();
        assert_eq!(first.records().summary(), second.records().summary());
        assert_eq!(
            first.authorization_evidence().summary(),
            second.authorization_evidence().summary()
        );
        assert_eq!(first.wake_root(), second.wake_root());
    }

    #[test]
    fn read_proof_changes_wake_root_without_changing_records() {
        let root = key(29);
        let reader = key(30);
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .collection(
                "read-repair",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::Open,
                ),
            )
            .unwrap();
        let before_snapshot = store.snapshot().unwrap();
        let before = collection_repair_overlay(&before_snapshot, collection.handle()).unwrap();
        store_proof(
            &mut store,
            root_proof(
                &root,
                &reader,
                scope(read_capability(), collection.handle()),
            ),
        );
        let after_snapshot = store.snapshot().unwrap();
        let after = collection_repair_overlay(&after_snapshot, collection.handle()).unwrap();

        assert_eq!(before.records().summary(), after.records().summary());
        assert_eq!(before.authorization_evidence().len(), 0);
        assert_eq!(after.authorization_evidence().len(), 1);
        assert_ne!(before.wake_root(), after.wake_root());
    }

    #[test]
    fn merge_and_derive_equations_participate_in_collection_repair() {
        let writer = key(3);
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .collection(
                "commit-only-activation",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let commit = CollectionCommit::sign(
            &writer,
            collection.handle(),
            data(31),
            empty_metadata_handle(),
        );
        store.insert(CollectionRecord::Commit(commit)).unwrap();

        let before_snapshot = store.snapshot().unwrap();
        let before = collection_repair_overlay(&before_snapshot, collection.handle()).unwrap();

        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&writer, collection.handle(), [data(31), data(32)], data(33))
                    .unwrap(),
            ))
            .unwrap();
        store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &writer,
                collection.handle(),
                triblespace_core::collection::SourceLocator::of(data(33).raw),
                data(34),
            )))
            .unwrap();

        let after_snapshot = store.snapshot().unwrap();
        let after = collection_repair_overlay(&after_snapshot, collection.handle()).unwrap();

        assert_ne!(before.records().summary(), after.records().summary());
        assert_ne!(before.wake_root(), after.wake_root());
        assert_eq!(after.records().len(), 3);
        assert_eq!(
            after
                .records()
                .get(CollectionRecord::Commit(commit).fingerprint()),
            Some(CollectionRecord::Commit(commit))
        );
        assert!(after.records().records().any(|record| matches!(
            record,
            CollectionRecord::Merge(merge)
                if merge.collection() == collection.handle()
        )));
        assert!(after.records().records().any(|record| matches!(
            record,
            CollectionRecord::Derive(derive)
                if derive.collection() == collection.handle()
        )));
    }

    #[test]
    fn unchanged_observations_preserve_evidence_and_admission() {
        let root = key(4);
        let reader = key(5);
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "unchanged-observation",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::Open,
                ),
            )
            .unwrap();
        let proof = root_proof(
            &root,
            &reader,
            scope(read_capability(), collection.handle()),
        );
        store.insert_proof(proof.clone()).unwrap();
        let before = store.snapshot().unwrap();
        let after = store.snapshot().unwrap();
        let first = collection_repair_overlay(&before, collection.handle()).unwrap();
        let second = collection_repair_overlay(&after, collection.handle()).unwrap();
        assert_eq!(first.wake_root(), second.wake_root());
        for evidence in [
            first.authorization_evidence(),
            second.authorization_evidence(),
        ] {
            assert!(evidence.reader_is_admitted_by(reader.verifying_key(), &[proof.clone()]));
        }
    }

    #[test]
    fn definition_arrival_changes_admission_without_changing_repair_membership() {
        let root = key(32);
        let reader = key(33);
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(read_capability()),
        };
        let mut store = MemoryRepo::default();
        let collection = store
            .put::<SimpleArchive, _>(descriptor.facts().clone())
            .unwrap();
        let proof = root_proof(&root, &reader, scope(read_capability(), collection));
        store.insert_proof(proof.clone()).unwrap();
        let before = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
        assert_eq!(
            before.authorization_evidence().get(proof.id()),
            Some(&proof)
        );
        assert!(!before
            .authorization_evidence()
            .reader_is_admitted_by(reader.verifying_key(), &[proof.clone()]));
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        let after = collection_repair_overlay(&store.snapshot().unwrap(), collection).unwrap();
        assert_eq!(before.wake_root(), after.wake_root());
        assert!(after
            .authorization_evidence()
            .reader_is_admitted_by(reader.verifying_key(), &[proof.clone()]));
        assert!(!before
            .authorization_evidence()
            .reader_is_admitted_by(reader.verifying_key(), &[proof]));
    }

    #[test]
    fn incoming_grant_can_use_a_resident_definition_absent_from_local_proofs() {
        let root = key(90);
        let reader = key(91);
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "incoming-definition",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::Open,
                ),
            )
            .unwrap();
        let definition = store
            .put::<SimpleArchive, _>(
                entity! {
                    capability_action: ACTION_READ,
                    capability_delegate_action: ACTION_READ,
                }
                .facts()
                .clone(),
            )
            .unwrap();
        let evidence =
            collection_authorization_evidence(&store.snapshot().unwrap(), collection.handle())
                .unwrap();
        assert!(evidence.is_empty());
        let proof = root_proof(&root, &reader, scope(definition, collection.handle()));
        evidence.validate_proof(&proof).unwrap();
        assert!(evidence.reader_is_admitted_by(reader.verifying_key(), &[proof]));
    }

    #[test]
    fn subordinate_resources_use_immutable_same_entity_routes_and_their_own_roots() {
        use triblespace_core::capability::policy::resource_handle;

        let collection_root = key(92);
        let resource_root = key(93);
        let reader = key(94);
        let unrelated_readers = [key(97), key(98), key(99), key(100)];
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "resource-audience",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(collection_root.verifying_key()),
                    AdmissionPolicy::direct(collection_root.verifying_key()),
                ),
            )
            .unwrap();
        let other = store
            .collection(
                "other-audience",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let unknown_definition = Inline::new([95; 32]);
        let resource = store.put::<SimpleArchive, _>(entity! {
            resource_collection: collection.handle(),
            resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key()).binding(unknown_definition),
        }.facts().clone()).unwrap();
        let same_root_resource = store.put::<SimpleArchive, _>(entity! {
            resource_collection: collection.handle(),
            resource_policy*: AdmissionPolicy::direct(collection_root.verifying_key()).binding(read_capability()),
        }.facts().clone()).unwrap();
        let wrong_audience = store.put::<SimpleArchive, _>(entity! {
            resource_collection: other.handle(),
            resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key()).binding(read_capability()),
        }.facts().clone()).unwrap();
        let split_entities = entity! { resource_collection: collection.handle() }
            + entity! { resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key()).binding(read_capability()) };
        let split_resource = store
            .put::<SimpleArchive, _>(split_entities.facts().clone())
            .unwrap();
        // A later ordinary C fact cannot reroute the hash-named R descriptor.
        store
            .commit(
                collection,
                &collection_root,
                entity! {
                    resource_handle: wrong_audience,
                    resource_collection: collection.handle(),
                },
            )
            .unwrap();
        let accepted = [
            root_proof(&resource_root, &reader, scope(unknown_definition, resource)),
            root_proof(
                &collection_root,
                &reader,
                scope(read_capability(), same_root_resource),
            ),
        ];
        let rejected = [
            root_proof(
                &collection_root,
                &unrelated_readers[0],
                scope(unknown_definition, resource),
            ),
            root_proof(
                &resource_root,
                &unrelated_readers[1],
                scope(read_capability(), wrong_audience),
            ),
            root_proof(
                &resource_root,
                &unrelated_readers[2],
                scope(read_capability(), split_resource),
            ),
            root_proof(
                &resource_root,
                &unrelated_readers[3],
                scope(read_capability(), Inline::new([96; 32])),
            ),
        ];
        for proof in accepted.iter().chain(&rejected) {
            store.insert_proof(proof.clone()).unwrap();
        }
        let snapshot = store.snapshot().unwrap();
        let overlay = collection_repair_overlay(&snapshot, collection.handle()).unwrap();
        let evidence = overlay.authorization_evidence();
        assert_eq!(evidence.len(), 2);
        for proof in &accepted {
            evidence.validate_proof(proof).unwrap();
            assert_eq!(evidence.get(proof.id()), Some(proof));
        }
        for proof in rejected {
            assert!(evidence.validate_proof(&proof).is_err());
            assert!(evidence.get(proof.id()).is_none());
        }
        assert!(!evidence.reader_is_admitted_by(reader.verifying_key(), &accepted));
        let mut candidates = overlay
            .discovery_candidates()
            .map(|key| key.to_bytes())
            .collect::<Vec<_>>();
        candidates.sort();
        candidates.dedup();
        let mut expected = [
            collection_root.verifying_key(),
            resource_root.verifying_key(),
            reader.verifying_key(),
        ]
        .map(|key| key.to_bytes());
        expected.sort();
        assert_eq!(
            candidates, expected,
            "only routed R evidence contributes; wrong roots, other audiences, split routes and missing R descriptors do not"
        );
        assert!(collection_read_bootstrap_proofs(
            &snapshot,
            collection.handle(),
            reader.verifying_key(),
            16
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn read_audience_keeps_intermediate_authority_despite_restricted_suffix() {
        let root = key(34);
        let intermediate = key(35);
        let leaf = key(36);
        let delegate_only_key = key(37);
        let invalid_leaf = key(38);
        let collection = Inline::new([39; 32]);
        let mut blobs = MemoryBlobStore::new();
        for (_, blob) in definitions().iter() {
            blobs.insert(blob);
        }
        let delegating = blobs.insert::<SimpleArchive>(
            entity! {
                capability_action: ACTION_READ,
                capability_delegate_action: ACTION_READ,
            }
            .facts()
            .clone()
            .to_blob(),
        );
        let delegate_only = blobs.insert::<SimpleArchive>(
            entity! {
                capability_delegate_action: ACTION_READ,
            }
            .facts()
            .clone()
            .to_blob(),
        );
        let parent = root_proof(&root, &intermediate, scope(delegating, collection));
        let child = parent
            .delegate(&intermediate, read_capability(), leaf.verifying_key())
            .unwrap();
        let restricted = parent
            .delegate(
                &intermediate,
                write_capability(),
                invalid_leaf.verifying_key(),
            )
            .unwrap();
        let delegate_only = root_proof(&root, &delegate_only_key, scope(delegate_only, collection));
        let evidence = canonical_authorization_evidence(
            &blobs.snapshot().unwrap(),
            collection,
            policy_facts(CollectionPolicy::new(
                AdmissionPolicy::direct(root.verifying_key()),
                AdmissionPolicy::Open,
            )),
            [child, delegate_only, restricted],
        )
        .unwrap();
        assert_eq!(
            evidence.len(),
            3,
            "byte-valid evidence remains repairable even when its suffix does not grant READ"
        );
        let CollectionReadAudience::Restricted(readers) = evidence.authorized_readers() else {
            panic!("restricted policy became open");
        };
        for key in [&root, &intermediate, &leaf] {
            assert!(readers.contains(&key.verifying_key()));
        }
        assert!(!readers.contains(&delegate_only_key.verifying_key()));
        assert!(!readers.contains(&invalid_leaf.verifying_key()));
    }

    #[test]
    fn authorization_membership_rejects_wrong_resource_root_and_signature() {
        let root = key(7);
        let writer = key(9);
        let collection = Inline::new([10; 32]);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(root.verifying_key()),
            AdmissionPolicy::direct(root.verifying_key()),
        );
        let proof = root_proof(&root, &writer, write_scope(collection));
        validate_authorization_evidence_proof(collection, &policy, &proof).unwrap();
        assert!(matches!(
            validate_authorization_evidence_proof(Inline::new([11; 32]), &policy, &proof),
            Err(CollectionAuthorizationEvidenceError::WrongResource)
        ));
        let unknown_definition =
            root_proof(&root, &writer, scope(Inline::new([12; 32]), collection));
        validate_authorization_evidence_proof(collection, &policy, &unknown_definition).unwrap();
        let wrong_root = root_proof(&key(8), &writer, write_scope(collection));
        assert!(matches!(
            validate_authorization_evidence_proof(collection, &policy, &wrong_root),
            Err(CollectionAuthorizationEvidenceError::WrongRoot)
        ));
        let mut bytes = proof.as_bytes().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let bad_signature = CapabilityProof::from_bytes(&bytes).unwrap();
        assert!(matches!(
            validate_authorization_evidence_proof(collection, &policy, &bad_signature),
            Err(CollectionAuthorizationEvidenceError::Invalid(
                CapabilityProofError::InvalidSignature { .. }
            ))
        ));
    }

    #[test]
    fn canonical_patch_ignores_arrival_order_duplicates_and_irrelevant_proofs() {
        let root = key(13);
        let other_root = key(14);
        let a = key(15);
        let b = key(16);
        let collection = Inline::new([17; 32]);
        let write_policy = AdmissionPolicy::direct(root.verifying_key());
        let first = root_proof(&root, &a, write_scope(collection));
        let second = root_proof(&root, &b, write_scope(collection));
        let read = root_proof(&root, &b, scope(read_capability(), collection));
        let irrelevant = root_proof(&other_root, &b, write_scope(collection));

        let policy =
            CollectionPolicy::new(AdmissionPolicy::direct(root.verifying_key()), write_policy);
        let left = canonical_authorization_evidence(
            &definitions(),
            collection,
            policy_facts(policy.clone()),
            [
                first.clone(),
                read.clone(),
                second.clone(),
                first.clone(),
                irrelevant,
            ],
        )
        .unwrap();
        let right = canonical_authorization_evidence(
            &definitions(),
            collection,
            policy_facts(policy),
            [second, first, read],
        )
        .unwrap();
        assert_eq!(left.len(), 3);
        assert_eq!(left.summary(), right.summary());
    }

    #[test]
    fn every_independent_root_path_needed_by_quorum_is_preserved() {
        let root_a = key(18);
        let root_b = key(19);
        let bridge = key(20);
        let writer = key(21);
        let collection = Inline::new([22; 32]);
        let write_policy =
            AdmissionPolicy::quorum([root_a.verifying_key(), root_b.verifying_key()], 2, None)
                .unwrap();
        let mut blobs = MemoryBlobStore::new();
        for (_, blob) in definitions().iter() {
            blobs.insert(blob);
        }
        let delegating = blobs.insert::<SimpleArchive>(
            entity! {
                capability_delegate_action: ACTION_WRITE,
            }
            .facts()
            .clone()
            .to_blob(),
        );
        let delegated = |root: &SigningKey| {
            root_proof(root, &bridge, scope(delegating, collection))
                .delegate(&bridge, write_capability(), writer.verifying_key())
                .unwrap()
        };
        let evidence = canonical_authorization_evidence(
            &blobs.snapshot().unwrap(),
            collection,
            policy_facts(CollectionPolicy::new(AdmissionPolicy::Open, write_policy)),
            [delegated(&root_a), delegated(&root_b)],
        )
        .unwrap();
        assert_eq!(evidence.len(), 2);
        assert!(capability_quorum_authorizes(
            &evidence.reader,
            evidence.proofs(),
            [root_a.verifying_key(), root_b.verifying_key()],
            writer.verifying_key(),
            CapabilityRequest::new(CapabilityResource::from(collection), ACTION_WRITE),
            NonZeroUsize::new(2).unwrap(),
        ));
    }

    #[test]
    fn missing_descriptor_fails_closed_before_overlay_exists() {
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let result = collection_repair_overlay(&snapshot, Inline::new([23; 32]));
        assert!(matches!(
            result,
            Err(CollectionRepairOverlayError::Descriptor(_))
        ));
    }

    #[test]
    fn read_bootstrap_is_exact_deterministic_and_transport_bounded() {
        let root = key(24);
        let other_root = key(25);
        let reader = key(26);
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .collection(
                "read-evidence",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::Open,
                ),
            )
            .unwrap();
        let relevant = root_proof(
            &root,
            &reader,
            scope(read_capability(), collection.handle()),
        );
        let wrong_action = root_proof(&root, &reader, write_scope(collection.handle()));
        let wrong_root = root_proof(
            &other_root,
            &reader,
            scope(read_capability(), collection.handle()),
        );
        let unrelated_reader = root_proof(
            &root,
            &key(28),
            scope(read_capability(), collection.handle()),
        );
        store_proof(&mut store, wrong_root);
        store_proof(&mut store, unrelated_reader);
        store_proof(&mut store, relevant.clone());
        store_proof(&mut store, wrong_action);

        let snapshot = store.snapshot().unwrap();
        let selected = collection_read_bootstrap_proofs(
            &snapshot,
            collection.handle(),
            reader.verifying_key(),
            1,
        )
        .unwrap();
        assert_eq!(selected, [relevant.clone()]);
        let overlay = collection_repair_overlay(&snapshot, collection.handle()).unwrap();
        assert!(overlay
            .authorization_evidence()
            .reader_is_admitted_by(reader.verifying_key(), &[relevant]));
        assert!(matches!(
            collection_read_bootstrap_proofs(
                &snapshot,
                collection.handle(),
                reader.verifying_key(),
                0
            ),
            Err(CollectionReadBootstrapError::TooMany { count: 1, limit: 0 })
        ));
    }

    #[test]
    fn read_bootstrap_trims_suffixes_without_losing_independent_root_shares() {
        let roots = [key(80), key(81)];
        let reader = key(82);
        let later = key(83);
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let delegating = store
            .put::<SimpleArchive, _>(
                entity! {
                    capability_action: ACTION_READ,
                    capability_delegate_action: ACTION_READ,
                }
                .facts()
                .clone(),
            )
            .unwrap();
        let collection = store
            .collection(
                "prefix-bootstrap-quorum",
                CollectionPolicy::new(
                    AdmissionPolicy::quorum(roots.iter().map(SigningKey::verifying_key), 2, None)
                        .unwrap(),
                    AdmissionPolicy::Open,
                ),
            )
            .unwrap();
        let witnesses = roots.map(|root| {
            let parent = root_proof(&root, &reader, scope(delegating, collection.handle()));
            // Store only longer paths. One suffix is a legal READ grant and
            // another is signed but exceeds its parent's delegated action.
            for capability in [read_capability(), write_capability()] {
                store_proof(
                    &mut store,
                    parent
                        .delegate(&reader, capability, later.verifying_key())
                        .unwrap(),
                );
            }
            parent
        });
        let snapshot = store.snapshot().unwrap();
        let selected = collection_read_bootstrap_proofs(
            &snapshot,
            collection.handle(),
            reader.verifying_key(),
            2,
        )
        .unwrap();
        assert_eq!(selected.len(), 2, "duplicate suffixes are not extra shares");
        for witness in &witnesses {
            assert!(selected.contains(witness));
        }
        for witness in &selected {
            assert_eq!(witness.leaf_key(), reader.verifying_key());
            assert_eq!(witness.capabilities().collect::<Vec<_>>(), [delegating]);
        }
        let overlay = collection_repair_overlay(&snapshot, collection.handle()).unwrap();
        assert!(overlay
            .authorization_evidence()
            .reader_is_admitted_by(reader.verifying_key(), &selected));
        assert!(!overlay
            .authorization_evidence()
            .reader_is_admitted_by(reader.verifying_key(), &selected[..1]));
        assert!(matches!(
            collection_read_bootstrap_proofs(
                &snapshot,
                collection.handle(),
                reader.verifying_key(),
                1
            ),
            Err(CollectionReadBootstrapError::TooMany { count: 2, limit: 1 })
        ));
    }

    #[test]
    fn read_bootstrap_skips_an_earlier_delegation_only_occurrence_of_the_subject() {
        let root = key(84);
        let reader = key(85);
        let later = key(86);
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        let delegate_only = store
            .put::<SimpleArchive, _>(
                entity! { capability_delegate_action: ACTION_READ }
                    .facts()
                    .clone(),
            )
            .unwrap();
        let delegating = store
            .put::<SimpleArchive, _>(
                entity! {
                    capability_action: ACTION_READ,
                    capability_delegate_action: ACTION_READ,
                }
                .facts()
                .clone(),
            )
            .unwrap();
        let collection = store
            .collection(
                "prefix-bootstrap-self-delegation",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(root.verifying_key()),
                    AdmissionPolicy::Open,
                ),
            )
            .unwrap();
        let delegation = root_proof(&root, &reader, scope(delegate_only, collection.handle()));
        let witness = delegation
            .delegate(&reader, delegating, reader.verifying_key())
            .unwrap();
        store_proof(
            &mut store,
            witness
                .delegate(&reader, read_capability(), later.verifying_key())
                .unwrap(),
        );
        let snapshot = store.snapshot().unwrap();
        let selected = collection_read_bootstrap_proofs(
            &snapshot,
            collection.handle(),
            reader.verifying_key(),
            1,
        )
        .unwrap();
        assert_eq!(selected, [witness]);
    }

    #[test]
    fn open_read_policy_needs_no_bootstrap_evidence() {
        let mut store = MemoryRepo::default();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_WRITE }.facts().clone())
            .unwrap();
        let collection = store
            .collection(
                "open-read",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let selected = collection_read_bootstrap_proofs(
            &snapshot,
            collection.handle(),
            key(27).verifying_key(),
            0,
        )
        .unwrap();
        assert!(selected.is_empty());
        assert!(collection_repair_overlay(&snapshot, collection.handle())
            .unwrap()
            .authorization_evidence()
            .reader_is_admitted_by(key(27).verifying_key(), &[]));
    }
}
