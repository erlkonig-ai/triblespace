//! Descriptor-driven, prefix-signed capability proofs.
//!
//! ```text
//! magic | resource | root | (capability handle | delegate | signature)+
//! ```
//!
//! Each signature covers the exact preceding prefix, including earlier
//! signatures. A capability definition is an immutable SimpleArchive whose
//! `capability_action` facts grant invocation and whose independent
//! `capability_delegate_action` facts grant delegation. For a child definition
//! Q following P, `invoke(Q) ∪ delegate(Q) ⊆ delegate(P)`. Delegation includes
//! permission to confer onward delegation; invocation alone never does.
//!
//! A request names a resource and an action, not a grant descriptor. The
//! consumer supplies that action's policy roots and quorum. Application
//! restrictions, such as a Secrets delivery deadline, are interpreted on each
//! supporting prefix before quorum counting; generic authority has no clock.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::num::NonZeroUsize;

use anybytes::{Bytes, View};
use ed25519::signature::Signer;
use ed25519::Signature;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
use crate::id::{id_hex, ExclusiveId, Id};
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::{Blake3, Handle, Hash};
use crate::inline::{Encodes, Inline, InlineEncoding, TryFromInline};
use crate::metadata::{self, MetaDescribe};
use crate::prelude::{attributes, entity, exists, find, pattern};
use crate::repo::BlobStoreGet;
use crate::trible::{Fragment, TribleSet};

/// Immutable resource-local capability policies, independent of collections.
pub mod policy;

/// Content address of one immutable capability definition.
pub type CapabilityHandle = Inline<Handle<SimpleArchive>>;
pub type CapabilityProofId = Inline<Hash<Blake3>>;

/// Handle of this grammar's SimpleArchive record description.
///
/// Its new descriptor anchor, minted with `trible genid` on 2026-09-14, is
/// `C7116B04EE6DA4BADFDE77D79692AEFF`. The pinned handle is checked against the
/// descriptor in `repo::pile::record_kind`.
pub const CAPABILITY_PROOF_MAGIC: [u8; 32] =
    hex_literal::hex!("9E00F6EB8D63E5EB1A3ECFA284118F157B2F08CBDC95ECCEB8C2392AD794069D");
pub const MAX_CAPABILITY_PROOF_STEPS: usize = u8::MAX as usize;
pub const CAPABILITY_PROOF_HEADER_LEN: usize = CAPABILITY_PROOF_MAGIC.len() + 32 + 32;
pub const CAPABILITY_PROOF_EDGE_LEN: usize = 32 + 32 + 64;
pub const MIN_CAPABILITY_PROOF_BYTES: usize =
    CAPABILITY_PROOF_HEADER_LEN + CAPABILITY_PROOF_EDGE_LEN;
pub const MAX_CAPABILITY_PROOF_BYTES: usize =
    CAPABILITY_PROOF_HEADER_LEN + MAX_CAPABILITY_PROOF_STEPS * CAPABILITY_PROOF_EDGE_LEN;

const RESOURCE_LEN: usize = 32;
const CAPABILITY_HANDLE_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 32;
const EDGE_BODY_LEN: usize = CAPABILITY_HANDLE_LEN + PUBLIC_KEY_LEN;

pub struct CapabilityResourceEncoding;

impl MetaDescribe for CapabilityResourceEncoding {
    fn describe() -> Fragment {
        let id = id_hex!("52297CA2A448E6163158E9498F10559C");
        entity! {
            ExclusiveId::force_ref(&id) @
                metadata::name: "capability_resource",
                metadata::description: "Opaque 32-byte resource identity interpreted by the exact capability action. The capability kernel compares these bytes without a registry or ambient resource hierarchy.",
                metadata::tag: metadata::KIND_INLINE_ENCODING,
        }
    }
}

impl InlineEncoding for CapabilityResourceEncoding {
    type ValidationError = Infallible;
    type Encoding = Self;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CapabilityResource([u8; RESOURCE_LEN]);

impl CapabilityResource {
    pub const fn new(bytes: [u8; RESOURCE_LEN]) -> Self {
        Self(bytes)
    }
    pub const fn into_bytes(self) -> [u8; RESOURCE_LEN] {
        self.0
    }
    pub const fn as_bytes(&self) -> &[u8; RESOURCE_LEN] {
        &self.0
    }
}

impl<S: InlineEncoding> From<Inline<S>> for CapabilityResource {
    fn from(resource: Inline<S>) -> Self {
        Self(resource.raw)
    }
}

impl Encodes<CapabilityResource> for CapabilityResourceEncoding {
    type Output = Inline<CapabilityResourceEncoding>;
    fn encode(source: CapabilityResource) -> Self::Output {
        Inline::new(source.0)
    }
}

impl Encodes<&CapabilityResource> for CapabilityResourceEncoding {
    type Output = Inline<CapabilityResourceEncoding>;
    fn encode(source: &CapabilityResource) -> Self::Output {
        Inline::new(source.0)
    }
}

impl TryFromInline<'_, CapabilityResourceEncoding> for CapabilityResource {
    type Error = Infallible;
    fn try_from_inline(value: &Inline<CapabilityResourceEncoding>) -> Result<Self, Self::Error> {
        Ok(Self(value.raw))
    }
}

attributes! {
    /// Action which this capability permits its recipient to invoke.
    /// Existing READ/WRITE definition blobs keep their exact facts and handles.
    /// Anchor minted with `trible genid` on 2026-08-24.
    "E68BACD3068B30DA051D3A4A2B8795FC" as pub capability_action: GenId;
    /// Action which this capability permits its recipient to delegate.
    /// This includes conferring invocation and onward delegation independently.
    /// Anchor minted with `trible genid` on 2026-09-14:
    /// `628AB41154C8BAE6F985591B58487374`.
    "628AB41154C8BAE6F985591B58487374" as pub capability_delegate_action: GenId;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityRequest {
    resource: CapabilityResource,
    action: Id,
}

impl CapabilityRequest {
    pub const fn new(resource: CapabilityResource, action: Id) -> Self {
        Self { resource, action }
    }
    pub const fn resource(self) -> CapabilityResource {
        self.resource
    }
    pub const fn action(self) -> Id {
        self.action
    }
}

#[derive(Clone, Copy)]
struct CapabilityProofEdge {
    capability: CapabilityHandle,
    delegate: VerifyingKey,
    signature: Signature,
    signature_offset: usize,
}

/// Structurally canonical proof bytes with shared immutable ownership.
///
/// Construction and cloning assign no authority. Byte-only signature checks
/// and descriptor interpretation remain separate from framing and residency.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityProof {
    bytes: View<[u8]>,
}

/// One exact signed prefix, borrowed without allocating or copying its bytes.
///
/// A prefix view alone does not assert validity. The quorum predicates receive
/// a prefix only after its signatures and delegation have been checked. A
/// consumer can inspect all its handles when interpreting action-specific
/// restrictions; constraints on a later suffix do not apply to this subject.
#[derive(Clone, Copy, Debug)]
pub struct CapabilityProofPrefix<'a> {
    proof: &'a CapabilityProof,
    steps: usize,
}

impl<'a> CapabilityProofPrefix<'a> {
    pub fn root_key(self) -> VerifyingKey {
        self.proof.root_key()
    }
    pub fn resource(self) -> CapabilityResource {
        self.proof.resource()
    }
    pub fn subject(self) -> VerifyingKey {
        self.proof
            .edges()
            .nth(self.steps - 1)
            .expect("prefix is nonempty")
            .delegate
    }
    pub const fn step_count(self) -> usize {
        self.steps
    }
    pub fn as_bytes(self) -> &'a [u8] {
        &self.proof.as_bytes()
            [..CAPABILITY_PROOF_HEADER_LEN + self.steps * CAPABILITY_PROOF_EDGE_LEN]
    }
    pub fn capabilities(self) -> impl ExactSizeIterator<Item = CapabilityHandle> + 'a {
        self.proof.capabilities().take(self.steps)
    }
}

impl CapabilityProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CapabilityProofDecodeError> {
        Self::validate_bytes(bytes)?;
        Ok(Self::from_validated_bytes(Bytes::from_source(
            bytes.to_vec(),
        )))
    }

    pub fn from_owned_bytes(bytes: Bytes) -> Result<Self, CapabilityProofDecodeError> {
        Self::validate_bytes(&bytes)?;
        Ok(Self::from_validated_bytes(bytes))
    }

    /// Retain bytes already accepted by the native decoder or constructed here.
    pub(crate) fn from_validated_bytes(bytes: Bytes) -> Self {
        Self {
            bytes: bytes.view().expect("every byte slice has a u8 view"),
        }
    }

    pub(crate) fn validate_bytes(bytes: &[u8]) -> Result<(), CapabilityProofDecodeError> {
        if bytes.len() < MIN_CAPABILITY_PROOF_BYTES
            || (bytes.len() - CAPABILITY_PROOF_HEADER_LEN) % CAPABILITY_PROOF_EDGE_LEN != 0
        {
            return Err(CapabilityProofDecodeError::InvalidLength {
                actual: bytes.len(),
            });
        }
        if bytes[..CAPABILITY_PROOF_MAGIC.len()] != CAPABILITY_PROOF_MAGIC {
            return Err(CapabilityProofDecodeError::InvalidMagic);
        }
        let steps = (bytes.len() - CAPABILITY_PROOF_HEADER_LEN) / CAPABILITY_PROOF_EDGE_LEN;
        if steps > MAX_CAPABILITY_PROOF_STEPS {
            return Err(CapabilityProofDecodeError::TooManySteps {
                count: steps,
                limit: MAX_CAPABILITY_PROOF_STEPS,
            });
        }
        parse_key(&bytes[CAPABILITY_PROOF_MAGIC.len() + RESOURCE_LEN..CAPABILITY_PROOF_HEADER_LEN])
            .ok_or(CapabilityProofDecodeError::InvalidKey { key: 0 })?;
        for (step, edge) in bytes[CAPABILITY_PROOF_HEADER_LEN..]
            .chunks_exact(CAPABILITY_PROOF_EDGE_LEN)
            .enumerate()
        {
            parse_key(&edge[CAPABILITY_HANDLE_LEN..EDGE_BODY_LEN])
                .ok_or(CapabilityProofDecodeError::InvalidKey { key: step + 1 })?;
        }
        Ok(())
    }

    /// Direct strong references only. The resource is not a blob reference.
    pub fn blob_references(&self) -> impl Iterator<Item = Inline<Handle<UnknownBlob>>> + '_ {
        self.capabilities().map(Inline::transmute)
    }

    /// Sign a root grant. Resource policy decides which actions this root may
    /// originate; signing bytes does not confer authority by itself.
    pub fn new(
        resource: CapabilityResource,
        root: &SigningKey,
        capability: CapabilityHandle,
        delegate: VerifyingKey,
    ) -> Self {
        assert!(is_valid_capability_principal(&root.verifying_key()));
        assert!(is_valid_capability_principal(&delegate));
        let mut bytes = Vec::with_capacity(MIN_CAPABILITY_PROOF_BYTES);
        bytes.extend_from_slice(&CAPABILITY_PROOF_MAGIC);
        bytes.extend_from_slice(resource.as_bytes());
        bytes.extend_from_slice(root.verifying_key().as_bytes());
        append_edge(&mut bytes, root, capability, delegate);
        Self::from_validated_bytes(Bytes::from_source(bytes))
    }

    /// Sign an extension of this exact path without acquiring definition blobs.
    ///
    /// This checks byte integrity and issuer identity, not authorization. A
    /// later interpretation accepts the child only when its invocation and
    /// delegation actions are all delegated by the parent descriptor.
    pub fn delegate(
        &self,
        signer: &SigningKey,
        capability: CapabilityHandle,
        delegate: VerifyingKey,
    ) -> Result<Self, CapabilityIssueError> {
        if self.step_count() == MAX_CAPABILITY_PROOF_STEPS {
            return Err(CapabilityIssueError::TooManySteps {
                limit: MAX_CAPABILITY_PROOF_STEPS,
            });
        }
        let expected = self.leaf_key();
        let actual = signer.verifying_key();
        if expected != actual {
            return Err(CapabilityIssueError::WrongIssuer {
                expected: expected.to_bytes(),
                actual: actual.to_bytes(),
            });
        }
        if !is_valid_capability_principal(&delegate) {
            return Err(CapabilityIssueError::InvalidDelegate {
                key: delegate.to_bytes(),
            });
        }
        self.verify_signatures()
            .map_err(CapabilityIssueError::InvalidParent)?;
        let mut bytes = Vec::with_capacity(self.bytes.len() + CAPABILITY_PROOF_EDGE_LEN);
        bytes.extend_from_slice(&self.bytes);
        append_edge(&mut bytes, signer, capability, delegate);
        Ok(Self::from_validated_bytes(Bytes::from_source(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes.to_vec()
    }
    pub fn id(&self) -> CapabilityProofId {
        Inline::new(Blake3::digest(self.as_bytes()))
    }
    pub fn resource(&self) -> CapabilityResource {
        CapabilityResource::new(
            self.bytes[CAPABILITY_PROOF_MAGIC.len()..CAPABILITY_PROOF_MAGIC.len() + RESOURCE_LEN]
                .try_into()
                .expect("fixed resource bytes"),
        )
    }
    pub fn step_count(&self) -> usize {
        (self.bytes.len() - CAPABILITY_PROOF_HEADER_LEN) / CAPABILITY_PROOF_EDGE_LEN
    }
    pub fn root_key(&self) -> VerifyingKey {
        parse_key(
            &self.bytes[CAPABILITY_PROOF_MAGIC.len() + RESOURCE_LEN..CAPABILITY_PROOF_HEADER_LEN],
        )
        .expect("proof root was validated at construction")
    }
    pub fn leaf_key(&self) -> VerifyingKey {
        self.edges()
            .next_back()
            .expect("proof is nonempty")
            .delegate
    }
    pub fn leaf_issuer(&self) -> VerifyingKey {
        self.edges()
            .rev()
            .nth(1)
            .map_or_else(|| self.root_key(), |edge| edge.delegate)
    }
    pub fn delegated_keys(&self) -> impl ExactSizeIterator<Item = VerifyingKey> + '_ {
        self.edges().map(|edge| edge.delegate)
    }
    pub fn capabilities(&self) -> impl ExactSizeIterator<Item = CapabilityHandle> + '_ {
        self.bytes[CAPABILITY_PROOF_HEADER_LEN..]
            .chunks_exact(CAPABILITY_PROOF_EDGE_LEN)
            .map(|edge| {
                Inline::new(
                    edge[..CAPABILITY_HANDLE_LEN]
                        .try_into()
                        .expect("fixed handle"),
                )
            })
    }
    pub fn prefixes(&self) -> impl ExactSizeIterator<Item = CapabilityProofPrefix<'_>> + '_ {
        (0..self.step_count()).map(|step| CapabilityProofPrefix {
            proof: self,
            steps: step + 1,
        })
    }

    /// Verify every signature, without needing capability definitions.
    pub fn verify_signatures(&self) -> Result<(), CapabilityProofError> {
        let mut issuer = self.root_key();
        for (step, edge) in self.edges().enumerate() {
            issuer
                .verify_strict(&self.bytes[..edge.signature_offset], &edge.signature)
                .map_err(|_| CapabilityProofError::InvalidSignature { step })?;
            issuer = edge.delegate;
        }
        Ok(())
    }

    /// Check all signatures and descriptor attenuation, without a policy or clock.
    pub fn validate_delegation<R: BlobStoreGet>(
        &self,
        reader: &R,
    ) -> Result<(), CapabilityProofError> {
        visit_prefixes(self, reader, &mut BTreeMap::new(), |_, _| true)
    }

    /// Verify invocation by one subject along this root's path.
    ///
    /// Only the supporting prefix matters: a bad or unavailable later suffix
    /// cannot revoke a valid earlier grant. The caller selects this root from
    /// the requested action's policy; the proof cannot select its own policy.
    pub fn verify<R: BlobStoreGet>(
        &self,
        reader: &R,
        trust_root: VerifyingKey,
        expected_subject: VerifyingKey,
        request: CapabilityRequest,
    ) -> Result<(), CapabilityProofError> {
        if self.root_key() != trust_root {
            return Err(CapabilityProofError::WrongRoot {
                expected: trust_root.to_bytes(),
                actual: self.root_key().to_bytes(),
            });
        }
        if self.resource() != request.resource() {
            return Err(CapabilityProofError::WrongResource {
                expected: request.resource(),
                actual: self.resource(),
            });
        }
        let mut found = false;
        visit_prefixes(self, reader, &mut BTreeMap::new(), |prefix, definition| {
            found = prefix.subject() == expected_subject && invokes(definition, request.action());
            !found
        })?;
        if found {
            Ok(())
        } else {
            Err(CapabilityProofError::RequestMismatch { requested: request })
        }
    }

    fn edges(
        &self,
    ) -> impl ExactSizeIterator<Item = CapabilityProofEdge> + DoubleEndedIterator + '_ {
        self.bytes[CAPABILITY_PROOF_HEADER_LEN..]
            .chunks_exact(CAPABILITY_PROOF_EDGE_LEN)
            .enumerate()
            .map(|(step, edge)| CapabilityProofEdge {
                capability: Inline::new(
                    edge[..CAPABILITY_HANDLE_LEN]
                        .try_into()
                        .expect("fixed capability handle"),
                ),
                delegate: parse_key(&edge[CAPABILITY_HANDLE_LEN..EDGE_BODY_LEN])
                    .expect("proof delegate was validated at construction"),
                signature: Signature::from_bytes(
                    edge[EDGE_BODY_LEN..].try_into().expect("fixed signature"),
                ),
                signature_offset: CAPABILITY_PROOF_HEADER_LEN
                    + step * CAPABILITY_PROOF_EDGE_LEN
                    + EDGE_BODY_LEN,
            })
    }
}

fn append_edge(
    bytes: &mut Vec<u8>,
    issuer: &SigningKey,
    capability: CapabilityHandle,
    delegate: VerifyingKey,
) {
    bytes.extend_from_slice(&capability.raw);
    bytes.extend_from_slice(delegate.as_bytes());
    let signature = issuer.sign(bytes.as_slice());
    bytes.extend_from_slice(&signature.to_bytes());
}

fn invokes(definition: &TribleSet, action: Id) -> bool {
    exists!(pattern!(definition, [{ capability_action: action }]))
}

/// Read only the definitions this operation actually visits. PATCH-backed
/// facts clone cheaply, and repeated grants share each immutable decode.
fn definition<R: BlobStoreGet>(
    reader: &R,
    definitions: &mut BTreeMap<CapabilityHandle, Option<TribleSet>>,
    handle: CapabilityHandle,
    step: usize,
) -> Result<TribleSet, CapabilityProofError> {
    definitions
        .entry(handle)
        .or_insert_with(|| reader.get(handle).ok())
        .clone()
        .ok_or(CapabilityProofError::UnavailableDefinition { step, handle })
}

fn visit_prefixes<R, F>(
    proof: &CapabilityProof,
    reader: &R,
    definitions: &mut BTreeMap<CapabilityHandle, Option<TribleSet>>,
    mut visit: F,
) -> Result<(), CapabilityProofError>
where
    R: BlobStoreGet,
    F: FnMut(CapabilityProofPrefix<'_>, &TribleSet) -> bool,
{
    let mut issuer = proof.root_key();
    let mut parent: Option<TribleSet> = None;
    for (step, edge) in proof.edges().enumerate() {
        issuer
            .verify_strict(&proof.bytes[..edge.signature_offset], &edge.signature)
            .map_err(|_| CapabilityProofError::InvalidSignature { step })?;
        let child = definition(reader, definitions, edge.capability, step)?;
        if let Some(parent) = &parent {
            let invoked = find!(action: Id, pattern!(&child, [{ capability_action: ?action }]));
            let delegated = find!(
                action: Id,
                pattern!(&child, [{ capability_delegate_action: ?action }])
            );
            for action in invoked.chain(delegated) {
                if !exists!(pattern!(parent, [{ capability_delegate_action: action }])) {
                    return Err(CapabilityProofError::UndelegatedAction { step, action });
                }
            }
        }
        let prefix = CapabilityProofPrefix {
            proof,
            steps: step + 1,
        };
        if !visit(prefix, &child) {
            return Ok(());
        }
        issuer = edge.delegate;
        parent = Some(child);
    }
    Ok(())
}

/// Decide an invocation using the roots of one action-specific policy.
pub fn capability_quorum_authorizes<'a, R: BlobStoreGet>(
    reader: &R,
    proofs: impl IntoIterator<Item = &'a CapabilityProof>,
    trust_roots: impl IntoIterator<Item = VerifyingKey>,
    expected_subject: VerifyingKey,
    request: CapabilityRequest,
    threshold: NonZeroUsize,
) -> bool {
    capability_quorum_authorizes_if(
        reader,
        proofs,
        trust_roots,
        expected_subject,
        request,
        threshold,
        |_| true,
    )
}

/// As [`capability_quorum_authorizes`], with action-specific prefix restrictions.
///
/// The predicate runs before a root share counts. It sees every descriptor
/// along that prefix, allowing a consumer to intersect ancestor restrictions.
/// A configured root originates its own unrestricted share for this action;
/// it is not constrained by grants it has issued to other subjects.
pub fn capability_quorum_authorizes_if<'a, R, F>(
    reader: &R,
    proofs: impl IntoIterator<Item = &'a CapabilityProof>,
    trust_roots: impl IntoIterator<Item = VerifyingKey>,
    expected_subject: VerifyingKey,
    request: CapabilityRequest,
    threshold: NonZeroUsize,
    mut accepts_prefix: F,
) -> bool
where
    R: BlobStoreGet,
    F: FnMut(CapabilityProofPrefix<'_>) -> bool,
{
    if !is_valid_capability_principal(&expected_subject) {
        return false;
    }
    let Some(roots) = canonical_roots(trust_roots, threshold) else {
        return false;
    };
    let subject = expected_subject.to_bytes();
    let mut support = BTreeSet::new();
    if roots.contains(&subject) {
        support.insert(subject);
    }
    if support.len() >= threshold.get() {
        return true;
    }
    let mut definitions = BTreeMap::new();
    for proof in proofs {
        let root = proof.root_key().to_bytes();
        if !roots.contains(&root)
            || support.contains(&root)
            || proof.resource() != request.resource()
        {
            continue;
        }
        let _ = visit_prefixes(proof, reader, &mut definitions, |prefix, definition| {
            if prefix.subject() == expected_subject
                && invokes(definition, request.action())
                && accepts_prefix(prefix)
            {
                support.insert(root);
                return false;
            }
            true
        });
        if support.len() >= threshold.get() {
            return true;
        }
    }
    false
}

/// Enumerate the finite audience of one action-specific rooted policy.
/// Open policies remain explicit at the caller: they have no finite audience.
pub fn capability_quorum_authorized_subjects<'a, R: BlobStoreGet>(
    reader: &R,
    proofs: impl IntoIterator<Item = &'a CapabilityProof>,
    trust_roots: impl IntoIterator<Item = VerifyingKey>,
    request: CapabilityRequest,
    threshold: NonZeroUsize,
) -> Vec<VerifyingKey> {
    capability_quorum_authorized_subjects_if(
        reader,
        proofs,
        trust_roots,
        request,
        threshold,
        |_| true,
    )
}

/// Enumerate an audience after applying restrictions to each root's prefix.
pub fn capability_quorum_authorized_subjects_if<'a, R, F>(
    reader: &R,
    proofs: impl IntoIterator<Item = &'a CapabilityProof>,
    trust_roots: impl IntoIterator<Item = VerifyingKey>,
    request: CapabilityRequest,
    threshold: NonZeroUsize,
    mut accepts_prefix: F,
) -> Vec<VerifyingKey>
where
    R: BlobStoreGet,
    F: FnMut(CapabilityProofPrefix<'_>) -> bool,
{
    let Some(roots) = canonical_roots(trust_roots, threshold) else {
        return Vec::new();
    };
    let mut authority: BTreeMap<[u8; PUBLIC_KEY_LEN], BTreeSet<[u8; PUBLIC_KEY_LEN]>> = roots
        .iter()
        .map(|root| (*root, BTreeSet::from([*root])))
        .collect();
    let mut definitions = BTreeMap::new();
    for proof in proofs {
        let root = proof.root_key().to_bytes();
        if !roots.contains(&root) || proof.resource() != request.resource() {
            continue;
        }
        let _ = visit_prefixes(proof, reader, &mut definitions, |prefix, definition| {
            if invokes(definition, request.action()) && accepts_prefix(prefix) {
                authority
                    .entry(prefix.subject().to_bytes())
                    .or_default()
                    .insert(root);
            }
            true
        });
    }
    authority
        .into_iter()
        .filter(|(_, roots)| roots.len() >= threshold.get())
        .map(|(subject, _)| {
            parse_key(&subject).expect("only canonical principals enter the audience")
        })
        .collect()
}

fn canonical_roots(
    roots: impl IntoIterator<Item = VerifyingKey>,
    threshold: NonZeroUsize,
) -> Option<BTreeSet<[u8; PUBLIC_KEY_LEN]>> {
    let roots: Option<BTreeSet<_>> = roots
        .into_iter()
        .map(|root| is_valid_capability_principal(&root).then(|| root.to_bytes()))
        .collect();
    roots.filter(|roots| roots.len() >= threshold.get())
}

fn parse_key(bytes: &[u8]) -> Option<VerifyingKey> {
    let raw: [u8; PUBLIC_KEY_LEN] = bytes.try_into().expect("fixed key slice");
    let key = VerifyingKey::from_bytes(&raw).ok()?;
    is_valid_capability_principal(&key).then_some(key)
}

/// Reject weak points and noncanonical aliases before counting key identities.
pub(crate) fn is_valid_capability_principal(key: &VerifyingKey) -> bool {
    is_canonical_edwards_y(key.as_bytes()) && !key.is_weak()
}

fn is_canonical_edwards_y(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    const P: [u8; PUBLIC_KEY_LEN] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut y = *bytes;
    y[PUBLIC_KEY_LEN - 1] &= 0x7f;
    for (actual, modulus) in y.iter().zip(P.iter()).rev() {
        match actual.cmp(modulus) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

/// Historical action-ID grammar, retained only to cross inert physical frames.
/// No old mode or validity participates in current authorization.
pub(crate) fn legacy_action_proof_is_structural(bytes: &[u8]) -> bool {
    const MAGIC: [u8; 16] = hex_literal::hex!("5C154102198D7FED2EA797720C2E258D");
    const HEADER: usize = 16 + 32 + 32;
    const EDGE: usize = 16 + 1 + 32 + 32 + 64;
    if bytes.len() < HEADER + EDGE
        || (bytes.len() - HEADER) % EDGE != 0
        || (bytes.len() - HEADER) / EDGE > MAX_CAPABILITY_PROOF_STEPS
        || bytes[..MAGIC.len()] != MAGIC
        || parse_key(&bytes[MAGIC.len() + RESOURCE_LEN..HEADER]).is_none()
    {
        return false;
    }
    bytes[HEADER..].chunks_exact(EDGE).all(|edge| {
        let flags = edge[16];
        let bounds = &edge[17..49];
        let validity_is_canonical = if flags & 4 == 0 {
            bounds.iter().all(|byte| *byte == 0)
        } else {
            i128::from_be_bytes(bounds[..16].try_into().expect("fixed lower bound"))
                <= i128::from_be_bytes(bounds[16..].try_into().expect("fixed upper bound"))
        };
        edge[..16].iter().any(|byte| *byte != 0)
            && flags & !7 == 0
            && flags & 3 != 0
            && validity_is_canonical
            && parse_key(&edge[49..81]).is_some()
    })
}

/// Golden body from the historical action-ID grammar.
#[cfg(test)]
pub(crate) const LEGACY_ACTION_PROOF_FIXTURE: [u8; 225] = hex_literal::hex!("5c154102198d7fed2ea797720c2e258d05050505050505050505050505050505050505050505050505050505050505058a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c040404040404040404040404040404040300000000000000000000000000000000000000000000000000000000000000008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394c013aaaadab79103f8cdb6e4b9948341e3d3b711a570743964318ee769315f6911ab060dcbb67ba1e3c7a56a6c14bcb3b3c12cb2ec3e25b86886dea6981bb20d");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityProofDecodeError {
    InvalidMagic,
    InvalidLength { actual: usize },
    TooManySteps { count: usize, limit: usize },
    InvalidKey { key: usize },
}

impl fmt::Display for CapabilityProofDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("invalid capability proof magic"),
            Self::InvalidLength { actual } => write!(f, "invalid capability proof length {actual}"),
            Self::TooManySteps { count, limit } => {
                write!(f, "capability proof has {count} steps; limit is {limit}")
            }
            Self::InvalidKey { key } => write!(f, "invalid capability proof key {key}"),
        }
    }
}
impl Error for CapabilityProofDecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityIssueError {
    TooManySteps {
        limit: usize,
    },
    WrongIssuer {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    InvalidDelegate {
        key: [u8; 32],
    },
    InvalidParent(CapabilityProofError),
}

impl fmt::Display for CapabilityIssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManySteps { limit } => write!(f, "proof exceeds {limit} steps"),
            Self::WrongIssuer { .. } => f.write_str("signer is not the proof leaf"),
            Self::InvalidDelegate { .. } => f.write_str("delegate is not a canonical non-weak key"),
            Self::InvalidParent(source) => write!(f, "invalid parent proof: {source}"),
        }
    }
}
impl Error for CapabilityIssueError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidParent(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityProofError {
    InvalidSignature {
        step: usize,
    },
    WrongRoot {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    WrongResource {
        expected: CapabilityResource,
        actual: CapabilityResource,
    },
    RequestMismatch {
        requested: CapabilityRequest,
    },
    UnavailableDefinition {
        step: usize,
        handle: CapabilityHandle,
    },
    UndelegatedAction {
        step: usize,
        action: Id,
    },
}

impl fmt::Display for CapabilityProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature { step } => write!(f, "invalid signature at edge {step}"),
            Self::WrongRoot { .. } => f.write_str("wrong capability root"),
            Self::WrongResource { .. } => f.write_str("wrong capability resource"),
            Self::RequestMismatch { .. } => f.write_str("capability does not satisfy request"),
            Self::UnavailableDefinition { step, handle } => {
                write!(
                    f,
                    "capability definition {handle:?} at edge {step} is not readable"
                )
            }
            Self::UndelegatedAction { step, action } => {
                write!(
                    f,
                    "action {action:?} at edge {step} was not delegated by its parent"
                )
            }
        }
    }
}
impl Error for CapabilityProofError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use crate::blob::{BlobEncoding, TryFromBlob};
    use crate::collection::{read_capability, write_capability, ACTION_READ, ACTION_WRITE};
    use crate::repo::memoryrepo::MemoryRepo;
    use crate::repo::{BlobStorePut, SnapshotSource};

    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }
    fn resource(byte: u8) -> CapabilityResource {
        CapabilityResource::new([byte; 32])
    }
    fn definition(repo: &mut MemoryRepo, invoke: &[Id], delegate: &[Id]) -> CapabilityHandle {
        let fragment = entity! {
            capability_action*: invoke.iter().copied(),
            capability_delegate_action*: delegate.iter().copied(),
        };
        repo.put::<SimpleArchive, _>(fragment.facts().clone())
            .unwrap()
    }
    fn read_request() -> CapabilityRequest {
        CapabilityRequest::new(resource(9), ACTION_READ)
    }
    fn threshold(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).unwrap()
    }

    #[test]
    fn standard_definition_identities_are_unchanged() {
        let mut repo = MemoryRepo::default();
        assert_eq!(
            definition(&mut repo, &[ACTION_READ], &[]),
            read_capability()
        );
        assert_eq!(
            definition(&mut repo, &[ACTION_WRITE], &[]),
            write_capability()
        );
    }

    #[test]
    fn exact_prefix_is_a_proof_with_no_mode_or_clock_bytes() {
        let root = key(1);
        let middle = key(2);
        let leaf = key(3);
        let cap = CapabilityHandle::new([4; 32]);
        let first = CapabilityProof::new(resource(9), &root, cap, middle.verifying_key());
        assert_eq!(CAPABILITY_PROOF_HEADER_LEN, 96);
        assert_eq!(CAPABILITY_PROOF_EDGE_LEN, 128);
        assert_eq!(first.as_bytes().len(), 224);
        assert_eq!(&first.as_bytes()[..32], &CAPABILITY_PROOF_MAGIC);
        assert_eq!(&first.as_bytes()[32..64], resource(9).as_bytes());
        assert_eq!(&first.as_bytes()[64..96], root.verifying_key().as_bytes());
        assert_eq!(&first.as_bytes()[96..128], &cap.raw);
        assert_eq!(
            &first.as_bytes()[128..160],
            middle.verifying_key().as_bytes()
        );
        root.verifying_key()
            .verify_strict(
                &first.as_bytes()[..160],
                &Signature::from_bytes(first.as_bytes()[160..].try_into().unwrap()),
            )
            .unwrap();
        let second = first.delegate(&middle, cap, leaf.verifying_key()).unwrap();
        assert_eq!(&second.as_bytes()[..224], first.as_bytes());
        assert_eq!(second.leaf_issuer(), middle.verifying_key());
        assert_eq!(second.leaf_key(), leaf.verifying_key());
        assert_eq!(
            second
                .prefixes()
                .map(|p| p.step_count())
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(
            CapabilityProof::from_bytes(second.prefixes().next().unwrap().as_bytes()).unwrap(),
            first
        );
        assert_eq!(
            CapabilityProof::from_bytes(second.as_bytes()).unwrap(),
            second
        );
        second.verify_signatures().unwrap();
    }

    #[test]
    fn owned_proof_clones_share_the_exact_view() {
        let expected = CapabilityProof::new(
            resource(9),
            &key(1),
            read_capability(),
            key(2).verifying_key(),
        );
        let mut storage = vec![0_u8; 11];
        storage.extend_from_slice(expected.as_bytes());
        storage.extend_from_slice(&[0_u8; 13]);
        let owner = Bytes::from_source(storage);
        let weak = owner.downgrade();
        let bytes = owner.slice(11..11 + expected.as_bytes().len());
        let address = bytes.as_ptr();
        let proof = CapabilityProof::from_owned_bytes(bytes).unwrap();
        let clone = proof.clone();
        assert_eq!(proof.as_bytes().as_ptr(), address);
        assert_eq!(clone.as_bytes().as_ptr(), address);
        assert_eq!(proof.id(), expected.id());
        drop((owner, proof));
        assert!(weak.upgrade().is_some());
        clone.verify_signatures().unwrap();
        assert_eq!(clone.into_bytes(), expected.as_bytes());
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn different_handles_attenuate_invocation_and_delegation_independently() {
        let mut repo = MemoryRepo::default();
        let compound = definition(&mut repo, &[ACTION_READ, ACTION_WRITE], &[ACTION_READ]);
        let read = definition(&mut repo, &[ACTION_READ], &[]);
        let root = key(1);
        let middle = key(2);
        let leaf = key(3);
        let first = CapabilityProof::new(resource(9), &root, compound, middle.verifying_key());
        let path = first.delegate(&middle, read, leaf.verifying_key()).unwrap();
        let snapshot = repo.snapshot().unwrap();
        assert_ne!(compound, read);
        path.verify(
            &snapshot,
            root.verifying_key(),
            leaf.verifying_key(),
            read_request(),
        )
        .unwrap();
        path.verify(
            &snapshot,
            root.verifying_key(),
            middle.verifying_key(),
            CapabilityRequest::new(resource(9), ACTION_WRITE),
        )
        .unwrap();
        assert!(path
            .verify(
                &snapshot,
                root.verifying_key(),
                leaf.verifying_key(),
                CapabilityRequest::new(resource(9), ACTION_WRITE)
            )
            .is_err());
        let write = definition(&mut repo, &[ACTION_WRITE], &[]);
        let overgrant = first
            .delegate(&middle, write, leaf.verifying_key())
            .unwrap();
        assert_eq!(
            overgrant.validate_delegation(&repo.snapshot().unwrap()),
            Err(CapabilityProofError::UndelegatedAction {
                step: 1,
                action: ACTION_WRITE
            })
        );
    }

    #[test]
    fn delegation_only_can_confer_invocation_and_onward_delegation() {
        let mut repo = MemoryRepo::default();
        let delegate = definition(&mut repo, &[], &[ACTION_READ]);
        let both = definition(&mut repo, &[ACTION_READ], &[ACTION_READ]);
        let read = definition(&mut repo, &[ACTION_READ], &[]);
        let root = key(1);
        let middle = key(2);
        let bridge = key(3);
        let leaf = key(4);
        let path = CapabilityProof::new(resource(9), &root, delegate, middle.verifying_key())
            .delegate(&middle, both, bridge.verifying_key())
            .unwrap()
            .delegate(&bridge, read, leaf.verifying_key())
            .unwrap();
        let snapshot = repo.snapshot().unwrap();
        assert!(path
            .verify(
                &snapshot,
                root.verifying_key(),
                middle.verifying_key(),
                read_request()
            )
            .is_err());
        path.verify(
            &snapshot,
            root.verifying_key(),
            bridge.verifying_key(),
            read_request(),
        )
        .unwrap();
        path.verify(
            &snapshot,
            root.verifying_key(),
            leaf.verifying_key(),
            read_request(),
        )
        .unwrap();
        let audience = capability_quorum_authorized_subjects(
            &snapshot,
            [&path],
            [root.verifying_key()],
            read_request(),
            threshold(1),
        );
        assert!(!audience.contains(&middle.verifying_key()));
        assert!(audience.contains(&bridge.verifying_key()));
        assert!(audience.contains(&leaf.verifying_key()));
    }

    #[test]
    fn invocation_alone_cannot_confer_any_child_right() {
        let mut repo = MemoryRepo::default();
        let read = definition(&mut repo, &[ACTION_READ], &[]);
        let delegate = definition(&mut repo, &[], &[ACTION_READ]);
        let root = key(1);
        let middle = key(2);
        let first = CapabilityProof::new(resource(9), &root, read, middle.verifying_key());
        for child in [read, delegate] {
            let path = first
                .delegate(&middle, child, key(3).verifying_key())
                .unwrap();
            assert_eq!(
                path.validate_delegation(&repo.snapshot().unwrap()),
                Err(CapabilityProofError::UndelegatedAction {
                    step: 1,
                    action: ACTION_READ
                })
            );
        }
    }

    #[test]
    fn unrelated_bad_or_unavailable_suffix_does_not_revoke_a_prefix() {
        let mut repo = MemoryRepo::default();
        let both = definition(&mut repo, &[ACTION_READ], &[ACTION_READ]);
        let root = key(1);
        let middle = key(2);
        let first = CapabilityProof::new(resource(9), &root, both, middle.verifying_key());
        let missing = first
            .delegate(
                &middle,
                CapabilityHandle::new([99; 32]),
                key(3).verifying_key(),
            )
            .unwrap();
        let mut bad = missing.as_bytes().to_vec();
        *bad.last_mut().unwrap() ^= 1;
        let bad = CapabilityProof::from_bytes(&bad).unwrap();
        let snapshot = repo.snapshot().unwrap();
        for path in [&missing, &bad] {
            assert!(path.validate_delegation(&snapshot).is_err());
            path.verify(
                &snapshot,
                root.verifying_key(),
                middle.verifying_key(),
                read_request(),
            )
            .unwrap();
            assert!(capability_quorum_authorizes(
                &snapshot,
                [path],
                [root.verifying_key()],
                middle.verifying_key(),
                read_request(),
                threshold(1)
            ));
            assert!(capability_quorum_authorized_subjects(
                &snapshot,
                [path],
                [root.verifying_key()],
                read_request(),
                threshold(1)
            )
            .contains(&middle.verifying_key()));
        }
    }

    #[test]
    fn quorum_counts_roots_not_proofs_and_never_borrows_other_action_roots() {
        let mut repo = MemoryRepo::default();
        let both = definition(&mut repo, &[ACTION_READ, ACTION_WRITE], &[]);
        let roots = [key(1), key(2), key(3)];
        let leaf = key(4);
        let proofs: Vec<_> = roots
            .iter()
            .map(|root| CapabilityProof::new(resource(9), root, both, leaf.verifying_key()))
            .collect();
        let snapshot = repo.snapshot().unwrap();
        assert!(!capability_quorum_authorizes(
            &snapshot,
            [&proofs[0], &proofs[0]],
            roots.iter().map(SigningKey::verifying_key),
            leaf.verifying_key(),
            read_request(),
            threshold(2)
        ));
        assert!(capability_quorum_authorizes(
            &snapshot,
            [&proofs[0], &proofs[1]],
            roots.iter().map(SigningKey::verifying_key),
            leaf.verifying_key(),
            read_request(),
            threshold(2)
        ));
        let write_request = CapabilityRequest::new(resource(9), ACTION_WRITE);
        assert!(!capability_quorum_authorizes(
            &snapshot,
            [&proofs[0]],
            [roots[1].verifying_key()],
            leaf.verifying_key(),
            write_request,
            threshold(1)
        ));
        assert!(!capability_quorum_authorizes(
            &snapshot,
            [&proofs[0]],
            [roots[0].verifying_key(), roots[0].verifying_key()],
            leaf.verifying_key(),
            read_request(),
            threshold(2)
        ));
        assert!(capability_quorum_authorizes(
            &snapshot,
            [],
            [roots[0].verifying_key()],
            roots[0].verifying_key(),
            read_request(),
            threshold(1)
        ));
        assert!(!capability_quorum_authorizes(
            &snapshot,
            [],
            roots.iter().map(SigningKey::verifying_key),
            roots[0].verifying_key(),
            read_request(),
            threshold(2)
        ));
    }

    #[test]
    fn sibling_paths_cannot_lend_delegation_to_each_other() {
        let mut repo = MemoryRepo::default();
        let read = definition(&mut repo, &[ACTION_READ], &[]);
        let delegate = definition(&mut repo, &[], &[ACTION_READ]);
        let root = key(1);
        let middle = key(2);
        let leaf = key(3);
        let invoke = CapabilityProof::new(resource(9), &root, read, middle.verifying_key());
        let sibling = CapabilityProof::new(resource(9), &root, delegate, middle.verifying_key());
        let bad_child = invoke
            .delegate(&middle, read, leaf.verifying_key())
            .unwrap();
        let snapshot = repo.snapshot().unwrap();
        assert!(!capability_quorum_authorizes(
            &snapshot,
            [&bad_child, &sibling],
            [root.verifying_key()],
            leaf.verifying_key(),
            read_request(),
            threshold(1)
        ));
        let good_child = sibling
            .delegate(&middle, read, leaf.verifying_key())
            .unwrap();
        assert!(capability_quorum_authorizes(
            &snapshot,
            [&good_child],
            [root.verifying_key()],
            leaf.verifying_key(),
            read_request(),
            threshold(1)
        ));
    }

    #[test]
    fn application_restrictions_apply_before_quorum_and_only_to_the_subject_prefix() {
        let mut repo = MemoryRepo::default();
        let unrestricted = definition(&mut repo, &[ACTION_READ], &[ACTION_READ]);
        let restricted_fragment = entity! {
            capability_action: ACTION_READ,
            capability_delegate_action: ACTION_READ,
            metadata::name: "consumer-defined restricted delivery",
        };
        let restricted = repo
            .put::<SimpleArchive, _>(restricted_fragment.facts().clone())
            .unwrap();
        let roots = [key(1), key(2)];
        let middle = key(3);
        let leaf = key(4);
        let first =
            CapabilityProof::new(resource(9), &roots[0], unrestricted, middle.verifying_key())
                .delegate(&middle, restricted, leaf.verifying_key())
                .unwrap();
        let second =
            CapabilityProof::new(resource(9), &roots[1], unrestricted, leaf.verifying_key());
        let snapshot = repo.snapshot().unwrap();
        let accepts = |prefix: CapabilityProofPrefix<'_>| {
            !prefix.capabilities().any(|handle| handle == restricted)
        };
        assert!(capability_quorum_authorizes_if(
            &snapshot,
            [&first],
            [roots[0].verifying_key()],
            middle.verifying_key(),
            read_request(),
            threshold(1),
            accepts
        ));
        assert!(capability_quorum_authorizes(
            &snapshot,
            [&first, &second],
            roots.iter().map(SigningKey::verifying_key),
            leaf.verifying_key(),
            read_request(),
            threshold(2)
        ));
        assert!(!capability_quorum_authorizes_if(
            &snapshot,
            [&first, &second],
            roots.iter().map(SigningKey::verifying_key),
            leaf.verifying_key(),
            read_request(),
            threshold(2),
            accepts
        ));
        assert!(!capability_quorum_authorized_subjects_if(
            &snapshot,
            [&first, &second],
            roots.iter().map(SigningKey::verifying_key),
            read_request(),
            threshold(2),
            accepts
        )
        .contains(&leaf.verifying_key()));
        // A child with a new handle cannot hide an ancestor restriction.
        let grandchild = first
            .delegate(&leaf, unrestricted, key(5).verifying_key())
            .unwrap();
        assert!(!capability_quorum_authorizes_if(
            &snapshot,
            [&grandchild],
            [roots[0].verifying_key()],
            key(5).verifying_key(),
            read_request(),
            threshold(1),
            accepts
        ));
    }

    #[test]
    fn unavailable_definitions_are_inert_but_the_proof_remains_transportable() {
        let mut repo = MemoryRepo::default();
        let missing = CapabilityHandle::new([0; 32]);
        let proof = CapabilityProof::new(resource(9), &key(1), missing, key(2).verifying_key());
        let decoded = CapabilityProof::from_bytes(proof.as_bytes()).unwrap();
        decoded.verify_signatures().unwrap();
        assert_eq!(
            decoded.blob_references().collect::<Vec<_>>(),
            [missing.transmute()]
        );
        assert_eq!(
            decoded.validate_delegation(&repo.snapshot().unwrap()),
            Err(CapabilityProofError::UnavailableDefinition {
                step: 0,
                handle: missing
            })
        );
        assert!(!capability_quorum_authorizes(
            &repo.snapshot().unwrap(),
            [&decoded],
            [key(1).verifying_key()],
            key(2).verifying_key(),
            read_request(),
            threshold(1)
        ));
    }

    #[test]
    fn annotations_do_not_restrict_generic_actions_or_introduce_a_clock() {
        let mut repo = MemoryRepo::default();
        let fragment = entity! {
            capability_action: ACTION_WRITE,
            metadata::name: "an annotated grant",
            metadata::description: "Application restrictions belong to their action's interpreter.",
        };
        let handle = repo
            .put::<SimpleArchive, _>(fragment.facts().clone())
            .unwrap();
        let root = key(1);
        let subject = key(2);
        let proof = CapabilityProof::new(resource(9), &root, handle, subject.verifying_key());
        let request = CapabilityRequest::new(resource(9), ACTION_WRITE);
        let snapshot = repo.snapshot().unwrap();
        assert!(capability_quorum_authorizes(
            &snapshot,
            [&proof],
            [root.verifying_key()],
            subject.verifying_key(),
            request,
            threshold(1),
        ));
        assert!(proof
            .verify(
                &repo.snapshot().unwrap(),
                root.verifying_key(),
                subject.verifying_key(),
                CapabilityRequest::new(resource(10), ACTION_WRITE),
            )
            .is_err());
    }

    #[test]
    fn changing_entity_ids_only_changes_the_descriptor_handle() {
        let mut repo = MemoryRepo::default();
        let first_id = crate::id::genid();
        let second_id = crate::id::genid();
        let first = entity! { &first_id @ capability_action: ACTION_READ };
        let second = entity! { &second_id @ capability_action: ACTION_READ };
        let first = repo.put::<SimpleArchive, _>(first.facts().clone()).unwrap();
        let second = repo
            .put::<SimpleArchive, _>(second.facts().clone())
            .unwrap();
        assert_ne!(first, second);
        let root = key(1);
        let subject = key(2);
        let snapshot = repo.snapshot().unwrap();
        for handle in [first, second] {
            let proof = CapabilityProof::new(resource(9), &root, handle, subject.verifying_key());
            proof
                .verify(
                    &snapshot,
                    root.verifying_key(),
                    subject.verifying_key(),
                    read_request(),
                )
                .unwrap();
        }
    }

    #[test]
    fn definition_reads_are_shared_within_one_quorum_operation() {
        struct Counted<R> {
            inner: R,
            reads: Cell<usize>,
        }
        impl<R: BlobStoreGet> BlobStoreGet for Counted<R> {
            type GetError<E: Error + Send + Sync + 'static> = R::GetError<E>;
            fn get<T, S>(
                &self,
                handle: Inline<Handle<S>>,
            ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
            where
                S: BlobEncoding + 'static,
                T: TryFromBlob<S>,
                Handle<S>: InlineEncoding,
            {
                self.reads.set(self.reads.get() + 1);
                self.inner.get(handle)
            }
        }
        let mut repo = MemoryRepo::default();
        let read = definition(&mut repo, &[ACTION_READ], &[]);
        let roots = [key(1), key(2)];
        let leaf = key(3);
        let proofs: Vec<_> = roots
            .iter()
            .map(|root| CapabilityProof::new(resource(9), root, read, leaf.verifying_key()))
            .collect();
        let counted = Counted {
            inner: repo.snapshot().unwrap(),
            reads: Cell::new(0),
        };
        assert!(capability_quorum_authorizes(
            &counted,
            &proofs,
            roots.iter().map(SigningKey::verifying_key),
            leaf.verifying_key(),
            read_request(),
            threshold(2)
        ));
        assert_eq!(counted.reads.get(), 1);
    }

    #[test]
    fn every_wire_field_is_bound_and_edges_cannot_be_grafted() {
        let first = CapabilityProof::new(
            resource(9),
            &key(1),
            read_capability(),
            key(2).verifying_key(),
        );
        let path = first
            .delegate(&key(2), write_capability(), key(3).verifying_key())
            .unwrap();
        for index in [
            0,
            32,
            64,
            96,
            128,
            160,
            224,
            256,
            288,
            path.as_bytes().len() - 1,
        ] {
            let mut bytes = path.as_bytes().to_vec();
            bytes[index] ^= 1;
            assert!(CapabilityProof::from_bytes(&bytes)
                .map_or(true, |proof| proof.verify_signatures().is_err()));
        }
        let other = CapabilityProof::new(
            resource(10),
            &key(1),
            read_capability(),
            key(2).verifying_key(),
        );
        let mut graft = other.into_bytes();
        graft.extend_from_slice(&path.as_bytes()[224..]);
        assert!(CapabilityProof::from_bytes(&graft)
            .unwrap()
            .verify_signatures()
            .is_err());
        assert!(matches!(
            first.delegate(&key(4), read_capability(), key(3).verifying_key()),
            Err(CapabilityIssueError::WrongIssuer { .. })
        ));
    }

    #[test]
    fn framing_rejects_empty_oversized_and_weak_key_paths() {
        let proof = CapabilityProof::new(
            resource(9),
            &key(1),
            read_capability(),
            key(2).verifying_key(),
        );
        for length in [
            0,
            CAPABILITY_PROOF_HEADER_LEN,
            MIN_CAPABILITY_PROOF_BYTES - 1,
            MIN_CAPABILITY_PROOF_BYTES + 1,
        ] {
            assert!(matches!(
                CapabilityProof::from_bytes(&vec![0; length]),
                Err(CapabilityProofDecodeError::InvalidLength { .. })
            ));
        }
        for key_index in [0, 1] {
            let offset = if key_index == 0 { 64 } else { 128 };
            let mut bytes = proof.as_bytes().to_vec();
            bytes[offset..offset + 32].fill(0);
            assert_eq!(
                CapabilityProof::from_bytes(&bytes),
                Err(CapabilityProofDecodeError::InvalidKey { key: key_index })
            );
        }
        let mut too_long = proof.as_bytes().to_vec();
        for _ in 1..=MAX_CAPABILITY_PROOF_STEPS {
            too_long.extend_from_slice(&proof.as_bytes()[96..]);
        }
        assert!(matches!(
            CapabilityProof::from_bytes(&too_long),
            Err(CapabilityProofDecodeError::TooManySteps { .. })
        ));
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        assert!(!is_canonical_edwards_y(&modulus));
        modulus[0] -= 1;
        assert!(is_canonical_edwards_y(&modulus));
    }

    #[test]
    fn legacy_action_fixture_is_inert_and_structurally_recognizable() {
        assert!(legacy_action_proof_is_structural(
            &LEGACY_ACTION_PROOF_FIXTURE
        ));
        assert!(CapabilityProof::from_bytes(&LEGACY_ACTION_PROOF_FIXTURE).is_err());
    }
}
