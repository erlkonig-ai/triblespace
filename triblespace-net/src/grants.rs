//! Grants gossip by participation (design: grants gossip by participation).
//!
//! A grant over resource R is shown to every node that takes part in R: a
//! root of R, a key named on a delegation-valid grant over R, or a node
//! peered for R. One passive mechanism serves every kind of resource, with
//! no routing by kind and no dial on a grant's behalf.
//!
//! - [`GrantIndex`] holds every grant this host stores, over any resource,
//!   keyed R | proof id, with R's participants. It is the only AUTH tree
//!   that is walked, summarised, listed or reported for health. A
//!   collection's authorization evidence PATCH is admission input only:
//!   unchanged in membership, it is never walked, summarised into a frontier
//!   or compared.
//! - [`Grants`] lists on every connection, as `recon/1` GRANT_ROOTS, the
//!   root and count of R's grants for every R the peer takes part in, and
//!   opens a grant walk over R ([`crate::walk`]) where the peer's listed
//!   root differs from this side's.
//! - A received grant goes through the walk's [`Gate`]: kept when it names
//!   this node, this node takes part in R, or the link is peered for R, and
//!   skipped otherwise, never failing the walk. A kept grant lands once R's
//!   descriptor is resident and it starts at one of R's roots; until the
//!   descriptor arrives it waits in bounded memory ([`Pending`]).
//! - What a waiting grant needs (R's descriptor and name, its definitions)
//!   is fetched over `blob/1`, from the peers that listed R first. A peering
//!   refused for want of definitions fetches them the same way.
//! - Every grant walk's end reaches the exchange ([`GrantWalkEnd`]). One that
//!   failed, was refused or could not start opens again on the same
//!   connection after a backoff of 1 s doubling to 60 s, while the peer's
//!   listed root still differs; a confirmed walk or a root change resets it.
//!   A pending grant given up (evicted, or its descriptor found nowhere)
//!   opens its walk again the same way, and a definition found nowhere is
//!   asked for again when the retry falls due, so recovery never waits for a
//!   listing that may not change.
//! - What this side holds of R's grants, and each connected peer's standing
//!   listing of R, is published into health as grant agreement
//!   ([`crate::health::GrantHealth`]); a collection's pair reads its grant
//!   part from there, with no age.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::capability::{
    CapabilityProof, CapabilityProofId, capability_action, capability_delegate_action,
};
use triblespace_core::collection::{AdmissionPolicy, CollectionHandle};
use triblespace_core::collection::descriptor::{
    ProofEvidenceError, name, resource_grant_policies, validate_proof_for_policies,
};
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::patch::{Blake3Merkle, Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::prelude::{exists, pattern};
use triblespace_core::repo::{BlobStoreGet, BlobStoreList, CapabilityProofRead, StoreChanges};
use triblespace_core::trible::TribleSet;

use crate::channel::{NetEvent, NetEventBatch};
use crate::clock::Mono;
use crate::connection::{ConnectionTable, Link, ReconEvent, Service};
use crate::host::{ActiveCollections, METADATA_BLOB_BYTES, StoreSnapshot};
use crate::patch_repair::PatchSummary;
use crate::protocol::{RawHash, op_get_blob_with_limit};
use crate::recon::{Frame, grant_roots_frames};
use crate::transport::{PeerId, Transport};
use crate::walk::{WalkKind, WalksHandle};

/// Bound on fetching one definition from one key.
const FETCH_DEADLINE: Duration = Duration::from_secs(30);
/// Proofs waiting in memory for their descriptor that one sender keeps,
/// counting each proof against every sender it waits for.
const MAX_PENDING_PER_SENDER: usize = 256;
/// Proofs every sender together keeps waiting in memory.
const MAX_PENDING: usize = 1024;
/// The first wait before a failed grant walk opens again; it doubles with
/// each failure up to [`MAX_RETRY`].
const MIN_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(60);

/// Resources a connection may list that this side takes no part in (a
/// non-syncing grantee learns its grants this way). Reset per connection.
pub(crate) const MAX_UNKNOWN_RESOURCES_PER_LINK: usize = 256;

/// Grants over one resource R: the indexed proofs, keyed R | proof id, and
/// the keys that take part in R.
#[derive(Clone, Debug, Default)]
pub(crate) struct ResourceGrants {
    /// Exact stored proof bytes under R | proof id.
    pub(crate) proofs: GrantProofs,
    /// R's roots, and the root and every delegated key of each indexed
    /// proof.
    pub(crate) participants: PATCH<32, IdentitySchema, ()>,
}

/// Indexed proofs of one resource, keyed R | proof id.
pub(crate) type GrantProofs = PATCH<64, IdentitySchema, CapabilityProof, Blake3Merkle>;

/// Why a stored proof is not indexed. Final: proofs, descriptors and
/// definitions are immutable once resident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Junk {
    /// It starts outside every root R's descriptor declares.
    Root,
    /// A signature in its chain is invalid.
    Signature,
    /// A step confers an action its parent's definition does not delegate.
    Delegation,
    /// A step's definition names no action, or a step extends a parent whose
    /// definition delegates nothing (participation hardening).
    NoActionStep,
}

/// The index's judgement of one stored proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    /// Offered for R, whose participants its keys join.
    Indexed(CollectionHandle),
    /// Never offered and names no participant.
    Junk(Junk),
    /// R's descriptor or a definition is not resident yet: every such
    /// handle. Neither offered nor a source of participants.
    Waiting(BTreeSet<RawHash>),
}

/// Every grant this host holds, over any resource R, with R's participants:
/// the one AUTH index for grants (design: grants gossip by participation).
///
/// It is the only AUTH tree that is walked, summarised, listed or reported.
/// A collection's authorization evidence PATCH stays what admission reads,
/// unchanged, and is never walked or summarised as a frontier.
///
/// Grow-only and built incrementally: each stored proof is judged once, and
/// a waiting proof again only when a handle it waits for becomes resident.
/// Indexed and junk verdicts are final; a resident blob that does not read
/// as an archive judges as one with no facts. Residency is checked in the
/// store's index, so an unrelated arrival reads no blob. A resource's entry is shared, by
/// `Arc`, with the previous index unless one of its grants landed. Nothing is
/// filtered by local selection; participation decides what is offered.
/// Building it reads the store and writes nothing.
#[derive(Clone, Default)]
pub(crate) struct GrantIndex {
    resources: PATCH<32, IdentitySchema, Arc<ResourceGrants>>,
    /// Proof id to verdict.
    verdicts: PATCH<32, IdentitySchema, Verdict>,
    /// Waiting proofs by id.
    waiting_proofs: BTreeMap<RawHash, CapabilityProof>,
    /// Missing handle to the waiting proofs that need it.
    waiting: BTreeMap<RawHash, BTreeSet<RawHash>>,
    /// Proofs judged so far, over the whole incremental chain.
    evaluations: u64,
}

impl GrantIndex {
    /// The index of `snapshot`, from `previous` (the index of an earlier
    /// snapshot of the same store) when given; `changes` classifies what
    /// changed since then.
    pub(crate) fn observe<R>(
        snapshot: &R,
        active: &ActiveCollections,
        previous: Option<&Arc<GrantIndex>>,
        changes: StoreChanges,
    ) -> Result<Arc<GrantIndex>, R::ProofsError>
    where
        R: BlobStoreGet + BlobStoreList + CapabilityProofRead,
    {
        let proofs_changed =
            previous.is_none() || changes.contains(StoreChanges::CAPABILITY_PROOFS);
        let blobs_changed = previous.is_none() || changes.contains(StoreChanges::BLOBS);
        let mut index = previous.map_or_else(GrantIndex::default, |index| GrantIndex::clone(index));
        let mut touched = false;
        if blobs_changed {
            // Waiting proofs one of whose handles became resident are judged
            // again; one still missing another handle waits on that.
            let ready: BTreeSet<RawHash> = index
                .waiting
                .iter()
                .filter(|(handle, _)| resident(snapshot, **handle))
                .flat_map(|(_, ids)| ids.iter().copied())
                .collect();
            for id in ready {
                let proof = index.unwait(id);
                index.evaluate(snapshot, proof);
                touched = true;
            }
        }
        if proofs_changed {
            for proof in snapshot.proofs()? {
                let proof = proof?;
                if index.verdicts.get(&proof.id().raw).is_none() {
                    index.evaluate(snapshot, proof);
                    touched = true;
                }
            }
        }
        // An active collection takes part through its roots even with no
        // grant; its descriptor is immutable, so this is done once.
        for raw in active.iter_ordered() {
            if index.resources.get(raw).is_some() || !resident(snapshot, *raw) {
                continue;
            }
            index.resources.insert(&PatchEntry::with_value(
                raw,
                Arc::new(ResourceGrants::rooted(&read_facts(snapshot, *raw))),
            ));
            touched = true;
        }
        Ok(match previous {
            Some(previous) if !touched => previous.clone(),
            _ => Arc::new(index),
        })
    }

    /// Judge one proof that has no final verdict, and index it if it is
    /// usable (steps 1-5 of the design note).
    fn evaluate<R: BlobStoreGet + BlobStoreList>(&mut self, snapshot: &R, proof: CapabilityProof) {
        self.evaluations += 1;
        let id = proof.id().raw;
        let resource = CollectionHandle::new(proof.resource().into_bytes());
        let missing: BTreeSet<RawHash> = std::iter::once(resource.raw)
            .chain(proof.capabilities().map(|handle| handle.raw))
            .filter(|handle| !resident(snapshot, *handle))
            .collect();
        if !missing.is_empty() {
            for handle in &missing {
                self.waiting.entry(*handle).or_default().insert(id);
            }
            self.waiting_proofs.insert(id, proof);
            self.verdicts
                .replace(&PatchEntry::with_value(&id, Verdict::Waiting(missing)));
            return;
        }
        let descriptor = read_facts(snapshot, resource.raw);
        let definitions: Vec<TribleSet> = proof
            .capabilities()
            .map(|handle| read_facts(snapshot, handle.raw))
            .collect();
        let verdict = judge(snapshot, resource, &descriptor, &definitions, &proof);
        if verdict == Verdict::Indexed(resource) {
            let mut grants = match self.resources.get(&resource.raw) {
                Some(grants) => ResourceGrants::clone(grants),
                None => ResourceGrants::rooted(&descriptor),
            };
            for key in std::iter::once(proof.root_key()).chain(proof.delegated_keys()) {
                grants.participants.insert(&PatchEntry::new(key.as_bytes()));
            }
            grants
                .proofs
                .insert(&PatchEntry::with_value(&grant_key(resource, proof.id()), proof));
            self.resources
                .replace(&PatchEntry::with_value(&resource.raw, Arc::new(grants)));
        }
        self.verdicts.replace(&PatchEntry::with_value(&id, verdict));
    }

    /// Take a waiting proof out of the waiting sets, for judging again.
    fn unwait(&mut self, id: RawHash) -> CapabilityProof {
        if let Some(Verdict::Waiting(missing)) = self.verdicts.get(&id) {
            for handle in missing {
                if let Some(ids) = self.waiting.get_mut(handle) {
                    ids.remove(&id);
                    if ids.is_empty() {
                        self.waiting.remove(handle);
                    }
                }
            }
        }
        self.waiting_proofs
            .remove(&id)
            .expect("a waiting verdict keeps its proof")
    }

    /// Root and count of R's indexed grants.
    pub(crate) fn summary(&self, resource: CollectionHandle) -> PatchSummary {
        self.grants(resource)
            .and_then(|grants| {
                grants.proofs.merkle_node(&resource.raw).map(|node| {
                    PatchSummary::new(Some(node.digest()), node.leaf_count())
                        .expect("an indexed resource prefix is nonempty")
                })
            })
            .unwrap_or_else(|| PatchSummary::new(None, 0).expect("the empty summary is canonical"))
    }

    /// R's entry, if it has an indexed grant or is an active collection.
    pub(crate) fn grants(&self, resource: CollectionHandle) -> Option<Arc<ResourceGrants>> {
        self.resources.get(&resource.raw).cloned()
    }

    /// One indexed grant over R.
    pub(crate) fn get(
        &self,
        resource: CollectionHandle,
        id: CapabilityProofId,
    ) -> Option<&CapabilityProof> {
        self.resources
            .get(&resource.raw)?
            .proofs
            .get(&grant_key(resource, id))
    }

    /// Whether `key` takes part in R.
    pub(crate) fn participates(&self, resource: CollectionHandle, key: PeerId) -> bool {
        self.resources
            .get(&resource.raw)
            .is_some_and(|grants| grants.participants.get(&key).is_some())
    }

    /// Every resource with an entry, in handle order.
    pub(crate) fn resources(&self) -> impl Iterator<Item = CollectionHandle> + '_ {
        self.resources
            .iter_ordered()
            .map(|raw| CollectionHandle::new(*raw))
    }

    /// Every waiting proof with every handle it waits for.
    pub(crate) fn waiting(
        &self,
    ) -> impl Iterator<Item = (CapabilityProofId, &BTreeSet<RawHash>)> + '_ {
        self.waiting_proofs
            .keys()
            .filter_map(|id| match self.verdicts.get(id) {
                Some(Verdict::Waiting(missing)) => Some((CapabilityProofId::new(*id), missing)),
                _ => None,
            })
    }

    /// Every waiting proof itself, with every handle it waits for.
    pub(crate) fn waiting_grants(
        &self,
    ) -> impl Iterator<Item = (&CapabilityProof, &BTreeSet<RawHash>)> + '_ {
        self.waiting_proofs
            .iter()
            .filter_map(|(id, proof)| match self.verdicts.get(id) {
                Some(Verdict::Waiting(missing)) => Some((proof, missing)),
                _ => None,
            })
    }

    /// The verdict on one stored proof, once judged.
    pub(crate) fn verdict(&self, id: CapabilityProofId) -> Option<&Verdict> {
        self.verdicts.get(&id.raw)
    }

    /// Proofs judged over the whole incremental chain of this index.
    pub(crate) fn evaluations(&self) -> u64 {
        self.evaluations
    }
}

impl ResourceGrants {
    /// An entry with R's roots as its only participants: the roots of every
    /// quorum binding of any entity of R's descriptor. Open bindings name no
    /// root.
    fn rooted(descriptor: &TribleSet) -> Self {
        let mut grants = Self::default();
        for policy in resource_grant_policies(descriptor) {
            for root in policy.roots().unwrap_or_default() {
                grants.participants.insert(&PatchEntry::new(root.as_bytes()));
            }
        }
        grants
    }
}

/// Whether the store's index holds `handle`; reads no blob.
fn resident<R: BlobStoreList>(snapshot: &R, handle: RawHash) -> bool {
    snapshot
        .contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
        .unwrap_or(false)
}

/// The facts of one resident blob; none when it does not read as an archive.
fn read_facts<R: BlobStoreGet>(snapshot: &R, handle: RawHash) -> TribleSet {
    snapshot
        .get::<TribleSet, SimpleArchive>(Inline::new(handle))
        .unwrap_or_default()
}

/// The verdict on a proof whose descriptor and definitions are all resident.
/// An unreadable descriptor names no root, and core's delegation check
/// rejects an unreadable definition.
///
/// Admission's own predicate decides root and signatures, and core's
/// delegation check decides attenuation. Participation hardening is local:
/// every step's definition must name an action, and every step after the
/// first must extend a parent whose definition delegates one. Core accepts a
/// step naming no action (it has no action to compare), so without this a
/// grantee with no delegation right could name any key.
fn judge<R: BlobStoreGet>(
    snapshot: &R,
    resource: CollectionHandle,
    descriptor: &TribleSet,
    definitions: &[TribleSet],
    proof: &CapabilityProof,
) -> Verdict {
    match validate_proof_for_policies(resource, resource_grant_policies(descriptor), proof) {
        Ok(()) => {}
        Err(ProofEvidenceError::Invalid(_)) => return Verdict::Junk(Junk::Signature),
        Err(_) => return Verdict::Junk(Junk::Root),
    }
    if proof.validate_delegation(snapshot).is_err() {
        return Verdict::Junk(Junk::Delegation);
    }
    let delegates =
        |definition: &TribleSet| exists!(pattern!(definition, [{ _?step @ capability_delegate_action: _?action }]));
    let names_action = |definition: &TribleSet| {
        delegates(definition)
            || exists!(pattern!(definition, [{ _?step @ capability_action: _?action }]))
    };
    if !definitions.iter().all(names_action)
        || !definitions.windows(2).all(|steps| delegates(&steps[0]))
    {
        return Verdict::Junk(Junk::NoActionStep);
    }
    Verdict::Indexed(resource)
}

/// The receiving side of one grant walk over R: which received proofs it
/// keeps and whether a kept one lands now (design: grants gossip by
/// participation).
///
/// A proof is kept when a prefix names this node, this node takes part in R,
/// or the link is peered for R; a proof over another resource or with a bad
/// signature is not. A kept proof lands once R's descriptor is resident and
/// the proof starts at one of R's roots; delegation is the index's concern,
/// not landing's. One whose descriptor is not resident is pending. Whatever
/// is not kept is skipped: it neither fails the walk nor records anything.
pub(crate) struct Gate {
    resource: CollectionHandle,
    /// The walk's link is peered for R.
    peered: bool,
    /// R's grant policies, read once from its resident descriptor; empty
    /// when that blob is no readable descriptor.
    policies: Option<Vec<AdmissionPolicy>>,
}

/// What a grant walk does with a received proof.
#[derive(Debug)]
pub(crate) enum Gated {
    Land(CapabilityProof),
    Pending(CapabilityProof),
    Skip,
}

impl Gate {
    pub(crate) fn new(resource: CollectionHandle, peered: bool) -> Self {
        Self {
            resource,
            peered,
            policies: None,
        }
    }

    /// Judge one decoded proof against the latest serving observation.
    pub(crate) fn admit(&mut self, snapshot: &StoreSnapshot, proof: CapabilityProof) -> Gated {
        if proof.resource().into_bytes() != self.resource.raw || proof.verify_signatures().is_err() {
            return Gated::Skip;
        }
        let local = snapshot.local();
        let named = proof
            .prefixes()
            .any(|prefix| prefix.subject().to_bytes() == local);
        if !named && !self.peered && !snapshot.grants().participates(self.resource, local) {
            return Gated::Skip;
        }
        let resource = self.resource;
        let Some(policies) = self.policies(snapshot) else {
            return Gated::Pending(proof);
        };
        match validate_proof_for_policies(resource, policies.iter().cloned(), &proof) {
            Ok(()) => Gated::Land(proof),
            Err(_) => Gated::Skip,
        }
    }

    /// R's grant policies, once its descriptor is resident.
    fn policies(&mut self, snapshot: &StoreSnapshot) -> Option<&[AdmissionPolicy]> {
        if self.policies.is_none() {
            let bytes = snapshot.get_blob(&self.resource.raw)?;
            self.policies = Some(descriptor_policies(bytes, self.resource));
        }
        self.policies.as_deref()
    }
}

/// The grant policies of a resident descriptor: none for a blob larger than
/// any descriptor this node fetches, or one that does not read as an
/// archive.
pub(crate) fn descriptor_policies(
    bytes: anybytes::Bytes,
    resource: CollectionHandle,
) -> Vec<AdmissionPolicy> {
    if bytes.len() as u64 > METADATA_BLOB_BYTES {
        return Vec::new();
    }
    Blob::<SimpleArchive>::with_handle(bytes, Inline::new(resource.raw))
        .try_from_blob::<TribleSet>()
        .map(|facts| resource_grant_policies(&facts).collect())
        .unwrap_or_default()
}

/// What a grant walk tells the grant exchange.
#[derive(Debug)]
pub(crate) enum GrantEvent {
    /// A walk with `peer` kept `proof`, but R's descriptor is not resident
    /// here: it waits in memory until it is.
    Pending { peer: PeerId, proof: CapabilityProof },
    /// A grant walk ended, or did not start.
    Ended(GrantWalkEnd),
}

/// How a grant walk with `peer` over R ended, or why it did not start: one
/// for every walk the walks task was asked to open or joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GrantWalkEnd {
    pub(crate) peer: PeerId,
    pub(crate) resource: CollectionHandle,
    pub(crate) outcome: GrantOutcome,
    /// Proofs the walk received here and skipped.
    pub(crate) skipped: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GrantOutcome {
    /// Both sides confirmed. `agreed` is what this side holds of what the
    /// walk carried: never a key it skipped or holds pending.
    Confirmed { agreed: PatchSummary },
    /// It ended any other way: failed, cut or timed out.
    Unconfirmed(Option<crate::exchange::Failure>),
    /// The peer refused it.
    Refused,
    /// Another walk with the peer over R took its place.
    Replaced,
    NotStarted(NotStarted),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NotStarted {
    /// No current connection to the peer.
    NoConnection,
    /// A walk with the peer over R is running.
    AlreadyRunning,
    /// This side would neither send nor receive, or no observation yet, or
    /// the queue of walks waiting for the peer is full.
    StartDeclined,
    /// It waits for one of the peer's running grant walks to end.
    Queued,
}

/// Bounds on the grants waiting in memory for their descriptor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingLimits {
    pub(crate) per_sender: usize,
    pub(crate) total: usize,
    pub(crate) bytes: usize,
}

/// Proofs every sender together keeps waiting, in bytes.
const MAX_PENDING_BYTES: usize = 1 << 20;

impl Default for PendingLimits {
    fn default() -> Self {
        Self {
            per_sender: MAX_PENDING_PER_SENDER,
            total: MAX_PENDING,
            bytes: MAX_PENDING_BYTES,
        }
    }
}

/// Grants a walk kept whose resource descriptor is not resident here
/// (design: land only after validation). They wait in memory, never in the
/// pile, each charged to the sender that delivered it, until R's descriptor
/// arrives: then each lands if it starts at one of R's roots and is dropped
/// otherwise. At most [`PendingLimits`] wait, per sender, in all and in
/// bytes; the oldest go first. A waiting grant neither admits anything nor
/// names a participant, and a sender's leave with its last connection.
#[derive(Default)]
pub(crate) struct Pending {
    limits: PendingLimits,
    /// Arrival sequence | sender | proof id: arrival order.
    proofs: PATCH<72, IdentitySchema, CapabilityProof>,
    bytes: usize,
    next: u64,
}

fn pending_key(seq: u64, sender: PeerId, id: CapabilityProofId) -> [u8; 72] {
    let mut key = [0; 72];
    key[..8].copy_from_slice(&seq.to_be_bytes());
    key[8..40].copy_from_slice(&sender);
    key[40..].copy_from_slice(&id.raw);
    key
}

fn pending_sender(key: &[u8; 72]) -> PeerId {
    key[8..40].try_into().unwrap()
}

impl Pending {
    #[cfg(test)]
    pub(crate) fn new(limits: PendingLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Keep `proof` for `sender`. Returns the (sender, resource) of every
    /// grant evicted to make room, `proof` itself when it can never fit.
    pub(crate) fn insert(
        &mut self,
        sender: PeerId,
        proof: CapabilityProof,
    ) -> Vec<(PeerId, CollectionHandle)> {
        if self.contains(sender, &proof) {
            return Vec::new();
        }
        let size = proof.as_bytes().len();
        let resource = CollectionHandle::new(proof.resource().into_bytes());
        if size > self.limits.bytes || self.limits.per_sender == 0 || self.limits.total == 0 {
            return vec![(sender, resource)];
        }
        let mut evicted = Vec::new();
        while self.kept(sender) >= self.limits.per_sender {
            evicted.extend(self.evict(|key| pending_sender(key) == sender));
        }
        while self.proofs.len() as usize >= self.limits.total
            || self.bytes + size > self.limits.bytes
        {
            evicted.extend(self.evict(|_| true));
        }
        let key = pending_key(self.next, sender, proof.id());
        self.next += 1;
        self.bytes += size;
        self.proofs.insert(&PatchEntry::with_value(&key, proof));
        evicted
    }

    /// Drop the oldest grant `which` selects.
    fn evict(&mut self, which: impl Fn(&[u8; 72]) -> bool) -> Option<(PeerId, CollectionHandle)> {
        let key = *self.proofs.iter_ordered().find(|key| which(key))?;
        Some(self.remove(&key))
    }

    fn remove(&mut self, key: &[u8; 72]) -> (PeerId, CollectionHandle) {
        let proof = self.proofs.get(key).expect("a pending key holds its proof");
        let resource = CollectionHandle::new(proof.resource().into_bytes());
        self.bytes -= proof.as_bytes().len();
        self.proofs.remove(key);
        (pending_sender(key), resource)
    }

    /// Whether `sender`'s `proof` waits.
    pub(crate) fn contains(&self, sender: PeerId, proof: &CapabilityProof) -> bool {
        self.proofs
            .iter()
            .any(|key| pending_sender(key) == sender && key[40..] == proof.id().raw)
    }

    /// How many grants wait for `sender`.
    pub(crate) fn kept(&self, sender: PeerId) -> usize {
        self.proofs
            .iter()
            .filter(|key| pending_sender(key) == sender)
            .count()
    }

    /// How many grants wait, and their bytes.
    #[cfg(test)]
    pub(crate) fn size(&self) -> (usize, usize) {
        (self.proofs.len() as usize, self.bytes)
    }

    /// Drop every grant over `resource`; the senders that delivered them.
    pub(crate) fn give_up(&mut self, resource: CollectionHandle) -> Vec<PeerId> {
        let keys: Vec<[u8; 72]> = self
            .proofs
            .iter()
            .filter(|key| self.proofs.get(key).unwrap().resource().into_bytes() == resource.raw)
            .copied()
            .collect();
        let mut senders: Vec<PeerId> = keys.iter().map(pending_sender).collect();
        for key in keys {
            self.remove(&key);
        }
        senders.sort_unstable();
        senders.dedup();
        senders
    }

    /// Drop every grant `sender` delivered.
    pub(crate) fn forget(&mut self, sender: PeerId) {
        let keys: Vec<[u8; 72]> = self
            .proofs
            .iter()
            .filter(|key| pending_sender(key) == sender)
            .copied()
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }

    /// Every waiting grant with its sender, oldest first.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (PeerId, &CapabilityProof)> + '_ {
        self.proofs
            .iter_ordered()
            .map(|key| (pending_sender(key), self.proofs.get(key).unwrap()))
    }

    /// Settle every grant `judge` decides: `Some(true)` lands it,
    /// `Some(false)` drops it, `None` keeps it waiting. Returns those to
    /// land, each once, with every sender that delivered it.
    pub(crate) fn settle(
        &mut self,
        mut judge: impl FnMut(&CapabilityProof) -> Option<bool>,
    ) -> Vec<(CapabilityProof, Vec<PeerId>)> {
        let mut land: Vec<(CapabilityProof, Vec<PeerId>)> = Vec::new();
        let decided: Vec<([u8; 72], bool)> = self
            .proofs
            .iter_ordered()
            .filter_map(|key| judge(self.proofs.get(key).unwrap()).map(|lands| (*key, lands)))
            .collect();
        for (key, lands) in decided {
            if lands {
                let proof = self.proofs.get(&key).unwrap().clone();
                let sender = pending_sender(&key);
                match land.iter_mut().find(|(landing, _)| landing.id() == proof.id()) {
                    Some((_, senders)) => senders.push(sender),
                    None => land.push((proof, vec![sender])),
                }
            }
            self.remove(&key);
        }
        land
    }
}

/// Whether a waiting grant over R lands: `None` while R's descriptor is not
/// resident in `snapshot`, else whether it starts at one of R's roots.
/// `policies` caches each descriptor's policies for one observation.
fn settles(
    snapshot: &StoreSnapshot,
    policies: &mut HashMap<RawHash, Vec<AdmissionPolicy>>,
    proof: &CapabilityProof,
) -> Option<bool> {
    let resource = CollectionHandle::new(proof.resource().into_bytes());
    if !policies.contains_key(&resource.raw) {
        let bytes = snapshot.get_blob(&resource.raw)?;
        policies.insert(resource.raw, descriptor_policies(bytes, resource));
    }
    let policies = policies[&resource.raw].iter().cloned();
    Some(validate_proof_for_policies(resource, policies, proof).is_ok())
}

/// Whether a resident descriptor describes a collection: an entity tagged as
/// a collection descriptor. None larger than any descriptor this node
/// fetches, or not readable as an archive, does.
fn is_collection_descriptor(bytes: anybytes::Bytes, resource: CollectionHandle) -> bool {
    use triblespace_core::collection::KIND_COLLECTION_DESCRIPTOR;
    use triblespace_core::metadata;
    if bytes.len() as u64 > METADATA_BLOB_BYTES {
        return false;
    }
    Blob::<SimpleArchive>::with_handle(bytes, Inline::new(resource.raw))
        .try_from_blob::<TribleSet>()
        .is_ok_and(|facts| {
            exists!(pattern!(&facts, [{ _?entity @ metadata::tag: KIND_COLLECTION_DESCRIPTOR }]))
        })
}

/// The name a resident descriptor gives its resource, if it reads as one.
fn descriptor_name(bytes: anybytes::Bytes, resource: CollectionHandle) -> Option<RawHash> {
    if bytes.len() as u64 > METADATA_BLOB_BYTES {
        return None;
    }
    let facts = Blob::<SimpleArchive>::with_handle(bytes, Inline::new(resource.raw))
        .try_from_blob::<TribleSet>()
        .ok()?;
    name(&facts).ok().flatten().map(|name| name.raw)
}

fn grant_key(resource: CollectionHandle, id: CapabilityProofId) -> [u8; 64] {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&resource.raw);
    key[32..].copy_from_slice(&id.raw);
    key
}

/// What the grant exchange asks of the host.
#[derive(Debug, Default)]
pub(crate) struct Effects {
    /// Proofs to land in the store.
    pub(crate) land: Vec<CapabilityProof>,
    pub(crate) fetch: Vec<Fetch>,
    /// Grant walks to open, by peer and resource.
    pub(crate) walks: Vec<(PeerId, CollectionHandle)>,
}

/// Metadata blobs to fetch, and the keys to ask, in order: what a grant
/// waiting here needs (its resource's descriptor and name, its definitions),
/// or a definition a refused peering waits for. Only keys this node is
/// connected to are asked.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Fetch {
    pub(crate) blobs: Vec<RawHash>,
    pub(crate) sources: Vec<PeerId>,
}

/// The keys to fetch the definitions `proofs` name from: `presenter`, then
/// each proof's root and delegated keys.
pub(crate) fn sources(presenter: PeerId, proofs: &[CapabilityProof]) -> Vec<PeerId> {
    let mut sources = vec![presenter];
    for proof in proofs {
        for key in std::iter::once(proof.root_key()).chain(proof.delegated_keys()) {
            if !sources.contains(&key.to_bytes()) {
                sources.push(key.to_bytes());
            }
        }
    }
    sources
}

/// One connection's listing state.
struct Listing {
    link: Link,
    /// The summary last listed to the peer, per R.
    sent: PATCH<32, IdentitySchema, PatchSummary>,
    /// The index the last listing was computed from; `None` once something
    /// else the listing depends on changed.
    from: Option<Arc<GrantIndex>>,
    /// The peer's last listed summary, per R: its standing statement of what
    /// it holds of R's grants, for the life of the connection.
    listed: PATCH<32, IdentitySchema, PatchSummary>,
    /// The peer summary a walk over R was last opened for.
    opened: PATCH<32, IdentitySchema, PatchSummary>,
    /// Listed resources this side took no part in when first heard, charged
    /// to the connection's budget before they are kept.
    unknown: PATCH<32, IdentitySchema, ()>,
    /// The resources the connection is peered for.
    peered: PATCH<32, IdentitySchema, (), Blake3Merkle>,
    /// Walks over R to open again after a failure, with their backoff.
    retries: PATCH<32, IdentitySchema, Retry>,
    /// What this side held of R's grants when the last walk over R
    /// confirmed.
    agreed: PATCH<32, IdentitySchema, PatchSummary>,
    /// Grant health counters per R.
    counters: PATCH<32, IdentitySchema, Counters>,
}

/// Grant health counters for one connection and resource.
#[derive(Clone, Copy, Debug, Default)]
struct Counters {
    ends: crate::health::Ends,
    skipped: u64,
    pending: u64,
    retries: u64,
}

/// A backoff for one connection and resource.
#[derive(Clone, Copy, Debug)]
struct Retry {
    /// The wait before the next attempt, doubled by each failure.
    delay: Duration,
    /// When it falls due; none while the attempt it started runs.
    at: Option<Mono>,
    /// This side's root when it was scheduled: a change resets the backoff.
    local: PatchSummary,
}

impl Listing {
    fn new(link: Link) -> Self {
        Self {
            link,
            sent: PATCH::new(),
            from: None,
            listed: PATCH::new(),
            opened: PATCH::new(),
            unknown: PATCH::new(),
            peered: PATCH::new(),
            retries: PATCH::new(),
            agreed: PATCH::new(),
            counters: PATCH::new(),
        }
    }

    /// Change R's counters.
    fn count(&mut self, resource: CollectionHandle, change: impl FnOnce(&mut Counters)) {
        let mut counters = self.counters.get(&resource.raw).copied().unwrap_or_default();
        change(&mut counters);
        self.counters
            .replace(&PatchEntry::with_value(&resource.raw, counters));
    }

    /// Open the walk over R again after a backoff: 1 s after the first
    /// failure, doubling to 60 s.
    fn schedule(&mut self, resource: CollectionHandle, local: PatchSummary, now: Mono) {
        let delay = self
            .retries
            .get(&resource.raw)
            .map_or(MIN_RETRY, |retry| (retry.delay * 2).min(MAX_RETRY));
        let retry = Retry {
            delay,
            at: Some(now + delay),
            local,
        };
        self.retries
            .replace(&PatchEntry::with_value(&resource.raw, retry));
    }

    /// Open a walk over R if the peer's listed root differs from `local`
    /// and no walk was opened for that root yet.
    fn reopen(&mut self, resource: CollectionHandle, local: PatchSummary) -> bool {
        let Some(theirs) = self.listed.get(&resource.raw).copied() else {
            return false;
        };
        if theirs == local || self.opened.get(&resource.raw) == Some(&theirs) {
            return false;
        }
        self.opened
            .replace(&PatchEntry::with_value(&resource.raw, theirs));
        true
    }
}

/// The grant exchange of one node (design: grants gossip by participation):
/// on every connection each side lists, as GRANT_ROOTS, the root and count
/// of its grants over every resource R the other takes part in, sent on
/// opening and whenever one changes. Where the peer's listed root differs
/// from this side's, a grant walk over R opens, once per connection,
/// resource and listed root. Nobody dials on a grant's behalf.
///
/// The peer takes part in R when it is a root of R, a key named on a grant
/// over R the index holds, or peered for R on that connection. A listing
/// for an R this side takes no part in is still heard (a non-syncing
/// grantee learns its grants this way), within
/// [`MAX_UNKNOWN_RESOURCES_PER_LINK`] such resources per connection, charged
/// before anything is kept.
///
/// Grants a walk kept but cannot validate wait in [`Pending`]. A stored
/// grant the index cannot judge yet, because R's descriptor or a definition
/// is not resident, has every missing handle fetched at once, from the
/// connected peers that listed R first, and R's name with them once its
/// descriptor is resident; the same happens for a waiting grant whenever
/// a peer lists its R.
pub(crate) struct Grants {
    local: PeerId,
    snapshot: Option<Arc<StoreSnapshot>>,
    /// By connection id.
    listings: HashMap<u64, Listing>,
    /// Grants walks kept whose descriptor is not resident here.
    waiting: Pending,
    /// Stored grants waiting in the index whose missing handles were asked
    /// for, by proof id.
    asked: PATCH<32, IdentitySchema, ()>,
    /// Grant agreement changed since it was last published.
    changed: bool,
}

impl Grants {
    pub(crate) fn new(local: PeerId) -> Self {
        Self {
            local,
            snapshot: None,
            listings: HashMap::new(),
            waiting: Pending::default(),
            asked: PATCH::new(),
            changed: false,
        }
    }

    /// The grants walks kept that wait for their descriptor.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> &Pending {
        &self.waiting
    }

    /// Publish grant agreement into `health`, if anything changed since the
    /// last call: for every active collection and every resource listed to or
    /// by a connected peer, the root and count of its grants in the index
    /// here and each such peer's standing listing of it, from the peer's
    /// newest connection. Returns whether it did.
    pub(crate) fn publish(&mut self, health: &crate::health::Health) -> bool {
        if !std::mem::take(&mut self.changed) {
            return false;
        }
        let grants = self.health();
        let named_unselected = self.named_unselected();
        health.update(|health| {
            health.grants = grants;
            health.named_unselected = named_unselected;
        });
        true
    }

    /// Collections an indexed grant names this node on that it has not
    /// selected, in handle order.
    fn named_unselected(&self) -> Vec<CollectionHandle> {
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        let index = snapshot.grants();
        index
            .resources()
            .filter(|resource| {
                index.participates(*resource, self.local) && snapshot.selected(*resource).is_none()
            })
            .filter(|resource| {
                index.grants(*resource).is_some_and(|grants| {
                    grants.proofs.iter_ordered().any(|key| {
                        grants
                            .proofs
                            .get(key)
                            .expect("an ordered grant key holds its proof")
                            .prefixes()
                            .any(|prefix| prefix.subject().to_bytes() == self.local)
                    })
                })
            })
            .filter(|resource| {
                snapshot
                    .get_blob(&resource.raw)
                    .is_some_and(|bytes| is_collection_descriptor(bytes, *resource))
            })
            .collect()
    }

    fn health(&self) -> Vec<crate::health::GrantHealth> {
        use crate::health::{GrantHealth, GrantPeerHealth};
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        let index = snapshot.grants();
        // Scratch for this publication only: each peer's newest connection
        // and the resources to report.
        let mut newest: BTreeMap<PeerId, &Listing> = BTreeMap::new();
        for listing in self.listings.values() {
            let peer = listing.link.peer();
            if newest
                .get(&peer)
                .is_none_or(|kept| kept.link.id() < listing.link.id())
            {
                newest.insert(peer, listing);
            }
        }
        let mut resources: BTreeSet<RawHash> = snapshot.active().map(|c| c.raw).collect();
        for listing in newest.values() {
            resources.extend(listing.listed.iter_ordered().copied());
            resources.extend(listing.sent.iter_ordered().copied());
            resources.extend(listing.counters.iter_ordered().copied());
        }
        resources
            .into_iter()
            .map(|raw| {
                let resource = CollectionHandle::new(raw);
                let peers = newest
                    .iter()
                    .filter(|(_, listing)| {
                        listing.listed.get(&raw).is_some()
                            || listing.sent.get(&raw).is_some()
                            || listing.counters.get(&raw).is_some()
                    })
                    .map(|(peer, listing)| {
                        let counters = listing.counters.get(&raw).copied().unwrap_or_default();
                        GrantPeerHealth {
                            peer: *peer,
                            listed: listing.listed.get(&raw).copied(),
                            agreed: listing.agreed.get(&raw).copied(),
                            ends: counters.ends,
                            skipped: counters.skipped,
                            pending: counters.pending,
                            retries: counters.retries,
                        }
                    })
                    .collect();
                GrantHealth {
                    resource,
                    local: index.summary(resource),
                    peers,
                }
            })
            .collect()
    }

    /// Hear one connection event: list on opening, forget on closing, and
    /// hear the peer's GRANT_ROOTS.
    pub(crate) fn event(&mut self, event: &ReconEvent) -> Effects {
        match event {
            ReconEvent::Opened(link) => {
                self.changed = true;
                if !link.closed() {
                    self.listings.insert(link.id(), Listing::new(link.clone()));
                    self.list(link.id());
                }
                Effects::default()
            }
            // Keys are free, so a grant waits in memory only while its
            // sender stays connected.
            ReconEvent::Closed(link) => {
                self.changed = true;
                self.listings.remove(&link.id());
                let sender = link.peer();
                if !self
                    .listings
                    .values()
                    .any(|listing| listing.link.peer() == sender)
                {
                    self.waiting.forget(sender);
                }
                Effects::default()
            }
            ReconEvent::Frame(link, Frame::GrantRoots(roots)) => self.hear(link.id(), roots),
            ReconEvent::Frame(..) => Effects::default(),
        }
    }

    fn summary(&self, resource: CollectionHandle) -> PatchSummary {
        self.snapshot.as_ref().map_or_else(
            || PatchSummary::new(None, 0).expect("the empty summary is canonical"),
            |snapshot| snapshot.grants().summary(resource),
        )
    }

    fn takes_part(&self, resource: CollectionHandle) -> bool {
        self.snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.grants().participates(resource, self.local))
    }

    /// The peer's GRANT_ROOTS: keep each listed root, within the unknown
    /// budget, open a walk where it differs from this side's, and fetch what
    /// grants over a listed R waiting here need from this peer first.
    fn hear(&mut self, id: u64, roots: &[(CollectionHandle, PatchSummary)]) -> Effects {
        let mut effects = Effects::default();
        self.changed = true;
        let mut heard = Vec::new();
        for (resource, theirs) in roots {
            let (resource, theirs) = (*resource, *theirs);
            let local = self.summary(resource);
            let takes_part = self.takes_part(resource);
            let Some(listing) = self.listings.get_mut(&id) else {
                return effects;
            };
            let known = takes_part
                || listing.peered.get(&resource.raw).is_some()
                || listing.listed.get(&resource.raw).is_some();
            if !known {
                if listing.unknown.len() as usize >= MAX_UNKNOWN_RESOURCES_PER_LINK {
                    continue;
                }
                listing.unknown.insert(&PatchEntry::new(&resource.raw));
            }
            if listing.listed.get(&resource.raw) != Some(&theirs) {
                // A root change resets the backoff.
                listing.retries.remove(&resource.raw);
            }
            listing
                .listed
                .replace(&PatchEntry::with_value(&resource.raw, theirs));
            if listing.reopen(resource, local) {
                effects.walks.push((listing.link.peer(), resource));
            }
            heard.push((listing.link.peer(), resource));
        }
        for (peer, resource) in heard {
            effects.fetch.extend(self.needed(resource, &[peer]));
        }
        effects
    }

    /// The connected peers that listed R.
    fn listers(&self, resource: CollectionHandle) -> Vec<PeerId> {
        let mut listers: Vec<PeerId> = self
            .listings
            .values()
            .filter(|listing| listing.listed.get(&resource.raw).is_some())
            .map(|listing| listing.link.peer())
            .collect();
        listers.sort_unstable();
        listers.dedup();
        listers
    }

    /// What every grant over R waiting here needs, asked of `first` and then
    /// of each grant's own keys: the index's missing handles, with R's name
    /// once its descriptor is resident, and a pending grant's descriptor.
    fn needed(&self, resource: CollectionHandle, first: &[PeerId]) -> Vec<Fetch> {
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        let mut fetches = Vec::new();
        for (proof, missing) in snapshot.grants().waiting_grants() {
            if proof.resource().into_bytes() == resource.raw && self.wanted(proof) {
                fetches.extend(self.fetch(proof, missing.iter().copied(), first));
            }
        }
        for (_, proof) in self.waiting.iter() {
            if proof.resource().into_bytes() == resource.raw {
                fetches.extend(self.fetch(proof, [resource.raw], first));
            }
        }
        fetches
    }

    /// Whether this node wants a grant completed: one naming it, or over a
    /// resource it takes part in.
    fn wanted(&self, proof: &CapabilityProof) -> bool {
        proof
            .prefixes()
            .any(|prefix| prefix.subject().to_bytes() == self.local)
            || self.takes_part(CollectionHandle::new(proof.resource().into_bytes()))
    }

    /// Fetch `missing` and whatever else of `proof`'s descriptor and
    /// definitions is not resident, with R's name once the descriptor is, so
    /// R can be presented, from `first`, R's listers and the proof's keys.
    /// R's other definitions wait for its selection, like the rest of its
    /// metadata.
    fn fetch(
        &self,
        proof: &CapabilityProof,
        missing: impl IntoIterator<Item = RawHash>,
        first: &[PeerId],
    ) -> Option<Fetch> {
        let snapshot = self.snapshot.as_ref()?;
        let resource = CollectionHandle::new(proof.resource().into_bytes());
        let resident = |handle: &RawHash| snapshot.get_blob(handle).is_some();
        let mut blobs: Vec<RawHash> = missing
            .into_iter()
            .chain(proof.capabilities().map(|handle| handle.raw))
            .collect();
        if let Some(descriptor) = snapshot.get_blob(&resource.raw) {
            blobs.extend(descriptor_name(descriptor, resource));
        }
        blobs.retain(|handle| !resident(handle));
        blobs.sort_unstable();
        blobs.dedup();
        if blobs.is_empty() {
            return None;
        }
        let mut keys: Vec<PeerId> = first.to_vec();
        keys.extend(self.listers(resource));
        keys.extend(sources(proof.root_key().to_bytes(), std::slice::from_ref(proof)));
        let mut sources = Vec::new();
        for key in keys {
            if key != self.local && !sources.contains(&key) {
                sources.push(key);
            }
        }
        Some(Fetch { blobs, sources })
    }

    /// List to connection `id` the root of every R its peer takes part in
    /// that changed since it was last listed there. Nothing is listed before
    /// the first observation.
    fn list(&mut self, id: u64) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let index = snapshot.grants();
        let Some(listing) = self.listings.get_mut(&id) else {
            return;
        };
        if listing
            .from
            .as_ref()
            .is_some_and(|from| Arc::ptr_eq(from, index))
        {
            return;
        }
        listing.from = Some(index.clone());
        let peer = listing.link.peer();
        let peered = listing
            .peered
            .iter_ordered()
            .map(|raw| CollectionHandle::new(*raw))
            .filter(|resource| index.grants(*resource).is_none());
        let resources = index
            .resources()
            .filter(|resource| {
                index.participates(*resource, peer)
                    || listing.peered.get(&resource.raw).is_some()
            })
            .chain(peered)
            .collect::<Vec<_>>();
        let mut roots = Vec::new();
        for resource in resources {
            let summary = index.summary(resource);
            if listing.sent.get(&resource.raw) != Some(&summary) {
                listing
                    .sent
                    .replace(&PatchEntry::with_value(&resource.raw, summary));
                roots.push((resource, summary));
            }
        }
        for frame in grant_roots_frames(&roots) {
            listing.link.send(frame);
        }
    }

    /// The resources each connection is peered for, by connection id. A
    /// connection newly peered for R lists R and walks R again where the
    /// peer's root still differs: grants it skipped before the peering
    /// existed are offered again.
    pub(crate) fn peered(
        &mut self,
        peered: impl IntoIterator<Item = (u64, CollectionHandle)>,
    ) -> Effects {
        self.changed = true;
        let mut now: HashMap<u64, PATCH<32, IdentitySchema, (), Blake3Merkle>> = HashMap::new();
        for (id, resource) in peered {
            now.entry(id)
                .or_default()
                .insert(&PatchEntry::new(&resource.raw));
        }
        let mut effects = Effects::default();
        let ids: Vec<u64> = self.listings.keys().copied().collect();
        for id in ids {
            let resources = now.remove(&id).unwrap_or_default();
            let fresh: Vec<CollectionHandle> = {
                let listing = &self.listings[&id];
                if resources.merkle_root() == listing.peered.merkle_root() {
                    continue;
                }
                resources
                    .iter_ordered()
                    .filter(|raw| listing.peered.get(raw).is_none())
                    .map(|raw| CollectionHandle::new(*raw))
                    .collect()
            };
            let locals: Vec<PatchSummary> =
                fresh.iter().map(|resource| self.summary(*resource)).collect();
            let listing = self.listings.get_mut(&id).unwrap();
            listing.peered = resources;
            listing.from = None;
            for (resource, local) in fresh.into_iter().zip(locals) {
                listing.opened.remove(&resource.raw);
                if listing.reopen(resource, local) {
                    effects.walks.push((listing.link.peer(), resource));
                }
            }
            self.list(id);
        }
        effects
    }

    /// When the next retry is due, if one is scheduled.
    pub(crate) fn deadline(&self) -> Option<Mono> {
        self.listings
            .values()
            .flat_map(|listing| {
                listing
                    .retries
                    .iter()
                    .filter_map(|key| listing.retries.get(key).unwrap().at)
            })
            .min()
    }

    /// Take the retries due at `now`: walk R again where the peer's listed
    /// root still differs, and fetch again what grants over R waiting here
    /// need, from that peer first.
    pub(crate) fn retry(&mut self, now: Mono) -> Effects {
        let mut effects = Effects::default();
        let ids: Vec<u64> = self.listings.keys().copied().collect();
        for id in ids {
            let due: Vec<CollectionHandle> = {
                let listing = &self.listings[&id];
                listing
                    .retries
                    .iter()
                    .filter(|key| {
                        listing
                            .retries
                            .get(key)
                            .unwrap()
                            .at
                            .is_some_and(|at| at <= now)
                    })
                    .map(|key| CollectionHandle::new(*key))
                    .collect()
            };
            for resource in due {
                let local = self.summary(resource);
                let listing = self.listings.get_mut(&id).unwrap();
                let peer = listing.link.peer();
                if listing.reopen(resource, local) {
                    let mut retry = *listing.retries.get(&resource.raw).unwrap();
                    retry.at = None;
                    listing
                        .retries
                        .replace(&PatchEntry::with_value(&resource.raw, retry));
                    listing.count(resource, |counters| counters.retries += 1);
                    self.changed = true;
                    effects.walks.push((peer, resource));
                } else {
                    listing.retries.remove(&resource.raw);
                }
                effects.fetch.extend(self.needed(resource, &[peer]));
            }
        }
        effects
    }

    /// A fetch of `handle` found it at no source. Pending grants over the
    /// resource it describes are given up, and their senders' walks over it
    /// open again after a backoff; stored grants waiting for it are fetched
    /// again from their listers then.
    pub(crate) fn fetch_failed(&mut self, handle: RawHash, now: Mono) -> Effects {
        let resource = CollectionHandle::new(handle);
        for sender in self.waiting.give_up(resource) {
            self.give_up(sender, resource, now);
        }
        let waiting: Vec<CollectionHandle> = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .grants()
                    .waiting_grants()
                    .filter(|(_, missing)| missing.contains(&handle))
                    .map(|(proof, _)| CollectionHandle::new(proof.resource().into_bytes()))
                    .collect()
            })
            .unwrap_or_default();
        for resource in waiting {
            let local = self.summary(resource);
            for listing in self.listings.values_mut() {
                if listing.listed.get(&resource.raw).is_some() {
                    listing.schedule(resource, local, now);
                }
            }
        }
        Effects::default()
    }

    /// A grant walk ended: a confirmed one resets the backoff; one that
    /// failed, was refused or could not start opens again after it. A
    /// replaced, running or queued one changes nothing.
    fn ended(&mut self, end: GrantWalkEnd, now: Mono) {
        let local = self.summary(end.resource);
        self.changed = true;
        for listing in self.listings.values_mut() {
            if listing.link.peer() != end.peer {
                continue;
            }
            listing.count(end.resource, |counters| {
                counters.skipped += end.skipped;
                match end.outcome {
                    GrantOutcome::Confirmed { .. } => counters.ends.ended(now, true),
                    GrantOutcome::Unconfirmed(_) | GrantOutcome::Refused => {
                        counters.ends.ended(now, false)
                    }
                    GrantOutcome::Replaced | GrantOutcome::NotStarted(_) => {}
                }
            });
            match end.outcome {
                GrantOutcome::Confirmed { agreed } => {
                    listing.retries.remove(&end.resource.raw);
                    listing
                        .agreed
                        .replace(&PatchEntry::with_value(&end.resource.raw, agreed));
                }
                GrantOutcome::Unconfirmed(_)
                | GrantOutcome::Refused
                | GrantOutcome::NotStarted(NotStarted::NoConnection | NotStarted::StartDeclined) => {
                    listing.opened.remove(&end.resource.raw);
                    listing.schedule(end.resource, local, now);
                }
                GrantOutcome::Replaced
                | GrantOutcome::NotStarted(NotStarted::AlreadyRunning | NotStarted::Queued) => {}
            }
        }
    }

    /// A grant `sender` delivered over R was dropped unlanded: the walk
    /// over R opens again after a backoff, whatever its peer lists next.
    fn give_up(&mut self, sender: PeerId, resource: CollectionHandle, now: Mono) {
        let local = self.summary(resource);
        for listing in self.listings.values_mut() {
            if listing.link.peer() == sender {
                listing.opened.remove(&resource.raw);
                listing.schedule(resource, local, now);
            }
        }
    }

    /// Hear what a grant walk reports: a kept grant whose descriptor is not
    /// resident waits in memory, and that descriptor and its definitions
    /// are fetched from the sender first.
    pub(crate) fn walked(&mut self, event: GrantEvent, now: Mono) -> Effects {
        let mut effects = Effects::default();
        match event {
            GrantEvent::Ended(end) => self.ended(end, now),
            GrantEvent::Pending { peer, proof } => {
                // The descriptor may have landed since the walk judged it.
                if let Some(snapshot) = self.snapshot.clone() {
                    match settles(&snapshot, &mut HashMap::new(), &proof) {
                        Some(true) => {
                            effects.land.push(proof);
                            return effects;
                        }
                        Some(false) => return effects,
                        None => {}
                    }
                }
                let resource = proof.resource().into_bytes();
                self.changed = true;
                for listing in self.listings.values_mut() {
                    if listing.link.peer() == peer {
                        listing.count(CollectionHandle::new(resource), |counters| {
                            counters.pending += 1
                        });
                    }
                }
                effects.fetch.extend(self.fetch(&proof, [resource], &[peer]));
                for (sender, resource) in self.waiting.insert(peer, proof) {
                    self.give_up(sender, resource, now);
                }
            }
        }
        effects
    }

    /// Take a new store observation: land the waiting grants whose
    /// descriptor arrived and that start at one of its roots, dropping the
    /// rest of those, fetch what newly waiting stored grants need, and list
    /// changed roots on every connection.
    pub(crate) fn observe(&mut self, snapshot: Arc<StoreSnapshot>) -> Effects {
        let mut effects = Effects::default();
        self.snapshot = Some(snapshot.clone());
        self.changed = true;
        let mut policies = HashMap::new();
        for (proof, senders) in self
            .waiting
            .settle(|proof| settles(&snapshot, &mut policies, proof))
        {
            effects.fetch.extend(self.fetch(&proof, [], &senders));
            effects.land.push(proof);
        }

        let index = snapshot.grants();
        let mut asked = PATCH::<32, IdentitySchema, ()>::new();
        for (proof, missing) in index.waiting_grants() {
            let id = proof.id().raw;
            if self.asked.get(&id).is_some() {
                asked.insert(&PatchEntry::new(&id));
            } else if self.wanted(proof) {
                asked.insert(&PatchEntry::new(&id));
                effects
                    .fetch
                    .extend(self.fetch(proof, missing.iter().copied(), &[]));
            }
        }
        self.asked = asked;

        // A change of this side's root resets the backoff and walks at once
        // where the peer's root still differs.
        let ids: Vec<u64> = self.listings.keys().copied().collect();
        for id in &ids {
            let listing = self.listings.get_mut(id).unwrap();
            let changed: Vec<CollectionHandle> = listing
                .retries
                .iter()
                .filter(|key| {
                    let resource = CollectionHandle::new(**key);
                    listing.retries.get(key).unwrap().local != index.summary(resource)
                })
                .map(|key| CollectionHandle::new(*key))
                .collect();
            for resource in changed {
                listing.retries.remove(&resource.raw);
                if listing.reopen(resource, index.summary(resource)) {
                    effects.walks.push((listing.link.peer(), resource));
                }
            }
        }
        for id in ids {
            self.list(id);
        }
        effects
    }
}

/// Carries out [`Effects`] for the host: lands proofs and fetched blobs
/// through the store's admission channel, fetches each blob once at a time,
/// reports a blob no source had on `failed`, and opens grant walks.
pub(crate) struct Sink<T: Transport, S> {
    connections: ConnectionTable<T, S>,
    admissions: tokio::sync::mpsc::Sender<NetEventBatch>,
    walks: WalksHandle,
    failed: tokio::sync::mpsc::UnboundedSender<RawHash>,
    fetching: Arc<Mutex<HashSet<RawHash>>>,
}

impl<T: Transport, S: Service> Sink<T, S> {
    pub(crate) fn new(
        connections: ConnectionTable<T, S>,
        admissions: tokio::sync::mpsc::Sender<NetEventBatch>,
        walks: WalksHandle,
        failed: tokio::sync::mpsc::UnboundedSender<RawHash>,
    ) -> Self {
        Self {
            connections,
            admissions,
            walks,
            failed,
            fetching: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub(crate) fn apply(&self, effects: Effects) {
        if !effects.land.is_empty() {
            let admissions = self.admissions.clone();
            let proofs = effects.land.into_iter().map(NetEvent::CapabilityProof);
            tokio::spawn(async move { land(&admissions, proofs).await });
        }
        for (peer, resource) in effects.walks {
            self.walks.open(peer, resource, WalkKind::Authorization);
        }
        for fetch in effects.fetch {
            let blobs = {
                let mut fetching = self.fetching.lock().unwrap();
                fetch
                    .blobs
                    .into_iter()
                    .filter(|blob| fetching.insert(*blob))
                    .collect::<Vec<_>>()
            };
            if blobs.is_empty() {
                continue;
            }
            tokio::spawn(fetch_blobs(
                self.connections.clone(),
                self.admissions.clone(),
                self.fetching.clone(),
                self.failed.clone(),
                blobs,
                fetch.sources,
            ));
        }
    }
}

async fn land(
    admissions: &tokio::sync::mpsc::Sender<NetEventBatch>,
    events: impl Iterator<Item = NetEvent>,
) {
    let mut batch = NetEventBatch::default();
    for event in events {
        if let Err(event) = batch.try_push(event) {
            if admissions.send(std::mem::take(&mut batch)).await.is_err() {
                return;
            }
            batch
                .try_push(event)
                .expect("an empty admission batch accepts one event");
        }
    }
    if !batch.is_empty() {
        let _ = admissions.send(batch).await;
    }
}

/// Fetch each blob from the first connected source that has it, and report
/// one no source had. Definitions and descriptors are metadata, bounded
/// alike.
async fn fetch_blobs<T: Transport, S: Service>(
    connections: ConnectionTable<T, S>,
    admissions: tokio::sync::mpsc::Sender<NetEventBatch>,
    fetching: Arc<Mutex<HashSet<RawHash>>>,
    failed: tokio::sync::mpsc::UnboundedSender<RawHash>,
    blobs: Vec<RawHash>,
    sources: Vec<PeerId>,
) {
    let local = connections.transport().local_id();
    for handle in blobs {
        let mut found = false;
        for source in &sources {
            let Some(connection) = connections.current(*source) else {
                continue;
            };
            let fetch = op_get_blob_with_limit(&connection, local, &handle, METADATA_BLOB_BYTES);
            let fetched = tokio::time::timeout(FETCH_DEADLINE, fetch).await;
            if let Ok(Ok(Some(blob))) = fetched {
                land(&admissions, std::iter::once(NetEvent::Blob(blob))).await;
                found = true;
                break;
            }
        }
        fetching.lock().unwrap().remove(&handle);
        if !found {
            let _ = failed.send(handle);
        }
    }
}

#[cfg(test)]
#[path = "grant_listing_tests.rs"]
mod grant_listing_tests;
