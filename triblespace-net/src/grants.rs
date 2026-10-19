//! Grant exchange on `recon/1` (design 2.7).
//!
//! A grant reaches its subject. On every connection, and whenever it changes,
//! each side sends the digest of the proofs it holds naming the other side:
//! the subject-truncated prefixes of its collections' evidence, as
//! [`proof_digest`] counts them. A receiver whose own proofs naming itself,
//! held or received, differ asks for the sender's with a PROOF_REQUEST. The
//! sender answers with the proofs naming the connection's authenticated
//! peer, at most [`MAX_PROOFS_PER_EXCHANGE`] of them, and a receiver takes no
//! more than that from one answer. A receiver asks once per digest and
//! connection, so a proof it drops is asked for again only after the
//! sender's digest changes, and a sender answers once per digest it sent.
//!
//! A received proof, in an answer or as a peer's credential, is kept only if
//! it names this node or its sender. It lands when it is evidence under its
//! collection's held descriptor and is dropped when it is not. A proof naming
//! this node whose descriptor is not held stays in memory if its signatures
//! hold, lists its collection as available, and lands once the descriptor
//! arrives. The descriptor is fetched over `blob/1` from each sender that
//! delivers the proof: a sender holds the collection it granted, so the
//! descriptor comes over the connection that brought the grant, before the
//! collection is selected here and without a lookup. Once it is held, the
//! name it carries is fetched the same way, so the collection can be
//! presented; its other definitions wait for its selection, like the rest
//! of its metadata. The proof waits for every sender that
//! delivered it, and leaves when the last connection of the last of them
//! closes. At most
//! [`MAX_PENDING_PER_SENDER`] of these wait for one sender, and
//! [`MAX_PENDING`] for all; the rest are dropped. A proof counts against each
//! sender it waits for, not only its first: a sender then keeps no more
//! waiting than its share however the others come and go, where charging
//! only the first would let a later one keep any number once the first left.
//! A proof that is evidence under a held descriptor never waits, so these
//! bounds keep none out. The definitions a kept proof names are fetched over
//! `blob/1` from its sender, then from its root and delegated keys among
//! connected peers. A peering refused for want of definitions fetches them
//! the same way.
//!
//! The host also dials the subject of every grant its own key signed, so the
//! exchange delivers it.
//!
//! # The grant index
//!
//! [`GrantIndex`] holds every grant this host stores, over any resource R,
//! keyed R | proof id, with R's participants: R's roots and the keys named on
//! delegation-valid, hardened grants over R. It is the only AUTH tree that is
//! walked, summarised, listed or reported for health. A collection's
//! authorization evidence PATCH is admission input only: unchanged in
//! membership, it is never walked, summarised into a frontier or compared.
//!
//! [`proof_digest`]: crate::collection_activation::CollectionAuthorizationEvidencePatch::proof_digest

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use triblespace_core::blob::Blob;
use triblespace_core::blob::TryFromBlob as _;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::capability::{
    CapabilityProof, CapabilityProofId, capability_action, capability_delegate_action,
};
use triblespace_core::collection::{AdmissionPolicy, CollectionHandle};
use triblespace_core::collection::descriptor::{
    ProofEvidenceError, capability_policies, name, resource_grant_policies,
    validate_proof_for_policies,
};
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::patch::{Blake3Merkle, Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::prelude::{exists, pattern};
use triblespace_core::repo::{BlobStoreGet, BlobStoreList, CapabilityProofRead, StoreChanges};
use triblespace_core::trible::TribleSet;

use crate::channel::{NetEvent, NetEventBatch};
use crate::collection_activation::{
    MAX_PROOFS_PER_EXCHANGE, SubjectProofPatch, subject_prefixes, subject_proof_key,
};
use crate::connection::{ConnectionTable, Link, ReconEvent, Service};
use crate::health::Health;
use crate::host::{ActiveCollections, METADATA_BLOB_BYTES, StoreSnapshot};
use crate::patch_repair::PatchSummary;
use crate::protocol::{RawHash, op_get_blob_with_limit};
use crate::recon::{Frame, proof_frames};
use crate::transport::{PeerId, Transport};

/// Bound on fetching one definition from one key.
const FETCH_DEADLINE: Duration = Duration::from_secs(30);
/// Proofs waiting in memory for their descriptor that one sender keeps,
/// counting each proof against every sender it waits for.
const MAX_PENDING_PER_SENDER: usize = 256;
/// Proofs every sender together keeps waiting in memory.
const MAX_PENDING: usize = 1024;

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

fn grant_key(resource: CollectionHandle, id: CapabilityProofId) -> [u8; 64] {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&resource.raw);
    key[32..].copy_from_slice(&id.raw);
    key
}

/// One connection's exchange.
struct Exchange {
    link: Link,
    /// The digest last sent on this connection.
    sent: Option<PatchSummary>,
    /// The digest last sent when the peer's last request was answered.
    answered: Option<PatchSummary>,
    /// The peer's digest last asked for on this connection.
    fetched: Option<PatchSummary>,
    /// Requests whose answer has not ended.
    outstanding: usize,
    /// Proofs taken from the oldest of them.
    taken: usize,
}

/// What the exchange asks of the host.
#[derive(Debug, Default)]
pub(crate) struct Effects {
    /// Proofs to land in the store.
    pub(crate) land: Vec<CapabilityProof>,
    pub(crate) fetch: Vec<Fetch>,
    /// Keys to dial.
    pub(crate) dial: Vec<PeerId>,
}

/// Metadata blobs to fetch, and the keys to ask, in order: the definitions
/// a proof names and, for a proof waiting for it, its collection's
/// descriptor. Only keys this node is connected to are asked.
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

/// Every proof one node holds or received naming each key, and its exchange
/// on each connection.
pub(crate) struct Grants {
    local: PeerId,
    snapshot: Option<Arc<StoreSnapshot>>,
    /// The active collections' subject indexes, unioned.
    held: SubjectProofPatch,
    /// Received proofs naming this node, under their keys in `held`.
    received: SubjectProofPatch,
    /// This node's own entries: `received` and those of `held`.
    own: SubjectProofPatch,
    /// Received proofs naming this node whose descriptor is not held, by
    /// id, with the keys they wait for: those that delivered them, within
    /// their shares.
    pending: BTreeMap<RawHash, (BTreeSet<PeerId>, CapabilityProof)>,
    /// The capability policies of resident descriptors of collections that
    /// are not active, by handle, decoded once per observation; `None` for
    /// a blob that is no descriptor.
    descriptors: HashMap<RawHash, Option<Vec<AdmissionPolicy>>>,
    exchanges: HashMap<u64, Exchange>,
    /// Grants this key signed whose subject was dialled, by id.
    dialled: HashSet<RawHash>,
    /// `pending` changed since it was last published.
    changed: bool,
}

impl Grants {
    pub(crate) fn new(local: PeerId) -> Self {
        Self {
            local,
            snapshot: None,
            held: SubjectProofPatch::new(),
            received: SubjectProofPatch::new(),
            own: SubjectProofPatch::new(),
            pending: BTreeMap::new(),
            descriptors: HashMap::new(),
            exchanges: HashMap::new(),
            dialled: HashSet::new(),
            changed: false,
        }
    }

    /// Hear one connection event. Frames about a collection are the
    /// peering's, but the credentials they carry are received here too.
    pub(crate) fn event(&mut self, event: &ReconEvent) -> Effects {
        match event {
            ReconEvent::Opened(link) => {
                if !link.closed() {
                    let exchange = Exchange {
                        link: link.clone(),
                        sent: None,
                        answered: None,
                        fetched: None,
                        outstanding: 0,
                        taken: 0,
                    };
                    self.exchanges.insert(link.id(), exchange);
                    self.send_digest(link.id());
                }
                Effects::default()
            }
            // Keys are free, so a proof waits in memory only while one of its
            // senders stays connected; otherwise keys that came and went
            // would hold the bound until a restart.
            ReconEvent::Closed(link) => {
                self.exchanges.remove(&link.id());
                let sender = link.peer();
                if !self
                    .exchanges
                    .values()
                    .any(|exchange| exchange.link.peer() == sender)
                {
                    self.forget(sender);
                }
                Effects::default()
            }
            ReconEvent::Frame(link, frame) => self.frame(link, frame),
        }
    }

    fn frame(&mut self, link: &Link, frame: &Frame) -> Effects {
        let id = link.id();
        if !self.exchanges.contains_key(&id) {
            return Effects::default();
        }
        match frame {
            Frame::PeerRequest { credentials, .. } | Frame::Credential { credentials, .. } => {
                return self.receive(link.peer(), credentials.clone());
            }
            // An empty digest holds nothing to ask for.
            Frame::ProofDigest(digest) => {
                let own = Self::digest(&self.own, self.local);
                let exchange = self.exchanges.get_mut(&id).unwrap();
                if digest.leaf_count() != 0 && *digest != own && exchange.fetched != Some(*digest) {
                    exchange.fetched = Some(*digest);
                    exchange.outstanding += 1;
                    link.send(Frame::ProofRequest);
                }
            }
            // The request names nobody: the answer is for the connection's
            // authenticated peer. A peer that asks again before the digest
            // changes gets nothing more.
            Frame::ProofRequest => {
                let exchange = self.exchanges.get_mut(&id).unwrap();
                if exchange.sent.is_some() && exchange.answered != exchange.sent {
                    exchange.answered = exchange.sent;
                    for frame in proof_frames(&Self::naming(&self.held, link.peer())) {
                        link.send(frame);
                    }
                }
            }
            Frame::Proofs(proofs) => {
                let exchange = self.exchanges.get_mut(&id).unwrap();
                if exchange.outstanding == 0 {
                    return Effects::default();
                }
                let taken = proofs.len().min(MAX_PROOFS_PER_EXCHANGE - exchange.taken);
                exchange.taken += taken;
                return self.receive(link.peer(), proofs[..taken].to_vec());
            }
            Frame::ProofsEnd => {
                let exchange = self.exchanges.get_mut(&id).unwrap();
                if exchange.outstanding > 0 {
                    exchange.outstanding -= 1;
                    exchange.taken = 0;
                }
            }
            _ => {}
        }
        Effects::default()
    }

    /// Keep the proofs naming this node or `sender`: land those that are
    /// evidence under their held descriptor, keep in memory those naming this
    /// node whose descriptor is not held, drop the rest, and fetch the
    /// definitions the kept ones name and the descriptors the waiting ones
    /// wait for.
    fn receive(&mut self, sender: PeerId, proofs: Vec<CapabilityProof>) -> Effects {
        let mut effects = Effects::default();
        for proof in proofs {
            let names = |key: PeerId| {
                proof
                    .prefixes()
                    .any(|prefix| prefix.subject().to_bytes() == key)
            };
            let mine = names(self.local);
            if !mine && !names(sender) {
                continue;
            }
            match self.validate(&proof) {
                Some(false) => continue,
                Some(true) => {
                    if !self.holds(&proof) {
                        effects.land.push(proof.clone());
                    }
                }
                // A proof another sender delivered waits for this one too,
                // within its share.
                None if mine && self.pending.contains_key(&proof.id().raw) => {
                    if self.kept(sender) < MAX_PENDING_PER_SENDER {
                        let (senders, _) = self.pending.get_mut(&proof.id().raw).unwrap();
                        senders.insert(sender);
                    }
                }
                // Only its signatures can be checked before the descriptor.
                None if mine && self.room(sender) && proof.verify_signatures().is_ok() => {
                    let senders = BTreeSet::from([sender]);
                    self.pending
                        .insert(proof.id().raw, (senders, proof.clone()));
                    self.changed = true;
                }
                None => continue,
            }
            if mine {
                for (subject, prefix) in subject_prefixes(&proof) {
                    if subject.to_bytes() == self.local {
                        let entry = PatchEntry::with_value(
                            &subject_proof_key(subject, prefix.id()),
                            prefix,
                        );
                        self.received.insert(&entry);
                        self.own.insert(&entry);
                    }
                }
            }
            let resident = |handle: &RawHash| {
                self.snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.get_blob(handle).is_some())
            };
            let mut blobs = Vec::new();
            let descriptor = proof.resource().into_bytes();
            if self.pending.contains_key(&proof.id().raw) && !resident(&descriptor) {
                blobs.push(descriptor);
            }
            blobs.extend(
                proof
                    .capabilities()
                    .map(|definition| definition.raw)
                    .filter(|definition| !resident(definition))
                    .collect::<BTreeSet<_>>(),
            );
            if !blobs.is_empty() {
                effects.fetch.push(Fetch {
                    blobs,
                    sources: sources(sender, std::slice::from_ref(&proof)),
                });
            }
        }
        effects
    }

    /// Stop keeping proofs waiting in memory for `sender`, and drop those no
    /// other sender keeps, with their entries among this node's own.
    fn forget(&mut self, sender: PeerId) {
        let mut left = self
            .pending
            .extract_if(.., |_, (senders, _)| {
                senders.remove(&sender);
                senders.is_empty()
            })
            .peekable();
        if left.peek().is_none() {
            return;
        }
        for (_, (_, proof)) in left {
            for (subject, prefix) in subject_prefixes(&proof) {
                self.received
                    .remove(&subject_proof_key(subject, prefix.id()));
            }
        }
        self.own_from_received();
        self.changed = true;
    }

    /// This node's own entries: those received and those held.
    fn own_from_received(&mut self) {
        self.own = self.received.clone();
        for key in Self::keys(&self.held, self.local, usize::MAX) {
            let prefix = self.held.get(&key).expect("an index key holds its prefix");
            self.own
                .insert(&PatchEntry::with_value(&key, prefix.clone()));
        }
    }

    /// Proofs waiting in memory for `sender`.
    fn kept(&self, sender: PeerId) -> usize {
        self.pending
            .values()
            .filter(|(senders, _)| senders.contains(&sender))
            .count()
    }

    /// Whether `sender` may keep one more proof waiting in memory.
    fn room(&self, sender: PeerId) -> bool {
        self.pending.len() < MAX_PENDING && self.kept(sender) < MAX_PENDING_PER_SENDER
    }

    /// Whether `proof` is evidence under its collection's descriptor, or
    /// `None` when that descriptor is not held. An active collection uses its
    /// pinned evidence, which also routes subordinate resources. A resident
    /// blob larger than any descriptor this node fetches is not taken for
    /// one.
    fn validate(&mut self, proof: &CapabilityProof) -> Option<bool> {
        let snapshot = self.snapshot.clone()?;
        let collection = CollectionHandle::new(proof.resource().into_bytes());
        if let Some(local) = snapshot.collection(collection) {
            let evidence = local.repair().authorization_evidence();
            return Some(evidence.validate_proof(proof).is_ok());
        }
        if !self.descriptors.contains_key(&collection.raw) {
            let bytes = snapshot.get_blob(&collection.raw)?;
            if bytes.len() as u64 > METADATA_BLOB_BYTES {
                return None;
            }
            let blob = Blob::<SimpleArchive>::with_handle(bytes, Inline::new(collection.raw));
            let policies = TribleSet::try_from_blob(blob).ok().map(|facts| {
                capability_policies(&facts, None)
                    .map(|(_, policy)| policy)
                    .collect()
            });
            self.descriptors.insert(collection.raw, policies);
        }
        let policies = self.descriptors[&collection.raw].as_ref();
        Some(policies.is_some_and(|policies| {
            validate_proof_for_policies(collection, policies.iter().cloned(), proof).is_ok()
        }))
    }

    /// Whether an active collection already holds `proof`.
    fn holds(&self, proof: &CapabilityProof) -> bool {
        let collection = CollectionHandle::new(proof.resource().into_bytes());
        self.snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.collection(collection))
            .is_some_and(|local| {
                local
                    .repair()
                    .authorization_evidence()
                    .get(proof.id())
                    .is_some()
            })
    }

    /// Take a new store observation: land or drop the proofs waiting for a
    /// descriptor that arrived, fetching a landed one's collection name from
    /// the senders that kept it waiting, send each connection's changed
    /// digest, and dial the subjects of grants this key newly signed.
    pub(crate) fn observe(&mut self, snapshot: Arc<StoreSnapshot>) -> Effects {
        let mut held = SubjectProofPatch::new();
        for collection in snapshot.active() {
            if let Some(local) = snapshot.collection(collection) {
                held.union(
                    local
                        .repair()
                        .authorization_evidence()
                        .subject_index()
                        .clone(),
                );
            }
        }
        let grew = held.merkle_root() != self.held.merkle_root();
        self.held = held;
        self.snapshot = Some(snapshot);
        self.descriptors.clear();

        let mut effects = Effects::default();
        let pending = std::mem::take(&mut self.pending);
        for (id, (senders, proof)) in pending {
            match self.validate(&proof) {
                None => {
                    self.pending.insert(id, (senders, proof));
                }
                Some(true) => {
                    let snapshot = self.snapshot.as_ref().expect("validated under a snapshot");
                    let wanted = snapshot
                        .get_blob(&proof.resource().into_bytes())
                        .filter(|bytes| bytes.len() as u64 <= METADATA_BLOB_BYTES)
                        .and_then(|bytes| {
                            Blob::<SimpleArchive>::new(bytes)
                                .try_from_blob::<TribleSet>()
                                .ok()
                        })
                        .and_then(|facts| name(&facts).ok().flatten())
                        .map(|name| name.raw)
                        .filter(|name| snapshot.get_blob(name).is_none());
                    if let Some(name) = wanted {
                        effects.fetch.push(Fetch {
                            blobs: vec![name],
                            sources: senders.into_iter().collect(),
                        });
                    }
                    effects.land.push(proof);
                }
                Some(false) => {
                    for (subject, prefix) in subject_prefixes(&proof) {
                        self.received
                            .remove(&subject_proof_key(subject, prefix.id()));
                    }
                }
            }
            self.changed |= !self.pending.contains_key(&id);
        }
        self.own_from_received();

        let exchanges = self.exchanges.keys().copied().collect::<Vec<_>>();
        for id in exchanges {
            self.send_digest(id);
        }

        if grew {
            for key in self.held.iter_ordered() {
                let prefix = self.held.get(key).expect("an index key holds its prefix");
                let subject = prefix.leaf_key().to_bytes();
                if prefix.leaf_issuer().to_bytes() == self.local
                    && subject != self.local
                    && self.dialled.insert(prefix.id().raw)
                {
                    effects.dial.push(subject);
                }
            }
            effects.dial.sort_unstable();
            effects.dial.dedup();
        }
        effects
    }

    /// Collections named by proofs naming this node that wait for their
    /// descriptor.
    pub(crate) fn available(&self) -> Vec<CollectionHandle> {
        self.pending
            .values()
            .map(|(_, proof)| CollectionHandle::new(proof.resource().into_bytes()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Publish the available collections, if they changed.
    pub(crate) fn publish(&mut self, health: &Health) {
        if std::mem::take(&mut self.changed) {
            let available = self.available();
            health.update(|health| health.available = available);
        }
    }

    /// Send the digest of the proofs naming the connection's peer, if it
    /// changed since the last one sent there. Nothing is sent before the
    /// first observation.
    fn send_digest(&mut self, id: u64) {
        if self.snapshot.is_none() {
            return;
        }
        let Some(exchange) = self.exchanges.get(&id) else {
            return;
        };
        let digest = Self::digest(&self.held, exchange.link.peer());
        let exchange = self.exchanges.get_mut(&id).unwrap();
        if exchange.sent != Some(digest) {
            exchange.sent = Some(digest);
            exchange.link.send(Frame::ProofDigest(digest));
        }
    }

    fn digest(index: &SubjectProofPatch, key: PeerId) -> PatchSummary {
        match index.merkle_node(&key) {
            Some(node) => PatchSummary::new(Some(node.digest()), node.leaf_count())
                .expect("an index node is nonempty"),
            None => PatchSummary::new(None, 0).expect("the empty summary is canonical"),
        }
    }

    /// The keys of at most `limit` entries naming `key`.
    fn keys(index: &SubjectProofPatch, key: PeerId, limit: usize) -> Vec<[u8; 64]> {
        index
            .merkle_node(&key)
            .map_or_else(Vec::new, |node| node.items_after(None, limit).collect())
    }

    /// The proofs naming `key`, at most an exchange's worth.
    fn naming(index: &SubjectProofPatch, key: PeerId) -> Vec<CapabilityProof> {
        Self::keys(index, key, MAX_PROOFS_PER_EXCHANGE)
            .iter()
            .map(|key| {
                index
                    .get(key)
                    .expect("an index key holds its prefix")
                    .clone()
            })
            .collect()
    }
}

/// Carries out [`Effects`] for the host: lands proofs and fetched
/// definitions through the store's admission channel, dials, and fetches
/// each definition once at a time.
pub(crate) struct Sink<T: Transport, S> {
    connections: ConnectionTable<T, S>,
    admissions: tokio::sync::mpsc::Sender<NetEventBatch>,
    fetching: Arc<Mutex<HashSet<RawHash>>>,
}

impl<T: Transport, S: Service> Sink<T, S> {
    pub(crate) fn new(
        connections: ConnectionTable<T, S>,
        admissions: tokio::sync::mpsc::Sender<NetEventBatch>,
    ) -> Self {
        Self {
            connections,
            admissions,
            fetching: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub(crate) fn apply(&self, effects: Effects) {
        if !effects.land.is_empty() {
            let admissions = self.admissions.clone();
            let proofs = effects.land.into_iter().map(NetEvent::CapabilityProof);
            tokio::spawn(async move { land(&admissions, proofs).await });
        }
        for peer in effects.dial {
            let connections = self.connections.clone();
            tokio::spawn(async move {
                let _ = connections.connect(peer).await;
            });
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

/// Fetch each blob from the first connected source that has it. Definitions
/// and descriptors are metadata, bounded alike.
async fn fetch_blobs<T: Transport, S: Service>(
    connections: ConnectionTable<T, S>,
    admissions: tokio::sync::mpsc::Sender<NetEventBatch>,
    fetching: Arc<Mutex<HashSet<RawHash>>>,
    blobs: Vec<RawHash>,
    sources: Vec<PeerId>,
) {
    let local = connections.transport().local_id();
    for handle in blobs {
        for source in &sources {
            let Some(connection) = connections.current(*source) else {
                continue;
            };
            let fetch = op_get_blob_with_limit(&connection, local, &handle, METADATA_BLOB_BYTES);
            let fetched = tokio::time::timeout(FETCH_DEADLINE, fetch).await;
            if let Ok(Ok(Some(blob))) = fetched {
                land(&admissions, std::iter::once(NetEvent::Blob(blob))).await;
                break;
            }
        }
        fetching.lock().unwrap().remove(&handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use tokio::sync::mpsc::Receiver;
    use triblespace_core::capability::{CapabilityHandle, CapabilityResource};
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionPolicy, CollectionStoreExt, read_capability, write_capability,
    };
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{CapabilityProofStore, SnapshotSource, StoreChanges};

    use triblespace_core::blob::encodings::UnknownBlob;
    use triblespace_core::repo::BlobStorePut as _;

    use crate::host::ActiveCollections;
    use crate::recon::{FRAME_PROOF_DIGEST, FRAME_PROOF_REQUEST, FRAME_PROOFS, FRAME_PROOFS_END};

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn grant(
        issuer: &SigningKey,
        subject: &SigningKey,
        action: CapabilityHandle,
        collection: CollectionHandle,
    ) -> CapabilityProof {
        CapabilityProof::new(
            CapabilityResource::from(collection),
            issuer,
            action,
            subject.verifying_key(),
        )
    }

    fn policy(owner: &SigningKey) -> CollectionPolicy {
        CollectionPolicy::new(
            AdmissionPolicy::direct(owner.verifying_key()),
            AdmissionPolicy::direct(owner.verifying_key()),
        )
    }

    fn ids(proofs: &[CapabilityProof]) -> BTreeSet<RawHash> {
        proofs.iter().map(|proof| proof.id().raw).collect()
    }

    /// One node's pile and grant exchange.
    struct Node {
        key: SigningKey,
        store: MemoryRepo,
        active: ActiveCollections,
        grants: Grants,
    }

    impl Node {
        fn new(byte: u8) -> Self {
            let key = key(byte);
            Self {
                grants: Grants::new(key.verifying_key().to_bytes()),
                key,
                store: MemoryRepo::default(),
                active: ActiveCollections::new(),
            }
        }

        fn id(&self) -> PeerId {
            self.key.verifying_key().to_bytes()
        }

        /// Hold and activate the collection `policy` names.
        fn hold(&mut self, policy: CollectionPolicy) -> CollectionHandle {
            let collection = self.store.collection("grants", policy).unwrap().handle();
            self.active.insert(&PatchEntry::new(&collection.raw));
            collection
        }

        fn learn(&mut self, proof: CapabilityProof) -> Effects {
            self.store.insert_proof(proof).unwrap();
            self.observe()
        }

        fn snapshot(&mut self) -> Arc<StoreSnapshot> {
            Arc::new(
                StoreSnapshot::from_store_changes(
                    self.store.snapshot().unwrap(),
                    &self.active,
                    self.key.verifying_key(),
                    None,
                    None,
                    StoreChanges::ALL,
                )
                .unwrap(),
            )
        }

        fn observe(&mut self) -> Effects {
            let snapshot = self.snapshot();
            self.grants.observe(snapshot)
        }
    }

    /// A connection between two nodes: each side's link and the frames
    /// queued on it.
    struct Wire {
        to_right: Link,
        from_left: Receiver<Frame>,
        to_left: Link,
        from_right: Receiver<Frame>,
    }

    fn connect(left: &mut Node, right: &mut Node, id: u64) -> Wire {
        let (to_right, from_left) = Link::detached(id, right.id());
        let (to_left, from_right) = Link::detached(id, left.id());
        left.grants.event(&ReconEvent::Opened(to_right.clone()));
        right.grants.event(&ReconEvent::Opened(to_left.clone()));
        Wire {
            to_right,
            from_left,
            to_left,
            from_right,
        }
    }

    /// Carry frames both ways until neither side sends. Returns the frames
    /// in delivery order, marked with the sending side, and the effects
    /// each side asked for.
    fn carry(
        left: &mut Node,
        right: &mut Node,
        wire: &mut Wire,
    ) -> (Vec<(&'static str, Frame)>, Effects, Effects) {
        let mut carried = Vec::new();
        let (mut on_left, mut on_right) = (Effects::default(), Effects::default());
        loop {
            let (frame, side, node, link, effects) = if let Ok(frame) = wire.from_left.try_recv() {
                (frame, "left", &mut *right, &wire.to_left, &mut on_right)
            } else if let Ok(frame) = wire.from_right.try_recv() {
                (frame, "right", &mut *left, &wire.to_right, &mut on_left)
            } else {
                return (carried, on_left, on_right);
            };
            carried.push((side, frame.clone()));
            let more = node.grants.event(&ReconEvent::Frame(link.clone(), frame));
            effects.land.extend(more.land);
            effects.fetch.extend(more.fetch);
            effects.dial.extend(more.dial);
        }
    }

    fn kinds(carried: &[(&'static str, Frame)]) -> Vec<(&'static str, u8)> {
        carried
            .iter()
            .map(|(side, frame)| (*side, frame.encode().0))
            .collect()
    }

    fn answered(carried: &[(&'static str, Frame)]) -> Vec<CapabilityProof> {
        carried
            .iter()
            .flat_map(|(_, frame)| match frame {
                Frame::Proofs(proofs) => proofs.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    /// The owner holds three grants. A reader asks once for the two naming
    /// it, and another key gets only the one naming that key. Once landed,
    /// the reader's own digest matches, and a new connection asks nothing.
    #[test]
    fn a_digest_exchange_discloses_only_proofs_naming_the_receiver() {
        let mut owner = Node::new(1);
        let mut reader = Node::new(2);
        let mut other = Node::new(3);
        let collection = owner.hold(policy(&owner.key));
        for node in [&mut reader, &mut other] {
            assert_eq!(node.hold(policy(&owner.key)), collection);
            node.observe();
        }
        let read = grant(&owner.key, &reader.key, read_capability(), collection);
        let write = grant(&owner.key, &reader.key, write_capability(), collection);
        let elsewhere = grant(&owner.key, &other.key, read_capability(), collection);
        for proof in [&read, &write, &elsewhere] {
            owner.store.insert_proof(proof.clone()).unwrap();
        }
        owner.observe();

        let mut wire = connect(&mut owner, &mut reader, 1);
        let (carried, _, received) = carry(&mut owner, &mut reader, &mut wire);
        assert_eq!(
            kinds(&carried),
            [
                ("left", FRAME_PROOF_DIGEST),
                ("right", FRAME_PROOF_DIGEST),
                ("right", FRAME_PROOF_REQUEST),
                ("left", FRAME_PROOFS),
                ("left", FRAME_PROOFS_END),
            ]
        );
        let expected = ids(&[read.clone(), write.clone()]);
        assert_eq!(ids(&answered(&carried)), expected);
        assert_eq!(ids(&received.land), expected);
        // Both definitions came with the descriptor.
        assert!(received.fetch.is_empty());

        let mut wire = connect(&mut owner, &mut other, 2);
        let (carried, _, received) = carry(&mut owner, &mut other, &mut wire);
        assert_eq!(answered(&carried), [elsewhere.clone()]);
        assert_eq!(received.land, [elsewhere]);

        for proof in received_proofs(&expected, [&read, &write]) {
            reader.store.insert_proof(proof).unwrap();
        }
        reader.observe();
        let mut wire = connect(&mut owner, &mut reader, 3);
        let (carried, _, _) = carry(&mut owner, &mut reader, &mut wire);
        assert_eq!(
            kinds(&carried),
            [("left", FRAME_PROOF_DIGEST), ("right", FRAME_PROOF_DIGEST)]
        );
    }

    fn received_proofs<'a>(
        ids: &BTreeSet<RawHash>,
        proofs: impl IntoIterator<Item = &'a CapabilityProof>,
    ) -> Vec<CapabilityProof> {
        proofs
            .into_iter()
            .filter(|proof| ids.contains(&proof.id().raw))
            .cloned()
            .collect()
    }

    /// A proof the receiver drops leaves the digests unequal, and the same
    /// digest is not asked for again on the connection; a changed one is.
    /// An empty digest and an unasked answer are ignored.
    #[test]
    fn a_dropped_proof_is_not_asked_for_again_until_the_digest_changes() {
        let owner = key(10);
        let mut reader = Node::new(11);
        let sender = key(12);
        let collection = reader.hold(policy(&owner));
        reader.observe();
        let (link, mut sent) = Link::detached(1, sender.verifying_key().to_bytes());
        reader.grants.event(&ReconEvent::Opened(link.clone()));
        assert!(matches!(sent.try_recv(), Ok(Frame::ProofDigest(_))));
        let mut hear = |reader: &mut Node, frame: Frame| {
            let effects = reader.grants.event(&ReconEvent::Frame(link.clone(), frame));
            let sent = std::iter::from_fn(|| sent.try_recv().ok()).collect::<Vec<_>>();
            (effects, sent)
        };

        let (_, asked) = hear(
            &mut reader,
            Frame::ProofDigest(PatchSummary::new(None, 0).unwrap()),
        );
        assert!(asked.is_empty());
        let digest = PatchSummary::new(Some([1; 32]), 1).unwrap();
        let (_, asked) = hear(&mut reader, Frame::ProofDigest(digest));
        assert_eq!(asked, [Frame::ProofRequest]);
        // Signed by a key that is not the collection's root.
        let forged = grant(&sender, &reader.key, read_capability(), collection);
        let (effects, _) = hear(&mut reader, Frame::Proofs(vec![forged.clone()]));
        assert!(effects.land.is_empty() && effects.fetch.is_empty());
        hear(&mut reader, Frame::ProofsEnd);
        assert!(reader.grants.available().is_empty());

        let (_, asked) = hear(&mut reader, Frame::ProofDigest(digest));
        assert!(asked.is_empty(), "the same digest is asked for once");
        let valid = grant(&owner, &reader.key, read_capability(), collection);
        let (effects, _) = hear(&mut reader, Frame::Proofs(vec![valid.clone()]));
        assert!(effects.land.is_empty(), "an answer nobody asked for");

        let changed = PatchSummary::new(Some([2; 32]), 2).unwrap();
        let (_, asked) = hear(&mut reader, Frame::ProofDigest(changed));
        assert_eq!(asked, [Frame::ProofRequest]);
        let (effects, _) = hear(&mut reader, Frame::Proofs(vec![forged, valid.clone()]));
        assert_eq!(effects.land, [valid]);
    }

    /// A peer that asks again before the digest it was sent changes queues
    /// no second answer here; a changed digest is answered again.
    #[test]
    fn a_proof_request_is_answered_once_per_digest_sent() {
        let mut owner = Node::new(13);
        let reader = key(14);
        let collection = owner.hold(policy(&owner.key));
        owner.learn(grant(&owner.key, &reader, read_capability(), collection));
        let (link, mut sent) = Link::detached(1, reader.verifying_key().to_bytes());
        owner.grants.event(&ReconEvent::Opened(link.clone()));
        let mut ask = |owner: &mut Node| {
            owner
                .grants
                .event(&ReconEvent::Frame(link.clone(), Frame::ProofRequest));
            std::iter::from_fn(|| sent.try_recv().ok())
                .map(|frame| frame.encode().0)
                .collect::<Vec<_>>()
        };
        let answer = [FRAME_PROOFS, FRAME_PROOFS_END];
        assert_eq!(
            ask(&mut owner),
            [&[FRAME_PROOF_DIGEST][..], &answer].concat()
        );
        for _ in 0..3 {
            assert!(ask(&mut owner).is_empty());
        }
        owner.learn(grant(&owner.key, &reader, write_capability(), collection));
        assert_eq!(
            ask(&mut owner),
            [&[FRAME_PROOF_DIGEST][..], &answer].concat()
        );
    }

    /// Without its descriptor, a proof naming this node waits in memory: it
    /// lists its collection as available, counts in this node's digest and
    /// fetches its descriptor and definition from the sender. It lands once
    /// the descriptor is held.
    #[test]
    fn a_proof_without_its_descriptor_waits_in_memory_until_the_descriptor_arrives() {
        let mut owner = Node::new(20);
        let mut subject = Node::new(21);
        let collection = owner.hold(policy(&owner.key));
        let read = grant(&owner.key, &subject.key, read_capability(), collection);
        owner.learn(read.clone());
        subject.observe();

        let mut wire = connect(&mut owner, &mut subject, 1);
        let (carried, _, received) = carry(&mut owner, &mut subject, &mut wire);
        assert_eq!(answered(&carried), [read.clone()]);
        assert!(received.land.is_empty());
        assert_eq!(
            received.fetch,
            [Fetch {
                blobs: vec![collection.raw, read_capability().raw],
                sources: vec![owner.id(), subject.id()],
            }]
        );
        assert_eq!(subject.grants.available(), [collection]);
        let mut wire = connect(&mut owner, &mut subject, 2);
        let (carried, _, _) = carry(&mut owner, &mut subject, &mut wire);
        assert_eq!(
            kinds(&carried),
            [("left", FRAME_PROOF_DIGEST), ("right", FRAME_PROOF_DIGEST)],
            "the proof in memory counts in the subject's digest"
        );

        assert_eq!(subject.hold(policy(&owner.key)), collection);
        let effects = subject.observe();
        assert_eq!(effects.land, [read]);
        assert!(subject.grants.available().is_empty());
    }

    /// A proof naming this node over a collection it does not hold asks its
    /// sender for the collection's descriptor: the sender holds the
    /// collection it granted, so nothing need be selected or looked up. Once
    /// the descriptor is resident the proof lands, though the collection is
    /// still not active here.
    #[test]
    fn a_proof_without_its_descriptor_fetches_the_descriptor_from_its_sender() {
        let mut owner = Node::new(40);
        let mut subject = Node::new(41);
        let collection = owner.hold(policy(&owner.key));
        let read = grant(&owner.key, &subject.key, read_capability(), collection);
        owner.learn(read.clone());
        subject.observe();

        let mut wire = connect(&mut owner, &mut subject, 1);
        let (_, _, received) = carry(&mut owner, &mut subject, &mut wire);
        assert!(received.land.is_empty());
        assert_eq!(
            received.fetch,
            [Fetch {
                blobs: vec![collection.raw, read_capability().raw],
                sources: vec![owner.id(), subject.id()],
            }],
            "the descriptor is asked for first, from the sender first"
        );
        assert_eq!(subject.grants.available(), [collection]);

        // The sink fetches the descriptor over `blob/1` from the owner, who
        // holds it, and lands it through admission.
        let descriptor = owner
            .snapshot()
            .get_blob(&collection.raw)
            .expect("the owner holds the descriptor of the collection it granted");
        subject
            .store
            .put::<UnknownBlob, _>(Blob::<UnknownBlob>::new(descriptor.clone()))
            .unwrap();
        let effects = subject.observe();
        assert_eq!(effects.land, [read]);
        assert!(subject.grants.available().is_empty());
        assert!(
            subject.active.get(&collection.raw).is_none(),
            "the descriptor landed without the collection being active"
        );
        // The collection's name comes from the same sender, so it can be
        // presented by name; its other definitions wait for its selection.
        let facts = Blob::<SimpleArchive>::new(descriptor)
            .try_from_blob::<TribleSet>()
            .unwrap();
        let name = name(&facts).unwrap().expect("a named collection");
        assert_eq!(
            effects.fetch,
            [Fetch {
                blobs: vec![name.raw],
                sources: vec![owner.id()],
            }]
        );
    }

    /// A proof whose descriptor is not held waits in memory only if its
    /// signatures hold; a forged one lists nothing as available.
    #[test]
    fn a_forged_proof_does_not_wait_in_memory() {
        let owner = key(34);
        let mut node = Node::new(35);
        node.observe();
        let collection = CollectionHandle::new([36; 32]);
        let mut bytes = grant(&owner, &node.key, read_capability(), collection).into_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        let forged = CapabilityProof::from_bytes(&bytes).unwrap();
        let (link, _sent) = Link::detached(1, owner.verifying_key().to_bytes());
        node.grants.event(&ReconEvent::Opened(link.clone()));
        let digest = PatchSummary::new(Some([1; 32]), 1).unwrap();
        node.grants
            .event(&ReconEvent::Frame(link.clone(), Frame::ProofDigest(digest)));
        let effects = node
            .grants
            .event(&ReconEvent::Frame(link, Frame::Proofs(vec![forged])));
        assert!(effects.land.is_empty() && effects.fetch.is_empty());
        assert!(node.grants.available().is_empty());
    }

    /// Keys that sign proofs naming this node over resources nobody holds
    /// keep at most their share each, and the total over all, in memory. A
    /// proof that is evidence under a held descriptor still lands from a key
    /// whose share is full.
    #[test]
    fn proofs_waiting_in_memory_are_bounded_per_sender_and_in_all() {
        let owner = key(60);
        let mut node = Node::new(61);
        let collection = node.hold(policy(&owner));
        node.observe();
        let subject = node.key.clone();
        let credentials = |node: &mut Node, sender: &SigningKey| {
            let (link, _sent) = Link::detached(1, sender.verifying_key().to_bytes());
            node.grants.event(&ReconEvent::Opened(link.clone()));
            let credentials = (0..=MAX_PENDING_PER_SENDER)
                .map(|index| {
                    let mut resource = sender.verifying_key().to_bytes();
                    resource[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    let resource = CollectionHandle::new(resource);
                    grant(sender, &subject, read_capability(), resource)
                })
                .collect();
            let frame = Frame::Credential {
                collection,
                credentials,
            };
            node.grants.event(&ReconEvent::Frame(link, frame))
        };
        let senders = (0..=MAX_PENDING / MAX_PENDING_PER_SENDER)
            .map(|index| key(62 + index as u8))
            .collect::<Vec<_>>();
        credentials(&mut node, &senders[0]);
        assert_eq!(node.grants.available().len(), MAX_PENDING_PER_SENDER);
        for sender in &senders[1..] {
            credentials(&mut node, sender);
        }
        assert_eq!(node.grants.available().len(), MAX_PENDING);
        let own = Grants::digest(&node.grants.own, node.id()).leaf_count();
        assert_eq!(own, MAX_PENDING as u64);

        let (link, _sent) = Link::detached(2, senders[0].verifying_key().to_bytes());
        node.grants.event(&ReconEvent::Opened(link.clone()));
        let valid = grant(&owner, &node.key, read_capability(), collection);
        let effects = node.grants.event(&ReconEvent::Frame(
            link,
            Frame::Credential {
                collection,
                credentials: vec![valid.clone()],
            },
        ));
        assert_eq!(effects.land, [valid]);
    }

    /// Proofs waiting in memory leave with their sender's last connection,
    /// so keys that came and went do not hold the bound, and a later grant
    /// still waits for its descriptor.
    #[test]
    fn proofs_waiting_in_memory_leave_with_their_sender() {
        let owner = key(70);
        let mut node = Node::new(71);
        let collection = node.hold(policy(&owner));
        node.observe();
        let subject = node.key.clone();
        let mut ids = 0;
        let mut send = |node: &mut Node, sender: &SigningKey, count: usize| {
            ids += 1;
            let (link, _sent) = Link::detached(ids, sender.verifying_key().to_bytes());
            node.grants.event(&ReconEvent::Opened(link.clone()));
            let credentials = (0..count)
                .map(|index| {
                    let mut resource = sender.verifying_key().to_bytes();
                    resource[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    let resource = CollectionHandle::new(resource);
                    grant(sender, &subject, read_capability(), resource)
                })
                .collect();
            let frame = Frame::Credential {
                collection,
                credentials,
            };
            node.grants.event(&ReconEvent::Frame(link.clone(), frame));
            link
        };
        let own = |node: &Node| Grants::digest(&node.grants.own, node.id()).leaf_count();
        let senders = (0..MAX_PENDING / MAX_PENDING_PER_SENDER)
            .map(|index| key(72 + index as u8))
            .collect::<Vec<_>>();
        let mut links = senders
            .iter()
            .map(|sender| send(&mut node, sender, MAX_PENDING_PER_SENDER))
            .collect::<Vec<_>>();
        assert_eq!(node.grants.pending.len(), MAX_PENDING);

        // A sender's second connection keeps its proofs when the first
        // closes; its last one takes them.
        let second = send(&mut node, &senders[0], 0);
        node.grants.event(&ReconEvent::Closed(links.remove(0)));
        assert_eq!(node.grants.pending.len(), MAX_PENDING);
        node.grants.event(&ReconEvent::Closed(second));
        assert_eq!(
            node.grants.pending.len(),
            MAX_PENDING - MAX_PENDING_PER_SENDER
        );
        for link in links {
            node.grants.event(&ReconEvent::Closed(link));
        }
        assert!(node.grants.pending.is_empty());
        assert!(node.grants.available().is_empty());
        assert_eq!(own(&node), 0);

        let later = key(80);
        send(&mut node, &later, 1);
        assert_eq!(node.grants.pending.len(), 1);
        assert_eq!(own(&node), 1);
    }

    /// A waiting proof waits for every sender that delivered it: when the
    /// first disconnects it stays for the second, and it leaves with the
    /// second.
    #[test]
    fn a_waiting_proof_stays_while_any_sender_is_connected() {
        let owner = key(90);
        let mut node = Node::new(91);
        let collection = node.hold(policy(&owner));
        node.observe();
        // A grant for a collection whose descriptor this node does not hold.
        let elsewhere = CollectionHandle::new([92; 32]);
        let proof = grant(&owner, &node.key, read_capability(), elsewhere);
        let [first, second] = [93, 94].map(|byte| {
            let sender = key(byte).verifying_key().to_bytes();
            let (link, _sent) = Link::detached(u64::from(byte), sender);
            node.grants.event(&ReconEvent::Opened(link.clone()));
            let credentials = vec![proof.clone()];
            let frame = Frame::Credential {
                collection,
                credentials,
            };
            node.grants.event(&ReconEvent::Frame(link.clone(), frame));
            link
        });
        assert_eq!(node.grants.available(), [elsewhere]);
        node.grants.event(&ReconEvent::Closed(first));
        assert_eq!(node.grants.available(), [elsewhere]);
        node.grants.event(&ReconEvent::Closed(second));
        assert!(node.grants.available().is_empty());
    }

    /// A waiting proof counts against each sender it waits for: a sender
    /// that delivered another's proofs has filled its own share with them,
    /// and keeps them when the other leaves.
    #[test]
    fn a_waiting_proof_counts_against_each_sender() {
        let owner = key(95);
        let mut node = Node::new(96);
        let collection = node.hold(policy(&owner));
        node.observe();
        let subject = node.key.clone();
        let proofs = (0..=MAX_PENDING_PER_SENDER)
            .map(|index| {
                let mut resource = [97; 32];
                resource[..8].copy_from_slice(&(index as u64).to_be_bytes());
                grant(
                    &owner,
                    &subject,
                    read_capability(),
                    CollectionHandle::new(resource),
                )
            })
            .collect::<Vec<_>>();
        let (shared, own) = proofs.split_at(MAX_PENDING_PER_SENDER);
        let mut deliver = |byte: u8, credentials: &[CapabilityProof]| {
            let sender = key(byte).verifying_key().to_bytes();
            let (link, _sent) = Link::detached(u64::from(byte), sender);
            node.grants.event(&ReconEvent::Opened(link.clone()));
            let frame = Frame::Credential {
                collection,
                credentials: credentials.to_vec(),
            };
            node.grants.event(&ReconEvent::Frame(link.clone(), frame));
            link
        };
        let first = deliver(98, shared);
        let second = deliver(99, shared);
        drop(deliver(99, own));
        assert_eq!(node.grants.pending.len(), MAX_PENDING_PER_SENDER);
        node.grants.event(&ReconEvent::Closed(first));
        assert_eq!(node.grants.pending.len(), MAX_PENDING_PER_SENDER);
        node.grants.event(&ReconEvent::Closed(second));
        assert!(node.grants.pending.is_empty());
    }

    /// A received proof is kept only if it names this node or its sender.
    #[test]
    fn received_proofs_must_name_this_node_or_the_sender() {
        let owner = key(30);
        let mut node = Node::new(31);
        let sender = key(32);
        let stranger = key(33);
        let collection = node.hold(policy(&owner));
        node.observe();
        let (link, _sent) = Link::detached(1, sender.verifying_key().to_bytes());
        node.grants.event(&ReconEvent::Opened(link.clone()));
        let senders = grant(&owner, &sender, read_capability(), collection);
        let mine = grant(&owner, &node.key, read_capability(), collection);
        let strangers = grant(&owner, &stranger, read_capability(), collection);
        let effects = node.grants.event(&ReconEvent::Frame(
            link,
            Frame::Credential {
                collection,
                credentials: vec![senders.clone(), strangers, mine.clone()],
            },
        ));
        assert_eq!(ids(&effects.land), ids(&[senders, mine]));
    }

    /// A resident archive of `count` tribles in `node`'s pile, and how long
    /// one decode of it takes.
    fn archive(node: &mut Node, count: u64) -> (CollectionHandle, Duration) {
        use triblespace_core::blob::IntoBlob as _;
        use triblespace_core::repo::BlobStorePut as _;
        use triblespace_core::trible::Trible;
        let mut archive = TribleSet::new();
        for index in 0..count {
            let mut raw = [1_u8; 64];
            raw[..8].copy_from_slice(&index.to_be_bytes());
            archive.insert(&Trible::force_raw(raw).unwrap());
        }
        let blob: Blob<SimpleArchive> = archive.to_blob();
        let handle = CollectionHandle::new(blob.get_handle().raw);
        node.store.put::<SimpleArchive, _>(blob.clone()).unwrap();
        node.observe();
        let started = std::time::Instant::now();
        TribleSet::try_from_blob(blob).unwrap();
        (handle, started.elapsed())
    }

    /// How long `node` takes over one CREDENTIAL frame of 32 proofs a
    /// stranger signed for itself over `resource`.
    fn credentials_over(node: &mut Node, resource: CollectionHandle) -> Duration {
        let stranger = key(59);
        let (link, _sent) = Link::detached(1, stranger.verifying_key().to_bytes());
        node.grants.event(&ReconEvent::Opened(link.clone()));
        let credentials = (0..32)
            .map(|_| grant(&stranger, &stranger, read_capability(), resource))
            .collect();
        let frame = Frame::Credential {
            collection: CollectionHandle::new([0xEE; 32]),
            credentials,
        };
        let started = std::time::Instant::now();
        node.grants.event(&ReconEvent::Frame(link, frame));
        started.elapsed()
    }

    /// Credentials over a resident blob larger than any descriptor make this
    /// node decode none of it.
    #[test]
    fn a_stranger_cannot_make_this_node_decode_a_large_blob() {
        let mut node = Node::new(52);
        let (large, one_decode) = archive(&mut node, 1 << 15);
        let frame = credentials_over(&mut node, large);
        assert!(
            frame < one_decode,
            "32 credentials took {frame:?}; one decode of the 2 MiB archive takes {one_decode:?}"
        );
    }

    /// Credentials over a resident archive within the descriptor bound make
    /// this node decode it once, not once per proof.
    #[test]
    fn a_stranger_cannot_make_this_node_decode_a_blob_per_proof() {
        let mut node = Node::new(53);
        let (resident, one_decode) = archive(&mut node, 1 << 12);
        let frame = credentials_over(&mut node, resident);
        assert!(
            frame < 4 * one_decode,
            "32 credentials took {frame:?}; one decode of the 256 KiB archive takes {one_decode:?}"
        );
    }

    /// The host dials the subject of each grant its key signed, once, and
    /// leaves grants others signed to their signers.
    #[test]
    fn a_grant_this_key_signed_dials_its_subject_once() {
        let mut owner = Node::new(40);
        let mut delegate = Node::new(41);
        let onward = key(42);
        let collection = owner.hold(policy(&owner.key));
        assert_eq!(delegate.hold(policy(&owner.key)), collection);
        assert!(owner.observe().dial.is_empty());

        let read = grant(&owner.key, &delegate.key, read_capability(), collection);
        assert_eq!(owner.learn(read.clone()).dial, [delegate.id()]);
        assert!(owner.observe().dial.is_empty());
        assert!(
            owner
                .learn(grant(
                    &owner.key,
                    &owner.key,
                    write_capability(),
                    collection
                ))
                .dial
                .is_empty()
        );

        let chain = read
            .delegate(&delegate.key, read_capability(), onward.verifying_key())
            .unwrap();
        assert!(owner.learn(chain.clone()).dial.is_empty());
        assert_eq!(
            delegate.learn(chain).dial,
            [onward.verifying_key().to_bytes()]
        );
    }
}
