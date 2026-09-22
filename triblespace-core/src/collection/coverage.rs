//! Downward coverage: which foundation commits a lattice node stands for.
//!
//! A COMMIT, MERGE, or DERIVE is an attestation about the relationship between
//! payloads, not an object worth reifying. What every consumer actually asks is
//! the *denotational* question — given this node of the lattice, which
//! foundation commits does it cover? — and that answer is a set, not a walk.
//!
//! This module folds records into exactly that answer. Each admitted record
//! contributes one monotone union:
//!
//! - `COMMIT(_, data)` — `coverage(data) ∪= {data}`; a commit is its own
//!   foundation.
//! - `MERGE(_, low, high, result)` — `coverage(result) ∪= coverage(low) ∪
//!   coverage(high)`; a merge is compaction inside the lattice.
//! - `DERIVE(_, input, output)` — `coverage(output) ∪= coverage(input)`; a
//!   derive is projection across lattices, and it carries the support through
//!   unchanged because the derived image denotes the same logical value.
//!
//! The representation is a doubly nested PATCH: the outer trie maps a result
//! payload handle to an inner trie of foundation commit handles. Nesting, not a
//! flat `result ‖ commit` key, is what preserves structural sharing — two nodes
//! covering the same commits share one inner root, and set operations between
//! nodes are then PATCH union and intersection over shared subtries rather than
//! per-member work.
//!
//! Beside the supports the fold keeps each collection's *frontier*: the nodes
//! whose support no driven MERGE of that collection has consumed. A MERGE takes
//! its inputs off and puts its result on; a DERIVE puts its output on the
//! target's frontier; a COMMIT puts itself on its root's. That is the set a
//! reader attaches, and it makes a read a lookup: the frontier, one support
//! per frontier node, and their union. Without it every read re-derived from
//! the records which nodes are maximal and what they stand for.
//!
//! Nothing here is persisted. The index is rebuilt by replaying the records a
//! store already holds, which is affordable precisely because the fold is a
//! union.
//!
//! # A record is reduced the moment it arrives
//!
//! [`CoverageIndex::apply`] keeps no record. It reduces one to the
//! [`Attestation`] it makes — one to three payload handles — and drops the
//! signature, the witnesses, and the metadata. Those exist to decide whether an
//! attestation may be believed; once that is decided, nothing downstream has a
//! use for them. Holding records here would be the reified-record habit wearing
//! an index for a costume.
//!
//! # Attestations that cannot be applied yet
//!
//! Two things can be missing when a record arrives: the evidence that its
//! signer may write its collection, and the coverage rows of its inputs. Both
//! are open-world absences — a proof or an input can still arrive later — so an
//! attestation that cannot be applied is parked rather than rejected, indexed
//! by what it waits on, and retried when that arrives.
//!
//! # Validate once, then walk
//!
//! Admission is checked here, at fold time, and never again. Consumers read
//! coverage rows without re-deciding whether the edges that built them were
//! authorized: that decision is already baked into which unions happened.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;

use crate::inline::encodings::ed25519::ED25519PublicKey;
use crate::inline::Inline;
use crate::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
use crate::repo::{BlobStoreGet, CapabilityProofRead};

use super::api::AdmissionEvidence;
use crate::capability::QuorumOutcome;
use super::store::CollectionRead;
use super::records::{CollectionData, CollectionHandle, CollectionRecord};

/// The foundation commits one lattice node covers.
///
/// Set algebra over these is PATCH algebra: union, intersection, and difference
/// share subtries instead of copying members.
pub type CoverageSet = PATCH<32, IdentitySchema, (), Blake3Merkle>;

/// The frontier of one collection: the nodes with a support that no driven
/// MERGE in that collection has consumed.
///
/// A plain key set, not a Merkle one: nothing compares two frontiers by
/// digest, and a frontier changes on every believed record.
pub type FrontierSet = PATCH<32, IdentitySchema, ()>;

/// One immutable observation of downward coverage.
///
/// This is the half of [`CoverageIndex`] a reader needs, and it is two
/// persistent PATCH roots, so publishing it into a snapshot is a constant-time
/// clone rather than a copy of the fold's bookkeeping. The builder's consumer
/// map and backlog exist to keep the index growing incrementally; nothing that
/// only asks questions has any use for them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Coverage {
    rows: PATCH<64, IdentitySchema, CoverageSet>,
    /// Per collection, the nodes a reader attaches: those with a support that
    /// no driven MERGE of the same collection has consumed. Kept beside the
    /// supports by the same fold, so a read is a lookup and not a walk over
    /// the records that produced the lattice.
    frontiers: PATCH<32, IdentitySchema, FrontierSet>,
    /// Per collection, the results of believed attestations that could not be
    /// driven yet because an input has no support: a record that arrived
    /// ahead of its input. While a collection has any, its frontier can move
    /// on a record landing in an ancestor; otherwise only its own records
    /// move it, which is what a reader tracking its observation needs to
    /// know.
    blocked: PATCH<32, IdentitySchema, FrontierSet>,
}

/// One row's key: the collection a node belongs to, then the node itself.
///
/// A payload handle is not a lattice coordinate on its own. Content
/// addressing makes the same bytes the same handle everywhere, but the
/// commits underneath a node belong to one collection, and commits from two
/// collections are not comparable — so scoping the row by its collection is
/// what keeps an unrelated lattice from putting its members in this one. It
/// costs nothing in sharing, because the commit set is a separate nested trie
/// either way, and two nodes that genuinely cover the same commits still
/// share one inner root.
fn row_key(collection: CollectionHandle, node: CollectionData) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&collection.raw);
    key[32..].copy_from_slice(&node.raw);
    key
}

impl Coverage {
    /// The foundation commits this node covers within that collection, if any
    /// admitted record has attested it.
    ///
    /// An absent row and an empty row are different answers: absent means no
    /// admitted attestation names this payload as a result in this collection.
    pub fn of(&self, collection: CollectionHandle, node: CollectionData) -> Option<&CoverageSet> {
        self.rows.get(&row_key(collection, node))
    }

    /// Whether this node is known to cover that foundation commit.
    pub fn covers(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
        commit: CollectionData,
    ) -> bool {
        self.of(collection, node)
            .is_some_and(|coverage| coverage.get(&commit.raw).is_some())
    }

    /// The union of what every one of these nodes covers, within one collection.
    ///
    /// Nodes with no row are reported rather than silently skipped: a caller
    /// asking for support needs to know its answer is partial. The union is
    /// PATCH union over shared subtries, so overlapping nodes cost nothing
    /// extra.
    pub fn union_over(
        &self,
        collection: CollectionHandle,
        nodes: impl IntoIterator<Item = CollectionData>,
    ) -> (CoverageSet, Vec<CollectionData>) {
        let mut union = CoverageSet::new();
        let mut unattested = Vec::new();
        for node in nodes {
            match self.of(collection, node) {
                Some(row) => union.union(row.clone()),
                None => unattested.push(node),
            }
        }
        (union, unattested)
    }

    /// The frontier of one collection: every node with a support that no
    /// driven MERGE of that collection has consumed, in ascending byte order.
    ///
    /// These are the nodes a reader attaches. A MERGE takes its two inputs
    /// off the frontier and puts its result on; a DERIVE puts its output on
    /// the target's frontier; a COMMIT puts itself on its root's. Records may
    /// arrive in any order, so a node is only put on when no MERGE that has
    /// already been driven consumes it. An image of a source node that a
    /// coarser image also covers stays on the frontier until a MERGE in the
    /// target consumes it: the frontier is about consumption, and a reader
    /// that wants the narrowest cover compares supports.
    pub fn frontier(
        &self,
        collection: CollectionHandle,
    ) -> impl Iterator<Item = CollectionData> + '_ {
        self.frontiers
            .get(&collection.raw)
            .into_iter()
            .flat_map(|frontier| frontier.iter_ordered().map(|raw| Inline::new(*raw)))
    }

    /// The frontier of one collection as the set it is kept as, for set
    /// operations against other indexes.
    pub fn frontier_set(&self, collection: CollectionHandle) -> Option<&FrontierSet> {
        self.frontiers.get(&collection.raw)
    }

    /// The union of what the frontier of one collection covers: the support
    /// a reader attaching that frontier stands on. Frontier nodes without a
    /// support cannot exist, so the reported list is always empty; it is
    /// kept for symmetry with [`Self::union_over`].
    pub fn frontier_support(&self, collection: CollectionHandle) -> (CoverageSet, Vec<CollectionData>) {
        let nodes: Vec<_> = self.frontier(collection).collect();
        self.union_over(collection, nodes)
    }

    /// Whether any believed attestation of this collection is still waiting
    /// for an input's support: a record ahead of its input. Only then can a
    /// record landing in an ancestor move this collection's frontier.
    pub fn has_blocked(&self, collection: CollectionHandle) -> bool {
        self.blocked
            .get(&collection.raw)
            .is_some_and(|blocked| !blocked.is_empty())
    }

    /// Number of lattice nodes with a coverage row.
    pub fn len(&self) -> usize {
        self.rows.len().min(usize::MAX as u64) as usize
    }

    /// Whether any node has a coverage row.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Whether two observations share one persistent root, and so are known
    /// equal without comparing members.
    pub fn shares_root(&self, other: &Self) -> bool {
        self.rows.shares_root(&other.rows)
    }
}

/// What driving one attestation did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Driven {
    /// The result's support grew.
    Grew,
    /// Every member was already there.
    Unchanged,
    /// An input has no support yet; retried when it gets one.
    Blocked,
}

/// What one record says about the relationship between payloads.
///
/// This is the whole of a record that coverage needs. Everything else a record
/// carries exists to decide whether this statement may be believed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Attestation {
    /// This payload is a member of the collection on its own authority.
    Foundation { data: CollectionData },
    /// This result is the join of two payloads in the same lattice.
    Join {
        low: CollectionData,
        high: CollectionData,
        result: CollectionData,
    },
    /// This output is the image of an input under a collection's mapping.
    Image {
        input: CollectionData,
        output: CollectionData,
    },
}

/// The `(collection, payload)` a record produces: its attestation's result.
///
/// Consumers name input PAYLOADS, so this is the half of the production
/// relation a record states about itself; the store indexes the other half.
pub(super) fn produced(record: CollectionRecord) -> CollectionData {
    Attestation::of(&record).result()
}

impl Attestation {
    /// The relationship a record states, with its proof stripped away.
    pub fn of(record: &CollectionRecord) -> Self {
        match record {
            CollectionRecord::Commit(commit) => Self::Foundation {
                data: commit.data(),
            },
            CollectionRecord::Merge(merge) => {
                let (low, high) = merge.inputs();
                Self::Join {
                    low,
                    high,
                    result: merge.result(),
                }
            }
            CollectionRecord::Derive(derive) => Self::Image {
                input: derive.input(),
                output: derive.output(),
            },
        }
    }

    /// The node whose coverage this attestation widens.
    pub fn result(&self) -> CollectionData {
        match self {
            Self::Foundation { data } => *data,
            Self::Join { result, .. } => *result,
            Self::Image { output, .. } => *output,
        }
    }

    /// The nodes whose coverage this attestation reads.
    fn inputs(&self) -> impl Iterator<Item = CollectionData> {
        let (first, second) = match self {
            Self::Foundation { .. } => (None, None),
            Self::Join { low, high, .. } => (Some(*low), Some(*high)),
            Self::Image { input, .. } => (Some(*input), None),
        };
        first.into_iter().chain(second)
    }
}

/// Whether an attestation's signer is known to be admitted to write its
/// collection.
///
/// There is no third `Refused` state on purpose. Capability proofs only ever
/// arrive, so the absence of one is a fact about *now*, not about the record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Admittance {
    /// The signer is admitted; the attestation may be believed.
    Admitted,
    /// No proof admits this signer yet; park the attestation under its key.
    Pending,
    /// Nothing is known about who may write here, because the collection's
    /// descriptor is not resident. Park the attestation under that descriptor:
    /// it is an ordinary blob, and its arrival is what re-offers the record --
    /// a proof would not.
    Undescribed,
    /// No resident evidence admits this signer, and some evidence is not
    /// resident: a policy definition the descriptor names, or a capability
    /// definition a proof for this signer names. Any of those blobs landing
    /// could change the answer, and so could a proof, so the attestation is
    /// parked under each of them and under the signer; whichever arrives
    /// first re-offers it, and that decision reads everything again.
    Undefined(Vec<CollectionHandle>),
}

/// What the fold must know about a collection before it can believe an
/// attestation naming it: which lineage the attestation belongs to, and
/// whether this signer may make it.
///
/// Implementors do the descriptor and capability work; this module only asks,
/// and only once per attestation.
pub trait RecordAdmission {
    /// The collection this one derives from, if any.
    ///
    /// Only a `DERIVE` needs this, and only one hop of it: the record names
    /// its target, while its input is a node in the target's source. A commit
    /// and a merge stay entirely inside the collection they name.
    ///
    /// Naming the *missing* descriptor rather than just failing is what lets a
    /// parked attestation be keyed on the exact blob whose arrival would
    /// unblock it.
    fn source(&self, collection: CollectionHandle) -> SourceResolution;

    /// Whether attestations this signer makes about this collection count.
    fn admits(&self, collection: CollectionHandle, signer: Inline<ED25519PublicKey>) -> Admittance;
}

/// What a collection's descriptor says about where it derives from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceResolution {
    /// The descriptor names no source: this collection is a lineage root.
    Root,
    /// The collection this one derives from.
    Derived(CollectionHandle),
    /// This descriptor is not resident, so the question has no answer yet. An
    /// absence, not a refusal — the blob may still arrive.
    Missing(CollectionHandle),
}

/// Admits every signer and treats every collection as its own foundation.
///
/// For stores that carry no admission evidence, and for exercising the fold
/// on its own — where each test collection is the root of its own lineage,
/// which is exactly what makes cross-lineage aliasing visible.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdmitEveryRecord;

impl RecordAdmission for AdmitEveryRecord {
    fn source(&self, _collection: CollectionHandle) -> SourceResolution {
        SourceResolution::Root
    }

    fn admits(
        &self,
        _collection: CollectionHandle,
        _signer: Inline<ED25519PublicKey>,
    ) -> Admittance {
        Admittance::Admitted
    }
}

/// One attestation and the collection it names, held until the evidence it
/// waits on arrives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Parked {
    collection: CollectionHandle,
    attestation: Attestation,
    signer: Inline<ED25519PublicKey>,
}

/// What a parked attestation is waiting for.
///
/// Both are open-world absences, and both are things a store *sees arrive*:
/// a descriptor is a blob, a proof is a record. Keying the backlog on the
/// awaited evidence is what lets a drain cost the events that happened rather
/// than the size of the backlog — which matters because under sync there is
/// no end of the run to defer to, only an endless sequence of appends.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Awaiting {
    /// The descriptor chain from this collection to its foundation is not
    /// fully resident. Retry when this blob lands.
    Lineage(CollectionHandle),
    /// No capability proof admits this signer to write yet. Retry when a
    /// proof arrives.
    Proof(Inline<ED25519PublicKey>),
}

/// What arrived since the last settle that could change an earlier decision.
///

/// One consumer edge: the collection it writes to, the one it reads from,
/// and the attestation itself.
type ConsumerEdge = (CollectionHandle, CollectionHandle, Attestation);
/// The edges that read one input, one entry per edge, keyed by
/// [`edge_key`]. Recording the k-th edge of a node costs one path, not a
/// copy of the other k-1; a node read by many records is the common case in
/// a lattice and used to make the fold quadratic in it.
type Edges = PATCH<96, IdentitySchema, ConsumerEdge>;
/// Collection-scoped input handle to the edges that read it.
type Consumers = PATCH<64, IdentitySchema, Edges>;
/// The attestations held under one awaited thing, one entry each, keyed by
/// [`parked_key`]; the same shape as [`Edges`], for the same reason.
type Held = PATCH<160, IdentitySchema, Parked>;
/// Attestations held until one named thing arrives, keyed by that thing.
type Waiters = PATCH<32, IdentitySchema, Held>;

/// What identifies a consumer edge under one of its inputs: where it writes,
/// what it produces, and the other input it reads -- zero for an image, which
/// reads one.
fn edge_key(
    writes_to: CollectionHandle,
    attestation: Attestation,
    input: CollectionData,
) -> [u8; 96] {
    let mut key = [0u8; 96];
    key[..32].copy_from_slice(&writes_to.raw);
    key[32..64].copy_from_slice(&attestation.result().raw);
    if let Attestation::Join { low, high, .. } = attestation {
        let other = if input == low { high } else { low };
        key[64..].copy_from_slice(&other.raw);
    }
    key
}

/// What identifies a parked attestation: the collection and signer that
/// would believe it, and the attestation itself.
fn parked_key(entry: &Parked) -> [u8; 160] {
    let mut key = [0u8; 160];
    key[..32].copy_from_slice(&entry.collection.raw);
    key[32..64].copy_from_slice(&entry.signer.raw);
    key[64..96].copy_from_slice(&entry.attestation.result().raw);
    match entry.attestation {
        Attestation::Foundation { .. } => {}
        Attestation::Join { low, high, .. } => {
            key[96..128].copy_from_slice(&low.raw);
            key[128..].copy_from_slice(&high.raw);
        }
        Attestation::Image { input, .. } => {
            key[96..128].copy_from_slice(&input.raw);
        }
    }
    key
}

/// Every attestation held in one waiter map.
fn held(held: &Held) -> impl Iterator<Item = Parked> + '_ {
    held.iter_ordered().filter_map(|key| held.get(key).copied())
}

/// Downward coverage for every lattice node a store has admitted.
///
/// Every part of this is a persistent PATCH root, so the whole index -- not
/// only its published half -- is a constant-time clone. That is what lets a
/// snapshot carry the index rather than a copy of the rows, and what lets a
/// reader compose on top of one: clone it, park a few more records, settle.
/// Only `fresh` is a plain vector, and it is empty whenever the index is
/// settled, which is the only time one is handed out.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoverageIndex {
    /// The half a reader sees: result payload handle to the commits it covers.
    published: Coverage,
    /// Which attestations read each input, so a row that grows can re-drive
    /// its consumers instead of forcing a full replay.
    consumers: Consumers,
    /// Waiting on a descriptor blob, keyed by that blob's handle.
    awaiting_lineage: Waiters,
    /// Waiting on a proof admitting their signer, keyed by the signer.
    awaiting_proof: Waiters,
    /// Attestations parked this batch that no oracle has seen yet.
    ///
    /// Replay cannot ask the oracle per record — the descriptor that answers
    /// it is a blob in the same file — so it parks here and the batch's single
    /// [`CoverageIndex::settle`] gives each one its first decision. This is
    /// distinct from `pending`, whose entries have already been decided
    /// against and are waiting on a *named* arrival.
    fresh: Waiters,
}

/// How many attestations a waiter map holds.
/// Count the parked attestations of one collection in a waiter map.
///
/// The map is keyed by the awaited evidence rather than by collection, because
/// that is what lets a drain cost the events that happened rather than the size
/// of the backlog. So a per-collection question is a scan of the backlog, which
/// is the right trade for a view: the backlog is small in the steady state, and
/// re-keying it to make this cheaper would make the drain expensive instead.
fn parked_in(waiters: &Waiters, collection: CollectionHandle) -> impl Iterator<Item = Parked> + '_ {
    waiters
        .iter_ordered()
        .filter_map(|key| waiters.get(key))
        .flat_map(held)
        .filter(move |parked| parked.collection == collection)
}

fn waiting(waiters: &Waiters) -> usize {
    waiters
        .iter_ordered()
        .map(|key| waiters.get(key).map_or(0, |held| held.len() as usize))
        .sum()
}

/// Move every attestation out of a waiter map.
fn drain(waiters: Waiters, into: &mut Vec<Parked>) {
    for key in waiters.iter_ordered() {
        if let Some(entries) = waiters.get(key) {
            into.extend(held(entries));
        }
    }
}

impl CoverageIndex {
    /// An index covering nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// The foundation commits this node covers, if any admitted record has
    /// attested it.
    ///
    /// An absent row and an empty row are different answers: absent means no
    /// admitted attestation names this payload as a result at all.
    pub fn coverage(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
    ) -> Option<&CoverageSet> {
        self.published.of(collection, node)
    }

    /// Whether this node is known to cover that foundation commit.
    pub fn covers(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
        commit: CollectionData,
    ) -> bool {
        self.published.covers(collection, node, commit)
    }

    /// The immutable observation to hand a reader.
    ///
    /// A constant-time clone: one persistent PATCH root, none of the fold's
    /// bookkeeping.
    pub fn published(&self) -> &Coverage {
        &self.published
    }

    /// Number of lattice nodes with a coverage row.
    pub fn len(&self) -> usize {
        self.published.len()
    }

    /// Whether any node has a coverage row.
    pub fn is_empty(&self) -> bool {
        self.published.is_empty()
    }

    /// Whether any attestation is still waiting on evidence.
    ///
    /// A store can skip building a reader entirely when this is false, which is
    /// the steady state once a pile has been replayed once.
    pub fn has_parked(&self) -> bool {
        !self.awaiting_lineage.is_empty() || !self.awaiting_proof.is_empty() || !self.fresh.is_empty()
    }

    /// Whether any attestation has never been offered a decision.
    pub fn has_fresh(&self) -> bool {
        !self.fresh.is_empty()
    }

    /// Number of attestations waiting on evidence that has not arrived.
    pub fn parked(&self) -> usize {
        waiting(&self.awaiting_lineage) + waiting(&self.awaiting_proof) + waiting(&self.fresh)
    }

    /// Number waiting specifically on a proof admitting their signer.
    pub fn parked_on_signers(&self) -> usize {
        waiting(&self.awaiting_proof)
    }

    /// Attestations OF ONE COLLECTION parked because no proof admits their
    /// signer yet: the per-collection form of [`Self::parked_on_signers`].
    ///
    /// Per-collection because the index-wide count cannot be acted on. Almost
    /// any live pile holds some unadmitted work, so "this pile has 127,912
    /// unadmitted records" is true, unchanging, and tells nobody where to
    /// look; "this collection has 204" names the thing to carry. A reader
    /// marking collections needs the second, and the backlog already carries
    /// each entry's collection, so this costs a filter rather than a fold.
    pub fn unadmitted_in(&self, collection: CollectionHandle) -> usize {
        parked_in(&self.awaiting_proof, collection).count()
    }

    /// WHICH members of `collection` no capability proof admits yet.
    ///
    /// The per-member form of [`unadmitted_in`](Self::unadmitted_in). A count
    /// says a collection holds unadmitted work; this says which elements it is,
    /// which is the difference between a number an operator can read and a mark
    /// an operator can point at.
    ///
    /// Nothing else answers this. Asking `coverage(collection, node)` and
    /// finding nothing conflates three different facts: a node no proof admits,
    /// a node reached only as somebody else's join input, and a node whose own
    /// inputs have not arrived. They need different remedies and belong to
    /// different people, so a view that draws them alike is worse than one that
    /// draws none of them.
    ///
    /// A set rather than a count of rows: two attestations may name one result,
    /// and that is agreement about a member rather than two unadmitted members.
    /// It follows that the size of this set can be SMALLER than
    /// [`unadmitted_in`](Self::unadmitted_in), and neither is wrong -- one
    /// counts waiting attestations, the other names waiting members.
    pub fn unadmitted_nodes_in(&self, collection: CollectionHandle) -> BTreeSet<CollectionData> {
        parked_in(&self.awaiting_proof, collection)
            .map(|parked| parked.attestation.result())
            .collect()
    }

    /// The same, for attestations waiting on a descriptor chain to land
    /// instead of on a proof.
    ///
    /// Kept apart from [`Self::unadmitted_in`] because the two absences have
    /// different remedies and different owners: a missing proof is a grant
    /// somebody must issue, a missing lineage is bytes that have not
    /// replicated yet and may simply arrive.
    pub fn awaiting_lineage_in(&self, collection: CollectionHandle) -> usize {
        parked_in(&self.awaiting_lineage, collection).count()
    }

    /// Number waiting specifically on a descriptor chain becoming resident.
    pub fn parked_on_lineages(&self) -> usize {
        waiting(&self.awaiting_lineage)
    }

    /// Fold one record into the index, keeping only what it attests.
    ///
    /// Applying is idempotent: the same record folded twice unions the same
    /// members. Records may arrive in any order — one whose inputs have no row
    /// yet contributes nothing now and is retried the moment they do.
    pub fn apply<A: RecordAdmission>(&mut self, record: &CollectionRecord, admission: &A) {
        self.attest(
            record.collection(),
            Attestation::of(record),
            record.public_key(),
            admission,
        );
    }

    /// Fold one stripped attestation, subject to its signer's admission.
    pub fn attest<A: RecordAdmission>(
        &mut self,
        collection: CollectionHandle,
        attestation: Attestation,
        signer: Inline<ED25519PublicKey>,
        admission: &A,
    ) {
        self.decide(
            Parked {
                collection,
                attestation,
                signer,
            },
            admission,
        );
    }

    /// Believe one attestation, or file it under the evidence it still needs.
    fn decide<A: RecordAdmission>(&mut self, entry: Parked, admission: &A) {
        // A projection is the one attestation whose inputs live somewhere
        // else: the record names its target, the input is a node in the
        // target's source. One descriptor hop answers that; a commit and a
        // merge need no hop at all.
        let reads_from = match entry.attestation {
            Attestation::Image { .. } => match admission.source(entry.collection) {
                SourceResolution::Derived(source) => source,
                SourceResolution::Missing(descriptor) => {
                    self.hold(Awaiting::Lineage(descriptor), entry);
                    return;
                }
                SourceResolution::Root => {
                    // A derive into a collection that derives from nothing has
                    // no source lattice to read, so it attests nothing.
                    return;
                }
            },
            Attestation::Foundation { .. } => {
                // A commit is a foundation attestation, which only a root can
                // make: a derived collection's members are images of its
                // source's, so a commit written straight into one names no
                // foundation and attests nothing. A missing descriptor is
                // decided below, where admission parks it on that blob.
                if let SourceResolution::Derived(_) = admission.source(entry.collection) {
                    return;
                }
                entry.collection
            }
            Attestation::Join { .. } => entry.collection,
        };
        match admission.admits(entry.collection, entry.signer) {
            Admittance::Admitted => {}
            Admittance::Pending => {
                self.hold(Awaiting::Proof(entry.signer), entry);
                return;
            }
            Admittance::Undescribed => {
                self.hold(Awaiting::Lineage(entry.collection), entry);
                return;
            }
            Admittance::Undefined(definitions) => {
                for definition in definitions {
                    self.hold(Awaiting::Lineage(definition), entry);
                }
                self.hold(Awaiting::Proof(entry.signer), entry);
                return;
            }
        }
        self.believe(entry.collection, reads_from, entry.attestation);
    }

    fn hold(&mut self, awaiting: Awaiting, entry: Parked) {
        let (waiters, key) = match awaiting {
            Awaiting::Lineage(descriptor) => (&mut self.awaiting_lineage, descriptor.raw),
            Awaiting::Proof(signer) => (&mut self.awaiting_proof, signer.raw),
        };
        // The inner map is a persistent root: cloning it is constant time,
        // and `insert` keeps an existing entry, so the same attestation parked
        // twice is held once. `replace` on the outer map, because `insert`
        // would keep the old inner map.
        let mut entries = waiters.get(&key).cloned().unwrap_or_default();
        entries.insert(&Entry::with_value(&parked_key(&entry), entry));
        waiters.replace(&Entry::with_value(&key, entries));
    }

    /// Record an attestation without deciding it yet.
    ///
    /// Replay is an index construction path, not an authorization pass: the
    /// descriptor that says who may write a collection, and the proofs that
    /// answer it, are themselves records in the same file and may sit after
    /// the records they authorize. So replay parks, and [`Self::settle`] gives
    /// each parked attestation its first decision once the batch has been
    /// applied. Nothing here defers a *re-*decision to a batch boundary —
    /// those are keyed on the arrival that would change the answer.
    pub fn park(
        &mut self,
        collection: CollectionHandle,
        attestation: Attestation,
        signer: Inline<ED25519PublicKey>,
    ) {
        let entry = Parked {
            collection,
            attestation,
            signer,
        };
        // Keyed by the collection it names, so a reader can decide one
        // lineage's records and leave every other lineage's parked.
        let mut held = self.fresh.get(&collection.raw).cloned().unwrap_or_default();
        held.insert(&Entry::with_value(&parked_key(&entry), entry));
        self.fresh.replace(&Entry::with_value(&collection.raw, held));
    }

    /// Reduce one record to what it attests and park it.
    pub fn park_record(&mut self, record: &CollectionRecord) {
        self.park(
            record.collection(),
            Attestation::of(record),
            record.public_key(),
        );
    }

    /// Note that a blob became resident, unblocking anything that waited for
    /// it as a descriptor.
    ///
    /// Cheap and unconditional: one map probe per blob. Almost every blob is
    /// not a descriptor anyone is waiting on, and the probe says so at once.
    pub fn blob_arrived(&mut self, handle: CollectionHandle) -> bool {
        self.awaiting_lineage.get(&handle.raw).is_some()
    }

    /// Note that a capability proof arrived, unblocking signers it may admit.
    ///
    /// Every signer-parked attestation is re-offered, not just the ones this
    /// proof names, because a proof does not expose its delegates. That is
    /// bounded by *proof arrivals*, which are rare, rather than by refreshes,
    /// which are not — which is the whole point. Keying on the delegate set
    /// would narrow it further if proofs ever become hot.
    pub fn proof_arrived(&self) -> bool {
        !self.awaiting_proof.is_empty()
    }

    /// Give every attestation whose evidence may have changed a decision.
    ///
    /// `arrivals` names the descriptor blobs that became resident in this
    /// batch; `proofs_arrived` says whether any capability proof did. Freshly
    /// parked attestations are always decided, because they have never been
    /// offered. Everything else is retried only if the evidence it was
    /// actually waiting on arrived — so a backlog nothing can admit costs
    /// nothing per append, which is what makes this work under continuous
    /// sync rather than only at the end of a replay.
    pub fn settle<A: RecordAdmission>(
        &mut self,
        admission: &A,
        arrivals: impl IntoIterator<Item = CollectionHandle>,
        proofs_arrived: bool,
    ) {
        let mut woken: Vec<Parked> = Vec::new();
        drain(std::mem::take(&mut self.fresh), &mut woken);
        for handle in arrivals {
            if let Some(entries) = self.awaiting_lineage.get(&handle.raw).cloned() {
                self.awaiting_lineage.remove(&handle.raw);
                woken.extend(held(&entries));
            }
        }
        if proofs_arrived {
            drain(std::mem::take(&mut self.awaiting_proof), &mut woken);
        }
        for entry in woken {
            self.decide(entry, admission);
        }
    }

    /// A descriptor landed: everything that waited on it is fresh again, to be
    /// decided the next time its collection is settled. No decision is made
    /// here, so this is one map move, not an admission query.
    pub fn wake_descriptor(&mut self, descriptor: CollectionHandle) {
        let Some(entries) = self.awaiting_lineage.get(&descriptor.raw).cloned() else {
            return;
        };
        self.awaiting_lineage.remove(&descriptor.raw);
        for entry in held(&entries) {
            self.park(entry.collection, entry.attestation, entry.signer);
        }
    }

    /// A proof landed: every attestation waiting on a signer is fresh again,
    /// to be decided when its collection is next settled. Proofs are rare and
    /// the move is one insert per entry, without an admission query.
    pub fn wake_proofs(&mut self) {
        let mut woken = Vec::new();
        drain(std::mem::take(&mut self.awaiting_proof), &mut woken);
        for entry in woken {
            self.park(entry.collection, entry.attestation, entry.signer);
        }
    }

    /// Decide every fresh attestation naming one of `collections`, and only
    /// those. A reader asks for exactly the lineage it reads -- foundation,
    /// sources, target -- which is closed under "reads from", so settling it
    /// alone publishes the same rows a full settle would for those
    /// collections; every other lineage's records stay parked, unpaid for.
    pub fn settle_collections<A: RecordAdmission>(
        &mut self,
        admission: &A,
        collections: &BTreeSet<CollectionHandle>,
    ) {
        let mut woken = Vec::new();
        for collection in collections {
            if let Some(entries) = self.fresh.get(&collection.raw).cloned() {
                self.fresh.remove(&collection.raw);
                woken.extend(held(&entries));
            }
        }
        for entry in woken {
            self.decide(entry, admission);
        }
    }

    /// Re-offer every parked attestation, whatever it is waiting for.
    ///
    /// The unconditional form, for a store that cannot say which evidence
    /// arrived. Correct but coarse: prefer [`Self::settle`] where the arrivals
    /// are observable.
    pub fn resolve<A: RecordAdmission>(&mut self, admission: &A) {
        let mut woken: Vec<Parked> = Vec::new();
        drain(std::mem::take(&mut self.fresh), &mut woken);
        drain(std::mem::take(&mut self.awaiting_lineage), &mut woken);
        drain(std::mem::take(&mut self.awaiting_proof), &mut woken);
        for entry in woken {
            self.decide(entry, admission);
        }
    }

    /// Fold an attestation whose collection resolves and whose signer is
    /// admitted.
    fn believe(
        &mut self,
        writes_to: CollectionHandle,
        reads_from: CollectionHandle,
        attestation: Attestation,
    ) {
        for input in attestation.inputs() {
            let key = row_key(reads_from, input);
            let mut edges = self.consumers.get(&key).cloned().unwrap_or_default();
            edges.insert(&Entry::with_value(
                &edge_key(writes_to, attestation, input),
                (writes_to, reads_from, attestation),
            ));
            self.consumers.replace(&Entry::with_value(&key, edges));
        }
        let mut grown = Vec::new();
        if self.drive(writes_to, reads_from, attestation) == Driven::Grew {
            grown.push((writes_to, attestation.result()));
        }
        // A row that grew may unblock or widen the attestations that read it,
        // and those may widen their own consumers in turn. Growth is bounded by
        // the finite set of foundation commits, so the worklist drains.
        while let Some((collection, node)) = grown.pop() {
            let Some(edges) = self.consumers.get(&row_key(collection, node)).cloned() else {
                continue;
            };
            for key in edges.iter_ordered() {
                let Some(&(writes_to, reads_from, consumer)) = edges.get(key) else {
                    continue;
                };
                if self.drive(writes_to, reads_from, consumer) == Driven::Grew {
                    grown.push((writes_to, consumer.result()));
                }
            }
        }
    }

    /// Note whether an attestation's result is still waiting for an input.
    fn mark_blocked(&mut self, collection: CollectionHandle, result: CollectionData, blocked: bool) {
        let mut set = self
            .published
            .blocked
            .get(&collection.raw)
            .cloned()
            .unwrap_or_default();
        if blocked {
            set.insert(&Entry::new(&result.raw));
        } else if set.get(&result.raw).is_some() {
            set.remove(&result.raw);
        } else {
            return;
        }
        self.published
            .blocked
            .replace(&Entry::with_value(&collection.raw, set));
    }

    /// Union one attestation's contribution into its result row.
    ///
    /// Says whether the row grew, which is the termination condition for the
    /// propagation worklist, or whether the attestation is still blocked on
    /// an input without a support.
    fn drive(
        &mut self,
        writes_to: CollectionHandle,
        reads_from: CollectionHandle,
        attestation: Attestation,
    ) -> Driven {
        let contribution = match attestation {
            Attestation::Foundation { data } => CoverageSet::from_keys(std::iter::once(data.raw)),
            Attestation::Join { low, high, .. } => {
                let (Some(low), Some(high)) = (
                    self.published.rows.get(&row_key(reads_from, low)),
                    self.published.rows.get(&row_key(reads_from, high)),
                ) else {
                    // All or nothing: a join that only saw one side would
                    // otherwise publish a support it never attested.
                    self.mark_blocked(writes_to, attestation.result(), true);
                    return Driven::Blocked;
                };
                let mut union = low.clone();
                union.union(high.clone());
                union
            }
            Attestation::Image { input, .. } => {
                // The input is a node in the source collection; the output
                // becomes a node in this one. The commit set travels across
                // unchanged, which is what makes the derived image denote the
                // same logical value.
                let Some(input) = self.published.rows.get(&row_key(reads_from, input)) else {
                    self.mark_blocked(writes_to, attestation.result(), true);
                    return Driven::Blocked;
                };
                input.clone()
            }
        };
        self.mark_blocked(writes_to, attestation.result(), false);
        // Union first, then ask whether anything changed: a PATCH compares
        // by its root hash, so that question costs nothing after the union.
        let key = row_key(writes_to, attestation.result());
        let (support, grew) = match self.published.rows.get(&key) {
            Some(existing) => {
                let mut merged = existing.clone();
                merged.union(contribution);
                let grew = merged != *existing;
                (merged, grew)
            }
            None => (contribution, true),
        };
        if grew {
            self.published
                .rows
                .replace(&Entry::with_value(&key, support));
        }
        // The frontier moves whenever the attestation is driven, grown or
        // not: a second route to a result that already has its support still
        // consumes that route's inputs.
        self.advance_frontier(writes_to, attestation);
        if grew {
            Driven::Grew
        } else {
            Driven::Unchanged
        }
    }

    /// Move one collection's frontier for an attestation that has just been
    /// driven: a join takes its inputs off and puts its result on, a
    /// foundation or an image puts its node on. Idempotent, because a driven
    /// attestation is driven again whenever one of its inputs grows.
    fn advance_frontier(&mut self, collection: CollectionHandle, attestation: Attestation) {
        let mut frontier = self
            .published
            .frontiers
            .get(&collection.raw)
            .cloned()
            .unwrap_or_default();
        let result = attestation.result();
        if let Attestation::Join { low, high, .. } = attestation {
            // `MERGE(x, x) -> x` is legal and appears in practice; it must not
            // take its own result off.
            for input in [low, high] {
                if input != result {
                    frontier.remove(&input.raw);
                }
            }
        }
        if !self.consumed(collection, result) {
            frontier.insert(&Entry::new(&result.raw));
        }
        self.published
            .frontiers
            .replace(&Entry::with_value(&collection.raw, frontier));
    }

    /// Whether a driven join of this collection reads this node: one whose
    /// result and other input both have supports. A join that was only
    /// registered, its other input still absent, has not consumed anything
    /// yet; it takes the node off the frontier when it is driven.
    fn consumed(&self, collection: CollectionHandle, node: CollectionData) -> bool {
        let Some(edges) = self.consumers.get(&row_key(collection, node)) else {
            return false;
        };
        edges
            .iter_ordered()
            .filter_map(|key| edges.get(key))
            .any(|&(writes_to, _, consumer)| {
                let Attestation::Join { low, high, result } = consumer else {
                    return false;
                };
                let other = if node == low { high } else { low };
                writes_to == collection
                    && result != node
                    && self.published.rows.get(&row_key(collection, result)).is_some()
                    && self.published.rows.get(&row_key(collection, other)).is_some()
            })
    }
}


/// Admission decided from one immutable store observation.
///
/// Evidence is discovered once per collection and cached, because a fold
/// touches the same handful of collections thousands of times and descriptor
/// resolution is the expensive half of the question. A collection whose
/// descriptor or proofs are not resident yet simply admits nobody — its
/// attestations park, and the next resolution pass retries them.
/// Why a collection yields no write evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Absent {
    /// The descriptor blob is not resident: nothing is known yet, and its
    /// arrival is what would change that.
    Descriptor,
    /// The descriptor is resident but yields no admission evidence this
    /// reader can use: it decodes to no policy, or to several descriptor
    /// entities, none of which may lend the others its policy.
    Evidence,
}

pub(crate) struct StoreWriters<'a, R> {
    reader: &'a R,
    /// Per collection: the evidence its resident policy definitions give,
    /// and the definitions that are not resident yet.
    evidence:
        RefCell<BTreeMap<CollectionHandle, Result<(AdmissionEvidence, Vec<CollectionHandle>), Absent>>>,
    sources: RefCell<BTreeMap<CollectionHandle, SourceResolution>>,
    /// One answer per (collection, signer) for the life of this reader. A
    /// fold asks once per record and a lattice holds thousands of records per
    /// signer, while the quorum check behind the answer walks and verifies
    /// the collection's proofs every time it is asked.
    admitted: RefCell<BTreeMap<(CollectionHandle, Inline<ED25519PublicKey>), Admittance>>,
}

impl<'a, R: BlobStoreGet + CapabilityProofRead> StoreWriters<'a, R> {
    /// Ask this reader who may write which collection.
    pub(crate) fn new(reader: &'a R) -> Self {
        Self {
            reader,
            evidence: RefCell::new(BTreeMap::new()),
            sources: RefCell::new(BTreeMap::new()),
            admitted: RefCell::new(BTreeMap::new()),
        }
    }

    /// Read one descriptor to see which collection this one derives from.
    ///
    /// One hop, not a walk: the fold only ever needs the collection an input
    /// node lives in, and that is the immediate source.
    fn read_source(&self, collection: CollectionHandle) -> SourceResolution {
        let Ok(descriptor) = super::api::load_collection_descriptor(self.reader, collection) else {
            return SourceResolution::Missing(collection);
        };
        match super::descriptor::source(descriptor.fragment.facts()) {
            Ok(Some(source)) => SourceResolution::Derived(source),
            Ok(None) => SourceResolution::Root,
            Err(_) => SourceResolution::Missing(collection),
        }
    }

    /// Resolve and cache who may WRITE this collection.
    ///
    /// Returns whether the question could be answered at all; a descriptor
    /// that is not resident answers nothing, and the caller parks.
    fn write_evidence(&self, collection: CollectionHandle) -> Result<(), Absent> {
        let mut cache = self.evidence.borrow_mut();
        let entry = cache.entry(collection).or_insert_with(|| {
            let descriptor = match super::api::load_collection_descriptor(self.reader, collection)
            {
                Ok(descriptor) => descriptor,
                Err(super::api::CollectionDescriptorError::Get { .. }) => {
                    return Err(Absent::Descriptor)
                }
                Err(_) => return Err(Absent::Evidence),
            };
            let facts = descriptor.fragment.facts();
            if super::descriptor::sole_descriptor_entity(facts).is_none() {
                return Err(Absent::Evidence);
            }
            let (policies, missing) = super::descriptor::admission_policies_with_missing(
                self.reader,
                facts,
                super::ACTION_WRITE,
                None,
            );
            super::api::discover_admission_evidence(
                self.reader,
                policies.into_iter(),
                super::ACTION_WRITE,
                collection,
            )
            .map(|evidence| (evidence, missing))
            .map_err(|_| Absent::Evidence)
        });
        entry.as_ref().map(|_| ()).map_err(|absent| *absent)
    }

    fn decide_admits(
        &self,
        collection: CollectionHandle,
        signer: Inline<ED25519PublicKey>,
    ) -> Admittance {
        match self.write_evidence(collection) {
            // Nothing is known about who may write here until the descriptor
            // lands; absence is a wait on that blob, never a refusal.
            Err(Absent::Descriptor) => return Admittance::Undescribed,
            // Resident but unusable to this reader: nothing this reader can
            // wait on would change that, so it is held like a missing proof.
            Err(Absent::Evidence) => return Admittance::Pending,
            Ok(()) => {}
        }
        let cache = self.evidence.borrow();
        let (evidence, missing) = cache
            .get(&collection)
            .and_then(|state| state.as_ref().ok())
            .expect("write evidence was just resolved");
        let Ok(subject) = VerifyingKey::from_bytes(&signer.raw) else {
            // A malformed key cannot be the subject of any proof, so no future
            // proof can admit it either — but the fold has no refusal state and
            // does not need one: this attestation simply never applies.
            return Admittance::Pending;
        };
        let mut definitions = missing.clone();
        match evidence.decide(self.reader, subject) {
            QuorumOutcome::Met => return Admittance::Admitted,
            QuorumOutcome::Unmet => {}
            QuorumOutcome::Undefined(handles) => definitions.extend(handles),
        }
        if definitions.is_empty() {
            Admittance::Pending
        } else {
            // A definition this reader could not read -- a policy the
            // descriptor names, or a capability a proof for this signer
            // names -- may be the one that admits the signer.
            Admittance::Undefined(definitions)
        }
    }
}

impl<R: BlobStoreGet + CapabilityProofRead> RecordAdmission for StoreWriters<'_, R> {
    fn source(&self, collection: CollectionHandle) -> SourceResolution {
        // Only a resolved answer is cached. A missing descriptor is a fact
        // about now, and the next arrival should be able to change it.
        if let Some(cached) = self.sources.borrow().get(&collection) {
            return *cached;
        }
        let resolved = self.read_source(collection);
        if !matches!(resolved, SourceResolution::Missing(_)) {
            self.sources.borrow_mut().insert(collection, resolved);
        }
        resolved
    }

    fn admits(&self, collection: CollectionHandle, signer: Inline<ED25519PublicKey>) -> Admittance {
        let key = (collection, signer);
        if let Some(cached) = self.admitted.borrow().get(&key) {
            return cached.clone();
        }
        let answer = self.decide_admits(collection, signer);
        self.admitted.borrow_mut().insert(key, answer.clone());
        answer
    }
}

/// Fold one store's whole record set into a coverage index.
///
/// The general path, for any store that enumerates records and can answer who
/// may write a collection. A backend that maintains the index across appends
/// — a pile does, during replay — should hand out its own instead of folding
/// again; this is what everything else uses, and what an equivalence check
/// compares that maintained index against.
pub(crate) fn coverage_of<R>(reader: &R) -> Result<CoverageIndex, R::RecordsError>
where
    R: CollectionRead + BlobStoreGet + CapabilityProofRead,
{
    let mut index = CoverageIndex::new();
    for record in reader.records()? {
        index.park_record(&record?);
    }
    index.resolve(&StoreWriters::new(reader));
    Ok(index)
}

#[cfg(test)]
mod tests;
