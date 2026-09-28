//! Downward coverage: which foundations of its own collection a lattice node
//! stands for.
//!
//! A COMMIT, MERGE, or DERIVE is an attestation about the relationship between
//! payloads, not an object worth reifying. What every consumer actually asks is
//! the *denotational* question — given this node of a collection's lattice,
//! which of that collection's foundations does it cover? — and that answer is
//! a set, not a walk.
//!
//! Every collection is a set of foundations, and each host joins that set
//! into a lattice of its own with MERGEs. This module folds records into
//! exactly that answer. Each believed record contributes one monotone union:
//!
//! - `COMMIT(root, data)` — `coverage(data) ∪= {data}`; a commit is a
//!   foundation of a root collection.
//! - `DERIVE(target, L -> output)` — `coverage(output) ∪= {output}`; a derive
//!   is a foundation (a leaf) of a derived collection. It reads no row: its
//!   input is the locator of a source foundation, not a node of this lattice.
//! - `MERGE(c; a1..ak -> result)` — `coverage(result) ∪= coverage(a1) ∪ … ∪
//!   coverage(ak)`, all or nothing; a merge is compaction inside one lattice.
//! - `MAP(attached; node -> attachment)` — no row at all: the attachment is
//!   recorded against the node in [`Coverage::attachments`], and its support
//!   is the node's support in the parent, looked up there.
//!
//! Foundations and merges are believed on different grounds. A COMMIT or a
//! DERIVE is believed when its signer may WRITE its collection; that is what
//! [`RecordAdmission`] decides, and nothing else asks it. A MERGE is believed
//! only when the index's host signed it ([`CoverageIndex::for_host`]): join is
//! associative, commutative and idempotent, so every host's own tree over the
//! same foundations stands for the same set, and nobody needs anybody else's.
//! A MERGE another key signed stays in the store and is never folded: it adds
//! no support, no consumer edge, no owner, and moves no frontier, so it cannot
//! widen what a node stands for. That closes support injection by other keys,
//! for records whose signatures were checked when they entered the store: the
//! fold compares the signer's public key with the host and verifies nothing.
//! Network ingress verifies every record; native pile replay and an object
//! store's listing decode their own persisted bytes without checking
//! signatures again, so a frame naming the host's key with a bad signature,
//! put there by `cat` or by anyone who can write the bucket, is believed. It
//! also says nothing about a bug in the host's own computation, whose merges
//! are believed as signed. An index without a host believes no MERGE at all,
//! and its frontier is every believed foundation. A MAP is believed on the
//! same ground as a MERGE, the host's key alone: an attachment adds no data.
//! Whether its node is believed is the reader's question, answered by
//! reaching the node in the parent's lattice; the fold stays collection-local.
//!
//! An attached collection has no foundations and no lattice of its own. A
//! COMMIT, DERIVE or MERGE aimed at one attests nothing and is dropped, not
//! parked: its descriptor names no policy, so nothing could ever admit it.
//!
//! Coverage is collection-local. Every row is keyed by its own collection and
//! every support is a set of that collection's own foundations: commit
//! payloads in a root, leaf images in a derived collection. No attestation
//! reads a row of another collection; the only link between a derived
//! collection and its source is the locator in each DERIVE, which the fold
//! publishes in [`Coverage::leaf_outputs`] and nowhere follows. Whether a
//! collection is a root or derived is still resolved, for one reason: a
//! COMMIT into a derived collection and a DERIVE into a root attest nothing.
//!
//! The representation is a doubly nested PATCH: the outer trie maps a result
//! payload handle to an inner trie of foundation handles. Nesting, not a flat
//! `result ‖ foundation` key, is what preserves structural sharing — two nodes
//! covering the same foundations share one inner root, and set operations
//! between nodes are then PATCH union and intersection over shared subtries
//! rather than per-member work.
//!
//! Beside the supports the fold keeps each collection's *frontier*: the nodes
//! whose support no driven MERGE of that collection has consumed. A MERGE takes
//! every input that is not its result off and puts its result on; a COMMIT or
//! a DERIVE puts its own node on. That is the set a reader attaches, and it
//! makes a read a lookup: the frontier, one support per frontier node, and
//! their union. It also keeps, per foundation, who produced it
//! ([`Coverage::owners`]), per derived collection which source locators have a
//! leaf, and the host's joins, so a reader finds the producers of a node by
//! its own key ([`Coverage::producers`]).
//!
//! Nothing here is persisted. The index is rebuilt by replaying the records a
//! store already holds, which is affordable precisely because the fold is a
//! union.
//!
//! # A record is reduced the moment it arrives
//!
//! [`CoverageIndex::apply`] keeps no record. It reduces one to the
//! [`Attestation`] it makes and its signer, and drops the signature and the
//! metadata. Those exist to decide whether an attestation may be believed;
//! once that is decided, nothing downstream has a use for them. Holding
//! records here would be the reified-record habit wearing an index for a
//! costume.
//!
//! # Attestations that cannot be applied yet
//!
//! Two things can be missing when a record arrives: the evidence that a
//! foundation's signer may write its collection, and the coverage rows of a
//! merge's inputs. Both are open-world absences — a proof or an input can
//! still arrive later — so a foundation that cannot be admitted is parked, a
//! host merge whose input has no support yet is blocked, and each is retried
//! when what it waits on arrives. The admission backlog therefore holds only
//! foundations; a host merge waits on its inputs alone.
//!
//! # Validate once, then walk
//!
//! Admission is checked here, at fold time, and never again. Consumers read
//! coverage rows without re-deciding whether the edges that built them were
//! authorized: that decision is already baked into which unions happened.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;

use crate::inline::encodings::ed25519::ED25519PublicKey;
use crate::inline::Inline;
use crate::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
use crate::repo::{BlobStoreGet, CapabilityProofRead};

use super::api::AdmissionEvidence;
use super::records::{
    CollectionData, CollectionHandle, CollectionRecord, MergeInputs, SourceLocator,
};
#[cfg(test)]
use super::store::CollectionRead;
use crate::capability::QuorumOutcome;

/// The foundations of its own collection one lattice node covers: commit
/// payloads in a root, leaf outputs in a derived collection.
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

/// Three 32-byte segments, so a prefix of one or two segments enumerates the
/// third.
mod triple_key {
    crate::key_segmentation!(Segments, 96, [32, 32, 32]);
    crate::key_schema!(Schema, Segments, 96, [0, 1, 2]);
}

/// The believed joins of one collection that cannot be driven yet, keyed by
/// [`edge_key`] (result, then the digest of the input set), so two joins
/// naming one result are tracked apart.
type BlockedJoins = PATCH<64, IdentitySchema, ()>;

/// `collection || node || signer`: who produced each believed foundation or
/// leaf. A join records no owner.
type OwnerSet = PATCH<96, triple_key::Schema, ()>;
/// `collection || locator || output`: every believed leaf of a derived
/// collection, keyed by the locator of the source foundation it maps.
type LeafSet = PATCH<96, triple_key::Schema, ()>;
/// `attached || node || attachment`: every believed MAP, keyed by the parent
/// node it indexes.
type AttachmentSet = PATCH<96, triple_key::Schema, ()>;

/// One immutable observation of downward coverage.
///
/// This is the half of [`CoverageIndex`] a reader needs, and it is persistent
/// PATCH roots, so publishing it into a snapshot is a constant-time clone
/// rather than a copy of the fold's bookkeeping. The builder's consumer map
/// and backlog exist to keep the index growing incrementally; nothing that
/// only asks questions has any use for them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Coverage {
    rows: PATCH<64, IdentitySchema, CoverageSet>,
    /// Per collection, the nodes a reader attaches: those with a support that
    /// no driven MERGE of the same collection has consumed. Kept beside the
    /// supports by the same fold, so a read is a lookup and not a walk over
    /// the records that produced the lattice.
    frontiers: PATCH<32, IdentitySchema, FrontierSet>,
    /// Per collection, the believed merges that could not be driven yet
    /// because an input of the same collection has no support: a record that
    /// arrived ahead of its input. Keyed per join, not per result, so the
    /// set depends only on which records are believed, never on the order
    /// they arrived in; a collection with none has no entry at all. Only
    /// that collection's own records can unblock them.
    blocked: PATCH<32, IdentitySchema, BlockedJoins>,
    /// `collection || node || signer` for every believed foundation and
    /// leaf: the signer of each COMMIT or DERIVE that produced the node. A
    /// join records no owner: every join the index believes is the host's.
    owners: OwnerSet,
    /// `collection || locator || output` for every believed leaf. Answers
    /// "has the source foundation with this locator been derived into this
    /// collection, and to what?" by the DERIVE relation's own key.
    leaves: LeafSet,
    /// `collection || result || join digest -> inputs`: every join of the
    /// host's the index believes, stored once. A join another key signed
    /// never reaches it, and a host join parked but not decided yet is kept
    /// apart until it is, so [`Self::producers`] reads exactly the driven
    /// ones by their result, the MERGE relation's own key.
    joins: Joins,
    /// `attached || node || attachment` for every believed MAP: the host's
    /// own attachments, keyed by the node they index. No support is kept:
    /// an attachment stands for its node's support in the parent.
    attachments: AttachmentSet,
}

/// One row's key: the collection a node belongs to, then the node itself.
///
/// A payload handle is not a lattice coordinate on its own. Content
/// addressing makes the same bytes the same handle everywhere, but the
/// foundations underneath a node belong to one collection, and foundations
/// from two collections are not comparable — so scoping the row by its
/// collection is what keeps an unrelated lattice from putting its members in
/// this one. It costs nothing in sharing, because the foundation set is a
/// separate nested trie either way, and two nodes that genuinely cover the
/// same foundations still share one inner root.
fn row_key(collection: CollectionHandle, node: CollectionData) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&collection.raw);
    key[32..].copy_from_slice(&node.raw);
    key
}

fn triple(first: [u8; 32], second: [u8; 32], third: [u8; 32]) -> [u8; 96] {
    let mut key = [0u8; 96];
    key[..32].copy_from_slice(&first);
    key[32..64].copy_from_slice(&second);
    key[64..].copy_from_slice(&third);
    key
}

impl Coverage {
    /// The foundations this node covers within that collection, if any
    /// admitted record has attested it.
    ///
    /// An absent row and an empty row are different answers: absent means no
    /// admitted attestation names this payload as a result in this collection.
    pub fn of(&self, collection: CollectionHandle, node: CollectionData) -> Option<&CoverageSet> {
        self.rows.get(&row_key(collection, node))
    }

    /// Whether this node is known to cover that foundation of its collection.
    pub fn covers(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
        foundation: CollectionData,
    ) -> bool {
        self.of(collection, node)
            .is_some_and(|coverage| coverage.get(&foundation.raw).is_some())
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
    /// These are the nodes a reader attaches. A MERGE takes every input that
    /// is not its own result off the frontier and puts its result on; a
    /// COMMIT or a DERIVE puts its own node on. Records may arrive in any
    /// order, so a node is only put on when no MERGE that has already been
    /// driven consumes it. A node whose support another frontier node also
    /// covers stays until a MERGE consumes it: the frontier is about
    /// consumption, and a reader that wants the narrowest cover compares
    /// supports.
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
    /// a reader attaching that frontier stands on, a set of that collection's
    /// own foundations. Frontier nodes without a support cannot exist, so the
    /// reported list is always empty; it is kept for symmetry with
    /// [`Self::union_over`].
    pub fn frontier_support(
        &self,
        collection: CollectionHandle,
    ) -> (CoverageSet, Vec<CollectionData>) {
        let nodes: Vec<_> = self.frontier(collection).collect();
        self.union_over(collection, nodes)
    }

    /// Whether any believed merge of this collection is still waiting for an
    /// input's support: a record ahead of its input. Only this collection's
    /// own records can move it.
    pub fn has_blocked(&self, collection: CollectionHandle) -> bool {
        self.blocked
            .get(&collection.raw)
            .is_some_and(|blocked| !blocked.is_empty())
    }

    /// The input sets of the host's driven joins of `collection` that
    /// produce `node`, in ascending order of their input digest.
    ///
    /// One prefix scan of the joins table on `collection || node`: the MERGE
    /// relation read by its own key, no record selected and nothing
    /// computed to look it up. Only believed joins are published -- a host
    /// join parked but not decided yet, in a collection nobody has settled,
    /// is not -- and a believed join still waiting for an input's support
    /// is skipped, so every input set named here has a support for each of
    /// its inputs, whether or not the caller settled `collection`. Only the
    /// host's joins are ever stored, so a MERGE another key signed is never
    /// a producer. An absorption `MERGE(a, node) -> node`
    /// names `node` among its own inputs; a caller descending through
    /// producers skips it there.
    pub fn producers(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
    ) -> Vec<MergeInputs> {
        let prefix = row_key(collection, node);
        let mut digests = Vec::new();
        self.joins.infixes(&prefix, |digest: &[u8; 32]| {
            digests.push(*digest);
        });
        let blocked = self.blocked.get(&collection.raw);
        digests
            .into_iter()
            .filter(|digest| {
                let mut edge = [0u8; 64];
                edge[..32].copy_from_slice(&node.raw);
                edge[32..].copy_from_slice(digest);
                blocked.map_or(true, |blocked| blocked.get(&edge).is_none())
            })
            .filter_map(|digest| {
                self.joins
                    .get(&triple(collection.raw, node.raw, digest))
                    .copied()
            })
            .collect()
    }

    /// Every signer of a believed COMMIT or DERIVE that produced this node,
    /// ascending. A node only a join produced has none.
    pub fn owners(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
    ) -> Vec<Inline<ED25519PublicKey>> {
        let mut prefix = [0u8; 64];
        prefix[..32].copy_from_slice(&collection.raw);
        prefix[32..].copy_from_slice(&node.raw);
        let mut owners = Vec::new();
        self.owners.infixes(&prefix, |signer: &[u8; 32]| {
            owners.push(Inline::new(*signer));
        });
        owners.sort_unstable_by(|left, right| left.raw.cmp(&right.raw));
        owners
    }

    /// Whether `signer` signed a believed record that produced this node.
    pub fn owned_by(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
        signer: Inline<ED25519PublicKey>,
    ) -> bool {
        self.owners
            .get(&triple(collection.raw, node.raw, signer.raw))
            .is_some()
    }

    /// Whether a believed leaf of `collection` maps the source foundation
    /// with this locator.
    pub fn has_leaf(&self, collection: CollectionHandle, locator: SourceLocator) -> bool {
        let mut prefix = [0u8; 64];
        prefix[..32].copy_from_slice(&collection.raw);
        prefix[32..].copy_from_slice(locator.as_bytes());
        self.leaves.has_prefix(&prefix)
    }

    /// The outputs believed leaves of `collection` give the source foundation
    /// with this locator, ascending. One, unless writers disagree.
    pub fn leaf_outputs(
        &self,
        collection: CollectionHandle,
        locator: SourceLocator,
    ) -> Vec<CollectionData> {
        let mut prefix = [0u8; 64];
        prefix[..32].copy_from_slice(&collection.raw);
        prefix[32..].copy_from_slice(locator.as_bytes());
        let mut outputs = Vec::new();
        self.leaves.infixes(&prefix, |output: &[u8; 32]| {
            outputs.push(Inline::new(*output));
        });
        outputs.sort_unstable_by(|left, right| left.raw.cmp(&right.raw));
        outputs
    }

    /// Every believed leaf of `collection` as `(locator, output)`, ascending.
    pub fn leaves(&self, collection: CollectionHandle) -> Vec<(SourceLocator, CollectionData)> {
        let mut locators = Vec::new();
        self.leaves.infixes(&collection.raw, |locator: &[u8; 32]| {
            locators.push(SourceLocator::from_raw(*locator));
        });
        locators.sort_unstable();
        let mut leaves = Vec::new();
        for locator in locators {
            for output in self.leaf_outputs(collection, locator) {
                leaves.push((locator, output));
            }
        }
        leaves
    }

    /// The attachments the host's believed MAPs give `node` in `attached`,
    /// ascending. One, unless the host mapped the node twice to different
    /// bytes. Whether the node itself is believed is not asked here: a
    /// reader reaches it in the parent's lattice first.
    pub fn attachments(
        &self,
        attached: CollectionHandle,
        node: CollectionData,
    ) -> Vec<CollectionData> {
        let prefix = row_key(attached, node);
        let mut attachments = Vec::new();
        self.attachments.infixes(&prefix, |attachment: &[u8; 32]| {
            attachments.push(Inline::new(*attachment));
        });
        attachments.sort_unstable_by(|left, right| left.raw.cmp(&right.raw));
        attachments
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
    /// This payload is a foundation of a root collection, on its own
    /// authority: a COMMIT.
    Foundation { data: CollectionData },
    /// This output is a foundation of a derived collection: the image of the
    /// source foundation named by `locator`. A DERIVE.
    Leaf {
        locator: SourceLocator,
        output: CollectionData,
    },
    /// This result is the join of these distinct nodes of the same lattice:
    /// a MERGE. The result may be one of the inputs.
    Join {
        inputs: MergeInputs,
        result: CollectionData,
    },
    /// This attachment indexes this node of the attached collection's
    /// parent: a MAP. It is no node of any lattice and widens no support.
    Attachment {
        node: CollectionData,
        attachment: CollectionData,
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
            CollectionRecord::Merge(merge) => Self::Join {
                inputs: merge.merge_inputs(),
                result: merge.result(),
            },
            CollectionRecord::Derive(derive) => Self::Leaf {
                locator: derive.input(),
                output: derive.output(),
            },
            CollectionRecord::Map(map) => Self::Attachment {
                node: map.node(),
                attachment: map.attachment(),
            },
        }
    }

    /// The node whose coverage this attestation widens, or for an
    /// attachment the blob it produces, which widens nothing.
    pub fn result(&self) -> CollectionData {
        match self {
            Self::Foundation { data } => *data,
            Self::Leaf { output, .. } => *output,
            Self::Join { result, .. } => *result,
            Self::Attachment { attachment, .. } => *attachment,
        }
    }

    /// The nodes of its own collection whose coverage this attestation reads:
    /// a join's inputs, and nothing for a foundation, a leaf or an
    /// attachment.
    fn inputs(&self) -> &[CollectionData] {
        match self {
            Self::Join { inputs, .. } => inputs.as_slice(),
            Self::Foundation { .. } | Self::Leaf { .. } | Self::Attachment { .. } => &[],
        }
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

/// What the fold must know about a collection before it can believe a
/// foundation naming it: whether it is a root, derived or attached, and
/// whether this signer may write it.
///
/// Admission is asked only for COMMIT and DERIVE. A MERGE or a MAP is
/// believed on the index's host key alone, with no WRITE check: neither adds
/// a foundation, and whether a merge's inputs are believed is the fold's own
/// question. A MERGE still asks [`Self::source`], so that one aimed at an
/// attached collection is dropped. Implementors do the descriptor and
/// capability work; this module only asks, and only once per foundation.
pub trait RecordAdmission {
    /// The collection this one derives from, if any.
    ///
    /// The fold reads only the kind from this: a COMMIT into a derived
    /// collection and a DERIVE into a root attest nothing. No row of the
    /// source is ever read.
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
    /// The descriptor names no source: this collection is a root.
    Root,
    /// The collection this one derives from.
    Derived(CollectionHandle),
    /// An attached collection: an index of another collection's nodes. It
    /// holds no foundations and no merges; only a MAP attests anything about
    /// it.
    Attached,
    /// This descriptor is not resident, so the question has no answer yet. An
    /// absence, not a refusal — the blob may still arrive.
    Missing(CollectionHandle),
}

/// Admits every signer and treats every collection as a root.
///
/// For stores that carry no admission evidence, and for exercising the fold
/// on its own — where each test collection is a root of its own, which is
/// exactly what makes cross-collection aliasing visible.
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
    /// A blob this decision reads is not resident: the collection's own
    /// descriptor, or a policy definition it names. Retry when it lands.
    Lineage(CollectionHandle),
    /// No capability proof admits this signer to write yet. Retry when a
    /// proof arrives.
    Proof(Inline<ED25519PublicKey>),
}

/// The joins that read one input, one key per distinct join: [`edge_key`],
/// the join's result and the digest of its input set. Every edge is
/// collection-local: the consumer map's own key names the collection. The
/// join's inputs are not copied here; they live once in the index's joins
/// table under `collection || edge key`. Recording the k-th edge of a node
/// costs one path, not a copy of the other k-1, and not a copy of the join.
type Edges = PATCH<64, IdentitySchema, ()>;
/// Collection-scoped input handle to the joins that read it.
type Consumers = PATCH<64, IdentitySchema, Edges>;
/// The attestations held under one awaited thing, one key each: a
/// [`parked_key`] names the collection, the signer, the result, the kind and
/// the locator or join digest, which is the whole attestation but a join's
/// inputs, and those are in the joins table. The same shape as [`Edges`], for
/// the same reason.
type Held = PATCH<160, IdentitySchema, ()>;
/// Attestations held until one named thing arrives, keyed by that thing.
type Waiters = PATCH<32, IdentitySchema, Held>;
/// `collection || result || join digest -> inputs`: every host join the
/// index has been handed, stored once. A MERGE carries a fixed 16-slot input
/// array; copying it into every consumer edge and every parked entry made a
/// k-input join cost k+1 copies of it. Three segments, so the joins
/// producing one node are a prefix scan on `collection || result`.
type Joins = PATCH<96, triple_key::Schema, MergeInputs>;

/// A fixed-width name for one join's input set: BLAKE3 over the inputs in
/// order. Only an index key, so two joins with the same result and different
/// inputs stay two entries; never a lookup target computed from outside.
fn join_digest(inputs: &MergeInputs) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for input in inputs.iter() {
        hasher.update(&input.raw);
    }
    *hasher.finalize().as_bytes()
}

/// What identifies a join under one of its inputs: its result and its input
/// set.
fn edge_key(attestation: &Attestation) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&attestation.result().raw);
    if let Attestation::Join { inputs, .. } = attestation {
        key[32..].copy_from_slice(&join_digest(inputs));
    }
    key
}

/// Where one join's inputs are kept: its collection, then its [`edge_key`].
fn join_key(collection: CollectionHandle, edge: &[u8; 64]) -> [u8; 96] {
    let mut key = [0u8; 96];
    key[..32].copy_from_slice(&collection.raw);
    key[32..].copy_from_slice(edge);
    key
}

/// The kind byte of a [`parked_key`].
const PARKED_FOUNDATION: u8 = 1;
const PARKED_LEAF: u8 = 2;
const PARKED_JOIN: u8 = 3;
const PARKED_ATTACHMENT: u8 = 4;

/// What identifies a parked attestation: the collection and signer that
/// would believe it, its result, its kind, and what distinguishes it among
/// attestations of that kind with the same result -- a leaf's locator, a
/// join's input set or an attachment's node. Together with the joins table
/// this is the whole entry, which is why a held entry is a key and nothing
/// else.
fn parked_key(entry: &Parked) -> [u8; 160] {
    let mut key = [0u8; 160];
    key[..32].copy_from_slice(&entry.collection.raw);
    key[32..64].copy_from_slice(&entry.signer.raw);
    key[64..96].copy_from_slice(&entry.attestation.result().raw);
    match &entry.attestation {
        Attestation::Foundation { .. } => key[96] = PARKED_FOUNDATION,
        Attestation::Leaf { locator, .. } => {
            key[96] = PARKED_LEAF;
            key[128..].copy_from_slice(locator.as_bytes());
        }
        Attestation::Join { inputs, .. } => {
            key[96] = PARKED_JOIN;
            key[128..].copy_from_slice(&join_digest(inputs));
        }
        Attestation::Attachment { node, .. } => {
            key[96] = PARKED_ATTACHMENT;
            key[128..].copy_from_slice(&node.raw);
        }
    }
    key
}

fn segment(key: &[u8], at: usize) -> [u8; 32] {
    key[at..at + 32]
        .try_into()
        .expect("a key segment is 32 bytes")
}

/// The collection a [`parked_key`] names.
fn parked_collection(key: &[u8; 160]) -> CollectionHandle {
    Inline::new(segment(key, 0))
}

/// The result a [`parked_key`] names.
fn parked_result(key: &[u8; 160]) -> CollectionData {
    Inline::new(segment(key, 64))
}

/// Every key held in one waiter map.
fn held_keys(held: &Held) -> impl Iterator<Item = [u8; 160]> + '_ {
    held.iter_ordered().copied()
}

/// Downward coverage for every lattice node a store has admitted.
///
/// Every part of this is a persistent PATCH root, so the whole index -- not
/// only its published half -- is a constant-time clone. That is what lets a
/// snapshot carry the index rather than a copy of the rows, and what lets a
/// reader compose on top of one: clone it, park a few more records, settle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CoverageIndex {
    /// The key whose MERGEs this index believes, constant for its life.
    ///
    /// It lives here rather than in [`RecordAdmission`] for two reasons:
    /// replay parks records before any admission exists, and one index is
    /// shared by every snapshot and reader of a store, so the key is one
    /// value per store. `None` believes no MERGE: the lattice is its
    /// foundations and the frontier is all of them.
    host: Option<Inline<ED25519PublicKey>>,
    /// The half a reader sees: rows, frontiers, owners, leaves and the
    /// host's joins.
    published: Coverage,
    /// Which joins read each input, so a row that grows can re-drive its
    /// consumers instead of forcing a full replay.
    consumers: Consumers,
    /// Waiting on a descriptor or definition blob, keyed by that blob's handle.
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
    /// The inputs of each host join parked in `fresh`, until it is decided.
    /// Kept apart from the published joins, so a reader of a collection
    /// nobody has settled is never shown a join nobody has believed.
    fresh_joins: Joins,
}

/// The keys of one collection's parked attestations in a waiter map.
///
/// The map is keyed by the awaited evidence rather than by collection, because
/// that is what lets a drain cost the events that happened rather than the size
/// of the backlog. So a per-collection question is a scan of the backlog, which
/// is the right trade for a view: the backlog is small in the steady state, and
/// re-keying it to make this cheaper would make the drain expensive instead.
fn parked_in(
    waiters: &Waiters,
    collection: CollectionHandle,
) -> impl Iterator<Item = [u8; 160]> + '_ {
    waiters
        .iter_ordered()
        .filter_map(|key| waiters.get(key))
        .flat_map(held_keys)
        .filter(move |key| parked_collection(key) == collection)
}

/// How many attestations a waiter map holds.
fn waiting(waiters: &Waiters) -> usize {
    waiters
        .iter_ordered()
        .map(|key| waiters.get(key).map_or(0, |held| held.len() as usize))
        .sum()
}

/// Move every held key out of a waiter map.
fn drain(waiters: Waiters, into: &mut Vec<[u8; 160]>) {
    for key in waiters.iter_ordered() {
        if let Some(entries) = waiters.get(key) {
            into.extend(held_keys(entries));
        }
    }
}

impl CoverageIndex {
    /// An index covering nothing, with no host: it believes no MERGE, so
    /// every believed foundation stays on its collection's frontier.
    pub fn new() -> Self {
        Self::default()
    }

    /// An index covering nothing that believes the MERGEs `host` signed,
    /// and no other key's.
    pub fn for_host(host: Inline<ED25519PublicKey>) -> Self {
        Self::with_host(Some(host))
    }

    /// An index covering nothing, with or without a host.
    pub fn with_host(host: Option<Inline<ED25519PublicKey>>) -> Self {
        Self {
            host,
            ..Self::default()
        }
    }

    /// The key whose MERGEs this index believes, if any.
    pub fn host(&self) -> Option<Inline<ED25519PublicKey>> {
        self.host
    }

    /// Whether this index folds an attestation at all: a foundation or a
    /// leaf always (admission decides it later), a join or an attachment
    /// only when the host signed it. Anything else is dropped before it
    /// touches any table, so another key's MERGE never reaches joins, the
    /// backlog, consumer edges, owners, blocked joins, rows or a frontier.
    fn folds(&self, attestation: &Attestation, signer: Inline<ED25519PublicKey>) -> bool {
        match attestation {
            Attestation::Join { .. } => self.host == Some(signer),
            Attestation::Foundation { .. } | Attestation::Leaf { .. } => true,
            // An attachment is the host's own index, like its merges.
            Attestation::Attachment { .. } => self.host == Some(signer),
        }
    }

    /// Keep a parked host join's inputs, once, where its parked key finds
    /// them, and say whether it still needs a decision: a join already
    /// believed does not. Idempotent: `insert` keeps an existing entry.
    fn keep_fresh_join(&mut self, collection: CollectionHandle, attestation: &Attestation) -> bool {
        let Attestation::Join { inputs, .. } = attestation else {
            return true;
        };
        let key = join_key(collection, &edge_key(attestation));
        if self.published.joins.get(&key).is_some() {
            return false;
        }
        self.fresh_joins.insert(&Entry::with_value(&key, *inputs));
        true
    }

    /// Publish a believed host join's inputs, once, where its consumer edges
    /// and readers find them, and forget its parked copy.
    fn publish_join(&mut self, collection: CollectionHandle, attestation: &Attestation) {
        if let Attestation::Join { inputs, .. } = attestation {
            let key = join_key(collection, &edge_key(attestation));
            self.fresh_joins.remove(&key);
            self.published
                .joins
                .insert(&Entry::with_value(&key, *inputs));
        }
    }

    /// The believed join one edge of `collection` names, read back from the
    /// joins table.
    fn edge_join(&self, collection: CollectionHandle, edge: &[u8; 64]) -> Option<Attestation> {
        let inputs = *self.published.joins.get(&join_key(collection, edge))?;
        Some(Attestation::Join {
            inputs,
            result: Inline::new(segment(edge, 0)),
        })
    }

    /// The whole parked entry a held key stands for.
    fn parked_entry(&self, key: &[u8; 160]) -> Option<Parked> {
        let collection = parked_collection(key);
        let result = parked_result(key);
        let attestation = match key[96] {
            PARKED_FOUNDATION => Attestation::Foundation { data: result },
            PARKED_LEAF => Attestation::Leaf {
                locator: SourceLocator::from_raw(segment(key, 128)),
                output: result,
            },
            PARKED_JOIN => {
                let mut edge = [0u8; 64];
                edge[..32].copy_from_slice(&result.raw);
                edge[32..].copy_from_slice(&key[128..]);
                // A parked copy of a join believed since is read back from
                // the published table; deciding it again changes nothing.
                let key = join_key(collection, &edge);
                let inputs = *self
                    .fresh_joins
                    .get(&key)
                    .or_else(|| self.published.joins.get(&key))?;
                Attestation::Join { inputs, result }
            }
            PARKED_ATTACHMENT => Attestation::Attachment {
                node: Inline::new(segment(key, 128)),
                attachment: result,
            },
            _ => return None,
        };
        Some(Parked {
            collection,
            attestation,
            signer: Inline::new(segment(key, 32)),
        })
    }

    /// The whole parked entries a list of held keys stands for.
    fn parked_entries(&self, keys: Vec<[u8; 160]>) -> Vec<Parked> {
        keys.iter()
            .filter_map(|key| self.parked_entry(key))
            .collect()
    }

    /// The believed joins of `collection` that read `node`, each as its
    /// input set and result, ascending by result. A join still waiting for
    /// another input's support is included: it is believed, not driven.
    ///
    /// This is the consumer side of the MERGE relation, read by its own key:
    /// what a maintainer asks to find whether a join of exactly these nodes
    /// is already believed, without computing anything to look it up. Every
    /// join here is the host's.
    pub fn joins_reading(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
    ) -> Vec<(MergeInputs, CollectionData)> {
        let Some(edges) = self.consumers.get(&row_key(collection, node)) else {
            return Vec::new();
        };
        edges
            .iter_ordered()
            .filter_map(|edge| match self.edge_join(collection, edge)? {
                Attestation::Join { inputs, result } => Some((inputs, result)),
                _ => None,
            })
            .collect()
    }

    /// Whether the index has driven the join of exactly `inputs` into
    /// `result` in `collection`: it is believed, and every input has a
    /// support, so the join stands for their union. A believed join still
    /// waiting for an input is not driven; [`Self::joins_reading`] still
    /// names it.
    ///
    /// A raw MERGE is not a belief: a store keeps MERGEs other keys signed,
    /// and those never reach the index. Only believed joins have consumer
    /// edges, so this reads the edges of the join's first input, the MERGE
    /// relation by its own key, looks for this one among them, and asks
    /// whether that edge is still blocked on an input.
    pub fn drives_join(
        &self,
        collection: CollectionHandle,
        inputs: &MergeInputs,
        result: CollectionData,
    ) -> bool {
        let Some(first) = inputs.iter().next() else {
            return false;
        };
        let Some(edges) = self.consumers.get(&row_key(collection, first)) else {
            return false;
        };
        let blocked = self.published.blocked.get(&collection.raw);
        edges.iter_ordered().any(|edge| {
            matches!(
                self.edge_join(collection, edge),
                Some(Attestation::Join { inputs: read, result: produced })
                    if read == *inputs && produced == result
            ) && blocked.map_or(true, |blocked| blocked.get(edge).is_none())
        })
    }

    /// How many distinct joins the index keeps inputs for, believed or
    /// still fresh: one entry per join, whatever its arity or the number of
    /// its edges and parked copies. Only the host's joins are ever kept.
    pub fn stored_joins(&self) -> usize {
        let stored = self.published.joins.len() + self.fresh_joins.len();
        stored.min(usize::MAX as u64) as usize
    }

    /// The foundations this node covers, if any admitted record has attested
    /// it.
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

    /// Whether this node is known to cover that foundation.
    pub fn covers(
        &self,
        collection: CollectionHandle,
        node: CollectionData,
        foundation: CollectionData,
    ) -> bool {
        self.published.covers(collection, node, foundation)
    }

    /// The immutable observation to hand a reader.
    ///
    /// A constant-time clone: persistent PATCH roots, none of the fold's
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
        !self.awaiting_lineage.is_empty()
            || !self.awaiting_proof.is_empty()
            || !self.fresh.is_empty()
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
            .map(|key| parked_result(&key))
            .collect()
    }

    /// The same, for attestations waiting on a descriptor or definition blob
    /// to land instead of on a proof.
    ///
    /// Kept apart from [`Self::unadmitted_in`] because the two absences have
    /// different remedies and different owners: a missing proof is a grant
    /// somebody must issue, a missing descriptor is bytes that have not
    /// replicated yet and may simply arrive.
    pub fn awaiting_lineage_in(&self, collection: CollectionHandle) -> usize {
        parked_in(&self.awaiting_lineage, collection).count()
    }

    /// Number waiting specifically on a descriptor or definition blob.
    pub fn parked_on_lineages(&self) -> usize {
        waiting(&self.awaiting_lineage)
    }

    /// Fold one record into the index, keeping only what it attests.
    ///
    /// Applying is idempotent: the same record folded twice unions the same
    /// members. Records may arrive in any order — a merge whose inputs have no
    /// row yet contributes nothing now and is retried the moment they do.
    pub fn apply<A: RecordAdmission>(&mut self, record: &CollectionRecord, admission: &A) {
        self.attest(
            record.collection(),
            Attestation::of(record),
            record.public_key(),
            admission,
        );
    }

    /// Fold one stripped attestation: a foundation subject to its signer's
    /// admission, a join only when the host signed it.
    pub fn attest<A: RecordAdmission>(
        &mut self,
        collection: CollectionHandle,
        attestation: Attestation,
        signer: Inline<ED25519PublicKey>,
        admission: &A,
    ) {
        if !self.folds(&attestation, signer) {
            return;
        }
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
        // Only the collection's kind is resolved here, never a row of another
        // collection: a foundation of a root is a COMMIT, a foundation of a
        // derived collection is a DERIVE, and the other pairing attests
        // nothing.
        match entry.attestation {
            Attestation::Attachment { .. } => {
                // A host's own attachment is believed on its key alone, like
                // its joins: no WRITE check and no descriptor. It reads no
                // row; whether its node is believed is the reader's
                // question, answered by reaching the node in the parent.
                if self.folds(&entry.attestation, entry.signer) {
                    self.believe(entry.collection, entry.attestation, entry.signer);
                }
                return;
            }
            Attestation::Join { .. } => {
                // A host's own join is believed on its key alone: no WRITE
                // check and no descriptor. It stays inside its collection
                // whatever that is, adds no foundation, and stands for
                // nothing until every input has a support, which `drive`
                // enforces all or nothing and the inputs' consumer edges
                // retry. Another key's join never gets here; the check is
                // the same one `attest` and `park` made. An attached
                // collection has no lattice: a join into one attests
                // nothing, when its descriptor says so.
                if matches!(
                    admission.source(entry.collection),
                    SourceResolution::Attached
                ) {
                    self.fresh_joins
                        .remove(&join_key(entry.collection, &edge_key(&entry.attestation)));
                    return;
                }
                if self.folds(&entry.attestation, entry.signer) {
                    self.believe(entry.collection, entry.attestation, entry.signer);
                }
                return;
            }
            Attestation::Leaf { .. } => match admission.source(entry.collection) {
                SourceResolution::Derived(_) => {}
                SourceResolution::Missing(descriptor) => {
                    // The kind is unknown until the collection's OWN
                    // descriptor lands; nothing about its source is read.
                    self.hold(Awaiting::Lineage(descriptor), entry);
                    return;
                }
                SourceResolution::Root | SourceResolution::Attached => {
                    // A derive into a root or an attached collection names
                    // no foundation of it.
                    return;
                }
            },
            Attestation::Foundation { .. } => {
                // A commit written straight into a derived or an attached
                // collection names no foundation of it. A missing descriptor
                // is decided below, where admission parks it on that blob.
                if let SourceResolution::Derived(_) | SourceResolution::Attached =
                    admission.source(entry.collection)
                {
                    return;
                }
            }
        }
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
        self.believe(entry.collection, entry.attestation, entry.signer);
    }

    fn hold(&mut self, awaiting: Awaiting, entry: Parked) {
        let (waiters, key) = match awaiting {
            Awaiting::Lineage(descriptor) => (&mut self.awaiting_lineage, descriptor.raw),
            Awaiting::Proof(signer) => (&mut self.awaiting_proof, signer.raw),
        };
        // The inner map is a persistent root: cloning it is constant time,
        // and `insert` keeps an existing entry, so the same attestation parked
        // twice is held once. `replace` on the outer map, because `insert`
        // would keep the old inner map. Only a foundation or a leaf is ever
        // held here: a host join is believed as soon as it is decided.
        let mut entries = waiters.get(&key).cloned().unwrap_or_default();
        entries.insert(&Entry::new(&parked_key(&entry)));
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
    ///
    /// A join another key signed is dropped here, before it is stored: the
    /// host is known without any admission, so nothing waits to decide it.
    /// A host join's inputs are kept apart from the published joins until
    /// it is decided, and a host join already believed is not parked again.
    pub fn park(
        &mut self,
        collection: CollectionHandle,
        attestation: Attestation,
        signer: Inline<ED25519PublicKey>,
    ) {
        if !self.folds(&attestation, signer) {
            return;
        }
        if !self.keep_fresh_join(collection, &attestation) {
            return;
        }
        let entry = Parked {
            collection,
            attestation,
            signer,
        };
        // Keyed by the collection it names, so a reader can decide one
        // collection's records and leave every other collection's parked.
        let mut held = self.fresh.get(&collection.raw).cloned().unwrap_or_default();
        held.insert(&Entry::new(&parked_key(&entry)));
        self.fresh
            .replace(&Entry::with_value(&collection.raw, held));
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
        let mut woken = Vec::new();
        drain(std::mem::take(&mut self.fresh), &mut woken);
        for handle in arrivals {
            if let Some(entries) = self.awaiting_lineage.get(&handle.raw).cloned() {
                self.awaiting_lineage.remove(&handle.raw);
                woken.extend(held_keys(&entries));
            }
        }
        if proofs_arrived {
            drain(std::mem::take(&mut self.awaiting_proof), &mut woken);
        }
        for entry in self.parked_entries(woken) {
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
        for entry in self.parked_entries(held_keys(&entries).collect()) {
            self.park(entry.collection, entry.attestation, entry.signer);
        }
    }

    /// A proof landed: every attestation waiting on a signer is fresh again,
    /// to be decided when its collection is next settled. Proofs are rare and
    /// the move is one insert per entry, without an admission query.
    pub fn wake_proofs(&mut self) {
        let mut woken = Vec::new();
        drain(std::mem::take(&mut self.awaiting_proof), &mut woken);
        for entry in self.parked_entries(woken) {
            self.park(entry.collection, entry.attestation, entry.signer);
        }
    }

    /// Decide every fresh attestation naming one of `collections`, and only
    /// those. Every collection is closed under "reads from" on its own, since
    /// no attestation reads another collection's rows, so settling a set of
    /// collections publishes the same rows a full settle would for them;
    /// every other collection's records stay parked, unpaid for.
    pub fn settle_collections<A: RecordAdmission>(
        &mut self,
        admission: &A,
        collections: &BTreeSet<CollectionHandle>,
    ) {
        let mut woken = Vec::new();
        for collection in collections {
            if let Some(entries) = self.fresh.get(&collection.raw).cloned() {
                self.fresh.remove(&collection.raw);
                woken.extend(held_keys(&entries));
            }
        }
        for entry in self.parked_entries(woken) {
            self.decide(entry, admission);
        }
    }

    /// Re-offer every parked attestation, whatever it is waiting for.
    ///
    /// The unconditional form, for a store that cannot say which evidence
    /// arrived. Correct but coarse: prefer [`Self::settle`] where the arrivals
    /// are observable.
    pub fn resolve<A: RecordAdmission>(&mut self, admission: &A) {
        let mut woken = Vec::new();
        drain(std::mem::take(&mut self.fresh), &mut woken);
        drain(std::mem::take(&mut self.awaiting_lineage), &mut woken);
        drain(std::mem::take(&mut self.awaiting_proof), &mut woken);
        for entry in self.parked_entries(woken) {
            self.decide(entry, admission);
        }
    }

    /// Fold a foundation whose collection resolves and whose signer is
    /// admitted, or a join or an attachment the host signed.
    fn believe(
        &mut self,
        collection: CollectionHandle,
        attestation: Attestation,
        signer: Inline<ED25519PublicKey>,
    ) {
        // An attachment is recorded against its node and touches nothing
        // else: no row, no frontier, no owner, no consumer edge.
        if let Attestation::Attachment { node, attachment } = attestation {
            self.published.attachments.insert(&Entry::new(&triple(
                collection.raw,
                node.raw,
                attachment.raw,
            )));
            return;
        }
        // Who produced a foundation, and for a leaf which source foundation
        // it maps: both are facts about the believed record. A join has no
        // owner to record: it is always the host's, and recording it would
        // make a foundation that is also an absorption result read as the
        // host's own foundation.
        if matches!(attestation, Attestation::Join { .. }) {
            self.publish_join(collection, &attestation);
        } else {
            self.published.owners.insert(&Entry::new(&triple(
                collection.raw,
                attestation.result().raw,
                signer.raw,
            )));
        }
        if let Attestation::Leaf { locator, output } = attestation {
            self.published.leaves.insert(&Entry::new(&triple(
                collection.raw,
                locator.raw(),
                output.raw,
            )));
        }
        for input in attestation.inputs() {
            let key = row_key(collection, *input);
            let mut edges = self.consumers.get(&key).cloned().unwrap_or_default();
            edges.insert(&Entry::new(&edge_key(&attestation)));
            self.consumers.replace(&Entry::with_value(&key, edges));
        }
        let mut grown = Vec::new();
        if self.drive(collection, attestation) == Driven::Grew {
            grown.push(attestation.result());
        }
        // A row that grew may unblock or widen the joins that read it, and
        // those may widen their own consumers in turn. Everything stays in
        // this collection. Growth is bounded by the finite set of its
        // foundations, so the worklist drains.
        while let Some(node) = grown.pop() {
            let Some(edges) = self.consumers.get(&row_key(collection, node)).cloned() else {
                continue;
            };
            for edge in edges.iter_ordered() {
                let Some(consumer) = self.edge_join(collection, edge) else {
                    continue;
                };
                if self.drive(collection, consumer) == Driven::Grew {
                    grown.push(consumer.result());
                }
            }
        }
    }

    /// Note whether one join is still waiting for an input.
    ///
    /// Keyed by the join itself ([`edge_key`]), so another route to the same
    /// result -- a foundation, a leaf, or a second join -- never clears a
    /// join that is still blocked. A join, once driven, stays drivable: rows
    /// only grow. An emptied set drops its collection's entry, so a history
    /// that blocked for a while equals one that never did.
    fn mark_blocked(
        &mut self,
        collection: CollectionHandle,
        attestation: &Attestation,
        blocked: bool,
    ) {
        let key = edge_key(attestation);
        let mut set = self
            .published
            .blocked
            .get(&collection.raw)
            .cloned()
            .unwrap_or_default();
        if blocked {
            if set.get(&key).is_some() {
                return;
            }
            set.insert(&Entry::new(&key));
        } else if set.get(&key).is_some() {
            set.remove(&key);
        } else {
            return;
        }
        if set.is_empty() {
            self.published.blocked.remove(&collection.raw);
        } else {
            self.published
                .blocked
                .replace(&Entry::with_value(&collection.raw, set));
        }
    }

    /// Union one attestation's contribution into its result row.
    ///
    /// Says whether the row grew, which is the termination condition for the
    /// propagation worklist, or whether the attestation is still blocked on
    /// an input without a support.
    fn drive(&mut self, collection: CollectionHandle, attestation: Attestation) -> Driven {
        let contribution = match attestation {
            Attestation::Foundation { data } => CoverageSet::from_keys(std::iter::once(data.raw)),
            // A leaf is a foundation of this collection: it stands for its
            // own output, and reads nothing.
            Attestation::Leaf { output, .. } => CoverageSet::from_keys(std::iter::once(output.raw)),
            // An attachment is no node of a lattice: it is never driven.
            Attestation::Attachment { .. } => return Driven::Unchanged,
            Attestation::Join { inputs, .. } => {
                // All or nothing: a join that saw only some of its inputs
                // would otherwise publish a support it never attested.
                let mut union = CoverageSet::new();
                for input in inputs.iter() {
                    let Some(row) = self.published.rows.get(&row_key(collection, input)) else {
                        self.mark_blocked(collection, &attestation, true);
                        return Driven::Blocked;
                    };
                    union.union(row.clone());
                }
                self.mark_blocked(collection, &attestation, false);
                union
            }
        };
        // Union first, then ask whether anything changed: a PATCH compares
        // by its root hash, so that question costs nothing after the union.
        let key = row_key(collection, attestation.result());
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
        self.advance_frontier(collection, attestation);
        if grew {
            Driven::Grew
        } else {
            Driven::Unchanged
        }
    }

    /// Move one collection's frontier for an attestation that has just been
    /// driven: a join takes every input that is not its result off and puts
    /// its result on, a foundation or a leaf puts its node on. Idempotent,
    /// because a driven attestation is driven again whenever one of its
    /// inputs grows. Every join driven here is the host's, so only the
    /// host's own merges ever consume a node.
    fn advance_frontier(&mut self, collection: CollectionHandle, attestation: Attestation) {
        let mut frontier = self
            .published
            .frontiers
            .get(&collection.raw)
            .cloned()
            .unwrap_or_default();
        let result = attestation.result();
        if let Attestation::Join { inputs, .. } = attestation {
            // `MERGE(a, c) -> c` is legal: it must not take its own result off.
            for input in inputs.iter() {
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
    /// result is not the node, and whose result and every other input have
    /// supports. A join that was only registered, an input still absent, has
    /// not consumed anything yet; it takes the node off the frontier when it
    /// is driven.
    fn consumed(&self, collection: CollectionHandle, node: CollectionData) -> bool {
        let Some(edges) = self.consumers.get(&row_key(collection, node)) else {
            return false;
        };
        edges
            .iter_ordered()
            .filter_map(|edge| self.edge_join(collection, edge))
            .any(|consumer| {
                let Attestation::Join { inputs, result } = consumer else {
                    return false;
                };
                result != node
                    && self
                        .published
                        .rows
                        .get(&row_key(collection, result))
                        .is_some()
                    && inputs.iter().filter(|input| *input != node).all(|input| {
                        self.published
                            .rows
                            .get(&row_key(collection, input))
                            .is_some()
                    })
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
    evidence: RefCell<
        BTreeMap<CollectionHandle, Result<(AdmissionEvidence, Vec<CollectionHandle>), Absent>>,
    >,
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

    /// Read one descriptor to see whether this collection is a root, derived
    /// or attached. The fold only needs that kind; it never reads the source
    /// or the parent.
    fn read_source(&self, collection: CollectionHandle) -> SourceResolution {
        let Ok(descriptor) = super::api::load_collection_descriptor(self.reader, collection) else {
            return SourceResolution::Missing(collection);
        };
        let facts = descriptor.fragment.facts();
        // Any parent at all makes it attached: how many it names is not the
        // fold's question.
        match super::descriptor::parents(facts) {
            Ok(parents) if !parents.is_empty() => return SourceResolution::Attached,
            Ok(_) => {}
            Err(_) => return SourceResolution::Missing(collection),
        }
        match super::descriptor::source(facts) {
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
            let descriptor = match super::api::load_collection_descriptor(self.reader, collection) {
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

/// Fold one store's whole record set into a coverage index from scratch.
///
/// The oracle an index a backend maintains across appends -- a pile does,
/// during replay -- is checked against in tests. Nothing else folds from
/// scratch: every store hands out its own index.
///
/// `host` is the key whose MERGEs the fold believes; `None` believes none.
#[cfg(test)]
pub(crate) fn coverage_of<R>(
    reader: &R,
    host: Option<Inline<ED25519PublicKey>>,
) -> Result<CoverageIndex, R::RecordsError>
where
    R: CollectionRead + BlobStoreGet + CapabilityProofRead,
{
    let mut index = CoverageIndex::with_host(host);
    for record in reader.records()? {
        index.park_record(&record?);
    }
    index.resolve(&StoreWriters::new(reader));
    Ok(index)
}

#[cfg(test)]
mod tests;
