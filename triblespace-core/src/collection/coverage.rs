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
use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;

use crate::inline::encodings::ed25519::ED25519PublicKey;
use crate::inline::Inline;
use crate::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
use crate::repo::{BlobStoreGet, CapabilityProofRead};

use super::api::AdmissionEvidence;
use super::records::{CollectionData, CollectionHandle, CollectionRecord};

/// The foundation commits one lattice node covers.
///
/// Set algebra over these is PATCH algebra: union, intersection, and difference
/// share subtries instead of copying members.
pub type CoverageSet = PATCH<32, IdentitySchema, (), Blake3Merkle>;

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admittance {
    /// The signer is admitted; the attestation may be believed.
    Admitted,
    /// No proof admits this signer yet; park the attestation under its key.
    Pending,
}

/// Decides whether one signer may write the collection an attestation names.
///
/// Implementors do the descriptor and capability work; this module only asks,
/// and only once per attestation.
pub trait RecordAdmission {
    /// Whether attestations this signer makes about this collection count.
    fn admits(&self, collection: CollectionHandle, signer: Inline<ED25519PublicKey>) -> Admittance;
}

/// Admits every signer. For stores that carry no admission evidence, and for
/// exercising the fold on its own.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdmitEveryRecord;

impl RecordAdmission for AdmitEveryRecord {
    fn admits(&self, _collection: CollectionHandle, _signer: Inline<ED25519PublicKey>) -> Admittance {
        Admittance::Admitted
    }
}

/// One attestation still waiting on the proof that admits its signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Parked {
    collection: CollectionHandle,
    attestation: Attestation,
}

/// Downward coverage for every lattice node a store has admitted.
#[derive(Debug, Default)]
pub struct CoverageIndex {
    /// Result payload handle to the foundation commits it covers.
    rows: PATCH<32, IdentitySchema, CoverageSet>,
    /// Input payload handle to the attestations that read it, so a row that
    /// grows can re-drive its consumers instead of forcing a full replay.
    consumers: BTreeMap<[u8; 32], Vec<Attestation>>,
    /// Attestations parked on a signer no proof admits yet.
    pending_on_signer: BTreeMap<[u8; 32], Vec<Parked>>,
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
    pub fn coverage(&self, node: CollectionData) -> Option<&CoverageSet> {
        self.rows.get(&node.raw)
    }

    /// Whether this node is known to cover that foundation commit.
    pub fn covers(&self, node: CollectionData, commit: CollectionData) -> bool {
        self.coverage(node)
            .is_some_and(|coverage| coverage.get(&commit.raw).is_some())
    }

    /// Number of lattice nodes with a coverage row.
    pub fn len(&self) -> usize {
        self.rows.len().min(usize::MAX as u64) as usize
    }

    /// Whether any node has a coverage row.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Whether any attestation is waiting on an admission decision.
    ///
    /// A store can skip building a reader entirely when this is false, which is
    /// the steady state once a pile has been replayed once.
    pub fn has_parked(&self) -> bool {
        !self.pending_on_signer.is_empty()
    }

    /// Number of attestations parked on a signer no proof admits yet.
    pub fn parked_on_signers(&self) -> usize {
        self.pending_on_signer
            .values()
            .map(|parked| parked.len())
            .sum()
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
        if admission.admits(collection, signer) == Admittance::Pending {
            self.pending_on_signer
                .entry(signer.raw)
                .or_default()
                .push(Parked {
                    collection,
                    attestation,
                });
            return;
        }
        self.believe(attestation);
    }

    /// Record an attestation without deciding its admission yet.
    ///
    /// Replay is an index construction path, not an authorization pass: the
    /// descriptor that says who may write a collection is itself a blob that
    /// may not be resident until the pass finishes. Parking everything and
    /// deciding once at the end costs one map insert per record and removes
    /// the ordering question entirely.
    pub fn park(
        &mut self,
        collection: CollectionHandle,
        attestation: Attestation,
        signer: Inline<ED25519PublicKey>,
    ) {
        self.pending_on_signer
            .entry(signer.raw)
            .or_default()
            .push(Parked {
                collection,
                attestation,
            });
    }

    /// Reduce one record to what it attests and park it.
    pub fn park_record(&mut self, record: &CollectionRecord) {
        self.park(
            record.collection(),
            Attestation::of(record),
            record.public_key(),
        );
    }

    /// Re-offer every parked attestation to this admission oracle.
    ///
    /// Call once whenever the evidence may have changed — after a replay pass,
    /// or when new capability proofs land. Attestations this oracle still
    /// cannot admit stay parked, because a proof can always arrive later.
    pub fn resolve<A: RecordAdmission>(&mut self, admission: &A) {
        if self.pending_on_signer.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending_on_signer);
        for (signer, entries) in pending {
            let signer = Inline::new(signer);
            for entry in entries {
                self.attest(entry.collection, entry.attestation, signer, admission);
            }
        }
    }

    /// Retry every attestation parked on this signer.
    ///
    /// Call when a capability proof arrives. Draining is monotone: an
    /// attestation that becomes believable stays believable.
    pub fn admit_signer(&mut self, signer: Inline<ED25519PublicKey>) {
        let Some(parked) = self.pending_on_signer.remove(&signer.raw) else {
            return;
        };
        for entry in parked {
            self.believe(entry.attestation);
        }
    }

    /// Fold an attestation whose signer is already admitted.
    fn believe(&mut self, attestation: Attestation) {
        for input in attestation.inputs() {
            let consumers = self.consumers.entry(input.raw).or_default();
            if !consumers.contains(&attestation) {
                consumers.push(attestation);
            }
        }
        let mut grown = Vec::new();
        if self.drive(attestation) {
            grown.push(attestation.result());
        }
        // A row that grew may unblock or widen the attestations that read it,
        // and those may widen their own consumers in turn. Growth is bounded by
        // the finite set of foundation commits, so the worklist drains.
        while let Some(node) = grown.pop() {
            let Some(consumers) = self.consumers.get(&node.raw) else {
                continue;
            };
            for consumer in consumers.clone() {
                if self.drive(consumer) {
                    grown.push(consumer.result());
                }
            }
        }
    }

    /// Union one attestation's contribution into its result row.
    ///
    /// Returns whether the row actually grew — the termination condition for
    /// the propagation worklist.
    fn drive(&mut self, attestation: Attestation) -> bool {
        let mut contribution = match attestation {
            Attestation::Foundation { data } => CoverageSet::from_keys(std::iter::once(data.raw)),
            Attestation::Join { low, high, .. } => {
                let (Some(low), Some(high)) = (self.rows.get(&low.raw), self.rows.get(&high.raw))
                else {
                    // All or nothing: a join that only saw one side would
                    // otherwise publish a support it never attested.
                    return false;
                };
                let mut union = low.clone();
                union.union(high.clone());
                union
            }
            Attestation::Image { input, .. } => {
                let Some(input) = self.rows.get(&input.raw) else {
                    return false;
                };
                input.clone()
            }
        };
        let result = attestation.result();
        if let Some(existing) = self.rows.get(&result.raw) {
            if contribution.difference(existing).is_empty() {
                return false;
            }
            contribution.union(existing.clone());
        }
        self.rows
            .replace(&Entry::with_value(&result.raw, contribution));
        true
    }
}


/// Admission decided from one immutable store observation.
///
/// Evidence is discovered once per collection and cached, because a fold
/// touches the same handful of collections thousands of times and descriptor
/// resolution is the expensive half of the question. A collection whose
/// descriptor or proofs are not resident yet simply admits nobody — its
/// attestations park, and the next resolution pass retries them.
pub(crate) struct StoreWriters<'a, R> {
    reader: &'a R,
    evidence: RefCell<BTreeMap<CollectionHandle, Option<AdmissionEvidence>>>,
}

impl<'a, R: BlobStoreGet + CapabilityProofRead> StoreWriters<'a, R> {
    /// Ask this reader who may write which collection.
    pub(crate) fn new(reader: &'a R) -> Self {
        Self {
            reader,
            evidence: RefCell::new(BTreeMap::new()),
        }
    }

    fn write_evidence(&self, collection: CollectionHandle) -> bool {
        let mut cache = self.evidence.borrow_mut();
        let entry = cache.entry(collection).or_insert_with(|| {
            let descriptor = super::api::load_collection_descriptor(self.reader, collection).ok()?;
            super::api::discover_admission_evidence(
                self.reader,
                super::descriptor::admission_policies(
                    self.reader,
                    descriptor.fragment.facts(),
                    super::ACTION_WRITE,
                    None,
                ),
                super::ACTION_WRITE,
                collection,
            )
            .ok()
        });
        entry.is_some()
    }
}

impl<R: BlobStoreGet + CapabilityProofRead> RecordAdmission for StoreWriters<'_, R> {
    fn admits(&self, collection: CollectionHandle, signer: Inline<ED25519PublicKey>) -> Admittance {
        if !self.write_evidence(collection) {
            // The descriptor is not resident, so nothing is known about who may
            // write here. Absence is pending, never refusal.
            return Admittance::Pending;
        }
        let cache = self.evidence.borrow();
        let evidence = cache
            .get(&collection)
            .and_then(Option::as_ref)
            .expect("write evidence was just resolved");
        let Ok(subject) = VerifyingKey::from_bytes(&signer.raw) else {
            // A malformed key cannot be the subject of any proof, so no future
            // proof can admit it either — but the fold has no refusal state and
            // does not need one: this attestation simply never applies.
            return Admittance::Pending;
        };
        if evidence.authorizes(self.reader, subject) {
            Admittance::Admitted
        } else {
            Admittance::Pending
        }
    }
}

#[cfg(test)]
mod tests;
