//! Stateless semantic resolution for discovered collection records.
//!
//! Discovery selects canonical records from trusted local storage; foreign
//! signatures are checked at ingress. This module starts one layer later: the
//! caller chooses whether membership roots come from authorized commits or an
//! explicit payload cover, and supplies concrete encoding and mapping
//! validation for every eligible claim. Only chosen roots and positively
//! accepted equations participate in the least fixed point.
//!
//! Semantic membership is independent of local blob residency. The resolver
//! retains a compact index of active construction lineage; callers may ask the
//! separate [`collection_physical_cover`] function how a changing resident set
//! covers the stable known frontier.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

#[cfg(test)]
use crate::id::Id;
use crate::repo::{BlobStoreGet, BlobStoreMeta};

use super::{
    CollectionCommit, CollectionData, CollectionDerive, CollectionEncoding, CollectionHandle,
    CollectionMerge, CollectionOperationError, CollectionRecord, DiscoveredCollectionRecords,
};

type MemberKey = (CollectionHandle, CollectionData);
type MergeEquation = (
    CollectionHandle,
    CollectionData,
    CollectionData,
    CollectionData,
);
type DeriveEquation = (CollectionHandle, CollectionData, CollectionData);
type MergeProducer = (CollectionData, CollectionData);
type DeriveProducer = (CollectionHandle, CollectionData);

/// One claim presented for concrete semantic validation.
///
/// The claim carries its descriptor handle(s). The callback owns descriptor
/// lookup, decoding, and validation as well as all encoding- and
/// mapping-specific work, including loading and validating the bytes named by
/// each endpoint.
/// It returns [`CollectionClaimValidation::Pending`] when required blobs are
/// absent. For `Derive`, the exact source and target collection handles
/// identify the mapping; this generic layer imposes no additional scope
/// relationship. Every accepted `Derive` belongs to the canonical
/// source-to-target mapping. Its join-homomorphism law preserves the induced
/// order for the exact collection pair. The callback is the trust boundary
/// for that law: this resolver diagnoses
/// direct functional conflicts and conflicts completed by active commuting
/// squares, but does not materialize every absorption equation or globally
/// re-prove order consistency among accepted claims.
#[derive(Clone, Copy, Debug)]
pub enum CollectionValidationRequest<'a> {
    /// An authorized, locally trusted commit whose descriptor and element
    /// still need concrete validation. Returning `Accepted` without inspecting
    /// the bytes is an explicit stronger trust decision by the callback, not a
    /// guarantee supplied by this resolver.
    Commit {
        /// Eligible commit claim.
        claim: &'a CollectionCommit,
    },
    /// A merge whose descriptor, inputs, and result need exact validation.
    Merge {
        /// Structurally canonical merge claim.
        claim: &'a CollectionMerge,
    },
    /// A derivation whose endpoint representations and canonical map need
    /// validation.
    Derive {
        /// Structurally canonical derive claim.
        claim: &'a CollectionDerive,
    },
}

impl CollectionValidationRequest<'_> {
    /// Exact native record being validated.
    pub fn record(&self) -> CollectionRecord {
        match self {
            Self::Commit { claim, .. } => CollectionRecord::Commit(**claim),
            Self::Merge { claim, .. } => CollectionRecord::Merge(**claim),
            Self::Derive { claim, .. } => CollectionRecord::Derive(**claim),
        }
    }
}

/// Caller verdict for one collection claim.
///
/// `Accepted` is durable positive evidence, not a statement that endpoint
/// bytes happen to be resident at this instant. A caller that wants accepted
/// semantic knowledge to survive garbage collection must preserve that
/// evidence (or retain the validation inputs); the stateless resolver keeps no
/// registry of earlier verdicts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionClaimValidation<D> {
    /// The exact claim is semantically valid under its descriptor(s), including
    /// the collection's ACI join law and, for a derivation, the canonical
    /// mapping law.
    Accepted,
    /// Validation cannot yet conclude, commonly because an endpoint is absent.
    Pending,
    /// The exact claim is invalid, with a caller-defined deterministic
    /// diagnostic.
    Rejected(D),
}

/// One deterministic output witness in a functional conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConflictingCollectionOutput {
    /// An actual accepted record witnessing this output, when one exists.
    ///
    /// A homomorphically implied output needs no signed record. Its complete
    /// equation is given by the enclosing conflict's inputs and [`Self::data`].
    pub record: Option<CollectionRecord>,
    /// Output asserted by that claim.
    pub data: CollectionData,
}

/// Two accepted or homomorphically implied equations assign different outputs
/// to one canonical operation.
///
/// Direct conflicts include accepted equations whose inputs are not currently
/// members. Conflicts implied by a commuting square become visible once the
/// square is active; deferring either kind would make future roots expose an
/// order-dependent semantic contradiction. This is deliberately not a global
/// algebra checker: order-only contradictions outside an active commuting
/// square remain the validation callback's responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionFunctionalConflict {
    /// One commutative merge key has two results.
    Merge {
        /// Collection containing the merge.
        collection: CollectionHandle,
        /// Canonically lower input.
        low: CollectionData,
        /// Canonically higher input.
        high: CollectionData,
        /// Lowest deterministic output witness.
        first: ConflictingCollectionOutput,
        /// Next distinct deterministic output witness.
        second: ConflictingCollectionOutput,
    },
    /// One mapping assigns two outputs to the same input.
    ///
    /// The target names the mapping: its descriptor says which collection it
    /// derives from and embeds the concrete mapping, so a conflict is
    /// about one target.
    Derive {
        /// Target collection.
        target: CollectionHandle,
        /// Source element.
        input: CollectionData,
        /// Lowest deterministic output witness.
        first: ConflictingCollectionOutput,
        /// Next distinct deterministic output witness.
        second: ConflictingCollectionOutput,
    },
}

impl fmt::Display for CollectionFunctionalConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Merge {
                collection,
                low,
                high,
                first,
                second,
            } => write!(
                f,
                "collection {collection} has conflicting merge outputs {first} and {second} for ({low}, {high})",
                collection = hex::encode_upper(collection.raw),
                low = hex::encode_upper(low.raw),
                high = hex::encode_upper(high.raw),
                first = hex::encode_upper(first.data.raw),
                second = hex::encode_upper(second.data.raw),
            ),
            Self::Derive {
                target,
                input,
                first,
                second,
            } => write!(
                f,
                "derivation into {target} has conflicting outputs {first} and {second} for {input}",
                target = hex::encode_upper(target.raw),
                input = hex::encode_upper(input.raw),
                first = hex::encode_upper(first.data.raw),
                second = hex::encode_upper(second.data.raw),
            ),
        }
    }
}

impl Error for CollectionFunctionalConflict {}

/// Failure that prevents a complete semantic resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionResolutionError<E> {
    /// The validation callback failed operationally. No partial snapshot is
    /// returned.
    Validation {
        /// Exact claim being validated.
        record: CollectionRecord,
        /// Caller-defined operational failure.
        source: E,
    },
    /// Positively accepted equations violate operation functionality.
    Conflict(Box<CollectionFunctionalConflict>),
}

impl<E: fmt::Display> fmt::Display for CollectionResolutionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { record, source } => {
                write!(
                    f,
                    "collection claim {fingerprint:X} validation failed: {source}",
                    fingerprint = record.fingerprint(),
                )
            }
            Self::Conflict(conflict) => conflict.fmt(f),
        }
    }
}

impl<E: Error + 'static> Error for CollectionResolutionError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Validation { source, .. } => Some(source),
            Self::Conflict(conflict) => Some(conflict),
        }
    }
}

/// Result of one stateless resolution pass.
///
/// The status sets are ordered by exact canonical record. Unauthorized commits are
/// absent altogether: they are policy-ineligible, not pending validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionResolution<D> {
    semantics: CollectionSemantics,
    admitted_claims: BTreeSet<CollectionRecord>,
    validation_pending: BTreeSet<CollectionRecord>,
    activation_pending: BTreeSet<CollectionRecord>,
    rejected: BTreeMap<CollectionRecord, D>,
}

impl<D> CollectionResolution<D> {
    /// Resolved semantic membership, frontier, and active lineage.
    pub fn semantics(&self) -> &CollectionSemantics {
        &self.semantics
    }

    /// Consume the report and retain only resolved semantics.
    pub fn into_semantics(self) -> CollectionSemantics {
        self.semantics
    }

    /// Claims that received a positive concrete validation verdict.
    ///
    /// This includes accepted equations whose membership prerequisites are
    /// not active yet. Unauthorized commits are absent, as are pending and
    /// rejected claims. This set is a semantic result only: physical retention
    /// follows structural references from every retained native record and
    /// does not consume admission results.
    pub fn admitted_claims(&self) -> &BTreeSet<CollectionRecord> {
        &self.admitted_claims
    }

    /// Claims awaiting a positive callback verdict, commonly because a
    /// descriptor or element blob is absent.
    pub fn validation_pending(&self) -> &BTreeSet<CollectionRecord> {
        &self.validation_pending
    }

    /// Accepted equations whose membership prerequisites are not yet known.
    pub fn activation_pending(&self) -> &BTreeSet<CollectionRecord> {
        &self.activation_pending
    }

    /// Semantically invalid claims and their caller-defined diagnostics.
    pub fn rejected(&self) -> &BTreeMap<CollectionRecord, D> {
        &self.rejected
    }
}

/// Least semantic closure of selected payload roots and accepted equations.
///
/// The known order is not materialized transitively; reachability is computed
/// from asserted and commuting-square-implied equations when needed. Metadata
/// and signatures remain on the supporting commit records rather than becoming
/// inputs to the data lattice.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CollectionSemantics {
    members: BTreeMap<CollectionHandle, BTreeSet<CollectionData>>,
    frontier: BTreeMap<CollectionHandle, BTreeSet<CollectionData>>,
    root_members: BTreeSet<MemberKey>,
    commit_records_by_member: BTreeMap<MemberKey, BTreeSet<CollectionCommit>>,
    merge_inputs_by_result: BTreeMap<MemberKey, BTreeSet<MergeProducer>>,
    order_results_by_input: BTreeMap<MemberKey, BTreeSet<CollectionData>>,
    derive_inputs_by_output: BTreeMap<MemberKey, BTreeSet<DeriveProducer>>,
    derive_outputs_by_input: BTreeMap<
        (CollectionHandle, CollectionHandle),
        BTreeMap<CollectionData, BTreeSet<CollectionData>>,
    >,
}

impl CollectionSemantics {
    /// Whether `data` belongs to the collection's least known closure.
    pub fn contains(&self, collection: CollectionHandle, data: CollectionData) -> bool {
        contains_member(&self.members, collection, data)
    }

    /// All known semantic members of `collection`.
    pub fn members(&self, collection: CollectionHandle) -> Option<&BTreeSet<CollectionData>> {
        self.members.get(&collection)
    }

    /// Maximal members under active merge and mapping lineage.
    pub fn frontier(&self, collection: CollectionHandle) -> Option<&BTreeSet<CollectionData>> {
        self.frontier.get(&collection)
    }

    /// Resident source-cover members which can replace at least two currently
    /// selected target members through the known sparse order. Direct source
    /// merge producers supply optional image-join witnesses; their absence
    /// never asks maintenance to construct intermediate source or target nodes.
    pub(crate) fn source_coarsenings(
        &self,
        source: CollectionHandle,
        target: CollectionHandle,
        source_cover: &BTreeSet<CollectionData>,
        target_cover: &BTreeSet<CollectionData>,
    ) -> Vec<(CollectionData, BTreeSet<(CollectionData, CollectionData)>)> {
        let Some(mappings) = self.derive_outputs_by_input.get(&(source, target)) else {
            return Vec::new();
        };
        // Reverse only the two sparse generating orders, not their transitive
        // closures. Each candidate walks its predecessors at most once.
        let mut predecessors = BTreeMap::<MemberKey, BTreeSet<CollectionData>>::new();
        for ((collection, lower), uppers) in &self.order_results_by_input {
            if *collection == source || *collection == target {
                for upper in uppers {
                    predecessors
                        .entry((*collection, *upper))
                        .or_default()
                        .insert(*lower);
                }
            }
        }

        let mut candidates = Vec::new();
        for upper in source_cover {
            // An equal or greater image already represented by ONE selected
            // target member is not useful work. A finer decomposition of that
            // image does not satisfy this coarsening test.
            let mut seen = BTreeSet::new();
            let mut pending = vec![*upper];
            let mut covered = false;
            while let Some(member) = pending.pop() {
                if !seen.insert(member) {
                    continue;
                }
                for image in mappings.get(&member).into_iter().flatten() {
                    if target_cover.contains(image)
                        || self
                            .first_strict_subsumer_in(target, *image, target_cover)
                            .is_some()
                    {
                        covered = true;
                        break;
                    }
                }
                if covered {
                    break;
                }
                pending.extend(
                    self.order_results_by_input
                        .get(&(source, member))
                        .into_iter()
                        .flatten(),
                );
            }
            if covered {
                continue;
            }

            let mut seen_source = BTreeSet::new();
            let mut pending_source = vec![*upper];
            let mut pending_target = Vec::new();
            while let Some(member) = pending_source.pop() {
                if !seen_source.insert(member) {
                    continue;
                }
                pending_target.extend(mappings.get(&member).into_iter().flatten().copied());
                pending_source.extend(predecessors.get(&(source, member)).into_iter().flatten());
            }
            let mut seen_target = BTreeSet::new();
            let mut dominated = BTreeSet::new();
            while let Some(member) = pending_target.pop() {
                if !seen_target.insert(member) {
                    continue;
                }
                if target_cover.contains(&member) {
                    dominated.insert(member);
                }
                pending_target.extend(predecessors.get(&(target, member)).into_iter().flatten());
            }
            if dominated.len() < 2 {
                continue;
            }

            let mut image_pairs = BTreeSet::new();
            for (low, high) in self
                .merge_inputs_by_result
                .get(&(source, *upper))
                .into_iter()
                .flatten()
            {
                for left in mappings.get(low).into_iter().flatten() {
                    for right in mappings.get(high).into_iter().flatten() {
                        image_pairs.insert(ordered(*left, *right));
                    }
                }
            }
            candidates.push((*upper, image_pairs));
        }
        candidates
    }

    /// Exact authorized commit records supporting one
    /// member through every known active construction path.
    ///
    /// The traversal is computed on demand and follows derives for provenance.
    /// Multiple commits of the same data remain distinct leaves.
    pub fn supporting_commits(
        &self,
        collection: CollectionHandle,
        data: CollectionData,
    ) -> BTreeSet<CollectionCommit> {
        if !self.contains(collection, data) {
            return BTreeSet::new();
        }

        let mut supporting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut pending = vec![(collection, data)];
        while let Some(member) = pending.pop() {
            if !visited.insert(member) {
                continue;
            }
            supporting.extend(
                self.commit_records_by_member
                    .get(&member)
                    .into_iter()
                    .flatten()
                    .copied(),
            );

            if let Some(producers) = self.merge_inputs_by_result.get(&member) {
                for (low, high) in producers {
                    pending.push((member.0, *low));
                    pending.push((member.0, *high));
                }
            }
            if let Some(producers) = self.derive_inputs_by_output.get(&member) {
                for (source, input) in producers {
                    pending.push((*source, *input));
                }
            }
        }
        supporting
    }

    /// Canonical root payloads supporting one member through every known
    /// active construction path.
    ///
    /// Unlike [`Self::supporting_commits`], multiple authorized commits of
    /// the same payload collapse to one leaf. A member is a root whenever it
    /// was supplied directly, either by an accepted commit or as an explicit
    /// payload root; traversal still follows active merge and derive producers
    /// so that every known support path contributes its roots.
    pub fn supporting_data(
        &self,
        collection: CollectionHandle,
        data: CollectionData,
    ) -> BTreeSet<CollectionData> {
        self.supporting_data_for([(collection, data)])
    }

    /// Canonical root payloads supporting several members through every
    /// known active construction path.
    ///
    /// The shared traversal visits an overlapping lineage only once. Roots
    /// from every encountered collection are returned; callers interested in
    /// one lattice can intersect the result with that lattice's explicit
    /// roots.
    pub(crate) fn supporting_data_for(
        &self,
        members: impl IntoIterator<Item = (CollectionHandle, CollectionData)>,
    ) -> BTreeSet<CollectionData> {
        let members: Vec<_> = members
            .into_iter()
            .filter(|(collection, data)| self.contains(*collection, *data))
            .collect();
        if members.is_empty() {
            return BTreeSet::new();
        }

        let mut supporting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut pending = members;
        while let Some(member) = pending.pop() {
            if !visited.insert(member) {
                continue;
            }
            if self.root_members.contains(&member) {
                supporting.insert(member.1);
            }

            if let Some(producers) = self.merge_inputs_by_result.get(&member) {
                for (low, high) in producers {
                    pending.push((member.0, *low));
                    pending.push((member.0, *high));
                }
            }
            if let Some(producers) = self.derive_inputs_by_output.get(&member) {
                for (source, input) in producers {
                    pending.push((*source, *input));
                }
            }
        }
        supporting
    }

    #[cfg(test)]
    fn subsumes(
        &self,
        collection: CollectionHandle,
        lower: CollectionData,
        upper: CollectionData,
    ) -> bool {
        if lower == upper {
            return true;
        }

        let mut visited = BTreeSet::from([lower]);
        let mut pending = vec![lower];
        while let Some(input) = pending.pop() {
            for result in self
                .order_results_by_input
                .get(&(collection, input))
                .into_iter()
                .flatten()
            {
                if *result == upper {
                    return true;
                }
                if visited.insert(*result) {
                    pending.push(*result);
                }
            }
        }
        false
    }

    /// Return the first canonical candidate strictly above `lower` in the
    /// sparse generating order.
    ///
    /// One reachability walk tests membership as it goes, instead of walking
    /// the same order graph once for every candidate. The explicit exclusion
    /// of `lower` preserves the resident-frontier meaning even if malformed
    /// accepted evidence introduced a cycle.
    fn first_strict_subsumer_in(
        &self,
        collection: CollectionHandle,
        lower: CollectionData,
        candidates: &BTreeSet<CollectionData>,
    ) -> Option<CollectionData> {
        let mut visited = BTreeSet::from([lower]);
        let mut pending = vec![lower];
        while let Some(input) = pending.pop() {
            for result in self
                .order_results_by_input
                .get(&(collection, input))
                .into_iter()
                .flatten()
            {
                if visited.insert(*result) {
                    pending.push(*result);
                }
            }
        }
        visited
            .into_iter()
            .find(|candidate| *candidate != lower && candidates.contains(candidate))
    }

    fn cover_element(
        &self,
        collection: CollectionHandle,
        element: CollectionData,
        resident_frontier: &BTreeSet<CollectionData>,
        mut path: BTreeSet<CollectionData>,
    ) -> Option<BTreeSet<CollectionData>> {
        if resident_frontier.contains(&element) {
            return Some(BTreeSet::from([element]));
        }
        if let Some(upper) = self.first_strict_subsumer_in(collection, element, resident_frontier) {
            return Some(BTreeSet::from([upper]));
        }
        if !path.insert(element) {
            return None;
        }

        for (low, high) in self
            .merge_inputs_by_result
            .get(&(collection, element))
            .into_iter()
            .flatten()
        {
            let Some(mut proof) =
                self.cover_element(collection, *low, resident_frontier, path.clone())
            else {
                continue;
            };
            let Some(right) =
                self.cover_element(collection, *high, resident_frontier, path.clone())
            else {
                continue;
            };
            proof.extend(right);
            return Some(proof);
        }
        None
    }
}

/// A deterministic proof view over currently resident collection elements.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CollectionPhysicalCover {
    /// Resident semantic members selected by the first known proof.
    pub cover: BTreeSet<CollectionData>,
    /// Semantic-frontier obligations with no proof from `cover`.
    pub missing: BTreeSet<CollectionData>,
}

/// Closure-aware result of selecting a physical collection cover.
pub(crate) struct CollectionCompletePhysicalCover {
    /// Complete resident members selected for immediate interpretation.
    pub physical: CollectionPhysicalCover,
    /// Missing representation blobs selected by the best otherwise-complete
    /// hypothetical cover.
    pub dependencies: BTreeSet<CollectionData>,
    /// Unusable selected member required only when no complete or merely
    /// incomplete alternative can cover the frontier.
    pub unusable: Option<(CollectionData, CollectionOperationError)>,
}

/// Compute a deterministic, overlap-aware resident cover of one collection.
///
/// This is a pure view over a resolved semantic snapshot and a caller-supplied
/// current resident set. A resident upper member may discharge a lower merge
/// obligation even through nonresident intermediates. If no resident upper is
/// known, an unavailable result may be expanded through any active exact merge.
/// Derives are intentionally excluded: source-representation bytes do not
/// physically substitute for a missing target-representation blob.
///
/// The first proof in canonical order is returned. It is deterministic, but it
/// is not promised to be globally minimum or hardware-optimal.
pub(crate) fn collection_physical_cover(
    semantics: &CollectionSemantics,
    collection: CollectionHandle,
    resident: &BTreeSet<CollectionData>,
) -> CollectionPhysicalCover {
    let obligations = semantics.frontier(collection).cloned().unwrap_or_default();
    collection_physical_cover_for(semantics, collection, &obligations, resident)
}

/// Select a deterministic physical cover whose representation closure is
/// resident.
///
/// Validated root residency is supplied as the first filter. Only members
/// selected by the current physical proof invoke the encoding-specific
/// dependency query; each incomplete or unusable root is removed and the cover
/// is recomputed. The loop therefore performs no payload work for irrelevant
/// historical materializations and terminates after at most one retry per
/// rejected root.
pub(crate) fn collection_complete_physical_cover<E, R>(
    semantics: &CollectionSemantics,
    collection: CollectionHandle,
    root_resident: &BTreeSet<CollectionData>,
    reader: &R,
) -> CollectionCompletePhysicalCover
where
    E: CollectionEncoding,
    R: BlobStoreGet + BlobStoreMeta,
{
    let mut candidates = root_resident.clone();
    let mut incomplete = BTreeMap::<CollectionData, Vec<CollectionData>>::new();
    let mut unusable = BTreeMap::<CollectionData, CollectionOperationError>::new();

    loop {
        let physical = collection_physical_cover(semantics, collection, &candidates);
        let mut removed = false;
        for member in &physical.cover {
            match E::missing_representation_dependencies(*member, reader) {
                Ok(missing) if missing.is_empty() => {}
                Ok(missing) => {
                    candidates.remove(member);
                    incomplete.insert(*member, missing);
                    removed = true;
                }
                Err(source) => {
                    candidates.remove(member);
                    unusable.insert(*member, source);
                    removed = true;
                }
            }
        }
        if removed {
            continue;
        }
        if physical.missing.is_empty() {
            return CollectionCompletePhysicalCover {
                physical,
                dependencies: BTreeSet::new(),
                unusable: None,
            };
        }

        // Reinsert only rejected roots to explain the failed selection. A
        // missing dependency is useful only if its member participates in the
        // best hypothetical cover; unrelated historical roots stay silent.
        let mut with_incomplete = candidates.clone();
        with_incomplete.extend(incomplete.keys().copied());
        let tentative = collection_physical_cover(semantics, collection, &with_incomplete);
        let dependencies = tentative
            .cover
            .iter()
            .filter_map(|member| incomplete.get(member))
            .flatten()
            .copied()
            .collect();
        if tentative.missing.is_empty() {
            return CollectionCompletePhysicalCover {
                physical,
                dependencies,
                unusable: None,
            };
        }

        let mut with_unusable = with_incomplete;
        with_unusable.extend(unusable.keys().copied());
        let last_resort = collection_physical_cover(semantics, collection, &with_unusable);
        if last_resort.missing.is_empty() {
            if let Some(member) = last_resort
                .cover
                .iter()
                .find(|member| unusable.contains_key(*member))
                .copied()
            {
                return CollectionCompletePhysicalCover {
                    physical,
                    dependencies,
                    unusable: Some((
                        member,
                        unusable.remove(&member).expect("selected unusable member"),
                    )),
                };
            }
        }

        return CollectionCompletePhysicalCover {
            physical: CollectionPhysicalCover {
                cover: physical.cover,
                missing: tentative.missing,
            },
            dependencies,
            unusable: None,
        };
    }
}

/// Compute a resident proof for caller-selected semantic obligations.
///
/// Unlike [`collection_physical_cover`], this does not implicitly choose the
/// collection frontier. It is used when two concrete Covers must be compared
/// under the sparse join order: every obligation is discharged by an equal or
/// greater resident member, or by recursively covering both inputs of an exact
/// merge producer.
pub(crate) fn collection_physical_cover_for(
    semantics: &CollectionSemantics,
    collection: CollectionHandle,
    obligations: &BTreeSet<CollectionData>,
    resident: &BTreeSet<CollectionData>,
) -> CollectionPhysicalCover {
    let Some(members) = semantics.members(collection) else {
        return CollectionPhysicalCover {
            cover: BTreeSet::new(),
            missing: obligations.clone(),
        };
    };
    let resident_members: BTreeSet<_> = resident.intersection(members).copied().collect();
    let mut resident_frontier = BTreeSet::new();
    for candidate in &resident_members {
        if semantics
            .first_strict_subsumer_in(collection, *candidate, &resident_members)
            .is_none()
        {
            resident_frontier.insert(*candidate);
        }
    }

    let mut result = CollectionPhysicalCover::default();
    for obligation in obligations.iter().copied() {
        if !members.contains(&obligation) {
            result.missing.insert(obligation);
            continue;
        }
        match semantics.cover_element(collection, obligation, &resident_frontier, BTreeSet::new()) {
            Some(proof) => result.cover.extend(proof),
            None => {
                result.missing.insert(obligation);
            }
        }
    }
    result
}

/// Resolve authorized and concretely validated records to their least semantic
/// fixed point.
///
/// Authorization is an eligibility set over already self-signed commits; it
/// does not validate the committed element. Descriptor lookup is owned by the
/// callback; [`Pending`](CollectionClaimValidation::Pending) verdicts are
/// retried by a later stateless call. Accepted-but-ungrounded equations are
/// retained only in the returned activation-pending report, while all accepted
/// equations participate in functional conflict detection before closure.
///
/// For a fixed validation policy, verdicts must be independent of record
/// enumeration order. Under append-only discovery, nonshrinking authorization,
/// and durable accepted verdicts, roots, membership, active lineage, and
/// supporting commit sets only grow. The maximal frontier can replace lower
/// elements, and physical cover can change freely with residency.
pub fn resolve_collection_semantics<D, E, V>(
    records: &DiscoveredCollectionRecords,
    lineage: &BTreeMap<CollectionHandle, CollectionHandle>,
    authorized_commits: &BTreeSet<CollectionCommit>,
    validate: V,
) -> Result<CollectionResolution<D>, CollectionResolutionError<E>>
where
    V: for<'a> FnMut(CollectionValidationRequest<'a>) -> Result<CollectionClaimValidation<D>, E>,
{
    resolve_collection_semantics_kernel(
        records,
        lineage,
        &BTreeSet::new(),
        authorized_commits,
        validate,
    )
}

/// Resolve collection semantics from canonical payload roots.
///
/// The roots are membership facts supplied by the caller rather than signed
/// `COMMIT` claims. They seed the same merge/derive closure as commits, but do
/// do not acquire admitted-claim status or commit
/// provenance. Stored commit records are deliberately ineligible in this
/// mode; callers that need signed admission use [`resolve_collection_semantics`].
pub(crate) fn resolve_collection_semantics_from_roots<D, E, V>(
    records: &DiscoveredCollectionRecords,
    lineage: &BTreeMap<CollectionHandle, CollectionHandle>,
    explicit_roots: &BTreeSet<(CollectionHandle, CollectionData)>,
    validate: V,
) -> Result<CollectionResolution<D>, CollectionResolutionError<E>>
where
    V: for<'a> FnMut(CollectionValidationRequest<'a>) -> Result<CollectionClaimValidation<D>, E>,
{
    resolve_collection_semantics_kernel(
        records,
        lineage,
        explicit_roots,
        &BTreeSet::new(),
        validate,
    )
}

fn resolve_collection_semantics_kernel<D, E, V>(
    records: &DiscoveredCollectionRecords,
    lineage: &BTreeMap<CollectionHandle, CollectionHandle>,
    explicit_roots: &BTreeSet<(CollectionHandle, CollectionData)>,
    authorized_commits: &BTreeSet<CollectionCommit>,
    mut validate: V,
) -> Result<CollectionResolution<D>, CollectionResolutionError<E>>
where
    V: for<'a> FnMut(CollectionValidationRequest<'a>) -> Result<CollectionClaimValidation<D>, E>,
{
    let mut accepted_commits = Vec::new();
    let mut accepted_merges = Vec::new();
    let mut accepted_derives = Vec::new();
    let mut validation_pending = BTreeSet::new();
    let mut rejected = BTreeMap::new();

    for claim in records.commits() {
        if !authorized_commits.contains(claim) {
            continue;
        }
        match validate_claim(&mut validate, CollectionValidationRequest::Commit { claim })? {
            CollectionClaimValidation::Accepted => accepted_commits.push(claim),
            CollectionClaimValidation::Pending => {
                validation_pending.insert(CollectionRecord::Commit(*claim));
            }
            CollectionClaimValidation::Rejected(diagnostic) => {
                rejected.insert(CollectionRecord::Commit(*claim), diagnostic);
            }
        }
    }

    for claim in records.merges() {
        match validate_claim(&mut validate, CollectionValidationRequest::Merge { claim })? {
            CollectionClaimValidation::Accepted => accepted_merges.push(claim),
            CollectionClaimValidation::Pending => {
                validation_pending.insert(CollectionRecord::Merge(*claim));
            }
            CollectionClaimValidation::Rejected(diagnostic) => {
                rejected.insert(CollectionRecord::Merge(*claim), diagnostic);
            }
        }
    }

    for claim in records.derives() {
        match validate_claim(&mut validate, CollectionValidationRequest::Derive { claim })? {
            CollectionClaimValidation::Accepted => accepted_derives.push(claim),
            CollectionClaimValidation::Pending => {
                validation_pending.insert(CollectionRecord::Derive(*claim));
            }
            CollectionClaimValidation::Rejected(diagnostic) => {
                rejected.insert(CollectionRecord::Derive(*claim), diagnostic);
            }
        }
    }

    check_functional(
        accepted_merges.iter().map(|claim| {
            let (low, high) = claim.inputs();
            (
                (claim.collection(), low, high, claim.result()),
                Some(**claim),
            )
        }),
        accepted_derives.iter().map(|claim| {
            (
                (claim.collection(), claim.input(), claim.output()),
                Some(**claim),
            )
        }),
    )
    .map_err(CollectionResolutionError::Conflict)?;

    let admitted_claims = accepted_commits
        .iter()
        .map(|claim| CollectionRecord::Commit(**claim))
        .chain(
            accepted_merges
                .iter()
                .map(|claim| CollectionRecord::Merge(**claim)),
        )
        .chain(
            accepted_derives
                .iter()
                .map(|claim| CollectionRecord::Derive(**claim)),
        )
        .collect();

    let mut members: BTreeMap<CollectionHandle, BTreeSet<CollectionData>> = BTreeMap::new();
    let mut root_members = explicit_roots.clone();
    for (collection, data) in explicit_roots {
        members.entry(*collection).or_default().insert(*data);
    }
    let mut commit_records_by_member: BTreeMap<MemberKey, BTreeSet<CollectionCommit>> =
        BTreeMap::new();
    for commit in accepted_commits {
        members
            .entry(commit.collection())
            .or_default()
            .insert(commit.data());
        root_members.insert((commit.collection(), commit.data()));
        commit_records_by_member
            .entry((commit.collection(), commit.data()))
            .or_default()
            .insert(*commit);
    }

    loop {
        let mut changed = false;
        for claim in &accepted_merges {
            let (low, high) = claim.inputs();
            if contains_member(&members, claim.collection(), low)
                && contains_member(&members, claim.collection(), high)
            {
                changed |= members
                    .entry(claim.collection())
                    .or_default()
                    .insert(claim.result());
            }
        }
        for claim in &accepted_derives {
            let (input, output) = (claim.input(), claim.output());
            let Some(source) = lineage.get(&claim.collection()).copied() else {
                continue;
            };
            if contains_member(&members, source, input) {
                changed |= members
                    .entry(claim.collection())
                    .or_default()
                    .insert(output);
            }
        }
        if !changed {
            break;
        }
    }

    // Which collection derives from which is a property of the target's
    // DESCRIPTOR, not of any record: a derivation is one canonical join
    // mapping, and individual records are observations of that map. The
    // caller supplies the lineage because it is the party holding descriptors;
    // resolution reads records only. A caller that cannot name a target's
    // source could not check the derivation either, since the mapping lives in
    // the same descriptor.
    let homomorphisms: BTreeSet<_> = lineage
        .iter()
        .map(|(target, source)| (*source, *target))
        .collect();

    let mut activation_pending = BTreeSet::new();
    let mut active_merges = BTreeMap::<MergeEquation, Option<CollectionMerge>>::new();
    let mut active_derives = BTreeMap::<DeriveEquation, Option<CollectionDerive>>::new();

    for claim in &accepted_merges {
        let collection = claim.collection();
        let (low, high) = claim.inputs();
        if !contains_member(&members, collection, low)
            || !contains_member(&members, collection, high)
        {
            activation_pending.insert(CollectionRecord::Merge(**claim));
            continue;
        }
        active_merges
            .entry((collection, low, high, claim.result()))
            .and_modify(|record| *record = (*record).min(Some(**claim)))
            .or_insert(Some(**claim));
    }

    for claim in &accepted_derives {
        let (input, output) = (claim.input(), claim.output());
        // A derive whose target declares no source has no mapping to be an
        // instance of, so it activates nothing.
        let Some(source) = lineage.get(&claim.collection()).copied() else {
            activation_pending.insert(CollectionRecord::Derive(**claim));
            continue;
        };
        if !contains_member(&members, source, input) {
            activation_pending.insert(CollectionRecord::Derive(**claim));
            continue;
        }
        debug_assert!(contains_member(&members, claim.collection(), output));
        active_derives
            .entry((claim.collection(), input, output))
            .and_modify(|record| *record = (*record).min(Some(**claim)))
            .or_insert(Some(**claim));
    }

    close_homomorphic_squares(&homomorphisms, &mut active_merges, &mut active_derives)
        .map_err(CollectionResolutionError::Conflict)?;

    let mut semantics = CollectionSemantics {
        frontier: members.clone(),
        members,
        root_members,
        commit_records_by_member,
        ..CollectionSemantics::default()
    };

    for &(collection, low, high, result) in active_merges.keys() {
        semantics
            .merge_inputs_by_result
            .entry((collection, result))
            .or_default()
            .insert((low, high));
        for input in [low, high] {
            if input != result {
                semantics
                    .order_results_by_input
                    .entry((collection, input))
                    .or_default()
                    .insert(result);
            }
        }
    }

    for &(target, input, output) in active_derives.keys() {
        let Some(source) = lineage.get(&target).copied() else {
            continue;
        };
        semantics
            .derive_inputs_by_output
            .entry((target, output))
            .or_default()
            .insert((source, input));
        semantics
            .derive_outputs_by_input
            .entry((source, target))
            .or_default()
            .entry(input)
            .or_default()
            .insert(output);
    }

    close_homomorphic_order(
        &semantics.derive_outputs_by_input,
        &mut semantics.order_results_by_input,
    );

    // Every stored edge is strict. Its input therefore cannot be maximal;
    // ordinary graph reachability supplies the transitive order on demand.
    for ((collection, element), results) in &semantics.order_results_by_input {
        if results.is_empty() {
            continue;
        }
        semantics
            .frontier
            .get_mut(collection)
            .expect("known order collection has members")
            .remove(element);
    }

    Ok(CollectionResolution {
        semantics,
        admitted_claims,
        validation_pending,
        activation_pending,
        rejected,
    })
}

/// Lift the sparse known order through every observed mapping.
///
/// A mapped source member starts one witness. Unmapped successors carry that
/// witness upward. At the next mapped successor, the corresponding target
/// edge is recorded and traversal for that witness stops: the successor's own
/// seed represents the reset. Consequently an all-mapped chain costs one
/// visit per source edge, while two mapped endpoints still discover the order
/// relation across any number of unmapped intermediates.
///
/// Target edges can themselves be sources for another mapping, so all
/// maps are revisited until no sparse edge is added. The graph remains a
/// generating relation; its transitive closure is never materialized.
fn close_homomorphic_order(
    mappings_by_homomorphism: &BTreeMap<
        (CollectionHandle, CollectionHandle),
        BTreeMap<CollectionData, BTreeSet<CollectionData>>,
    >,
    order_results_by_input: &mut BTreeMap<MemberKey, BTreeSet<CollectionData>>,
) {
    loop {
        let mut changed = false;
        for ((source, target), mappings) in mappings_by_homomorphism {
            let additions =
                nearest_mapped_order_edges(*source, *target, mappings, order_results_by_input);
            for (lower, upper) in additions {
                changed |= order_results_by_input
                    .entry((*target, lower))
                    .or_default()
                    .insert(upper);
            }
        }
        if !changed {
            return;
        }
    }
}

fn nearest_mapped_order_edges(
    source: CollectionHandle,
    target: CollectionHandle,
    mappings: &BTreeMap<CollectionData, BTreeSet<CollectionData>>,
    order_results_by_input: &BTreeMap<MemberKey, BTreeSet<CollectionData>>,
) -> BTreeSet<(CollectionData, CollectionData)> {
    let mut pending = Vec::new();
    for (input, outputs) in mappings {
        for output in outputs {
            for successor in order_results_by_input
                .get(&(source, *input))
                .into_iter()
                .flatten()
            {
                pending.push((*successor, *output));
            }
        }
    }

    let mut visited = BTreeSet::new();
    let mut additions = BTreeSet::new();
    while let Some((source_member, lower_output)) = pending.pop() {
        if !visited.insert((source_member, lower_output)) {
            continue;
        }

        if let Some(upper_outputs) = mappings.get(&source_member) {
            for upper_output in upper_outputs {
                if lower_output != *upper_output
                    && !order_results_by_input
                        .get(&(target, lower_output))
                        .is_some_and(|results| results.contains(upper_output))
                {
                    additions.insert((lower_output, *upper_output));
                }
            }
            continue;
        }

        for successor in order_results_by_input
            .get(&(source, source_member))
            .into_iter()
            .flatten()
        {
            pending.push((*successor, lower_output));
        }
    }
    additions
}

/// Close active equations under the commuting-square law.
///
/// For a mapping `f : S -> T`, a source equation `a join b = c`
/// completes either missing side of
///
/// ```text
/// a join b = c
/// |    |     |
/// f    f     f
/// v    v     v
/// x join y = z
/// ```
///
/// when the other three edges are known. Equations are endpoint tuples, not
/// signed records: an inferred theorem needs no author and is never published
/// or admitted as a stored claim. Actual records remain optional diagnostic
/// witnesses, outside equation identity.
fn close_homomorphic_squares(
    homomorphisms: &BTreeSet<(CollectionHandle, CollectionHandle)>,
    active_merges: &mut BTreeMap<MergeEquation, Option<CollectionMerge>>,
    active_derives: &mut BTreeMap<DeriveEquation, Option<CollectionDerive>>,
) -> Result<(), Box<CollectionFunctionalConflict>> {
    loop {
        let joins = index_merge_outputs(
            active_merges
                .iter()
                .map(|(equation, record)| (*equation, *record)),
        );
        let maps = index_derive_outputs(
            active_derives
                .iter()
                .map(|(equation, record)| (*equation, *record)),
        );
        let mut merge_theorems = BTreeSet::new();
        let mut derive_theorems = BTreeSet::new();

        for (source, target) in homomorphisms {
            for &(collection, left, right, result) in active_merges.keys() {
                if collection != *source {
                    continue;
                }
                let Some(left_outputs) = maps.get(&(*target, left)) else {
                    continue;
                };
                let Some(right_outputs) = maps.get(&(*target, right)) else {
                    continue;
                };

                for left_output in left_outputs.keys() {
                    for right_output in right_outputs.keys() {
                        let (target_low, target_high) = ordered(*left_output, *right_output);

                        // Target join + source join + endpoint maps imply the
                        // mapping of the source result.
                        if let Some(outputs) = joins.get(&(*target, target_low, target_high)) {
                            for output in outputs.keys() {
                                derive_theorems.insert((*target, result, *output));
                            }
                        }

                        // Source-result map + source join + endpoint maps
                        // imply the exact target join.
                        if let Some(outputs) = maps.get(&(*target, result)) {
                            for output in outputs.keys() {
                                merge_theorems.insert((*target, target_low, target_high, *output));
                            }
                        }
                    }
                }
            }
        }

        let mut changed = false;
        for theorem in merge_theorems {
            if let std::collections::btree_map::Entry::Vacant(entry) = active_merges.entry(theorem)
            {
                entry.insert(None);
                changed = true;
            }
        }
        for theorem in derive_theorems {
            if let std::collections::btree_map::Entry::Vacant(entry) = active_derives.entry(theorem)
            {
                entry.insert(None);
                changed = true;
            }
        }

        check_functional(
            active_merges
                .iter()
                .map(|(equation, record)| (*equation, *record)),
            active_derives
                .iter()
                .map(|(equation, record)| (*equation, *record)),
        )?;
        if !changed {
            return Ok(());
        }
    }
}

fn ordered(
    mut left: CollectionData,
    mut right: CollectionData,
) -> (CollectionData, CollectionData) {
    if right < left {
        std::mem::swap(&mut left, &mut right);
    }
    (left, right)
}

fn index_merge_outputs(
    merges: impl IntoIterator<Item = (MergeEquation, Option<CollectionMerge>)>,
) -> BTreeMap<
    (CollectionHandle, CollectionData, CollectionData),
    BTreeMap<CollectionData, Option<CollectionMerge>>,
> {
    let mut outputs: BTreeMap<
        (CollectionHandle, CollectionData, CollectionData),
        BTreeMap<CollectionData, Option<CollectionMerge>>,
    > = BTreeMap::new();
    for ((collection, low, high, result), claim) in merges {
        outputs
            .entry((collection, low, high))
            .or_default()
            .entry(result)
            .and_modify(|record| {
                if let Some(claim) = claim {
                    *record = Some(record.map_or(claim, |known| known.min(claim)));
                }
            })
            .or_insert(claim);
    }
    outputs
}

fn index_derive_outputs(
    derives: impl IntoIterator<Item = (DeriveEquation, Option<CollectionDerive>)>,
) -> BTreeMap<(CollectionHandle, CollectionData), BTreeMap<CollectionData, Option<CollectionDerive>>>
{
    // Keyed on the target alone: a target has one source, stated by its
    // descriptor, so naming the source here would only repeat it.
    let mut outputs: BTreeMap<
        (CollectionHandle, CollectionData),
        BTreeMap<CollectionData, Option<CollectionDerive>>,
    > = BTreeMap::new();
    for ((target, input, output), claim) in derives {
        outputs
            .entry((target, input))
            .or_default()
            .entry(output)
            .and_modify(|record| {
                if let Some(claim) = claim {
                    *record = Some(record.map_or(claim, |known| known.min(claim)));
                }
            })
            .or_insert(claim);
    }
    outputs
}

fn validate_claim<D, E, V>(
    validate: &mut V,
    request: CollectionValidationRequest<'_>,
) -> Result<CollectionClaimValidation<D>, CollectionResolutionError<E>>
where
    V: for<'a> FnMut(CollectionValidationRequest<'a>) -> Result<CollectionClaimValidation<D>, E>,
{
    let record = request.record();
    validate(request).map_err(|source| CollectionResolutionError::Validation { record, source })
}

fn contains_member(
    members: &BTreeMap<CollectionHandle, BTreeSet<CollectionData>>,
    collection: CollectionHandle,
    data: CollectionData,
) -> bool {
    members
        .get(&collection)
        .is_some_and(|elements| elements.contains(&data))
}

fn check_functional(
    merges: impl IntoIterator<Item = (MergeEquation, Option<CollectionMerge>)>,
    derives: impl IntoIterator<Item = (DeriveEquation, Option<CollectionDerive>)>,
) -> Result<(), Box<CollectionFunctionalConflict>> {
    for ((collection, low, high), outputs) in index_merge_outputs(merges) {
        if outputs.len() > 1 {
            let mut outputs = outputs.into_iter();
            let (first_data, first_claim) = outputs.next().expect("conflict has first output");
            let (second_data, second_claim) = outputs.next().expect("conflict has second output");
            return Err(Box::new(CollectionFunctionalConflict::Merge {
                collection,
                low,
                high,
                first: ConflictingCollectionOutput {
                    record: first_claim.map(CollectionRecord::Merge),
                    data: first_data,
                },
                second: ConflictingCollectionOutput {
                    record: second_claim.map(CollectionRecord::Merge),
                    data: second_data,
                },
            }));
        }
    }

    for ((target, input), outputs) in index_derive_outputs(derives) {
        if outputs.len() > 1 {
            let mut outputs = outputs.into_iter();
            let (first_data, first_claim) = outputs.next().expect("conflict has first output");
            let (second_data, second_claim) = outputs.next().expect("conflict has second output");
            return Err(Box::new(CollectionFunctionalConflict::Derive {
                target,
                input,
                first: ConflictingCollectionOutput {
                    record: first_claim.map(CollectionRecord::Derive),
                    data: first_data,
                },
                second: ConflictingCollectionOutput {
                    record: second_claim.map(CollectionRecord::Derive),
                    data: second_data,
                },
            }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Resolve with a stated lineage.
    ///
    /// A derive record no longer names its source -- the target's descriptor
    /// does -- so a test that exercises a derivation says which mapping its
    /// records are instances of. Passing an empty lineage is meaningful: it
    /// declares that nothing derives from anything, and derives resolve
    /// against nothing.
    fn resolve_with_derive_lineage<D, E, V>(
        records: &DiscoveredCollectionRecords,
        lineage: &[(CollectionHandle, CollectionHandle)],
        authorized_commits: &BTreeSet<CollectionCommit>,
        validate: V,
    ) -> Result<CollectionResolution<D>, CollectionResolutionError<E>>
    where
        V: for<'a> FnMut(
            CollectionValidationRequest<'a>,
        ) -> Result<CollectionClaimValidation<D>, E>,
    {
        let lineage: BTreeMap<CollectionHandle, CollectionHandle> =
            lineage.iter().copied().collect();
        resolve_collection_semantics(records, &lineage, authorized_commits, validate)
    }
    use super::*;

    use std::convert::Infallible;

    use ed25519_dalek::SigningKey;

    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::blob::{Blob, IntoBlob};
    use crate::collection::descriptor::{identity_for_tests, named_for_tests};
    use crate::collection::simplearchive_union::{self, SimpleArchiveUnionValidationError};
    use crate::collection::{CollectionRead, CollectionRecord, CollectionStore};
    use crate::inline::encodings::hash::{Blake3, Handle, Hash};
    use crate::inline::Inline;
    use crate::repo::{memoryrepo::MemoryRepo, BlobStoreGet, SnapshotSource};
    use crate::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

    #[derive(Default)]
    struct ProbeStore {
        records: Vec<Result<CollectionRecord, Infallible>>,
    }

    impl CollectionRead for ProbeStore {
        type RecordsError = Infallible;
        type RecordIter<'a> = std::vec::IntoIter<Result<CollectionRecord, Self::RecordsError>>;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            Ok(self.records.clone().into_iter())
        }
    }

    impl CollectionStore for ProbeStore {
        type InsertError = Infallible;

        fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
            self.records.push(Ok(record));
            Ok(())
        }
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn data(byte: u8) -> CollectionData {
        Inline::new([byte; 32])
    }

    fn signed_merge(
        collection: CollectionHandle,
        left: CollectionData,
        right: CollectionData,
        result: CollectionData,
    ) -> CollectionMerge {
        CollectionMerge::sign(
            &SigningKey::from_bytes(&[31; 32]),
            collection,
            left,
            right,
            result,
        )
    }

    fn signed_derive(
        target: CollectionHandle,
        input: CollectionData,
        output: CollectionData,
    ) -> CollectionDerive {
        CollectionDerive::sign(&SigningKey::from_bytes(&[31; 32]), target, input, output)
    }

    fn commit(definition: &Fragment, element: CollectionData, key: u8) -> CollectionCommit {
        CollectionCommit::sign(
            &SigningKey::from_bytes(&[key; 32]),
            identity_for_tests(definition),
            element,
            super::super::empty_metadata_handle(),
        )
    }

    fn commit_record(commit: CollectionCommit) -> CollectionRecord {
        CollectionRecord::Commit(commit)
    }

    fn merge_record(merge: CollectionMerge) -> CollectionRecord {
        CollectionRecord::Merge(merge)
    }

    fn derive_record(derive: CollectionDerive) -> CollectionRecord {
        CollectionRecord::Derive(derive)
    }

    fn discover(
        _descriptors: &[Fragment],
        commits: &[CollectionCommit],
        merges: &[CollectionMerge],
        derives: &[CollectionDerive],
        reverse: bool,
    ) -> DiscoveredCollectionRecords {
        let mut records: Vec<CollectionRecord> = commits
            .iter()
            .copied()
            .map(CollectionRecord::Commit)
            .chain(merges.iter().copied().map(CollectionRecord::Merge))
            .chain(derives.iter().copied().map(CollectionRecord::Derive))
            .collect();
        if reverse {
            records.reverse();
        }
        let mut store = ProbeStore::default();
        for record in records {
            CollectionStore::insert(&mut store, record).unwrap();
        }
        super::super::discover_collection_records(&store).unwrap()
    }

    fn accepted(
        _: CollectionValidationRequest<'_>,
    ) -> Result<CollectionClaimValidation<()>, Infallible> {
        Ok(CollectionClaimValidation::Accepted)
    }

    fn reference_cover_element(
        semantics: &CollectionSemantics,
        collection: CollectionHandle,
        element: CollectionData,
        resident_frontier: &BTreeSet<CollectionData>,
        mut path: BTreeSet<CollectionData>,
    ) -> Option<BTreeSet<CollectionData>> {
        if let Some(upper) = resident_frontier
            .iter()
            .find(|upper| semantics.subsumes(collection, element, **upper))
        {
            return Some(BTreeSet::from([*upper]));
        }
        if !path.insert(element) {
            return None;
        }
        for (low, high) in semantics
            .merge_inputs_by_result
            .get(&(collection, element))
            .into_iter()
            .flatten()
        {
            let Some(mut proof) = reference_cover_element(
                semantics,
                collection,
                *low,
                resident_frontier,
                path.clone(),
            ) else {
                continue;
            };
            let Some(right) = reference_cover_element(
                semantics,
                collection,
                *high,
                resident_frontier,
                path.clone(),
            ) else {
                continue;
            };
            proof.extend(right);
            return Some(proof);
        }
        None
    }

    fn reference_physical_cover(
        semantics: &CollectionSemantics,
        collection: CollectionHandle,
        resident: &BTreeSet<CollectionData>,
    ) -> CollectionPhysicalCover {
        let Some(members) = semantics.members(collection) else {
            return CollectionPhysicalCover::default();
        };
        let resident_members: BTreeSet<_> = resident.intersection(members).copied().collect();
        let mut resident_frontier = BTreeSet::new();
        for candidate in &resident_members {
            let dominated = resident_members.iter().any(|other| {
                candidate != other && semantics.subsumes(collection, *candidate, *other)
            });
            if !dominated {
                resident_frontier.insert(*candidate);
            }
        }

        let mut result = CollectionPhysicalCover::default();
        for obligation in semantics
            .frontier(collection)
            .into_iter()
            .flatten()
            .copied()
        {
            match reference_cover_element(
                semantics,
                collection,
                obligation,
                &resident_frontier,
                BTreeSet::new(),
            ) {
                Some(proof) => result.cover.extend(proof),
                None => {
                    result.missing.insert(obligation);
                }
            }
        }
        result
    }

    fn numbered_data(number: u32) -> CollectionData {
        let mut raw = [0u8; 32];
        raw[28..].copy_from_slice(&number.to_be_bytes());
        Inline::new(raw)
    }

    #[test]
    fn authorization_and_validator_status_are_distinct() {
        let definition = named_for_tests("c1", id(2));
        let missing_collection = named_for_tests("c9", id(2));
        let authorized = commit(&definition, data(1), 1);
        let unauthorized = commit(&definition, data(2), 2);
        let missing_descriptor_commit = commit(&missing_collection, data(3), 3);
        let rejected_merge =
            signed_merge(identity_for_tests(&definition), data(4), data(5), data(6));
        let callback_pending_merge =
            signed_merge(identity_for_tests(&definition), data(7), data(8), data(9));
        let missing_descriptor_merge = signed_merge(
            identity_for_tests(&missing_collection),
            data(10),
            data(11),
            data(12),
        );
        let missing_descriptor_derive =
            signed_derive(identity_for_tests(&missing_collection), data(1), data(13));
        let records = discover(
            &[definition.clone()],
            &[
                authorized.clone(),
                unauthorized.clone(),
                missing_descriptor_commit.clone(),
            ],
            &[
                rejected_merge.clone(),
                callback_pending_merge.clone(),
                missing_descriptor_merge.clone(),
            ],
            &[missing_descriptor_derive.clone()],
            false,
        );
        let authorized_commits = BTreeSet::from([authorized, missing_descriptor_commit]);
        let mut called = Vec::new();
        let resolution =
            resolve_with_derive_lineage(&records, &[], &authorized_commits, |request| {
                let claim = request.record();
                called.push(claim);
                let descriptor_available = match request {
                    CollectionValidationRequest::Commit { claim } => {
                        claim.collection() == identity_for_tests(&definition)
                    }
                    CollectionValidationRequest::Merge { claim } => {
                        claim.collection() == identity_for_tests(&definition)
                    }
                    CollectionValidationRequest::Derive { claim } => {
                        claim.collection() == identity_for_tests(&definition)
                    }
                };
                if claim == merge_record(rejected_merge) {
                    Ok::<_, Infallible>(CollectionClaimValidation::Rejected("bad merge"))
                } else if claim == merge_record(callback_pending_merge) || !descriptor_available {
                    Ok(CollectionClaimValidation::Pending)
                } else {
                    Ok(CollectionClaimValidation::Accepted)
                }
            })
            .unwrap();

        assert_eq!(
            called.len(),
            6,
            "each eligible claim is presented to the validator once"
        );
        let called: BTreeSet<_> = called.into_iter().collect();
        assert_eq!(
            called,
            BTreeSet::from([
                commit_record(authorized),
                commit_record(missing_descriptor_commit),
                merge_record(rejected_merge),
                merge_record(callback_pending_merge),
                merge_record(missing_descriptor_merge),
                derive_record(missing_descriptor_derive),
            ])
        );
        assert!(!called.contains(&commit_record(unauthorized)));
        assert_eq!(
            resolution.validation_pending(),
            &BTreeSet::from([
                commit_record(missing_descriptor_commit),
                merge_record(callback_pending_merge),
                merge_record(missing_descriptor_merge),
                derive_record(missing_descriptor_derive),
            ])
        );
        assert_eq!(
            resolution.rejected(),
            &BTreeMap::from([(merge_record(rejected_merge), "bad merge")])
        );
        assert!(resolution.activation_pending().is_empty());
        assert!(resolution
            .semantics()
            .contains(identity_for_tests(&definition), authorized.data()));
        assert!(!resolution
            .semantics()
            .contains(identity_for_tests(&definition), unauthorized.data()));
    }

    #[test]
    fn explicit_payload_roots_drive_merge_and_derive_closure_without_provenance() {
        let source = named_for_tests("source", id(2));
        let target = named_for_tests("target", id(4));
        let source_handle = identity_for_tests(&source);
        let target_handle = identity_for_tests(&target);
        let merge = signed_merge(source_handle, data(1), data(2), data(3));
        let derive = signed_derive(target_handle, data(3), data(4));
        let records = discover(
            &[source, target],
            &[],
            &[merge.clone()],
            &[derive.clone()],
            false,
        );
        let roots = BTreeSet::from([(source_handle, data(1)), (source_handle, data(2))]);
        let lineage = BTreeMap::from([(target_handle, source_handle)]);

        let resolution =
            resolve_collection_semantics_from_roots(&records, &lineage, &roots, accepted).unwrap();
        let semantics = resolution.semantics();

        assert_eq!(
            semantics.members(source_handle),
            Some(&BTreeSet::from([data(1), data(2), data(3)]))
        );
        assert_eq!(
            semantics.members(target_handle),
            Some(&BTreeSet::from([data(4)]))
        );
        assert_eq!(
            semantics.frontier(source_handle),
            Some(&BTreeSet::from([data(3)]))
        );
        assert_eq!(
            semantics.supporting_data(target_handle, data(4)),
            BTreeSet::from([data(1), data(2)])
        );
        assert!(semantics
            .supporting_commits(target_handle, data(4))
            .is_empty());
        assert_eq!(
            resolution.admitted_claims(),
            &BTreeSet::from([merge_record(merge), derive_record(derive)])
        );
    }

    #[test]
    fn explicit_payload_roots_ignore_duplicate_commit_provenance() {
        let definition = named_for_tests("c1", id(2));
        let collection = identity_for_tests(&definition);
        let first = commit(&definition, data(1), 1);
        let duplicate = commit(&definition, data(1), 2);
        let merge = signed_merge(collection, data(1), data(2), data(3));
        let merge_record = merge_record(merge);
        let roots = BTreeSet::from([(collection, data(1)), (collection, data(2))]);
        let with_duplicates = discover(
            &[definition.clone()],
            &[first, duplicate],
            &[merge.clone()],
            &[],
            false,
        );
        let without_commits = discover(&[definition], &[], &[merge], &[], false);
        let mut validated = Vec::new();

        let actual = resolve_collection_semantics_from_roots(
            &with_duplicates,
            &BTreeMap::new(),
            &roots,
            |request| {
                validated.push(request.record());
                Ok::<_, Infallible>(CollectionClaimValidation::<()>::Accepted)
            },
        )
        .unwrap();
        let expected = resolve_collection_semantics_from_roots(
            &without_commits,
            &BTreeMap::new(),
            &roots,
            accepted,
        )
        .unwrap();

        assert_eq!(actual, expected);
        assert_eq!(validated, vec![merge_record]);
        assert!(actual
            .semantics()
            .supporting_commits(collection, data(3))
            .is_empty());
    }

    #[test]
    fn authorized_commit_resolution_still_tracks_claim_provenance() {
        let definition = named_for_tests("c1", id(2));
        let collection = identity_for_tests(&definition);
        let root = commit(&definition, data(1), 1);
        let records = discover(&[definition], &[root.clone()], &[], &[], false);

        let resolution = resolve_collection_semantics(
            &records,
            &BTreeMap::new(),
            &BTreeSet::from([root]),
            accepted,
        )
        .unwrap();

        assert_eq!(
            resolution.admitted_claims(),
            &BTreeSet::from([commit_record(root)])
        );
        assert_eq!(
            resolution
                .semantics()
                .supporting_commits(collection, root.data()),
            BTreeSet::from([root])
        );
        assert_eq!(
            resolution
                .semantics()
                .supporting_data(collection, root.data()),
            BTreeSet::from([root.data()])
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct InjectedFailure;

    impl fmt::Display for InjectedFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "injected failure")
        }
    }

    impl Error for InjectedFailure {}

    #[test]
    fn callback_failure_names_the_claim_and_returns_no_snapshot() {
        let definition = named_for_tests("c1", id(2));
        let root = commit(&definition, data(1), 1);
        let records = discover(&[definition], &[root.clone()], &[], &[], false);
        let error =
            resolve_with_derive_lineage::<(), _, _>(&records, &[], &BTreeSet::from([root]), |_| {
                Err(InjectedFailure)
            })
            .unwrap_err();
        assert_eq!(
            error,
            CollectionResolutionError::Validation {
                record: commit_record(root),
                source: InjectedFailure,
            }
        );
    }

    #[test]
    fn alternating_merge_derive_merge_reaches_the_least_fixed_point() {
        let raw = named_for_tests("c1", id(2));
        // A deliberately different scope proves that the generic resolver does
        // not preempt the derivation validator's compatibility policy.
        let rollup = named_for_tests("c9", id(4));
        let raw_one = commit(&raw, data(1), 1);
        let raw_two = commit(&raw, data(2), 2);
        let rollup_four = commit(&rollup, data(4), 3);
        let raw_merge = signed_merge(identity_for_tests(&raw), data(1), data(2), data(3));
        let derive = signed_derive(identity_for_tests(&rollup), data(3), data(5));
        let rollup_merge = signed_merge(identity_for_tests(&rollup), data(4), data(5), data(6));
        let definitions = [raw.clone(), rollup.clone()];
        let commits = [raw_one.clone(), raw_two.clone(), rollup_four.clone()];
        let merges = [raw_merge, rollup_merge];
        let derives = [derive];
        let authorized = commits.iter().copied().collect();

        let forward = discover(&definitions, &commits, &merges, &derives, false);
        let reverse = discover(&definitions, &commits, &merges, &derives, true);
        let forward = resolve_with_derive_lineage(
            &forward,
            &[(identity_for_tests(&rollup), identity_for_tests(&raw))],
            &authorized,
            accepted,
        )
        .unwrap();
        let reverse = resolve_with_derive_lineage(
            &reverse,
            &[(identity_for_tests(&rollup), identity_for_tests(&raw))],
            &authorized,
            accepted,
        )
        .unwrap();
        assert_eq!(forward, reverse);
        assert!(forward.validation_pending().is_empty());
        assert!(forward.activation_pending().is_empty());

        let semantics = forward.semantics();
        assert_eq!(
            semantics.members(identity_for_tests(&raw)),
            Some(&BTreeSet::from([data(1), data(2), data(3)]))
        );
        assert_eq!(
            semantics.members(identity_for_tests(&rollup)),
            Some(&BTreeSet::from([data(4), data(5), data(6)]))
        );
        assert_eq!(
            semantics.frontier(identity_for_tests(&raw)),
            Some(&BTreeSet::from([data(3)]))
        );
        assert_eq!(
            semantics.frontier(identity_for_tests(&rollup)),
            Some(&BTreeSet::from([data(6)]))
        );
        assert_eq!(
            semantics.supporting_commits(identity_for_tests(&rollup), data(6)),
            BTreeSet::from([raw_one, raw_two, rollup_four])
        );
    }

    #[test]
    fn derive_lifts_source_subsumption_without_a_target_merge() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let first = commit(&source, data(1), 1);
        let second = commit(&source, data(2), 2);
        let source_merge = signed_merge(identity_for_tests(&source), data(1), data(2), data(3));
        let lower = signed_derive(identity_for_tests(&target), data(1), data(11));
        let upper = signed_derive(identity_for_tests(&target), data(3), data(13));
        let records = discover(
            &[source.clone(), target.clone()],
            &[first.clone(), second.clone()],
            &[source_merge],
            &[lower, upper],
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(identity_for_tests(&target), identity_for_tests(&source))],
            &BTreeSet::from([first, second]),
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();

        assert!(semantics.subsumes(identity_for_tests(&target), data(11), data(13)));
        assert_eq!(
            semantics.frontier(identity_for_tests(&target)),
            Some(&BTreeSet::from([data(13)]))
        );
        assert_eq!(
            collection_physical_cover(
                semantics,
                identity_for_tests(&target),
                &BTreeSet::from([data(13)])
            ),
            CollectionPhysicalCover {
                cover: BTreeSet::from([data(13)]),
                missing: BTreeSet::new(),
            }
        );
    }

    #[test]
    fn derive_lifts_order_across_unmapped_source_members() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let commits = [
            commit(&source, data(1), 1),
            commit(&source, data(2), 2),
            commit(&source, data(4), 3),
        ];
        let merges = [
            signed_merge(identity_for_tests(&source), data(1), data(2), data(3)),
            signed_merge(identity_for_tests(&source), data(3), data(4), data(7)),
        ];
        let derives = [
            signed_derive(identity_for_tests(&target), data(1), data(11)),
            signed_derive(identity_for_tests(&target), data(7), data(17)),
        ];
        let records = discover(
            &[source.clone(), target.clone()],
            &commits,
            &merges,
            &derives,
            false,
        );
        let authorized = commits.iter().copied().collect();
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(identity_for_tests(&target), identity_for_tests(&source))],
            &authorized,
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();

        assert!(semantics.subsumes(identity_for_tests(&target), data(11), data(17)));
        assert_eq!(
            semantics.frontier(identity_for_tests(&target)),
            Some(&BTreeSet::from([data(17)]))
        );
    }

    #[test]
    fn source_coarsening_skips_intermediates_and_reuses_only_direct_image_pairs() {
        let source = named_for_tests("source-guidance", id(2));
        let target = named_for_tests("target-guidance", id(5));
        let source_id = identity_for_tests(&source);
        let target_id = identity_for_tests(&target);
        let commits = [
            commit(&source, data(1), 1),
            commit(&source, data(2), 2),
            commit(&source, data(4), 3),
        ];
        let merges = [
            signed_merge(source_id, data(1), data(2), data(3)),
            signed_merge(source_id, data(3), data(4), data(7)),
        ];
        let derives = [
            signed_derive(target_id, data(1), data(11)),
            signed_derive(target_id, data(2), data(12)),
            signed_derive(target_id, data(4), data(14)),
        ];
        let records = discover(&[source, target], &commits, &merges, &derives, false);
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(target_id, source_id)],
            &commits.into_iter().collect(),
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();
        let target_cover = BTreeSet::from([data(11), data(12), data(14)]);
        assert_eq!(
            semantics.source_coarsenings(
                source_id,
                target_id,
                &BTreeSet::from([data(7)]),
                &target_cover
            ),
            vec![(data(7), BTreeSet::new())],
            "map the coarsest resident source once; do not manufacture image(3)",
        );
        assert_eq!(
            semantics.source_coarsenings(
                source_id,
                target_id,
                &BTreeSet::from([data(3), data(4)]),
                &target_cover
            ),
            vec![(data(3), BTreeSet::from([(data(11), data(12))]))],
        );
    }

    #[test]
    fn source_coarsening_distinguishes_finer_coverage_from_one_existing_upper_image() {
        let source = named_for_tests("source-guidance", id(2));
        let target = named_for_tests("target-guidance", id(5));
        let source_id = identity_for_tests(&source);
        let target_id = identity_for_tests(&target);
        let commits = [
            commit(&source, data(1), 1),
            commit(&source, data(2), 2),
            commit(&source, data(4), 3),
        ];
        let merges = [
            signed_merge(source_id, data(1), data(2), data(3)),
            signed_merge(target_id, data(13), data(14), data(19)),
        ];
        let derives = [
            signed_derive(target_id, data(1), data(11)),
            signed_derive(target_id, data(2), data(12)),
            signed_derive(target_id, data(3), data(13)),
            signed_derive(target_id, data(4), data(14)),
        ];
        let records = discover(&[source, target], &commits, &merges, &derives, false);
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(target_id, source_id)],
            &commits.into_iter().collect(),
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();
        let source_cover = BTreeSet::from([data(3), data(4)]);
        assert!(
            !semantics
                .source_coarsenings(
                    source_id,
                    target_id,
                    &source_cover,
                    &BTreeSet::from([data(11), data(12), data(14)]),
                )
                .is_empty(),
            "a missing upper image may still improve its complete finer cover"
        );
        for resident in [
            BTreeSet::from([data(13), data(14)]),
            BTreeSet::from([data(19)]),
        ] {
            assert!(
                semantics
                    .source_coarsenings(source_id, target_id, &source_cover, &resident,)
                    .is_empty(),
                "an equal or greater resident target image is already enough"
            );
        }
    }

    #[test]
    fn derive_carries_incomparable_leaf_witnesses_through_unmapped_joins() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let commits = [
            commit(&source, data(1), 1),
            commit(&source, data(2), 2),
            commit(&source, data(4), 3),
            commit(&source, data(8), 4),
        ];
        let merges = [
            signed_merge(identity_for_tests(&source), data(1), data(2), data(3)),
            signed_merge(identity_for_tests(&source), data(4), data(8), data(12)),
            signed_merge(identity_for_tests(&source), data(3), data(12), data(15)),
        ];
        let derives = [
            signed_derive(identity_for_tests(&target), data(1), data(21)),
            signed_derive(identity_for_tests(&target), data(2), data(22)),
            signed_derive(identity_for_tests(&target), data(4), data(24)),
            signed_derive(identity_for_tests(&target), data(8), data(28)),
            signed_derive(identity_for_tests(&target), data(15), data(35)),
        ];
        let records = discover(
            &[source.clone(), target.clone()],
            &commits,
            &merges,
            &derives,
            false,
        );
        let authorized = commits.iter().copied().collect();
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(identity_for_tests(&target), identity_for_tests(&source))],
            &authorized,
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();

        for lower in [data(21), data(22), data(24), data(28)] {
            assert!(semantics.subsumes(identity_for_tests(&target), lower, data(35)));
        }
        assert_eq!(
            semantics.frontier(identity_for_tests(&target)),
            Some(&BTreeSet::from([data(35)]))
        );
    }

    #[test]
    fn lifted_order_reaches_a_second_homomorphism() {
        let source = named_for_tests("c1", id(2));
        let middle = named_for_tests("c4", id(5));
        let target = named_for_tests("c7", id(8));
        let commits = [commit(&source, data(1), 1), commit(&source, data(2), 2)];
        let merges = [signed_merge(
            identity_for_tests(&source),
            data(1),
            data(2),
            data(3),
        )];
        let derives = [
            signed_derive(identity_for_tests(&middle), data(1), data(11)),
            signed_derive(identity_for_tests(&middle), data(3), data(13)),
            signed_derive(identity_for_tests(&target), data(11), data(21)),
            signed_derive(identity_for_tests(&target), data(13), data(23)),
        ];
        let records = discover(
            &[source.clone(), middle.clone(), target.clone()],
            &commits,
            &merges,
            &derives,
            false,
        );
        let authorized = commits.iter().copied().collect();
        let resolution = resolve_with_derive_lineage(
            &records,
            &[
                (identity_for_tests(&middle), identity_for_tests(&source)),
                (identity_for_tests(&target), identity_for_tests(&middle)),
            ],
            &authorized,
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();

        assert!(semantics.subsumes(identity_for_tests(&middle), data(11), data(13)));
        assert!(semantics.subsumes(identity_for_tests(&target), data(21), data(23)));
        assert_eq!(
            semantics.frontier(identity_for_tests(&target)),
            Some(&BTreeSet::from([data(23)]))
        );
    }

    #[test]
    fn homomorphic_square_supplies_target_physical_fallback() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let first = commit(&source, data(1), 1);
        let second = commit(&source, data(2), 2);
        let source_merge = signed_merge(identity_for_tests(&source), data(1), data(2), data(3));
        let derives = [
            signed_derive(identity_for_tests(&target), data(1), data(11)),
            signed_derive(identity_for_tests(&target), data(2), data(12)),
            signed_derive(identity_for_tests(&target), data(3), data(13)),
        ];
        let records = discover(
            &[source.clone(), target.clone()],
            &[first.clone(), second.clone()],
            &[source_merge],
            &derives,
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(identity_for_tests(&target), identity_for_tests(&source))],
            &BTreeSet::from([first, second]),
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();

        assert_eq!(
            semantics.frontier(identity_for_tests(&target)),
            Some(&BTreeSet::from([data(13)]))
        );
        assert_eq!(
            collection_physical_cover(
                semantics,
                identity_for_tests(&target),
                &BTreeSet::from([data(11), data(12)])
            ),
            CollectionPhysicalCover {
                cover: BTreeSet::from([data(11), data(12)]),
                missing: BTreeSet::new(),
            }
        );
    }

    #[test]
    fn target_merge_completes_the_reverse_side_of_the_square() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let first = commit(&source, data(1), 1);
        let second = commit(&source, data(2), 2);
        let source_merge = signed_merge(identity_for_tests(&source), data(1), data(2), data(3));
        let lower = signed_derive(identity_for_tests(&target), data(1), data(11));
        let upper = signed_derive(identity_for_tests(&target), data(2), data(12));
        let target_merge = signed_merge(identity_for_tests(&target), data(11), data(12), data(13));
        let records = discover(
            &[source.clone(), target.clone()],
            &[first.clone(), second.clone()],
            &[source_merge, target_merge],
            &[lower, upper],
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(identity_for_tests(&target), identity_for_tests(&source))],
            &BTreeSet::from([first, second]),
            accepted,
        )
        .unwrap();

        assert!(resolution
            .semantics()
            .derive_inputs_by_output
            .get(&(identity_for_tests(&target), data(13)))
            .is_some_and(|producers| {
                producers.contains(&(identity_for_tests(&source), data(3)))
            }));
        assert!(
            !resolution.admitted_claims().iter().any(|record| {
                matches!(record, CollectionRecord::Derive(claim)
                if claim.collection() == identity_for_tests(&target) && claim.input() == data(3))
            }),
            "an inferred equation must not manufacture a signed record"
        );
    }

    #[test]
    fn commuting_square_conflicts_are_rejected() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let first = commit(&source, data(1), 1);
        let second = commit(&source, data(2), 2);
        let source_merge = signed_merge(identity_for_tests(&source), data(1), data(2), data(3));
        let target_merge = signed_merge(identity_for_tests(&target), data(11), data(12), data(13));
        let derives = [
            signed_derive(identity_for_tests(&target), data(1), data(11)),
            signed_derive(identity_for_tests(&target), data(2), data(12)),
            signed_derive(identity_for_tests(&target), data(3), data(14)),
        ];
        let records = discover(
            &[source.clone(), target.clone()],
            &[first.clone(), second.clone()],
            &[source_merge, target_merge],
            &derives,
            false,
        );

        assert_eq!(
            resolve_with_derive_lineage(
                &records,
                &[(identity_for_tests(&target), identity_for_tests(&source))],
                &BTreeSet::from([first, second]),
                accepted,
            )
            .unwrap_err(),
            CollectionResolutionError::Conflict(Box::new(CollectionFunctionalConflict::Merge {
                collection: identity_for_tests(&target),
                low: data(11),
                high: data(12),
                first: ConflictingCollectionOutput {
                    record: Some(merge_record(target_merge)),
                    data: data(13),
                },
                second: ConflictingCollectionOutput {
                    record: None,
                    data: data(14),
                },
            }))
        );
    }

    #[test]
    fn distinct_signed_endorsements_are_one_semantic_equation() {
        let source = named_for_tests("endorsed-source", id(2));
        let target = named_for_tests("endorsed-target", id(5));
        let source_handle = identity_for_tests(&source);
        let target_handle = identity_for_tests(&target);
        let commits = [commit(&source, data(1), 1), commit(&source, data(2), 2)];
        let source_merge = signed_merge(source_handle, data(1), data(2), data(3));
        let derives = [
            signed_derive(target_handle, data(1), data(11)),
            signed_derive(target_handle, data(2), data(12)),
            signed_derive(target_handle, data(3), data(13)),
        ];
        let other_key = SigningKey::from_bytes(&[32; 32]);
        let second_merge =
            CollectionMerge::sign(&other_key, source_handle, data(1), data(2), data(3));
        let second_derive = CollectionDerive::sign(&other_key, target_handle, data(1), data(11));
        assert_ne!(source_merge, second_merge);
        assert_ne!(derives[0], second_derive);
        second_merge.verify_strict().unwrap();
        second_derive.verify_strict().unwrap();

        let definitions = [source, target];
        let once = discover(&definitions, &commits, &[source_merge], &derives, false);
        let twice = discover(
            &definitions,
            &commits,
            &[source_merge, second_merge],
            &[derives[0], derives[1], derives[2], second_derive],
            true,
        );
        let roots = BTreeSet::from(commits);
        let once =
            resolve_with_derive_lineage(&once, &[(target_handle, source_handle)], &roots, accepted)
                .unwrap();
        let twice = resolve_with_derive_lineage(
            &twice,
            &[(target_handle, source_handle)],
            &roots,
            accepted,
        )
        .unwrap();

        assert_eq!(once.semantics(), twice.semantics());
        assert_eq!(
            twice.admitted_claims().len(),
            once.admitted_claims().len() + 2
        );
        assert_eq!(
            twice.semantics().merge_inputs_by_result[&(target_handle, data(13))],
            BTreeSet::from([(data(11), data(12))]),
        );
        assert_eq!(
            twice.semantics().derive_inputs_by_output[&(target_handle, data(11))],
            BTreeSet::from([(source_handle, data(1))]),
        );
    }

    #[test]
    fn accepted_pending_merge_conflict_is_hard_and_permutation_independent() {
        let definition = named_for_tests("c1", id(2));
        let first = signed_merge(identity_for_tests(&definition), data(1), data(2), data(3));
        let second = signed_merge(identity_for_tests(&definition), data(1), data(2), data(4));
        let definitions = [definition.clone()];
        let merges = [first.clone(), second.clone()];
        let forward = discover(&definitions, &[], &merges, &[], false);
        let reverse = discover(&definitions, &[], &merges, &[], true);

        let forward =
            resolve_with_derive_lineage(&forward, &[], &BTreeSet::new(), accepted).unwrap_err();
        let reverse =
            resolve_with_derive_lineage(&reverse, &[], &BTreeSet::new(), accepted).unwrap_err();
        assert_eq!(forward, reverse);
        assert_eq!(
            forward,
            CollectionResolutionError::Conflict(Box::new(CollectionFunctionalConflict::Merge {
                collection: identity_for_tests(&definition),
                low: data(1),
                high: data(2),
                first: ConflictingCollectionOutput {
                    record: Some(merge_record(first)),
                    data: data(3),
                },
                second: ConflictingCollectionOutput {
                    record: Some(merge_record(second)),
                    data: data(4),
                },
            }))
        );
    }

    #[test]
    fn derive_conflicts_are_functional_by_exact_collection_pair_and_input() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let first = signed_derive(identity_for_tests(&target), data(1), data(2));
        let second = signed_derive(identity_for_tests(&target), data(1), data(3));
        let records = discover(
            &[source.clone(), target.clone()],
            &[],
            &[],
            &[first.clone(), second.clone()],
            false,
        );

        assert_eq!(
            resolve_with_derive_lineage(
                &records,
                &[(identity_for_tests(&target), identity_for_tests(&source))],
                &BTreeSet::new(),
                accepted
            )
            .unwrap_err(),
            CollectionResolutionError::Conflict(Box::new(CollectionFunctionalConflict::Derive {
                target: identity_for_tests(&target),
                input: data(1),
                first: ConflictingCollectionOutput {
                    record: Some(derive_record(first)),
                    data: data(2),
                },
                second: ConflictingCollectionOutput {
                    record: Some(derive_record(second)),
                    data: data(3),
                },
            }))
        );
    }

    #[test]
    fn rejected_equations_do_not_conflict_or_activate() {
        let definition = named_for_tests("c1", id(2));
        let first = signed_merge(identity_for_tests(&definition), data(1), data(2), data(3));
        let second = signed_merge(identity_for_tests(&definition), data(1), data(2), data(4));
        let records = discover(
            &[definition],
            &[],
            &[first.clone(), second.clone()],
            &[],
            false,
        );
        let resolution = resolve_with_derive_lineage(&records, &[], &BTreeSet::new(), |request| {
            if request.record() == merge_record(second) {
                Ok::<_, Infallible>(CollectionClaimValidation::Rejected("wrong output"))
            } else {
                Ok(CollectionClaimValidation::Accepted)
            }
        })
        .unwrap();
        assert_eq!(
            resolution.activation_pending(),
            &BTreeSet::from([merge_record(first)])
        );
        assert_eq!(
            resolution.rejected(),
            &BTreeMap::from([(merge_record(second), "wrong output")])
        );
        assert!(resolution.semantics().members(first.collection()).is_none());
    }

    #[test]
    fn pending_validation_and_authorization_growth_are_retried_monotonically() {
        let definition = named_for_tests("c1", id(2));
        let first = commit(&definition, data(1), 1);
        let second = commit(&definition, data(2), 2);
        let merge = signed_merge(identity_for_tests(&definition), data(1), data(2), data(3));
        let records = discover(
            &[definition.clone()],
            &[first.clone(), second.clone()],
            &[merge.clone()],
            &[],
            false,
        );

        let first_pass =
            resolve_with_derive_lineage(&records, &[], &BTreeSet::from([first]), accepted).unwrap();
        assert!(first_pass.validation_pending().is_empty());
        assert_eq!(
            first_pass.activation_pending(),
            &BTreeSet::from([merge_record(merge)])
        );
        assert!(!first_pass
            .semantics()
            .contains(identity_for_tests(&definition), data(3)));

        let authorized = BTreeSet::from([first, second]);
        let callback_pending = resolve_with_derive_lineage(&records, &[], &authorized, |request| {
            if request.record() == merge_record(merge) {
                Ok::<_, Infallible>(CollectionClaimValidation::<()>::Pending)
            } else {
                Ok(CollectionClaimValidation::Accepted)
            }
        })
        .unwrap();
        assert_eq!(
            callback_pending.validation_pending(),
            &BTreeSet::from([merge_record(merge)])
        );
        assert!(!callback_pending
            .semantics()
            .contains(identity_for_tests(&definition), data(3)));

        let final_pass = resolve_with_derive_lineage(&records, &[], &authorized, accepted).unwrap();
        assert!(final_pass
            .semantics()
            .contains(identity_for_tests(&definition), data(3)));
        assert!(first_pass
            .semantics()
            .members(identity_for_tests(&definition))
            .unwrap()
            .is_subset(
                final_pass
                    .semantics()
                    .members(identity_for_tests(&definition))
                    .unwrap()
            ));
    }

    #[test]
    fn idempotent_and_subsuming_merges_preserve_frontier_and_provenance() {
        let definition = named_for_tests("c1", id(2));
        let first = commit(&definition, data(1), 1);
        let same_data_other_commit = commit(&definition, data(1), 3);
        let second = commit(&definition, data(2), 2);
        let self_merge = signed_merge(identity_for_tests(&definition), data(1), data(1), data(1));
        let subsuming = signed_merge(identity_for_tests(&definition), data(1), data(2), data(2));
        let records = discover(
            &[definition.clone()],
            &[
                first.clone(),
                same_data_other_commit.clone(),
                second.clone(),
            ],
            &[self_merge, subsuming],
            &[],
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[],
            &BTreeSet::from([first, same_data_other_commit, second]),
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();
        assert_eq!(
            semantics.frontier(identity_for_tests(&definition)),
            Some(&BTreeSet::from([data(2)]))
        );
        assert_eq!(
            semantics.supporting_commits(identity_for_tests(&definition), data(2)),
            BTreeSet::from([first, same_data_other_commit, second])
        );

        // The decomposition contains its own unavailable result. It must not
        // recurse forever or fake a proof from only the lower resident input.
        assert_eq!(
            collection_physical_cover(
                semantics,
                identity_for_tests(&definition),
                &BTreeSet::from([data(1)])
            ),
            CollectionPhysicalCover {
                cover: BTreeSet::new(),
                missing: BTreeSet::from([data(2)]),
            }
        );
    }

    #[test]
    fn payload_support_collapses_duplicate_commit_provenance() {
        let definition = named_for_tests("c1", id(2));
        let first = commit(&definition, data(1), 1);
        let same_payload_other_commit = commit(&definition, data(1), 2);
        let records = discover(
            &[definition.clone()],
            &[first.clone(), same_payload_other_commit.clone()],
            &[],
            &[],
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[],
            &BTreeSet::from([first, same_payload_other_commit]),
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();
        let collection = identity_for_tests(&definition);

        assert_eq!(
            semantics.supporting_commits(collection, data(1)),
            BTreeSet::from([first, same_payload_other_commit])
        );
        assert_eq!(
            semantics.supporting_data(collection, data(1)),
            BTreeSet::from([data(1)])
        );
    }

    #[test]
    fn payload_support_follows_active_merge_and_derive_producers() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let first = commit(&source, data(1), 1);
        let second = commit(&source, data(2), 2);
        let target_root = commit(&target, data(5), 3);
        let source_merge = signed_merge(identity_for_tests(&source), data(1), data(2), data(3));
        let derive = signed_derive(identity_for_tests(&target), data(3), data(4));
        let target_merge = signed_merge(identity_for_tests(&target), data(4), data(5), data(6));
        let records = discover(
            &[source.clone(), target.clone()],
            &[first.clone(), second.clone(), target_root.clone()],
            &[source_merge, target_merge],
            &[derive],
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(identity_for_tests(&target), identity_for_tests(&source))],
            &BTreeSet::from([first, second, target_root]),
            accepted,
        )
        .unwrap();

        assert_eq!(
            resolution
                .semantics()
                .supporting_data(identity_for_tests(&target), data(6)),
            BTreeSet::from([data(1), data(2), data(5)])
        );
    }

    #[test]
    fn physical_cover_reuses_overlaps_and_follows_nonresident_intermediates() {
        let definition = named_for_tests("c1", id(2));
        let commits: Vec<_> = [(1, 1), (2, 2), (4, 3), (8, 4)]
            .into_iter()
            .map(|(element, key)| commit(&definition, data(element), key))
            .collect();
        let merges = [
            signed_merge(identity_for_tests(&definition), data(1), data(2), data(3)),
            signed_merge(identity_for_tests(&definition), data(2), data(4), data(6)),
            signed_merge(identity_for_tests(&definition), data(6), data(8), data(14)),
        ];
        let records = discover(&[definition.clone()], &commits, &merges, &[], false);
        let authorized = commits.iter().copied().collect();
        let resolution = resolve_with_derive_lineage(&records, &[], &authorized, accepted).unwrap();
        let semantics = resolution.semantics();
        assert_eq!(
            semantics.frontier(identity_for_tests(&definition)),
            Some(&BTreeSet::from([data(3), data(14)]))
        );

        // 14 covers the shared input 2 through nonresident 6; it is then
        // reused as the direct proof of the other frontier obligation.
        assert_eq!(
            collection_physical_cover(
                semantics,
                identity_for_tests(&definition),
                &BTreeSet::from([data(1), data(9), data(14)])
            ),
            CollectionPhysicalCover {
                cover: BTreeSet::from([data(1), data(14)]),
                missing: BTreeSet::new(),
            }
        );
        assert_eq!(
            collection_physical_cover(semantics, identity_for_tests(&definition), &BTreeSet::new())
                .missing,
            BTreeSet::from([data(3), data(14)])
        );
    }

    #[test]
    fn sparse_physical_cover_matches_pairwise_reference_including_cycles() {
        let collection = identity_for_tests(&named_for_tests("c1", id(2)));
        let elements = [data(1), data(2), data(3)];
        let members = BTreeSet::from(elements);
        let directed_edges: Vec<_> = elements
            .iter()
            .copied()
            .flat_map(|lower| {
                elements
                    .iter()
                    .copied()
                    .filter(move |upper| *upper != lower)
                    .map(move |upper| (lower, upper))
            })
            .collect();

        for graph in 0u16..(1u16 << directed_edges.len()) {
            let mut semantics = CollectionSemantics {
                members: BTreeMap::from([(collection, members.clone())]),
                frontier: BTreeMap::from([(collection, members.clone())]),
                ..CollectionSemantics::default()
            };
            for (index, (lower, upper)) in directed_edges.iter().copied().enumerate() {
                if graph & (1 << index) != 0 {
                    semantics
                        .order_results_by_input
                        .entry((collection, lower))
                        .or_default()
                        .insert(upper);
                }
            }

            for resident_bits in 0u8..(1u8 << elements.len()) {
                let resident = elements
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(index, element)| {
                        (resident_bits & (1 << index) != 0).then_some(element)
                    })
                    .collect();
                assert_eq!(
                    collection_physical_cover(&semantics, collection, &resident),
                    reference_physical_cover(&semantics, collection, &resident),
                    "graph={graph:03x}, resident={resident_bits:01x}",
                );
            }
        }
    }

    #[test]
    fn many_independent_resident_members_cover_themselves() {
        let collection = identity_for_tests(&named_for_tests("c1", id(2)));
        let members: BTreeSet<_> = (1..=4_096).map(numbered_data).collect();
        let semantics = CollectionSemantics {
            members: BTreeMap::from([(collection, members.clone())]),
            frontier: BTreeMap::from([(collection, members.clone())]),
            ..CollectionSemantics::default()
        };

        assert_eq!(
            collection_physical_cover(&semantics, collection, &members),
            CollectionPhysicalCover {
                cover: members,
                missing: BTreeSet::new(),
            }
        );
    }

    #[test]
    fn derives_propagate_commit_provenance_but_never_substitute_physical_bytes() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c9", id(4));
        let root = commit(&source, data(1), 1);
        let derive = signed_derive(identity_for_tests(&target), data(1), data(2));
        let records = discover(
            &[source.clone(), target.clone()],
            &[root.clone()],
            &[],
            &[derive],
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[(identity_for_tests(&target), identity_for_tests(&source))],
            &BTreeSet::from([root]),
            accepted,
        )
        .unwrap();
        let semantics = resolution.semantics();
        assert_eq!(
            semantics.supporting_commits(identity_for_tests(&target), data(2)),
            BTreeSet::from([root])
        );
        assert_eq!(
            collection_physical_cover(
                semantics,
                identity_for_tests(&target),
                &BTreeSet::from([data(1)])
            ),
            CollectionPhysicalCover {
                cover: BTreeSet::new(),
                missing: BTreeSet::from([data(2)]),
            }
        );
        assert_eq!(
            collection_physical_cover(
                semantics,
                identity_for_tests(&target),
                &BTreeSet::from([data(2)])
            ),
            CollectionPhysicalCover {
                cover: BTreeSet::from([data(2)]),
                missing: BTreeSet::new(),
            }
        );
    }

    #[test]
    fn supporting_commit_walk_handles_an_active_merge_derive_cycle() {
        let source = named_for_tests("c1", id(2));
        let target = named_for_tests("c4", id(5));
        let first = commit(&source, data(1), 1);
        let second = commit(&source, data(2), 2);
        let merge = signed_merge(identity_for_tests(&source), data(1), data(2), data(3));
        let forward = signed_derive(identity_for_tests(&target), data(3), data(4));
        let backward = signed_derive(identity_for_tests(&source), data(4), data(3));
        let records = discover(
            &[source.clone(), target.clone()],
            &[first.clone(), second.clone()],
            &[merge],
            &[forward, backward],
            false,
        );
        let resolution = resolve_with_derive_lineage(
            &records,
            &[
                (identity_for_tests(&target), identity_for_tests(&source)),
                (identity_for_tests(&source), identity_for_tests(&target)),
            ],
            &BTreeSet::from([first, second]),
            accepted,
        )
        .unwrap();

        assert_eq!(
            resolution
                .semantics()
                .supporting_commits(identity_for_tests(&target), data(4)),
            BTreeSet::from([first, second])
        );
    }

    fn row(entity: u8, attribute: u8, value: u8) -> [u8; TRIBLE_LEN] {
        let mut row = [value; TRIBLE_LEN];
        row[..16].fill(entity);
        row[16..32].fill(attribute);
        row
    }

    fn archive(rows: impl IntoIterator<Item = [u8; TRIBLE_LEN]>) -> Blob<SimpleArchive> {
        let mut facts = TribleSet::new();
        for row in rows {
            facts.insert(&Trible::force_raw(row).unwrap());
        }
        facts.to_blob()
    }

    fn archive_data(blob: &Blob<SimpleArchive>) -> CollectionData {
        Inline::<Hash<Blake3>>::new(Blake3::digest(&blob.bytes))
    }

    fn load_archive<R: BlobStoreGet>(
        reader: &R,
        data: CollectionData,
    ) -> Option<Blob<SimpleArchive>> {
        let handle: Inline<Handle<SimpleArchive>> = data.transmute();
        reader.get(handle).ok()
    }

    /// A descriptor read back out of storage: loose facts, with no fragment
    /// structure to recover, so it is lifted into one for the validators.
    fn load_descriptor<R: BlobStoreGet>(reader: &R, handle: CollectionHandle) -> Option<Fragment> {
        let blob: Blob<SimpleArchive> = reader.get(handle).ok()?;
        <TribleSet as crate::blob::TryFromBlob<SimpleArchive>>::try_from_blob(blob)
            .ok()
            .map(Fragment::from)
    }

    fn validate_union<R: BlobStoreGet>(
        reader: &R,
        request: CollectionValidationRequest<'_>,
    ) -> Result<CollectionClaimValidation<SimpleArchiveUnionValidationError>, Infallible> {
        let verdict = match request {
            CollectionValidationRequest::Commit { claim } => {
                let (Some(descriptor), Some(blob)) = (
                    load_descriptor(reader, claim.collection()),
                    load_archive(reader, claim.data()),
                ) else {
                    return Ok(CollectionClaimValidation::Pending);
                };
                match simplearchive_union::validate_commit(&descriptor, claim, &blob) {
                    Ok(()) => CollectionClaimValidation::Accepted,
                    Err(error) => CollectionClaimValidation::Rejected(error),
                }
            }
            CollectionValidationRequest::Merge { claim } => {
                let (low, high) = claim.inputs();
                let (Some(descriptor), Some(low), Some(high), Some(result)) = (
                    load_descriptor(reader, claim.collection()),
                    load_archive(reader, low),
                    load_archive(reader, high),
                    load_archive(reader, claim.result()),
                ) else {
                    return Ok(CollectionClaimValidation::Pending);
                };
                match simplearchive_union::validate_merge(&descriptor, claim, &low, &high, &result)
                {
                    Ok(()) => CollectionClaimValidation::Accepted,
                    Err(error) => CollectionClaimValidation::Rejected(error),
                }
            }
            CollectionValidationRequest::Derive { .. } => CollectionClaimValidation::Pending,
        };
        Ok(verdict)
    }

    #[test]
    fn simplearchive_union_validation_integrates_with_discovery_and_resolution() {
        let definition = simplearchive_union::descriptor(
            "resolved",
            crate::collection::CollectionPolicy::new(
                crate::collection::AdmissionPolicy::direct(
                    SigningKey::from_bytes(&[1; 32]).verifying_key(),
                ),
                crate::collection::AdmissionPolicy::direct(
                    SigningKey::from_bytes(&[1; 32]).verifying_key(),
                ),
            ),
        );
        let left = archive([row(1, 1, 1)]);
        let right = archive([row(2, 1, 2)]);
        let result = simplearchive_union::join(&left, &right).unwrap();
        let first = commit(&definition, archive_data(&left), 1);
        let second = commit(&definition, archive_data(&right), 2);
        let merge = signed_merge(
            identity_for_tests(&definition),
            archive_data(&left),
            archive_data(&right),
            archive_data(&result),
        );
        let authorized = BTreeSet::from([first, second]);

        let mut store = MemoryRepo::default();
        store.blobs.insert(IntoBlob::<SimpleArchive>::to_blob(
            definition.facts().clone(),
        ));
        for record in [
            CollectionRecord::Commit(first),
            CollectionRecord::Commit(second),
            CollectionRecord::Merge(merge),
        ] {
            CollectionStore::insert(&mut store, record).unwrap();
        }
        store.blobs.insert(left);
        store.blobs.insert(right);

        let snapshot = store.snapshot().unwrap();
        let records = super::super::discover_collection_records(&snapshot).unwrap();
        let pending = resolve_with_derive_lineage(&records, &[], &authorized, |request| {
            validate_union(&snapshot, request)
        })
        .unwrap();
        assert_eq!(
            pending.validation_pending(),
            &BTreeSet::from([merge_record(merge)])
        );
        assert!(!pending
            .semantics()
            .contains(identity_for_tests(&definition), merge.result()));

        store.blobs.insert(result);
        let snapshot = store.snapshot().unwrap();
        let records = super::super::discover_collection_records(&snapshot).unwrap();
        let resolved = resolve_with_derive_lineage(&records, &[], &authorized, |request| {
            validate_union(&snapshot, request)
        })
        .unwrap();
        assert!(resolved.validation_pending().is_empty());
        assert!(resolved.rejected().is_empty());
        assert_eq!(
            resolved
                .semantics()
                .frontier(identity_for_tests(&definition)),
            Some(&BTreeSet::from([merge.result()]))
        );
        assert_eq!(
            resolved
                .semantics()
                .supporting_commits(identity_for_tests(&definition), merge.result()),
            authorized
        );
    }
}
