//! Realization planned from the coverage index.
//!
//! Every question maintenance used to answer by resolving a lineage's records
//! again is a question about supports, and the coverage index already holds
//! those: what each node stands for, and which nodes of a collection are its
//! frontier. So a derived target's obligation -- its frontier stands for what
//! its source's frontier stands for -- is one set difference; the images it
//! owes are the source frontier nodes whose support that difference meets; a
//! carry pairs frontier nodes within a tier keyed by the size of their
//! support; and a fine image that a coarser one covers is consumed by one
//! MERGE whose result is the coarser image, so the redundancy disappears in
//! the fold instead of being coarsened at every read.
//!
//! No record is enumerated on the ordinary path. Records are read only to
//! descend: when a frontier node is too wide for the request, or its bytes are
//! not here, or the mapping cannot take it, the MERGE that produced it names
//! the finer nodes beneath, and the produced-member index finds that MERGE
//! without a walk.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use ed25519_dalek::SigningKey;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::Blob;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::patch::Entry;
use crate::repo::{BlobStoreGet, Store, StoreRead};
use crate::trible::Fragment;

use super::coverage::{Coverage, CoverageSet};
use super::encoding::{collection_member_availability, CollectionMemberAvailability};
use super::exact_derived::{
    data_identity, load_lineage, producer_is_admitted, require_support, structural_certificate,
    CollectionRealizationError, Lineage,
};
use super::operation_snapshot::{OperationFrontier, OperationSnapshot};
use super::{
    Collection, CollectionData, CollectionDerive, CollectionEncoding, CollectionHandle,
    CollectionMapping, CollectionMerge, CollectionOperationError, CollectionRecord,
    CollectionRecordSelector, Cover, Support,
};

/// One lattice node and what it stands for.
type Node = (CollectionData, CoverageSet);

/// What one collection can stand on for a requested support.
struct Selection {
    /// Resident, complete nodes whose supports lie inside the request, widest
    /// first, none inside the union of the ones before it.
    cover: Vec<Node>,
    /// The union of the cover's supports.
    covered: CoverageSet,
    /// Nodes met on the way whose bytes are not resident.
    absent: Vec<Node>,
    /// Representation dependencies missing beside resident roots.
    dependencies: Vec<CollectionData>,
    /// Every DERIVE met on the way, by input: the outputs it was given.
    images: BTreeMap<CollectionData, BTreeSet<CollectionData>>,
}

impl Selection {
    /// What the request still lacks.
    fn needed(&self, requested: &CoverageSet) -> CoverageSet {
        requested.difference(&self.covered)
    }

    /// Something to fetch before computing: an absent node whose support
    /// meets what is still needed, or a missing representation dependency,
    /// skipping what has been tried.
    fn acquirable(
        &self,
        needed: &CoverageSet,
        tried: &BTreeSet<CollectionData>,
    ) -> Option<CollectionData> {
        self.absent
            .iter()
            .filter(|(_, support)| !support.intersect(needed).is_empty())
            .map(|(node, _)| *node)
            .chain(self.dependencies.iter().copied())
            .find(|node| !tried.contains(node))
    }

    /// The absent nodes whose support meets what is still needed.
    fn missing(&self, needed: &CoverageSet) -> Vec<CollectionData> {
        self.absent
            .iter()
            .filter(|(_, support)| !support.intersect(needed).is_empty())
            .map(|(node, _)| *node)
            .collect()
    }

    fn nodes(&self) -> Vec<CollectionData> {
        self.cover.iter().map(|(node, _)| *node).collect()
    }

    /// A mapping is a function: one input given two different admitted
    /// outputs is a conflict, and residency must never decide which of the
    /// two a reader or a producer endorses next.
    fn conflict(&self, target: CollectionHandle) -> Result<(), CollectionRealizationError> {
        for (input, outputs) in &self.images {
            let mut outputs = outputs.iter();
            if let (Some(first), Some(second)) = (outputs.next(), outputs.next()) {
                return Err(CollectionRealizationError::Resolution(format!(
                    "derivation into {} has conflicting outputs {} and {} for {}",
                    hex::encode_upper(target.raw),
                    hex::encode_upper(first.raw),
                    hex::encode_upper(second.raw),
                    hex::encode_upper(input.raw),
                )));
            }
        }
        Ok(())
    }
}

/// The request at lattice granularity: a row is a node's downward closure,
/// so the union of the requested rows is the closure of the request, and a
/// node whose row lies inside it stands for nothing the request did not ask
/// for. A requested member with no row stays in as itself.
fn closure(coverage: &Coverage, foundation: CollectionHandle, requested: &Support) -> CoverageSet {
    let (mut set, unattested) = coverage.union_over(foundation, requested.data_members());
    set.union(CoverageSet::from_keys(
        unattested.into_iter().map(|member| member.raw),
    ));
    set
}

fn members(set: &CoverageSet) -> Vec<CollectionData> {
    set.iter_ordered().map(|raw| Inline::new(*raw)).collect()
}

/// Choose what `collection` stands on for `requested`, from the index.
///
/// The frontier is the starting point, widest node first. A node whose
/// support lies inside the request and inside nothing chosen before it is
/// taken when its bytes are here and complete and `usable` allows it. Any
/// other node -- wider than the request, absent, incomplete, refused -- is
/// descended: the MERGEs that produced it name the finer nodes beneath. A node
/// inside what is already covered adds nothing and is neither taken nor
/// descended.
fn select<R, E>(
    snapshot: &R,
    coverage: &Coverage,
    lineage: &Lineage,
    collection: Collection<E>,
    requested: &CoverageSet,
    usable: &dyn Fn(CollectionData) -> bool,
) -> Result<Selection, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let handle = collection.handle();
    let mut selection = Selection {
        cover: Vec::new(),
        covered: CoverageSet::new(),
        absent: Vec::new(),
        dependencies: Vec::new(),
        images: BTreeMap::new(),
    };
    let empty = super::coverage::FrontierSet::new();
    let frontier = coverage.frontier_set(handle).unwrap_or(&empty);
    let resident = snapshot.resident(frontier).map_err(|error| {
        CollectionRealizationError::storage("intersect frontier with residency", error)
    })?;
    let mut pending = BinaryHeap::new();
    let mut visited = BTreeSet::new();
    for raw in frontier.iter_ordered() {
        let node: CollectionData = Inline::new(*raw);
        if let Some(support) = coverage.of(handle, node) {
            visited.insert(node);
            pending.push((support.len(), Reverse(node.raw), node));
        }
    }
    let consider = |selection: &mut Selection,
                        node: CollectionData,
                        support: &CoverageSet,
                        descend: bool,
                        pending: &mut BinaryHeap<(u64, Reverse<[u8; 32]>, CollectionData)>,
                        visited: &mut BTreeSet<CollectionData>|
     -> Result<(), CollectionRealizationError> {
        let already = support <= &selection.covered;
        let mut taken = false;
        if !already && support <= requested {
            let is_resident = if frontier.get(&node.raw).is_some() {
                resident.get(&node.raw).is_some()
            } else {
                snapshot
                    .metadata(Handle::<E>::from_hash(node))
                    .map_err(|error| {
                        CollectionRealizationError::storage("inspect lattice node residency", error)
                    })?
                    .is_some()
            };
            if is_resident {
                let missing = E::missing_representation_dependencies(node, snapshot)
                    .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?;
                if missing.is_empty() {
                    if usable(node) {
                        selection.covered.union(support.clone());
                        selection.cover.push((node, support.clone()));
                        taken = true;
                    }
                } else {
                    selection.dependencies.extend(missing);
                }
            } else {
                selection.absent.push((node, support.clone()));
            }
        }
        // The node's producers: one indexed lookup. A DERIVE is remembered
        // for the functional check, also for a node that adds nothing -- a
        // second image of one input is exactly such a node. A MERGE names the
        // finer nodes beneath, descended when this node was neither taken nor
        // already covered.
        let producers = BTreeSet::from([CollectionRecordSelector::ProducedMember(handle, node)]);
        let records = snapshot.select_records(&producers).map_err(|error| {
            CollectionRealizationError::storage("select the producers of a lattice node", error)
        })?;
        for record in records {
            match record {
                CollectionRecord::Derive(derive) => {
                    selection
                        .images
                        .entry(derive.input())
                        .or_default()
                        .insert(node);
                }
                CollectionRecord::Merge(merge) if descend && !taken && !already => {
                    let (low, high) = merge.inputs();
                    for input in [low, high] {
                        if input == node || !visited.insert(input) {
                            continue;
                        }
                        if let Some(support) = coverage.of(handle, input) {
                            pending.push((support.len(), Reverse(input.raw), input));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    };
    while let Some((_, _, node)) = pending.pop() {
        let support = coverage
            .of(handle, node)
            .expect("a pending node was pushed with its row");
        consider(
            &mut selection,
            node,
            support,
            true,
            &mut pending,
            &mut visited,
        )?;
    }
    // A record of this collection ahead of its input's support -- an input
    // whose producer is not admitted here, though its records exist -- has
    // no row, and the fold holds it. What its admitted producer named is
    // still a certificate, read structurally from the records beneath it,
    // the way the record walk reads it. Nothing beneath is re-admitted.
    if coverage.has_blocked(handle) {
        for (node, support) in structural_nodes::<R, E>(snapshot, lineage, collection, &visited)? {
            visited.insert(node);
            consider(
                &mut selection,
                node,
                &support,
                false,
                &mut pending,
                &mut visited,
            )?;
        }
    }
    Ok(selection)
}

/// The nodes this collection's own admitted records produce that the fold
/// has no row for, each with the certificate its record's inputs reduce to.
/// Records that reduce to an unknown, or that the fold already indexed, are
/// left out. Widest first.
fn structural_nodes<R, E>(
    snapshot: &R,
    lineage: &Lineage,
    collection: Collection<E>,
    indexed: &BTreeSet<CollectionData>,
) -> Result<Vec<Node>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let handle = collection.handle();
    let descriptor = lineage.descriptor(handle);
    let evidence = super::api::discover_admission_evidence(
        snapshot,
        super::descriptor::admission_policies(
            snapshot,
            descriptor.facts(),
            super::ACTION_WRITE,
            Some(E::id()),
        ),
        super::ACTION_WRITE,
        handle,
    )
    .map_err(|error| CollectionRealizationError::storage("read target WRITE evidence", error))?;
    let candidates = snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(handle)]))
        .map_err(|error| CollectionRealizationError::storage("read target records", error))?;
    let mut admitted = BTreeMap::new();
    let mut nodes = BTreeMap::<CollectionData, CoverageSet>::new();
    for record in candidates {
        if matches!(record, CollectionRecord::Commit(_)) {
            continue;
        }
        let produced = super::coverage::produced(record);
        if indexed.contains(&produced) || nodes.contains_key(&produced) {
            continue;
        }
        let authorized = *admitted.entry(record.public_key().raw).or_insert_with(|| {
            ed25519_dalek::VerifyingKey::from_bytes(&record.public_key().raw)
                .ok()
                .is_some_and(|key| evidence.authorizes(snapshot, key))
        });
        if !authorized {
            continue;
        }
        if let Some(certificate) = structural_certificate(snapshot, lineage, record)? {
            nodes.insert(produced, certificate);
        }
    }
    let mut nodes: Vec<Node> = nodes.into_iter().collect();
    nodes.sort_by(|left, right| {
        right
            .1
            .len()
            .cmp(&left.1.len())
            .then_with(|| left.0.raw.cmp(&right.0.raw))
    });
    Ok(nodes)
}

/// Every resident frontier node of one collection inside `within`, widest
/// first, dominated nodes included: what a carry works on.
fn resident_frontier<R>(
    snapshot: &R,
    coverage: &Coverage,
    collection: CollectionHandle,
    within: &CoverageSet,
) -> Result<Vec<Node>, CollectionRealizationError>
where
    R: StoreRead,
{
    let Some(frontier) = coverage.frontier_set(collection) else {
        return Ok(Vec::new());
    };
    let resident = snapshot.resident(frontier).map_err(|error| {
        CollectionRealizationError::storage("intersect frontier with residency", error)
    })?;
    let mut nodes = Vec::new();
    for raw in resident.iter_ordered() {
        let node: CollectionData = Inline::new(*raw);
        if let Some(support) = coverage.of(collection, node) {
            if support <= within {
                nodes.push((node, support.clone()));
            }
        }
    }
    nodes.sort_by(|left, right| {
        right
            .1
            .len()
            .cmp(&left.1.len())
            .then_with(|| left.0.raw.cmp(&right.0.raw))
    });
    Ok(nodes)
}

fn coverage_of<R>(
    snapshot: &R,
    lineage: &BTreeSet<CollectionHandle>,
) -> Result<Coverage, CollectionRealizationError>
where
    R: StoreRead,
{
    snapshot
        .coverage(lineage)
        .map_err(|error| CollectionRealizationError::storage("settle downward coverage", error))
}

fn open<S: Store>(
    store: &mut S,
    frontier: &OperationFrontier<S::Snapshot>,
    operation: &'static str,
) -> Result<OperationSnapshot<S::Snapshot, S::Snapshot>, CollectionRealizationError> {
    Ok(frontier.view(
        store
            .snapshot()
            .map_err(|error| CollectionRealizationError::storage(operation, error))?,
    ))
}

fn publish<S: Store>(
    store: &mut S,
    frontier: &mut OperationFrontier<S::Snapshot>,
    record: CollectionRecord,
    operation: &'static str,
) -> Result<(), CollectionRealizationError> {
    store
        .insert(record)
        .map_err(|error| CollectionRealizationError::storage(operation, error))?;
    frontier.include_record(record);
    Ok(())
}

fn ordered(left: CollectionData, right: CollectionData) -> (CollectionData, CollectionData) {
    if left.raw <= right.raw {
        (left, right)
    } else {
        (right, left)
    }
}

/// Observe the complete target realization for one explicit support.
pub(crate) fn attach_collection_exact<R, E>(
    snapshot: &R,
    target: Collection<E>,
    requested: &Support,
) -> Result<(Support, Cover<E>), CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let lineage = load_lineage(snapshot, target)?;
    require_support(&lineage, requested)?;
    let coverage = coverage_of(snapshot, &lineage.handles())?;
    let closure = closure(&coverage, lineage.foundation.handle(), requested);
    let selection = select(snapshot, &coverage, &lineage, target, &closure, &|_| true)?;
    selection.conflict(target.handle())?;
    let mut cover = selection.nodes();
    let mut covered = selection.covered.clone();
    if target.handle() == lineage.foundation.handle() {
        // An explicit root cover is also a low-level content selection: its
        // directly resident members need no COMMIT to be read. This does not
        // manufacture admission; publication still requires real records.
        for member in members(&closure.difference(&covered)) {
            if matches!(
                collection_member_availability::<E, _>(member, snapshot).map_err(|error| {
                    CollectionRealizationError::storage("inspect explicit root member", error)
                })?,
                CollectionMemberAvailability::Complete
            ) {
                cover.push(member);
                covered.insert(&Entry::new(&member.raw));
            }
        }
    }
    let needed = closure.difference(&covered);
    if !needed.is_empty() {
        return Err(CollectionRealizationError::IncompleteCover {
            missing: selection.missing(&needed),
            unsupported_members: members(&needed),
        });
    }
    Ok((requested.clone(), Cover::from_data(target, cover)))
}

/// What a root still has to acquire for one explicit support: `None` when the
/// support is readable now.
pub(super) fn root_acquisitions<R>(
    snapshot: &R,
    target: Collection<SimpleArchive>,
    requested: &Support,
) -> Result<Option<Vec<CollectionData>>, CollectionRealizationError>
where
    R: StoreRead,
{
    let lineage = load_lineage(snapshot, target)?;
    if lineage.foundation != target {
        return Err(CollectionRealizationError::InvalidCover(
            "a derived SimpleArchive target requires an explicit mapping".into(),
        ));
    }
    require_support(&lineage, requested)?;
    let coverage = coverage_of(snapshot, &lineage.handles())?;
    let closure = closure(&coverage, lineage.foundation.handle(), requested);
    let selection = select(snapshot, &coverage, &lineage, target, &closure, &|_| true)?;
    let mut needed = selection.needed(&closure);
    if needed.is_empty() {
        return Ok(None);
    }
    // Explicit root covers remain useful for reading content without
    // publishing a COMMIT. New equations still require record witnesses.
    for member in members(&needed) {
        if snapshot
            .metadata(Handle::<SimpleArchive>::from_hash(member))
            .map_err(|error| {
                CollectionRealizationError::storage("inspect explicit root member", error)
            })?
            .is_some()
        {
            needed.remove(&member.raw);
        }
    }
    if needed.is_empty() {
        return Ok(None);
    }
    // A merge that stands for a needed payload before the payload itself:
    // one fetch instead of many. Then the payloads.
    let mut acquisitions = selection.missing(&needed);
    acquisitions.extend(selection.dependencies.iter().copied());
    acquisitions.extend(members(&needed));
    Ok(Some(acquisitions))
}

/// One mapping bound to its lineage.
struct Bound<M> {
    foundation: CollectionHandle,
    handles: BTreeSet<CollectionHandle>,
    lineage: Lineage,
    source: CollectionHandle,
    mapping: M,
    descriptor: Fragment,
}

fn bind<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
    requested: &Support,
) -> Result<Bound<M>, CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    let lineage = load_lineage(snapshot, target)?;
    require_support(&lineage, requested)?;
    let source = lineage
        .source_by_target
        .get(&target.handle())
        .copied()
        .ok_or_else(|| {
            CollectionRealizationError::Resolution(
                "ensure requires a derived target descriptor".to_owned(),
            )
        })?;
    let source_descriptor = lineage.descriptor(source);
    let target_descriptor = lineage.descriptor(target.handle());
    super::encoding::validate_descriptor_type::<M::Source>(source_descriptor).map_err(|error| {
        CollectionRealizationError::Resolution(format!(
            "mapping source descriptor has the wrong representation: {error}"
        ))
    })?;
    let mapping = M::bind(source_descriptor, target_descriptor).map_err(|error| {
        CollectionRealizationError::Resolution(format!(
            "target descriptor does not bind the requested mapping: {error}"
        ))
    })?;
    let descriptor = target_descriptor.clone();
    Ok(Bound {
        foundation: lineage.foundation.handle(),
        handles: lineage.handles(),
        lineage,
        source,
        mapping,
        descriptor,
    })
}

impl Lineage {
    pub(super) fn handles(&self) -> BTreeSet<CollectionHandle> {
        self.descriptors.keys().copied().collect()
    }
}

/// Whether the target already stands for the whole requested support with
/// resident images, read from the index alone.
pub(super) fn images_exact<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
    requested: &Support,
) -> Result<bool, CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    let bound: Bound<M> = bind(snapshot, target, requested)?;
    let coverage = coverage_of(snapshot, &bound.handles)?;
    let closure = closure(&coverage, bound.foundation, requested);
    let targets = select(snapshot, &coverage, &bound.lineage, target, &closure, &|_| true)?;
    targets.conflict(target.handle())?;
    Ok(targets.needed(&closure).is_empty())
}

/// Publish the images one mapping owes for the requested support.
///
/// Each round reads both frontiers from the index: what the target stands
/// for, what the request still lacks, and which resident source nodes meet
/// that lack, widest first. An existing image whose bytes are elsewhere is
/// asked for before anything is computed. A source node the mapping cannot
/// take at its size is descended to the nodes its MERGE consumed.
pub(super) fn realize_images<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    requested: &Support,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let bound: Bound<M> = bind(
        &open(store, frontier, "open exact mapping snapshot")?,
        target,
        requested,
    )?;
    let source = Collection::<M::Source>::from_handle(bound.source);
    let mut blocked = BTreeMap::<CollectionData, String>::new();
    // Stall detection: the work is identified by the input being mapped.
    let mut published = BTreeSet::<CollectionData>::new();
    loop {
        let snapshot = open(store, frontier, "open exact mapping snapshot")?;
        let coverage = coverage_of(&snapshot, &bound.handles)?;
        let closure = closure(&coverage, bound.foundation, requested);
        let targets = select(&snapshot, &coverage, &bound.lineage, target, &closure, &|_| true)?;
        targets.conflict(target.handle())?;
        let needed = targets.needed(&closure);
        if needed.is_empty() {
            return Ok(());
        }
        // Fetch an existing image before computing one.
        if let Some(member) = targets.acquirable(&needed, unavailable) {
            return Err(CollectionRealizationError::MissingDependency { member });
        }
        let sources = select(&snapshot, &coverage, &bound.lineage, source, &closure, &|node| {
            !blocked.contains_key(&node)
        })?;
        let candidates: Vec<Node> = sources
            .cover
            .iter()
            .filter(|(_, support)| !(support <= &targets.covered))
            .cloned()
            .collect();
        if candidates.is_empty() {
            if let Some(member) = sources.acquirable(&needed, unavailable) {
                return Err(CollectionRealizationError::MissingDependency { member });
            }
            let missing = members(&needed);
            return Err(if blocked.is_empty() {
                CollectionRealizationError::IncompleteCover {
                    missing: sources.missing(&needed),
                    unsupported_members: missing,
                }
            } else {
                CollectionRealizationError::UnrepresentableCover {
                    blocked: blocked.into_iter().collect(),
                    missing,
                }
            });
        }
        if !producer_is_admitted(&snapshot, target, signing_key)? {
            return Err(CollectionRealizationError::UnauthorizedProducer {
                collection: target.handle(),
            });
        }
        drop(snapshot);

        let mut covered = targets.covered.clone();
        for (input_data, support) in candidates {
            if &support <= &covered {
                continue;
            }
            if !published.insert(input_data) {
                return Err(CollectionRealizationError::Stalled {
                    cover: targets.nodes(),
                });
            }
            let snapshot = open(store, frontier, "open mapping dependency snapshot")?;
            let input: Blob<M::Source> = snapshot
                .get(Handle::<M::Source>::from_hash(input_data))
                .map_err(|error| {
                    CollectionRealizationError::storage("load source member for mapping", error)
                })?;
            let output = bound.mapping.map(&input, &snapshot);
            drop(snapshot);
            let output = match output {
                Ok(output) => output,
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Derive {
                        input: input_data,
                        reason,
                    });
                }
                Err(CollectionOperationError::Capacity(reason)) => {
                    // Replan: the selection descends beneath a blocked node.
                    blocked.insert(input_data, reason);
                    break;
                }
                Err(CollectionOperationError::MissingDependency(member)) => {
                    return Err(CollectionRealizationError::MissingDependency { member });
                }
            };
            let output_data = data_identity::<M::Target>(&output);
            store.put::<M::Target, _>(output).map_err(|error| {
                CollectionRealizationError::storage("store derived target member", error)
            })?;
            publish(
                store,
                frontier,
                CollectionRecord::Derive(CollectionDerive::sign(
                    signing_key,
                    target.handle(),
                    input_data,
                    output_data,
                )),
                "publish target DERIVE",
            )?;
            covered.union(support);
        }
    }
}

/// Reuse coarsening already paid for by the source. This is optional
/// maintenance over an exact target, never coverage repair or upstream work.
///
/// A resident source frontier node that no single image covers, while its
/// support is covered by several, gets one image: when exactly two images
/// sit beneath it and stand for all of it, the mapping may join them with
/// the source union in hand and the join is published as a MERGE beside the
/// DERIVE; otherwise the node is mapped. Without target WRITE authority, the
/// existing finer realization is retained.
fn coarsen_images<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    requested: &Support,
    bound: &Bound<M>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let source = Collection::<M::Source>::from_handle(bound.source);
    let mut attempted = BTreeSet::new();
    loop {
        let snapshot = open(store, frontier, "open source-guided maintenance snapshot")?;
        let coverage = coverage_of(&snapshot, &bound.handles)?;
        let closure = closure(&coverage, bound.foundation, requested);
        let targets = select(&snapshot, &coverage, &bound.lineage, target, &closure, &|_| true)?;
        let sources = select(&snapshot, &coverage, &bound.lineage, source, &closure, &|_| true)?;
        let candidate = sources.cover.iter().find(|(node, support)| {
            !attempted.contains(node)
                && !targets
                    .cover
                    .iter()
                    .any(|(_, image)| support <= image)
        });
        let Some((input_data, support)) = candidate.cloned() else {
            return Ok(());
        };
        if !producer_is_admitted(&snapshot, target, signing_key)? {
            return Ok(());
        }
        attempted.insert(input_data);
        let input: Blob<M::Source> = snapshot
            .get(Handle::<M::Source>::from_hash(input_data))
            .map_err(|error| {
                CollectionRealizationError::storage("load resident source coarsening", error)
            })?;
        let under: Vec<&Node> = targets
            .cover
            .iter()
            .filter(|(_, image)| image <= &support)
            .collect();
        let mut joined = None;
        if let [left, right] = under[..] {
            let (low, high) = ordered(left.0, right.0);
            let mut union = left.1.clone();
            union.union(right.1.clone());
            if union == support {
                let low_blob: Blob<M::Target> = snapshot
                    .get(Handle::<M::Target>::from_hash(low))
                    .map_err(|error| {
                        CollectionRealizationError::storage("load lower reusable target image", error)
                    })?;
                let high_blob: Blob<M::Target> = snapshot
                    .get(Handle::<M::Target>::from_hash(high))
                    .map_err(|error| {
                        CollectionRealizationError::storage(
                            "load higher reusable target image",
                            error,
                        )
                    })?;
                match bound.mapping.join_images(
                    &bound.descriptor,
                    Some(&input),
                    &low_blob,
                    &high_blob,
                    &snapshot,
                ) {
                    Ok(Some(output)) => joined = Some((output, low, high)),
                    Ok(None)
                    | Err(CollectionOperationError::Capacity(_))
                    | Err(CollectionOperationError::MissingDependency(_)) => {}
                    Err(CollectionOperationError::Fatal(reason)) => {
                        return Err(CollectionRealizationError::Merge { low, high, reason });
                    }
                }
            }
        }
        let (output, pair) = match joined {
            Some((output, low, high)) => (output, Some((low, high))),
            None => match bound.mapping.map(&input, &snapshot) {
                Ok(output) => (output, None),
                Err(CollectionOperationError::Capacity(_))
                | Err(CollectionOperationError::MissingDependency(_)) => continue,
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Derive {
                        input: input_data,
                        reason,
                    });
                }
            },
        };
        drop(snapshot);
        let output_data = data_identity::<M::Target>(&output);
        store.put::<M::Target, _>(output).map_err(|error| {
            CollectionRealizationError::storage("store source-guided target member", error)
        })?;
        if let Some((low, high)) = pair {
            publish(
                store,
                frontier,
                CollectionRecord::Merge(CollectionMerge::sign(
                    signing_key,
                    target.handle(),
                    low,
                    high,
                    output_data,
                )),
                "publish source-guided target MERGE",
            )?;
        }
        publish(
            store,
            frontier,
            CollectionRecord::Derive(CollectionDerive::sign(
                signing_key,
                target.handle(),
                input_data,
                output_data,
            )),
            "publish source-guided target DERIVE",
        )?;
    }
}

/// Ensure one mapping and then carry its target lattice to the deterministic
/// LSM fixed point.
pub(super) fn maintain_images<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    requested: &Support,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    realize_images::<S, M>(store, target, signing_key, requested, unavailable, frontier)?;
    let bound: Bound<M> = bind(
        &open(store, frontier, "open source-guided maintenance snapshot")?,
        target,
        requested,
    )?;
    coarsen_images(store, target, signing_key, requested, &bound, frontier)?;
    let handles = bound.handles.clone();
    carry_target(
        store,
        target,
        signing_key,
        requested,
        bound.foundation,
        &handles,
        frontier,
        |descriptor, low, high, reader| {
            bound
                .mapping
                .join_images(descriptor, None, low, high, reader)
        },
    )
}

/// Which tier a node carries in: the order of magnitude of its support.
fn tier(support: u64) -> u32 {
    support.max(1).ilog2()
}

/// Carry one target lattice to its deterministic dyadic LSM fixed point
/// feasible under the producer's target WRITE authority.
///
/// Each round reads the resident frontier from the index. A node whose
/// support lies inside another frontier node's is consumed first, by a MERGE
/// whose result is the wider node: no bytes move, and the fine image a coarser
/// one already covers leaves the frontier for good. Then the lowest colliding
/// tier -- nodes whose supports have the same order of magnitude -- is carried
/// as one batch of pairwise-disjoint inputs before the frontier is read again.
/// Since publication only adds equations and never consumes an input twice,
/// an earlier carry cannot invalidate a later pair in the batch. Each result
/// is stored and published immediately, so a later failure preserves the
/// complete successful prefix.
pub(super) fn carry_target<S, E, J>(
    store: &mut S,
    target: Collection<E>,
    signing_key: &SigningKey,
    requested: &Support,
    foundation: CollectionHandle,
    lineage: &BTreeSet<CollectionHandle>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    mut join: J,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    E: CollectionEncoding,
    J: FnMut(
        &Fragment,
        &Blob<E>,
        &Blob<E>,
        &OperationSnapshot<S::Snapshot, S::Snapshot>,
    ) -> Result<Option<Blob<E>>, CollectionOperationError>,
{
    let descriptor = {
        let snapshot = open(store, frontier, "open target-maintenance snapshot")?;
        let descriptor = super::api::load_collection_descriptor(&snapshot, target.handle())
            .map_err(|error| {
                CollectionRealizationError::Resolution(format!(
                    "load target descriptor for maintenance: {error}"
                ))
            })?
            .fragment;
        super::encoding::validate_descriptor_type::<E>(&descriptor).map_err(|error| {
            CollectionRealizationError::Resolution(format!(
                "invalid target descriptor for maintenance: {error}"
            ))
        })?;
        descriptor
    };
    let mut blocked = BTreeSet::new();
    let mut seen = BTreeSet::new();
    loop {
        let snapshot = open(store, frontier, "open target-maintenance snapshot")?;
        let coverage = coverage_of(&snapshot, lineage)?;
        let closure = closure(&coverage, foundation, requested);
        let nodes = resident_frontier(&snapshot, &coverage, target.handle(), &closure)?;
        let identity: Vec<CollectionData> = nodes.iter().map(|(node, _)| *node).collect();
        if !seen.insert(identity.clone()) {
            return Err(CollectionRealizationError::Stalled { cover: identity });
        }
        if nodes.len() < 2 {
            return Ok(());
        }
        // A node inside another's support is consumed by that node. Two nodes
        // with one support keep the lower one, which is also the one a reader
        // keeps.
        let mut dominated = Vec::new();
        for (node, support) in &nodes {
            let dominator = nodes.iter().find(|(other, wider)| {
                other != node && support <= wider && (support != wider || node.raw > other.raw)
            });
            if let Some((other, _)) = dominator {
                dominated.push((*node, *other));
            }
        }
        if !dominated.is_empty() {
            if !producer_is_admitted(&snapshot, target, signing_key)? {
                return Ok(());
            }
            drop(snapshot);
            for (node, result) in dominated {
                let (low, high) = ordered(node, result);
                publish(
                    store,
                    frontier,
                    CollectionRecord::Merge(CollectionMerge::sign(
                        signing_key,
                        target.handle(),
                        low,
                        high,
                        result,
                    )),
                    "publish target MERGE",
                )?;
            }
            continue;
        }
        let mut tiers = BTreeMap::<u32, BTreeSet<CollectionData>>::new();
        for (node, support) in &nodes {
            tiers.entry(tier(support.len())).or_default().insert(*node);
        }
        if !tiers.values().any(|members| members.len() >= 2) {
            return Ok(());
        }
        if !producer_is_admitted(&snapshot, target, signing_key)? {
            return Ok(());
        }
        drop(snapshot);
        if !publish_carry_round(
            store,
            target,
            signing_key,
            &descriptor,
            tiers,
            &mut blocked,
            frontier,
            &mut join,
        )? {
            return Ok(());
        }
    }
}

fn publish_carry_round<S, E, J>(
    store: &mut S,
    target: Collection<E>,
    signing_key: &SigningKey,
    descriptor: &Fragment,
    tiers: BTreeMap<u32, BTreeSet<CollectionData>>,
    blocked: &mut BTreeSet<(CollectionData, CollectionData)>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    join: &mut J,
) -> Result<bool, CollectionRealizationError>
where
    S: Store,
    E: CollectionEncoding,
    J: FnMut(
        &Fragment,
        &Blob<E>,
        &Blob<E>,
        &OperationSnapshot<S::Snapshot, S::Snapshot>,
    ) -> Result<Option<Blob<E>>, CollectionOperationError>,
{
    for (_, mut members) in tiers {
        let mut published = false;
        while members.len() >= 2 {
            let low_data = members
                .pop_first()
                .expect("colliding target tier contains a lower member");
            let high_data = members
                .pop_first()
                .expect("colliding target tier contains a higher member");
            if blocked.contains(&(low_data, high_data)) {
                members.insert(high_data);
                continue;
            }
            let snapshot = open(store, frontier, "open target-carry snapshot")?;
            let low = snapshot
                .get(Handle::<E>::from_hash(low_data))
                .map_err(|error| {
                    CollectionRealizationError::storage("load lower target-carry member", error)
                })?;
            let high = snapshot
                .get(Handle::<E>::from_hash(high_data))
                .map_err(|error| {
                    CollectionRealizationError::storage("load higher target-carry member", error)
                })?;
            let output = join(descriptor, &low, &high, &snapshot);
            drop(snapshot);
            match output {
                Ok(Some(output)) => {
                    let result = data_identity::<E>(&output);
                    store.put::<E, _>(output).map_err(|error| {
                        CollectionRealizationError::storage("store merged target member", error)
                    })?;
                    publish(
                        store,
                        frontier,
                        CollectionRecord::Merge(CollectionMerge::sign(
                            signing_key,
                            target.handle(),
                            low_data,
                            high_data,
                            result,
                        )),
                        "publish target MERGE",
                    )?;
                    published = true;
                }
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Merge {
                        low: low_data,
                        high: high_data,
                        reason,
                    });
                }
                Ok(None)
                | Err(CollectionOperationError::Capacity(_))
                | Err(CollectionOperationError::MissingDependency(_)) => {
                    // Retire the lower input for this planning pass and leave
                    // the higher one eligible for the next deterministic pair.
                    // The exact finer cover remains the valid result.
                    blocked.insert((low_data, high_data));
                    members.insert(high_data);
                }
            }
        }
        if published {
            return Ok(true);
        }
    }
    Ok(false)
}
