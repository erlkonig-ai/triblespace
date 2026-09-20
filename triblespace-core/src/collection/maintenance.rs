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
//! descend: when a frontier node's bytes are not here, or the mapping cannot
//! take it, the MERGE that produced it names the finer nodes beneath, and the
//! produced-member index finds that MERGE without a walk.
//!
//! There is no request. A target stands for what its source stands on --
//! the resident source frontier, never a source node whose bytes are
//! elsewhere, which is the root's business to fetch -- and a root stands for
//! what its admitted commits say; two targets of one source read from one
//! snapshot agree by construction.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use ed25519_dalek::SigningKey;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::Blob;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::repo::{BlobStoreGet, Store, StoreRead};
use crate::trible::Fragment;

use super::coverage::{Coverage, CoverageSet};
use super::exact_derived::{
    data_identity, load_lineage, producer_is_admitted, CollectionRealizationError, Lineage,
};
use super::operation_snapshot::{OperationFrontier, OperationSnapshot};
use super::{
    Collection, CollectionData, CollectionDerive, CollectionEncoding, CollectionHandle,
    CollectionMapping, CollectionMerge, CollectionOperationError, CollectionRecord,
    CollectionRecordSelector,
};

/// One lattice node and what it stands for.
type Node = (CollectionData, CoverageSet);

/// What one collection stands on right now.
struct Selection {
    /// Resident, complete nodes, widest first, none inside the union of the
    /// ones before it.
    cover: Vec<Node>,
    /// The union of the cover's supports.
    covered: CoverageSet,
    /// Nodes met on the way whose bytes are not resident.
    absent: Vec<Node>,
    /// Representation dependencies missing beside resident roots.
    dependencies: Vec<CollectionData>,
}

impl Selection {
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
}

fn members(set: &CoverageSet) -> Vec<CollectionData> {
    set.iter_ordered().map(|raw| Inline::new(*raw)).collect()
}

/// What `collection` stands on, from the index.
///
/// The frontier is the starting point, widest node first. A node inside
/// nothing chosen before it is taken when its bytes are here and complete
/// and `usable` allows it. Any other node -- absent, incomplete, refused --
/// is descended: the MERGEs that produced it name the finer nodes beneath. A
/// node inside what is already covered adds nothing and is neither taken nor
/// descended.
fn select<R, E>(
    snapshot: &R,
    coverage: &Coverage,
    collection: Collection<E>,
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
    };
    let Some(frontier) = coverage.frontier_set(handle) else {
        return Ok(selection);
    };
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
    while let Some((_, _, node)) = pending.pop() {
        let support = coverage
            .of(handle, node)
            .expect("a pending node was pushed with its row");
        if support <= &selection.covered {
            continue;
        }
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
                    continue;
                }
            } else {
                selection.dependencies.extend(missing);
            }
        } else {
            selection.absent.push((node, support.clone()));
        }
        // Descend: the MERGEs that produced this node name the finer nodes
        // beneath it, one indexed lookup.
        let producers = BTreeSet::from([CollectionRecordSelector::ProducedMember(handle, node)]);
        let records = snapshot.select_records(&producers).map_err(|error| {
            CollectionRealizationError::storage("select the producers of a lattice node", error)
        })?;
        for record in records {
            let CollectionRecord::Merge(merge) = record else {
                continue;
            };
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
    }
    Ok(selection)
}

/// Every resident frontier node of one collection, widest first, dominated
/// nodes included: what a carry works on.
fn resident_frontier<R>(
    snapshot: &R,
    coverage: &Coverage,
    collection: CollectionHandle,
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
            nodes.push((node, support.clone()));
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

/// What a root still lacks before it stands on every admitted commit.
struct RootGap {
    needed: CoverageSet,
    selection: Selection,
}

fn root_gap<R>(
    snapshot: &R,
    target: Collection<SimpleArchive>,
) -> Result<RootGap, CollectionRealizationError>
where
    R: StoreRead,
{
    let lineage = load_lineage(snapshot, target)?;
    if lineage.foundation != target {
        return Err(CollectionRealizationError::InvalidCover(
            "a derived SimpleArchive target requires an explicit mapping".into(),
        ));
    }
    let coverage = coverage_of(snapshot, &lineage.handles())?;
    let (admitted, _) = coverage.frontier_support(target.handle());
    let selection = select(snapshot, &coverage, target, &|_| true)?;
    let needed = admitted.difference(&selection.covered);
    Ok(RootGap { needed, selection })
}

/// What a root still has to acquire before it stands on every admitted
/// commit: `None` when it does.
pub(super) fn root_acquisitions<R>(
    snapshot: &R,
    target: Collection<SimpleArchive>,
) -> Result<Option<Vec<CollectionData>>, CollectionRealizationError>
where
    R: StoreRead,
{
    let gap = root_gap(snapshot, target)?;
    if gap.needed.is_empty() {
        return Ok(None);
    }
    // A merge that stands for a needed payload before the payload itself:
    // one fetch instead of many. Then the payloads.
    let mut acquisitions = gap.selection.missing(&gap.needed);
    acquisitions.extend(gap.selection.dependencies.iter().copied());
    acquisitions.extend(members(&gap.needed));
    Ok(Some(acquisitions))
}

/// The error a root reports when it cannot stand on every admitted commit
/// and nothing more can be acquired.
pub(super) fn root_incomplete<R>(
    snapshot: &R,
    target: Collection<SimpleArchive>,
) -> Result<(), CollectionRealizationError>
where
    R: StoreRead,
{
    let gap = root_gap(snapshot, target)?;
    if gap.needed.is_empty() {
        return Ok(());
    }
    Err(CollectionRealizationError::IncompleteCover {
        missing: gap.selection.missing(&gap.needed),
        unsupported_members: members(&gap.needed),
    })
}

/// One mapping bound to its lineage.
struct Bound<M> {
    handles: BTreeSet<CollectionHandle>,
    source: CollectionHandle,
    mapping: M,
    descriptor: Fragment,
}

fn bind<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
) -> Result<Bound<M>, CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    let lineage = load_lineage(snapshot, target)?;
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
        handles: lineage.handles(),
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

/// Whether the target already stands for everything its source stands on,
/// with resident images, read from the index alone.
pub(super) fn images_current<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
) -> Result<bool, CollectionRealizationError>
where
    R: StoreRead,
    M: CollectionMapping,
{
    let bound: Bound<M> = bind(snapshot, target)?;
    let coverage = coverage_of(snapshot, &bound.handles)?;
    let source = Collection::<M::Source>::from_handle(bound.source);
    let targets = select(snapshot, &coverage, target, &|_| true)?;
    let sources = select(snapshot, &coverage, source, &|_| true)?;
    Ok(sources.covered <= targets.covered)
}

/// Publish the images one mapping owes its source.
///
/// Each round reads both frontiers from the index: what the resident source
/// stands on, what the target stands on, and which resident source nodes
/// meet the difference, widest first. An existing image whose bytes are
/// elsewhere is asked for before anything is computed. A source node whose
/// bytes are elsewhere is not an obligation here; fetching payloads is the
/// root's job. A source node the mapping cannot take at its size is
/// descended to the nodes its MERGE consumed.
pub(super) fn realize_images<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let bound: Bound<M> = bind(&open(store, frontier, "open mapping snapshot")?, target)?;
    let source = Collection::<M::Source>::from_handle(bound.source);
    let mut blocked = BTreeMap::<CollectionData, String>::new();
    // Stall detection: the work is identified by the input being mapped.
    let mut published = BTreeSet::<CollectionData>::new();
    loop {
        let snapshot = open(store, frontier, "open mapping snapshot")?;
        let coverage = coverage_of(&snapshot, &bound.handles)?;
        let targets = select(&snapshot, &coverage, target, &|_| true)?;
        let sources = select(&snapshot, &coverage, source, &|node| {
            !blocked.contains_key(&node)
        })?;
        // What the resident source stands on that the target does not.
        let needed = sources.covered.difference(&targets.covered);
        if needed.is_empty() {
            if blocked.is_empty() {
                return Ok(());
            }
            // The resident source is covered, but a blocked node stood for
            // more than its resident inputs do: say so rather than pass.
            let (source_support, _) = coverage.frontier_support(source.handle());
            let uncovered = source_support.difference(&targets.covered);
            if uncovered.is_empty() {
                return Ok(());
            }
            return Err(CollectionRealizationError::UnrepresentableCover {
                blocked: blocked.into_iter().collect(),
                missing: members(&uncovered),
            });
        }
        // Fetch an existing image before computing one.
        if let Some(member) = targets.acquirable(&needed, unavailable) {
            return Err(CollectionRealizationError::MissingDependency { member });
        }
        let candidates: Vec<Node> = sources
            .cover
            .iter()
            .filter(|(_, support)| !(support <= &targets.covered))
            .cloned()
            .collect();
        if candidates.is_empty() {
            // Cannot happen: `needed` lies inside the union of the candidates'
            // supports. Report rather than spin.
            return Err(CollectionRealizationError::IncompleteCover {
                missing: sources.missing(&needed),
                unsupported_members: members(&needed),
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
/// maintenance over a current target, never coverage repair or upstream work.
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
        let targets = select(&snapshot, &coverage, target, &|_| true)?;
        let sources = select(&snapshot, &coverage, source, &|_| true)?;
        let candidate = sources.cover.iter().find(|(node, support)| {
            !attempted.contains(node)
                && support <= &targets.covered
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
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    realize_images::<S, M>(store, target, signing_key, unavailable, frontier)?;
    let bound: Bound<M> = bind(
        &open(store, frontier, "open source-guided maintenance snapshot")?,
        target,
    )?;
    coarsen_images(store, target, signing_key, &bound, frontier)?;
    let handles = bound.handles.clone();
    carry_target(
        store,
        target,
        signing_key,
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
        let nodes = resident_frontier(&snapshot, &coverage, target.handle())?;
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
