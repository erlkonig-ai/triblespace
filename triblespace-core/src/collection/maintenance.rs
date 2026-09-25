//! Maintenance planned from the coverage index, per owner.
//!
//! Every collection is a lattice of its own foundations joined by MERGEs,
//! and a maintainer merges or derives only what it owns
//! ([`owns`](super::ownership::owns)). There are two kinds of work, and
//! neither compares supports across collections:
//!
//! - A root carries its maintainer's own frontier nodes. A node whose support
//!   lies inside another own node's is absorbed by it, `MERGE(node, wider) ->
//!   wider`. Whenever one tier -- `floor(log_8 |support|)` -- holds
//!   [`MERGE_FAN_IN`] own nodes, the eight lowest handles are joined by one
//!   n-ary MERGE, until no tier holds eight. Nobody else's payload is read,
//!   so nobody else's absence can stall it.
//! - A derived collection derives what its maintainer wrote. Every source
//!   foundation it owns whose locator has no leaf in the target yet is mapped
//!   and published as `DERIVE(target, L(F), f(F))`, empty images included.
//!   Every source MERGE producing a node it owns is mirrored, bottom-up, as a
//!   target MERGE over the images of its inputs, the result computed by
//!   mapping the merged source node's own bytes. A derived collection has no
//!   carry of its own: its merges are its source's merges, one level down.
//!
//! Records are selected only to descend: the MERGEs that produced a merged
//! source node come from the produced-member index, and a mirror already
//! published is found through the target's consumer edges, the MERGE
//! relation read by its own key. The only link between a view and its source
//! is the locator each leaf carries.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::Blob;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::patch::Entry;
use crate::repo::{BlobStoreGet, BlobStoreMeta, Store, StoreRead};
use crate::trible::Fragment;

use super::coverage::{Coverage, CoverageIndex, CoverageSet, FrontierSet};
use super::exact_derived::{
    data_identity, load_lineage, producer_is_admitted, CollectionRealizationError, Lineage,
};
use super::operation_snapshot::{OperationFrontier, OperationSnapshot};
use super::ownership::owns;
use super::{
    Collection, CollectionData, CollectionDerive, CollectionEncoding, CollectionHandle,
    CollectionMapping, CollectionMerge, CollectionOperationError, CollectionRecord,
    CollectionRecordSelector, MergeInputs, SourceLocator,
};

/// How many own nodes of one tier a root carry joins into one MERGE, and the
/// base of the tier logarithm.
pub const MERGE_FAN_IN: usize = 8;

/// Which tier a node carries in: `floor(log_8 |support|)`.
fn tier(support: u64) -> u32 {
    support.max(1).ilog(MERGE_FAN_IN as u64)
}

/// One lattice node and what it stands for.
pub(super) type Node = (CollectionData, CoverageSet);

/// What one collection stands on right now.
pub(super) struct Selection {
    /// Resident, complete nodes, widest first, none inside the union of the
    /// ones before it.
    pub(super) cover: Vec<Node>,
    /// The union of the cover's supports.
    pub(super) covered: CoverageSet,
    /// Nodes met on the way whose bytes are not resident.
    pub(super) absent: Vec<Node>,
    /// Representation dependencies missing beside resident roots.
    pub(super) dependencies: Vec<CollectionData>,
}

impl Selection {
    /// The absent nodes whose support meets what is still needed.
    fn missing(&self, needed: &CoverageSet) -> Vec<CollectionData> {
        self.absent
            .iter()
            .filter(|(_, support)| !support.intersect(needed).is_empty())
            .map(|(node, _)| *node)
            .collect()
    }

    pub(super) fn nodes(&self) -> Vec<CollectionData> {
        self.cover.iter().map(|(node, _)| *node).collect()
    }
}

fn members(set: &CoverageSet) -> Vec<CollectionData> {
    set.iter_ordered().map(|raw| Inline::new(*raw)).collect()
}

/// What `collection` stands on, from the index: the reader's selection.
///
/// The frontier is the starting point, widest node first. A node inside
/// nothing chosen before it is taken when its bytes are here and complete.
/// Any other node -- absent or incomplete -- is descended: the MERGEs that
/// produced it name the finer nodes beneath. A node inside what is already
/// covered adds nothing and is neither taken nor descended.
pub(super) fn select<R, E>(
    snapshot: &R,
    coverage: &Coverage,
    collection: Collection<E>,
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
                selection.covered.union(support.clone());
                selection.cover.push((node, support.clone()));
                continue;
            }
            selection.dependencies.extend(missing);
        } else {
            selection.absent.push((node, support.clone()));
        }
        // Descend: the MERGEs that produced this node name the finer nodes
        // beneath it, one indexed lookup.
        for merge in producers(snapshot, handle, node)? {
            for &input in merge.inputs() {
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

/// The MERGEs of `collection` that produce `node`, in the store's
/// deterministic order: one produced-member lookup.
fn producers<R>(
    snapshot: &R,
    collection: CollectionHandle,
    node: CollectionData,
) -> Result<Vec<CollectionMerge>, CollectionRealizationError>
where
    R: StoreRead,
{
    let selector = BTreeSet::from([CollectionRecordSelector::ProducedMember(collection, node)]);
    let records = snapshot.select_records(&selector).map_err(|error| {
        CollectionRealizationError::storage("select the producers of a lattice node", error)
    })?;
    Ok(records
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Merge(merge) if merge.result() == node => Some(merge),
            _ => None,
        })
        .collect())
}

fn coverage_of<R>(
    snapshot: &R,
    scope: &BTreeSet<CollectionHandle>,
) -> Result<Coverage, CollectionRealizationError>
where
    R: StoreRead,
{
    snapshot
        .coverage(scope)
        .map_err(|error| CollectionRealizationError::storage("settle coverage", error))
}

fn index_of<R>(
    snapshot: &R,
    scope: &BTreeSet<CollectionHandle>,
) -> Result<CoverageIndex, CollectionRealizationError>
where
    R: StoreRead,
{
    snapshot
        .index(scope)
        .map_err(|error| CollectionRealizationError::storage("settle coverage index", error))
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

/// Sign one MERGE the planner chose. Its inputs are distinct nodes, two to
/// sixteen of them, so an arity refusal is a planning bug, reported as such.
fn sign_merge(
    signing_key: &SigningKey,
    collection: CollectionHandle,
    inputs: impl IntoIterator<Item = CollectionData>,
    result: CollectionData,
) -> Result<CollectionMerge, CollectionRealizationError> {
    CollectionMerge::sign(signing_key, collection, inputs, result).map_err(|error| {
        CollectionRealizationError::Resolution(format!("plan an invalid MERGE: {error}"))
    })
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
    let selection = select(snapshot, &coverage, target)?;
    let needed = admitted.difference(&selection.covered);
    Ok(RootGap { needed, selection })
}

/// What a root still has to acquire before a reader stands on every
/// admitted commit, whoever wrote it: `None` when it does.
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

/// The error a root reports when a reader cannot stand on every admitted
/// commit and nothing more can be acquired.
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

impl Lineage {
    pub(super) fn handles(&self) -> BTreeSet<CollectionHandle> {
        self.descriptors.keys().copied().collect()
    }
}

/// The maintaining key's own frontier nodes of one collection, widest first.
///
/// An own node whose bytes are not here is asked for; one that could not be
/// acquired sits out. Nobody else's node is looked at, resident or not.
fn own_frontier<R>(
    snapshot: &R,
    coverage: &Coverage,
    collection: CollectionHandle,
    key: &VerifyingKey,
    unavailable: &BTreeSet<CollectionData>,
) -> Result<Vec<Node>, CollectionRealizationError>
where
    R: StoreRead,
{
    let Some(frontier) = coverage.frontier_set(collection) else {
        return Ok(Vec::new());
    };
    let mut own = FrontierSet::new();
    for raw in frontier.iter_ordered() {
        if owns(coverage, collection, Inline::new(*raw), key) {
            own.insert(&Entry::new(raw));
        }
    }
    let resident = snapshot.resident(&own).map_err(|error| {
        CollectionRealizationError::storage("intersect own frontier with residency", error)
    })?;
    let mut nodes = Vec::new();
    for raw in own.iter_ordered() {
        let node: CollectionData = Inline::new(*raw);
        if resident.get(raw).is_none() {
            if unavailable.contains(&node) {
                continue;
            }
            return Err(CollectionRealizationError::MissingDependency { member: node });
        }
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

fn load_descriptor<R, E>(
    snapshot: &R,
    target: Collection<E>,
) -> Result<Fragment, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let descriptor = super::api::load_collection_descriptor(snapshot, target.handle())
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
    Ok(descriptor)
}

/// Carry the maintaining key's own nodes of one root to their LSM fixed
/// point.
///
/// Each round reads the own frontier from the index. A node whose support
/// lies inside another own node's is consumed first, by `MERGE(node, wider)
/// -> wider`: no bytes move. Then every tier holding [`MERGE_FAN_IN`] own
/// nodes is carried, the lowest such tier first, eight lowest handles per
/// MERGE, joined by the encoding's k-way join, before the frontier is read
/// again. Each result is stored and published at once, so a later failure
/// keeps the complete successful prefix. Without WRITE authority nothing is
/// published; the own finer cover is then the fixed point.
pub(super) fn carry_root<S, E>(
    store: &mut S,
    target: Collection<E>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    E: CollectionEncoding,
{
    let key = signing_key.verifying_key();
    let scope = BTreeSet::from([target.handle()]);
    let descriptor = load_descriptor(&open(store, frontier, "open root-carry snapshot")?, target)?;
    let mut seen = BTreeSet::new();
    let mut declined = BTreeSet::<Vec<CollectionData>>::new();
    let mut progressed = true;
    loop {
        let snapshot = open(store, frontier, "open root-carry snapshot")?;
        let coverage = coverage_of(&snapshot, &scope)?;
        let nodes = own_frontier(&snapshot, &coverage, target.handle(), &key, unavailable)?;
        let identity: Vec<CollectionData> = nodes.iter().map(|(node, _)| *node).collect();
        if progressed && !seen.insert(identity.clone()) {
            return Err(CollectionRealizationError::Stalled { cover: identity });
        }
        if nodes.len() < 2 {
            return Ok(());
        }
        // A node inside another own node's support is consumed by its widest
        // such node. Two nodes with one support keep the lower handle, which
        // is also the one a reader keeps.
        let absorbed: Vec<(CollectionData, CollectionData)> = nodes
            .iter()
            .filter_map(|(node, support)| {
                nodes
                    .iter()
                    .find(|(other, wider)| {
                        other != node
                            && support <= wider
                            && (support != wider || node.raw > other.raw)
                    })
                    .map(|(wider, _)| (*node, *wider))
            })
            .collect();
        if !absorbed.is_empty() {
            if !producer_is_admitted(&snapshot, target, signing_key)? {
                return Ok(());
            }
            drop(snapshot);
            for (node, wider) in absorbed {
                publish(
                    store,
                    frontier,
                    CollectionRecord::Merge(sign_merge(
                        signing_key,
                        target.handle(),
                        [node, wider],
                        wider,
                    )?),
                    "publish root absorption MERGE",
                )?;
            }
            progressed = true;
            continue;
        }
        let mut tiers = BTreeMap::<u32, BTreeSet<CollectionData>>::new();
        for (node, support) in &nodes {
            tiers.entry(tier(support.len())).or_default().insert(*node);
        }
        // The lowest tier with a full group; within it, consecutive groups of
        // the lowest handles, each group pairwise disjoint from the others.
        let round: Vec<Vec<CollectionData>> = tiers
            .into_values()
            .map(|members| {
                let members: Vec<CollectionData> = members.into_iter().collect();
                members
                    .chunks_exact(MERGE_FAN_IN)
                    .map(<[CollectionData]>::to_vec)
                    .filter(|group| !declined.contains(group))
                    .collect::<Vec<_>>()
            })
            .find(|groups| !groups.is_empty())
            .unwrap_or_default();
        if round.is_empty() {
            return Ok(());
        }
        if !producer_is_admitted(&snapshot, target, signing_key)? {
            return Ok(());
        }
        drop(snapshot);
        progressed = false;
        for group in round {
            let snapshot = open(store, frontier, "open root-carry join snapshot")?;
            let blobs = group
                .iter()
                .map(|node| snapshot.get::<Blob<E>, E>(Handle::<E>::from_hash(*node)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    CollectionRealizationError::storage("load an own node to carry", error)
                })?;
            let joined = E::join_many(&descriptor, &blobs, &snapshot);
            drop(snapshot);
            match joined {
                Ok(output) => {
                    let result = data_identity::<E>(&output);
                    store.put::<E, _>(output).map_err(|error| {
                        CollectionRealizationError::storage("store a carried root node", error)
                    })?;
                    publish(
                        store,
                        frontier,
                        CollectionRecord::Merge(sign_merge(
                            signing_key,
                            target.handle(),
                            group.iter().copied(),
                            result,
                        )?),
                        "publish root carry MERGE",
                    )?;
                    progressed = true;
                }
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Merge {
                        inputs: group,
                        reason,
                    });
                }
                Err(CollectionOperationError::Capacity(_))
                | Err(CollectionOperationError::MissingDependency(_)) => {
                    // The finer cover stays the valid result for this group.
                    declined.insert(group);
                }
            }
        }
    }
}

/// One mapping bound to its target and its immediate source.
struct Bound<M> {
    source: CollectionHandle,
    mapping: M,
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
                "derived maintenance requires a derived target descriptor".to_owned(),
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
    Ok(Bound { source, mapping })
}

/// Derive the maintaining key's missing leaves into one derived collection,
/// and, when `aligned`, mirror its own source merges.
///
/// `ensure` is the leaves alone; `maintain` is both. A leaf the mapping
/// cannot represent is reported after everything else has been done, so one
/// unrepresentable foundation does not hold back the rest.
pub(super) fn maintain_derived<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    aligned: bool,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let bound: Bound<M> = bind(&open(store, frontier, "open mapping snapshot")?, target)?;
    let blocked = derive_leaves(store, target, &bound, signing_key, unavailable, frontier)?;
    if aligned {
        mirror_merges(store, target, &bound, signing_key, unavailable, frontier)?;
    }
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(CollectionRealizationError::Unmappable { blocked })
    }
}

/// Publish a leaf for every own source foundation whose locator the target
/// has none for: `DERIVE(target, L(F), f(F))`, an empty image included.
///
/// The source's foundations are what its frontier stands for; the ones the
/// key owns are its to derive. An own leaf that exists but whose image is
/// not here is fetched; when it cannot be, the foundation is mapped again to
/// restore the bytes, and a leaf is published only if the image differs.
/// Returns the foundations the mapping could not represent.
fn derive_leaves<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    bound: &Bound<M>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<Vec<(CollectionData, String)>, CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let key = signing_key.verifying_key();
    let scope = BTreeSet::from([bound.source, target.handle()]);
    let snapshot = open(store, frontier, "open leaf-derivation snapshot")?;
    let coverage = coverage_of(&snapshot, &scope)?;
    let (foundations, _) = coverage.frontier_support(bound.source);
    // Each own foundation, its locator, and the images its existing leaves
    // name: none for a foundation still owed a leaf.
    let mut owed = Vec::new();
    let mut derived = Vec::new();
    for raw in foundations.iter_ordered() {
        let foundation: CollectionData = Inline::new(*raw);
        if !owns(&coverage, bound.source, foundation, &key) {
            continue;
        }
        let locator = SourceLocator::of(foundation.raw);
        let outputs = coverage.leaf_outputs(target.handle(), locator);
        if outputs.is_empty() {
            owed.push((foundation, locator, outputs));
        } else {
            derived.push((foundation, locator, outputs));
        }
    }
    let new_leaves = !owed.is_empty();
    if !derived.is_empty() {
        let mut images = FrontierSet::new();
        for (_, _, outputs) in &derived {
            for output in outputs {
                images.insert(&Entry::new(&output.raw));
            }
        }
        let resident = snapshot.resident(&images).map_err(|error| {
            CollectionRealizationError::storage("intersect own leaves with residency", error)
        })?;
        for (foundation, locator, outputs) in derived {
            if outputs
                .iter()
                .any(|output| resident.get(&output.raw).is_some())
            {
                continue;
            }
            if let Some(member) = outputs.iter().find(|output| !unavailable.contains(*output)) {
                return Err(CollectionRealizationError::MissingDependency { member: *member });
            }
            // Nobody could hand the image over: map the own foundation again.
            owed.push((foundation, locator, outputs));
        }
    }
    if owed.is_empty() {
        return Ok(Vec::new());
    }
    let admitted = producer_is_admitted(&snapshot, target, signing_key)?;
    if new_leaves && !admitted {
        return Err(CollectionRealizationError::UnauthorizedProducer {
            collection: target.handle(),
        });
    }
    drop(snapshot);

    let mut blocked = Vec::new();
    for (foundation, locator, existing) in owed {
        let snapshot = open(store, frontier, "open leaf mapping snapshot")?;
        let handle = Handle::<M::Source>::from_hash(foundation);
        let resident = snapshot
            .metadata(handle)
            .map_err(|error| {
                CollectionRealizationError::storage("inspect own source foundation", error)
            })?
            .is_some();
        if !resident {
            if unavailable.contains(&foundation) {
                blocked.push((
                    foundation,
                    "the source foundation is not resident and could not be acquired".to_owned(),
                ));
                continue;
            }
            return Err(CollectionRealizationError::MissingDependency { member: foundation });
        }
        let input: Blob<M::Source> = snapshot.get(handle).map_err(|error| {
            CollectionRealizationError::storage("load own source foundation", error)
        })?;
        let output = bound.mapping.map(&input, &snapshot);
        drop(snapshot);
        match output {
            Ok(output) => {
                let output_data = data_identity::<M::Target>(&output);
                store.put::<M::Target, _>(output).map_err(|error| {
                    CollectionRealizationError::storage("store a leaf image", error)
                })?;
                if existing.contains(&output_data) || !admitted {
                    // The restored bytes of a leaf already believed.
                    continue;
                }
                publish(
                    store,
                    frontier,
                    CollectionRecord::Derive(CollectionDerive::sign(
                        signing_key,
                        target.handle(),
                        locator,
                        output_data,
                    )),
                    "publish leaf DERIVE",
                )?;
            }
            Err(CollectionOperationError::Capacity(reason)) => blocked.push((foundation, reason)),
            Err(CollectionOperationError::MissingDependency(member))
                if unavailable.contains(&member) =>
            {
                blocked.push((
                    foundation,
                    format!(
                        "the mapping requires blob {}, which could not be acquired",
                        hex::encode_upper(member.raw)
                    ),
                ));
            }
            Err(CollectionOperationError::MissingDependency(member)) => {
                return Err(CollectionRealizationError::MissingDependency { member });
            }
            Err(CollectionOperationError::Fatal(reason)) => {
                return Err(CollectionRealizationError::Derive {
                    input: foundation,
                    reason,
                });
            }
        }
    }
    Ok(blocked)
}

/// Mirror every source MERGE producing a node the key owns, bottom-up.
///
/// The walk starts at the key's own source frontier and descends through the
/// MERGEs that produced each merged node. A foundation's image is its leaf. A
/// merged node's image is found, in order: all its inputs share one image,
/// which is then its image too; a target MERGE of exactly its inputs' images
/// is already believed, whose result is its image; or the key owns it, and it
/// is mapped from its own bytes and `MERGE(target; images -> image)` is
/// published. A node the mapping declines is not mirrored, and neither is
/// anything that needs it; its inputs' images stay on the target frontier.
fn mirror_merges<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    bound: &Bound<M>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: CollectionMapping,
{
    let key = signing_key.verifying_key();
    let source = bound.source;
    let scope = BTreeSet::from([source, target.handle()]);
    // Read everything the walk needs from one planning snapshot, then let
    // it go: a publishing operation holds only its control snapshot while it
    // writes. What is read is the index and, for each merged node beneath
    // the key's own source frontier, the MERGEs that produced it.
    let planning = open(store, frontier, "open merge-mirror snapshot")?;
    let index = index_of(&planning, &scope)?;
    let coverage = index.published();
    let tops: Vec<CollectionData> = coverage
        .frontier(source)
        .filter(|node| owns(coverage, source, *node, &key))
        .collect();
    let mut produced = BTreeMap::new();
    let mut pending = tops.clone();
    let mut seen = BTreeSet::new();
    while let Some(node) = pending.pop() {
        if !seen.insert(node) || coverage.covers(source, node, node) {
            continue;
        }
        let merges: Vec<MergeInputs> = producers(&planning, source, node)?
            .iter()
            .map(CollectionMerge::merge_inputs)
            .collect();
        pending.extend(merges.iter().flat_map(|inputs| inputs.iter()));
        produced.insert(node, merges);
    }
    let admitted = producer_is_admitted(&planning, target, signing_key)?;
    drop(planning);

    let mut mirror = Mirror {
        store,
        frontier,
        target,
        bound,
        signing_key,
        key,
        unavailable,
        index,
        produced,
        images: BTreeMap::new(),
        visiting: BTreeSet::new(),
        joined: BTreeMap::new(),
        admitted,
    };
    for node in tops {
        mirror.image(node)?;
    }
    Ok(())
}

/// One pass of aligned mirroring: what it read at the start, and what it has
/// resolved and published since. It holds no store snapshot.
struct Mirror<'a, S, M>
where
    S: Store,
    M: CollectionMapping,
{
    store: &'a mut S,
    frontier: &'a mut OperationFrontier<S::Snapshot>,
    target: Collection<M::Target>,
    bound: &'a Bound<M>,
    signing_key: &'a SigningKey,
    key: VerifyingKey,
    unavailable: &'a BTreeSet<CollectionData>,
    index: CoverageIndex,
    /// The input sets of the MERGEs producing each merged source node the
    /// walk can reach.
    produced: BTreeMap<CollectionData, Vec<MergeInputs>>,
    /// Each source node's image, or `None` when it has none to give.
    images: BTreeMap<CollectionData, Option<CollectionData>>,
    /// The source nodes being resolved, so a cyclic lattice ends.
    visiting: BTreeSet<CollectionData>,
    /// Target MERGEs this pass published, by their input set.
    joined: BTreeMap<Vec<CollectionData>, CollectionData>,
    /// Whether the key may write the target.
    admitted: bool,
}

impl<S, M> Mirror<'_, S, M>
where
    S: Store,
    M: CollectionMapping,
{
    /// The image of one source node in the target, publishing the mirror
    /// that makes it one when the key owns the node.
    fn image(
        &mut self,
        node: CollectionData,
    ) -> Result<Option<CollectionData>, CollectionRealizationError> {
        if let Some(image) = self.images.get(&node) {
            return Ok(*image);
        }
        if !self.visiting.insert(node) {
            return Ok(None);
        }
        let image = self.resolve(node);
        self.visiting.remove(&node);
        let image = image?;
        self.images.insert(node, image);
        Ok(image)
    }

    fn resolve(
        &mut self,
        node: CollectionData,
    ) -> Result<Option<CollectionData>, CollectionRealizationError> {
        let source = self.bound.source;
        let target = self.target.handle();
        let coverage = self.index.published();
        if coverage.covers(source, node, node) {
            // A foundation's image is its leaf, whoever derived it.
            return Ok(coverage
                .leaf_outputs(target, SourceLocator::of(node.raw))
                .first()
                .copied());
        }
        let owned = owns(coverage, source, node, &self.key);
        let (absorbing, proper): (Vec<MergeInputs>, Vec<MergeInputs>) = self
            .produced
            .get(&node)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .partition(|inputs| inputs.contains(node));
        let mut image = None;
        for inputs in proper {
            let Some(images) = self.input_images(inputs.as_slice(), None)? else {
                continue;
            };
            // The result is a property of the node, not of the producer: one
            // attempt settles it.
            image = self.join_of(images, node, owned)?;
            break;
        }
        let Some(image) = image else {
            return Ok(None);
        };
        // `MERGE(a, node) -> node` in the source is `MERGE(f(a), f(node)) ->
        // f(node)` in the target: an absorption needs no mapping.
        for inputs in absorbing {
            let Some(images) = self.input_images(inputs.as_slice(), Some((node, image)))? else {
                continue;
            };
            if images.len() < 2 || self.existing(&images).is_some() || !owned {
                continue;
            }
            if !self.admitted {
                break;
            }
            self.publish_mirror(images, image)?;
        }
        Ok(Some(image))
    }

    /// The images of a merge's inputs, sorted and distinct, or `None` when
    /// one of them has none. `known` substitutes an image being resolved.
    ///
    /// Every input is resolved even after one has come back without an
    /// image: a sibling of a node the mapping declined is still mirrored.
    fn input_images(
        &mut self,
        inputs: &[CollectionData],
        known: Option<(CollectionData, CollectionData)>,
    ) -> Result<Option<Vec<CollectionData>>, CollectionRealizationError> {
        let mut images = Vec::with_capacity(inputs.len());
        let mut complete = true;
        for &input in inputs {
            let image = match known {
                Some((node, image)) if node == input => Some(image),
                _ => self.image(input)?,
            };
            match image {
                Some(image) => images.push(image),
                None => complete = false,
            }
        }
        if !complete {
            return Ok(None);
        }
        images.sort_unstable_by(|left, right| left.raw.cmp(&right.raw));
        images.dedup();
        Ok(Some(images))
    }

    /// The target MERGE of exactly these images, if one is believed or was
    /// published by this pass: its result.
    fn existing(&self, images: &[CollectionData]) -> Option<CollectionData> {
        if let Some(result) = self.joined.get(images) {
            return Some(*result);
        }
        let first = *images.first()?;
        self.index
            .joins_reading(self.target.handle(), first)
            .into_iter()
            .find(|(inputs, _)| inputs.as_slice() == images)
            .map(|(_, result)| result)
    }

    /// The image of a merged source node whose inputs have these images.
    fn join_of(
        &mut self,
        images: Vec<CollectionData>,
        node: CollectionData,
        owned: bool,
    ) -> Result<Option<CollectionData>, CollectionRealizationError> {
        if let [only] = images[..] {
            // Every input has one image, and a join of it with itself is it.
            return Ok(Some(only));
        }
        if let Some(result) = self.existing(&images) {
            return Ok(Some(result));
        }
        // Someone else's merge is theirs to mirror.
        if !owned || !self.admitted {
            return Ok(None);
        }
        let Some(output) = self.map_merged(node)? else {
            return Ok(None);
        };
        self.publish_mirror(images, output)?;
        Ok(Some(output))
    }

    /// Map one own merged source node from its own bytes: `Some(image)`, or
    /// `None` when the mapping declines it.
    fn map_merged(
        &mut self,
        node: CollectionData,
    ) -> Result<Option<CollectionData>, CollectionRealizationError> {
        let snapshot = open(
            self.store,
            self.frontier,
            "open merge-mirror mapping snapshot",
        )?;
        let handle = Handle::<M::Source>::from_hash(node);
        let resident = snapshot
            .metadata(handle)
            .map_err(|error| {
                CollectionRealizationError::storage("inspect own merged source node", error)
            })?
            .is_some();
        if !resident {
            if self.unavailable.contains(&node) {
                return Ok(None);
            }
            return Err(CollectionRealizationError::MissingDependency { member: node });
        }
        let input: Blob<M::Source> = snapshot.get(handle).map_err(|error| {
            CollectionRealizationError::storage("load own merged source node", error)
        })?;
        let output = self.bound.mapping.map(&input, &snapshot);
        drop(snapshot);
        match output {
            Ok(output) => {
                let output_data = data_identity::<M::Target>(&output);
                self.store.put::<M::Target, _>(output).map_err(|error| {
                    CollectionRealizationError::storage("store a mirrored image", error)
                })?;
                Ok(Some(output_data))
            }
            Err(CollectionOperationError::Capacity(_))
            | Err(CollectionOperationError::MissingDependency(_)) => Ok(None),
            Err(CollectionOperationError::Fatal(reason)) => {
                Err(CollectionRealizationError::Derive {
                    input: node,
                    reason,
                })
            }
        }
    }

    fn publish_mirror(
        &mut self,
        images: Vec<CollectionData>,
        result: CollectionData,
    ) -> Result<(), CollectionRealizationError> {
        publish(
            self.store,
            self.frontier,
            CollectionRecord::Merge(sign_merge(
                self.signing_key,
                self.target.handle(),
                images.iter().copied(),
                result,
            )?),
            "publish mirrored MERGE",
        )?;
        self.joined.insert(images, result);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::tier;

    #[test]
    fn tiers_are_powers_of_the_fan_in() {
        assert_eq!(tier(0), 0);
        assert_eq!(tier(1), 0);
        assert_eq!(tier(7), 0);
        assert_eq!(tier(8), 1);
        assert_eq!(tier(63), 1);
        assert_eq!(tier(64), 2);
        assert_eq!(tier(511), 2);
        assert_eq!(tier(512), 3);
    }
}
