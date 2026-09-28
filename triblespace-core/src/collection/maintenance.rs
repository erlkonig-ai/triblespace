//! Maintenance planned from the coverage index.
//!
//! Every collection is a set of foundations, and each host joins what it
//! holds of that set into a lattice of its own: join is associative,
//! commutative and idempotent, so two hosts' different trees over the same
//! foundations stand for the same set. The store's fold believes only the
//! host's own MERGEs, so the carry signs with the host's key and merges
//! every held node, whoever signed the foundations beneath it. A merge needs
//! no WRITE: it adds no foundation. A derive is a function, so it derives
//! what its maintainer owns first and then what an absent owner has left
//! underived. There are two kinds of work, and neither compares supports
//! across collections:
//!
//! - A root carries every frontier node whose bytes are here. A frontier
//!   node whose support lies inside a held node's is absorbed by it,
//!   `MERGE(node, wider) -> wider`, whether or not its own bytes are here:
//!   an absorption reads none. Whenever one tier -- `floor(log_8
//!   |support|)` -- holds [`MERGE_FAN_IN`] held nodes, the eight lowest
//!   handles are joined by one n-ary MERGE, until no tier holds eight. A
//!   frontier node whose bytes are not here is never joined: nothing is
//!   fetched for it, so an absent payload never stalls or restarts the
//!   carry.
//! - A derived collection derives what its maintainer wrote. Every source
//!   foundation it owns whose locator has no leaf in the target yet is mapped
//!   and published as `DERIVE(target, L(F), f(F))`, empty images included;
//!   then, when the view admits the maintainer and the mapping does not
//!   depend on what a host holds, every foundation another key owns that has
//!   no leaf at all and whose payload is already here, so a reader never
//!   waits on an owner who is offline; what that mapping cannot do with such
//!   a foundation stays the owner's lag. Every source MERGE it signed that
//!   the store drives is mirrored, bottom-up, as a target MERGE over the
//!   images of its inputs, the result computed by mapping the merged source
//!   node's own bytes. A derived collection has no carry of its own: its
//!   merges are its source's merges, one level down.
//!
//! A reader descends from a frontier node to the finer nodes beneath it
//! through the host's driven joins, read from the index by the node's own
//! key ([`Coverage::producers`]); no record is selected for it. The mirror
//! still selects the MERGE records that produced a merged source node from
//! the produced-member index, and keeps only those the key signed and the
//! source's coverage believes. A mirror already published is found through
//! the target's consumer edges, the MERGE relation read by its own key. The
//! only link between a view and its source is the locator each leaf
//! carries.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::UnknownBlob;
use crate::blob::Blob;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::patch::Entry;
use crate::repo::{BlobStoreGet, BlobStoreMeta, Store, StoreRead};

use super::coverage::{Coverage, CoverageIndex, CoverageSet, FrontierSet};
use super::exact_derived::{
    data_identity, load_lineage, producer_is_admitted, CollectionRealizationError, Lineage,
};
use super::operation_snapshot::{OperationFrontier, OperationSnapshot};
use super::ownership::{owns, owns_merge};
use super::{
    Collection, CollectionData, CollectionDerive, CollectionEncoding, CollectionHandle,
    CollectionMap, CollectionMerge, CollectionOperationError, CollectionRecord,
    CollectionRecordSelector, DeriveMapping, MapMapping, MergeInputs, SourceLocator,
};

/// How many held nodes of one tier a root carry joins into one MERGE, and the
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

/// Walk one collection's lattice from its frontier, widest node first,
/// taking every node `take` accepts and descending from every other one.
///
/// A node inside what is already covered adds nothing and is neither taken
/// nor descended. A node `take` refuses is descended: the host's driven
/// joins that produced it name the finer nodes beneath, read from the index
/// by the node's own key ([`Coverage::producers`]). A MERGE another key
/// signed is never folded, so it is never descended; a join's own result
/// among its inputs (an absorption) and a node already met are skipped, so
/// a cycle ends. Returns the union of the supports of the nodes taken.
///
/// This is the one walk every cover is chosen by: a reader's resident cover
/// ([`select`]), an attached collection's cover of usable attachments
/// ([`select_attached`]), and the attachments maintenance builds
/// ([`attach_frontier`]) differ only in what they take.
fn walk<F>(
    coverage: &Coverage,
    collection: CollectionHandle,
    mut take: F,
) -> Result<CoverageSet, CollectionRealizationError>
where
    F: FnMut(CollectionData, &CoverageSet) -> Result<bool, CollectionRealizationError>,
{
    let mut covered = CoverageSet::new();
    let Some(frontier) = coverage.frontier_set(collection) else {
        return Ok(covered);
    };
    let mut pending = BinaryHeap::new();
    let mut visited = BTreeSet::new();
    for raw in frontier.iter_ordered() {
        let node: CollectionData = Inline::new(*raw);
        if let Some(support) = coverage.of(collection, node) {
            visited.insert(node);
            pending.push((support.len(), Reverse(node.raw), node));
        }
    }
    while let Some((_, _, node)) = pending.pop() {
        let support = coverage
            .of(collection, node)
            .expect("a pending node was pushed with its row");
        if support <= &covered {
            continue;
        }
        if take(node, support)? {
            covered.union(support.clone());
            continue;
        }
        for inputs in coverage.producers(collection, node) {
            for input in inputs.iter() {
                if input == node || !visited.insert(input) {
                    continue;
                }
                if let Some(support) = coverage.of(collection, input) {
                    pending.push((support.len(), Reverse(input.raw), input));
                }
            }
        }
    }
    Ok(covered)
}

/// What `collection` stands on, from the index: the reader's selection.
///
/// The frontier is the starting point, widest node first. A node inside
/// nothing chosen before it is taken when its bytes are here and complete.
/// Any other node -- absent or incomplete -- is descended ([`walk`]).
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
    let mut cover = Vec::new();
    let mut absent = Vec::new();
    let mut dependencies = Vec::new();
    let resident = match coverage.frontier_set(handle) {
        Some(frontier) => snapshot.resident(frontier).map_err(|error| {
            CollectionRealizationError::storage("intersect frontier with residency", error)
        })?,
        None => FrontierSet::new(),
    };
    let frontier = coverage.frontier_set(handle);
    let covered = walk(coverage, handle, |node, support| {
        let is_resident = if frontier.is_some_and(|frontier| frontier.get(&node.raw).is_some()) {
            resident.get(&node.raw).is_some()
        } else {
            snapshot
                .metadata(Handle::<E>::from_hash(node))
                .map_err(|error| {
                    CollectionRealizationError::storage("inspect lattice node residency", error)
                })?
                .is_some()
        };
        if !is_resident {
            absent.push((node, support.clone()));
            return Ok(false);
        }
        let missing = E::missing_representation_dependencies(node, snapshot)
            .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?;
        if missing.is_empty() {
            cover.push((node, support.clone()));
            return Ok(true);
        }
        dependencies.extend(missing);
        Ok(false)
    })?;
    Ok(Selection {
        cover,
        covered,
        absent,
        dependencies,
    })
}

/// What an attached collection stands on right now: usable attachments of
/// its parent's nodes, and what they do not reach.
pub(super) struct AttachedSelection {
    /// `(parent node, attachment)` for every attachment taken, widest node
    /// first.
    pub(super) cover: Vec<(CollectionData, CollectionData)>,
    /// The parent foundations the taken attachments stand for.
    pub(super) covered: CoverageSet,
    /// The parent foundations no taken attachment reaches: read the raw
    /// node, build its attachment, or report it as a gap.
    pub(super) residual: CoverageSet,
}

/// An attachment of `node` in `attached` a reader can use: a believed MAP
/// whose attachment is resident with every representation dependency it
/// names (a Rank9 attachment's raw Succinct child, say).
fn usable_attachment<R, E>(
    snapshot: &R,
    coverage: &Coverage,
    attached: CollectionHandle,
    node: CollectionData,
) -> Result<Option<CollectionData>, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    for attachment in coverage.attachments(attached, node) {
        let resident = snapshot
            .metadata(Handle::<E>::from_hash(attachment))
            .map_err(|error| {
                CollectionRealizationError::storage("inspect attachment residency", error)
            })?
            .is_some();
        if !resident {
            continue;
        }
        let missing = E::missing_representation_dependencies(attachment, snapshot)
            .map_err(|error| CollectionRealizationError::Resolution(error.to_string()))?;
        if missing.is_empty() {
            return Ok(Some(attachment));
        }
    }
    Ok(None)
}

/// An attachment of `node` in a sibling attached collection whose bytes are
/// here. A sibling's own representation dependencies are the sibling's
/// business; a mapping reading it names what else it needs.
fn resident_attachment<R>(
    snapshot: &R,
    coverage: &Coverage,
    attached: CollectionHandle,
    node: CollectionData,
) -> Result<Option<CollectionData>, CollectionRealizationError>
where
    R: StoreRead,
{
    for attachment in coverage.attachments(attached, node) {
        if snapshot
            .metadata(Handle::<UnknownBlob>::from_hash(attachment))
            .map_err(|error| {
                CollectionRealizationError::storage("inspect sibling attachment residency", error)
            })?
            .is_some()
        {
            return Ok(Some(attachment));
        }
    }
    Ok(None)
}

/// The attached cover: for each node of the parent's frontier, widest
/// first, its usable attachment; failing that, the attachments of the
/// highest nodes beneath it that have one ([`walk`]). What no taken
/// attachment reaches is the residual, a set of parent foundations.
///
/// Only attachments of nodes the walk reaches are read, so a MAP whose node
/// the parent's lattice does not reach -- a node only a foreign merge
/// produced, or one of a join still blocked -- is never used, and only the
/// host's MAPs are believed in the first place.
pub(super) fn select_attached<R, E>(
    snapshot: &R,
    coverage: &Coverage,
    parent: CollectionHandle,
    attached: Collection<E>,
) -> Result<AttachedSelection, CollectionRealizationError>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let mut cover = Vec::new();
    let covered = walk(coverage, parent, |node, _| {
        match usable_attachment::<R, E>(snapshot, coverage, attached.handle(), node)? {
            Some(attachment) => {
                cover.push((node, attachment));
                Ok(true)
            }
            None => Ok(false),
        }
    })?;
    let (believed, _) = coverage.frontier_support(parent);
    let residual = believed.difference(&covered);
    Ok(AttachedSelection {
        cover,
        covered,
        residual,
    })
}

/// The MERGE records of `collection` that produce `node`, whoever signed
/// them, in the store's deterministic order: one produced-member lookup.
///
/// Only the mirror still reads records this way, and filters them by signer
/// and belief itself; a reader descends through [`Coverage::producers`].
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
///
/// The gap is the believed foundations the reader's selection does not
/// reach. Only the host's own merges are folded, so an absent node met on
/// the way down is a foundation or a host merge result whose bytes are
/// gone. A host merge over the needed payloads is asked for first, since
/// one fetch then stands for many; commits whose payloads no host merge
/// covers -- every commit, on a store without a host -- are fetched one by
/// one. Another key's merge is never a shortcut: it is not believed here.
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
    // A host merge that stands for a needed payload before the payload
    // itself: one fetch instead of many. Then the payloads.
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

/// Every frontier node of one collection, and those of them whose bytes are
/// here, each widest first.
///
/// The frontier is every believed foundation, whoever signed it, and the
/// host's own merge results. Only a held node is ever joined or absorbs
/// another. A node whose bytes are not here is not asked for, so a host
/// holding another key's commit records without their payloads neither
/// fetches them nor restarts the carry once per payload; it can still be
/// absorbed by a held node that covers it, which reads no bytes, and it
/// rejoins the carry proper when its bytes arrive.
fn frontier_nodes<R>(
    snapshot: &R,
    coverage: &Coverage,
    collection: CollectionHandle,
) -> Result<(Vec<Node>, Vec<Node>), CollectionRealizationError>
where
    R: StoreRead,
{
    let Some(frontier) = coverage.frontier_set(collection) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let resident = snapshot.resident(frontier).map_err(|error| {
        CollectionRealizationError::storage("intersect frontier with residency", error)
    })?;
    let mut every = Vec::new();
    let mut held = Vec::new();
    for raw in frontier.iter_ordered() {
        let node: CollectionData = Inline::new(*raw);
        if let Some(support) = coverage.of(collection, node) {
            if resident.get(raw).is_some() {
                held.push((node, support.clone()));
            }
            every.push((node, support.clone()));
        }
    }
    for nodes in [&mut every, &mut held] {
        nodes.sort_by(|left, right| {
            right
                .1
                .len()
                .cmp(&left.1.len())
                .then_with(|| left.0.raw.cmp(&right.0.raw))
        });
    }
    Ok((every, held))
}

/// Refuse to publish a MERGE the store would not fold.
///
/// The fold believes only its host's MERGEs. A carry signing with any other
/// key -- or into a store with no host -- would publish merges nothing here
/// believes: the frontier would not move and the carry would report a
/// stall, or publish the same merges again on every pass. So a mismatch is
/// an error that names both keys, raised where a merge is about to be
/// published; a carry with nothing to merge needs no host.
fn require_host(
    index: &CoverageIndex,
    signing_key: &SigningKey,
) -> Result<(), CollectionRealizationError> {
    let signer = Inline::new(signing_key.verifying_key().to_bytes());
    let host = index.host();
    if host == Some(signer) {
        Ok(())
    } else {
        Err(CollectionRealizationError::HostMismatch { host, signer })
    }
}

/// Carry every held node of one root to its LSM fixed point.
///
/// Each round reads the frontier from the index, whoever signed the
/// foundations beneath it. A frontier node whose support lies inside a held
/// node's -- one whose bytes are here -- is consumed first, by `MERGE(node,
/// wider) -> wider`: no bytes move, so the absorbed node's own bytes need
/// not be here. Then every tier holding [`MERGE_FAN_IN`] held nodes is
/// carried, the lowest such tier first, eight lowest handles per MERGE,
/// joined by the encoding's k-way join, before the frontier is read again.
/// Each result is stored and published at once, so a later failure keeps
/// the complete successful prefix. A merge needs no WRITE authority, only
/// the store's host key: publishing with any other key is an error
/// ([`CollectionRealizationError::HostMismatch`]). A frontier node whose
/// bytes are not here is never joined and nothing is fetched for it; a host
/// merge result whose bytes are gone and that no held node covers therefore
/// stays on the frontier, and a reader descends it to its inputs.
///
/// Only a root carries. A derived collection whose encoding happens to be a
/// root's is refused: its merges are its source's, mirrored through its
/// mapping, and it has no carry of its own.
pub(super) fn carry_root<S, E>(
    store: &mut S,
    target: Collection<E>,
    signing_key: &SigningKey,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    E: CollectionEncoding,
{
    let scope = BTreeSet::from([target.handle()]);
    let lineage = load_lineage(&open(store, frontier, "open root-carry snapshot")?, target)?;
    if lineage.foundation.handle() != target.handle() {
        return Err(CollectionRealizationError::InvalidCover(
            "a derived collection has no carry of its own; maintain it through its mapping".into(),
        ));
    }
    let descriptor = lineage.descriptor(target.handle()).clone();
    let mut seen = BTreeSet::new();
    let mut declined = BTreeSet::<Vec<CollectionData>>::new();
    let mut progressed = true;
    loop {
        let snapshot = open(store, frontier, "open root-carry snapshot")?;
        let index = index_of(&snapshot, &scope)?;
        let (every, nodes) = frontier_nodes(&snapshot, index.published(), target.handle())?;
        let identity: Vec<CollectionData> = every.iter().map(|(node, _)| *node).collect();
        if progressed && !seen.insert(identity.clone()) {
            return Err(CollectionRealizationError::Stalled { cover: identity });
        }
        if every.len() < 2 || nodes.is_empty() {
            return Ok(());
        }
        // A frontier node inside a held node's support is consumed by its
        // widest such node. Two nodes with one support keep the lower held
        // handle, which is also the one a reader keeps. Only a strictly
        // wider node can hold a node properly, and `nodes` is widest first,
        // so each node tests inclusion against the held nodes before its
        // own width alone; an equal support is found by its Merkle root.
        // Fresh commits -- pairwise disjoint singletons, all of one width --
        // then cost no inclusion test at all, however many of them a root
        // holds.
        let mut keepers = BTreeMap::<[u8; 32], CollectionData>::new();
        for (node, support) in &nodes {
            if let Some(root) = support.merkle_root() {
                // Within one width `nodes` ascends by handle: the first seen
                // is the lowest.
                keepers.entry(root).or_insert(*node);
            }
        }
        let absorbed: Vec<(CollectionData, CollectionData)> = every
            .iter()
            .filter_map(|(node, support)| {
                let wider = nodes
                    .iter()
                    .take_while(|(_, wider)| wider.len() > support.len())
                    .find(|(_, wider)| support <= wider)
                    .map(|(wider, _)| *wider)
                    .or_else(|| {
                        let keeper = *keepers.get(&support.merkle_root()?)?;
                        (keeper != *node).then_some(keeper)
                    })?;
                Some((*node, wider))
            })
            .collect();
        if !absorbed.is_empty() {
            require_host(&index, signing_key)?;
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
        require_host(&index, signing_key)?;
        drop(snapshot);
        progressed = false;
        for group in round {
            let snapshot = open(store, frontier, "open root-carry join snapshot")?;
            let blobs = group
                .iter()
                .map(|node| snapshot.get::<Blob<E>, E>(Handle::<E>::from_hash(*node)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    CollectionRealizationError::storage("load a held node to carry", error)
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

/// One attached collection's mapping, bound to its descriptor and parent.
pub(super) struct BoundAttachment<M> {
    pub(super) parent: Collection<SimpleArchive>,
    pub(super) mapping: M,
    pub(super) siblings: Vec<CollectionHandle>,
}

/// Read an attached collection's descriptor and its parent's, and bind the
/// mapping the descriptor names.
///
/// The parent must be a root: an attached collection indexes the nodes of a
/// lattice of `SimpleArchive`s. Whether a derived collection may be a parent
/// is left open; one is refused here rather than half served.
pub(super) fn bind_attached<R, M>(
    snapshot: &R,
    attached: Collection<M::Target>,
) -> Result<BoundAttachment<M>, CollectionRealizationError>
where
    R: StoreRead,
    M: MapMapping,
{
    let (parent, attached_descriptor, parent_descriptor) = attached_lineage(snapshot, attached)?;
    let mapping = M::bind(&parent_descriptor, &attached_descriptor).map_err(|error| {
        CollectionRealizationError::Resolution(format!(
            "attached descriptor does not bind the requested mapping: {error}"
        ))
    })?;
    let siblings = mapping.siblings();
    Ok(BoundAttachment {
        parent,
        mapping,
        siblings,
    })
}

/// An attached collection's parent and both descriptors, or the descriptor
/// that is not resident as a [`CollectionRealizationError::MissingDependency`].
pub(super) fn attached_lineage<R, E>(
    snapshot: &R,
    attached: Collection<E>,
) -> Result<
    (
        Collection<SimpleArchive>,
        crate::trible::Fragment,
        crate::trible::Fragment,
    ),
    CollectionRealizationError,
>
where
    R: StoreRead,
    E: CollectionEncoding,
{
    let load = |collection: CollectionHandle| {
        if !snapshot.contains_blob(collection).map_err(|error| {
            CollectionRealizationError::storage("inspect collection descriptor residency", error)
        })? {
            return Err(CollectionRealizationError::MissingDependency {
                member: Handle::<SimpleArchive>::to_hash(collection),
            });
        }
        super::api::load_collection_descriptor(snapshot, collection)
            .map(|loaded| loaded.fragment)
            .map_err(|error| {
                CollectionRealizationError::Resolution(format!(
                    "load collection descriptor {}: {error}",
                    hex::encode_upper(collection.raw),
                ))
            })
    };
    let attached_descriptor = load(attached.handle())?;
    super::encoding::validate_descriptor_type::<E>(&attached_descriptor).map_err(|error| {
        CollectionRealizationError::Resolution(format!(
            "attached descriptor has the wrong representation: {error}"
        ))
    })?;
    let parents = super::descriptor::parents(attached_descriptor.facts()).map_err(|error| {
        CollectionRealizationError::Resolution(format!("decode attached parent: {error}"))
    })?;
    // An attached read walks one parent's lattice. A descriptor naming
    // several parents is one this reader does not read; attaching never
    // writes one.
    let parent = match parents.as_slice() {
        [parent] => *parent,
        [] => {
            return Err(CollectionRealizationError::InvalidCover(format!(
                "collection {} is not an attached collection",
                hex::encode_upper(attached.handle().raw),
            )))
        }
        _ => {
            return Err(CollectionRealizationError::InvalidCover(format!(
                "attached collection {} names {} parents; an attached read walks one parent's \
                 lattice",
                hex::encode_upper(attached.handle().raw),
                parents.len(),
            )))
        }
    };
    let parent_descriptor = load(parent)?;
    let parent_is_root = super::descriptor::source(parent_descriptor.facts())
        .map_err(|error| {
            CollectionRealizationError::Resolution(format!("decode parent source: {error}"))
        })?
        .is_none()
        && super::descriptor::parents(parent_descriptor.facts())
            .map_err(|error| {
                CollectionRealizationError::Resolution(format!("decode parent kind: {error}"))
            })?
            .is_empty();
    if !parent_is_root {
        return Err(CollectionRealizationError::InvalidCover(
            "an attached collection's parent must be a root collection".to_owned(),
        ));
    }
    super::encoding::validate_descriptor_type::<SimpleArchive>(&parent_descriptor).map_err(
        |error| {
            CollectionRealizationError::Resolution(format!(
                "attached parent is not a SimpleArchive root: {error}"
            ))
        },
    )?;
    Ok((
        Collection::from_handle(parent),
        attached_descriptor,
        parent_descriptor,
    ))
}

/// Give every node of the parent's frontier whose attachment is missing one,
/// signed by the host.
///
/// The same walk a reader makes ([`walk`]), taking a node that already has a
/// usable attachment, and otherwise building one: the node's own bytes, and
/// a usable attachment of the node in each sibling the mapping reads, are
/// mapped, the image stored and `MAP(attached; node -> image)` published. A
/// node whose bytes or siblings are not here, or whose attachment the
/// mapping cannot represent (`Capacity`), is descended, so its finer nodes
/// get attachments instead: frontier nodes first, finer ones only where a
/// frontier node cannot have one. A dependency the mapping names is
/// acquired, and the operation runs again; one that cannot be acquired
/// leaves that node to its finer ones, and what no node covers is a reader's
/// residual. Only frontier nodes are maintained: an interior node a merge
/// has consumed needs no attachment, and one a MAP gave before its merge
/// stays in the store until a compaction collects it.
pub(super) fn attach_frontier<S, M>(
    store: &mut S,
    attached: Collection<M::Target>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: MapMapping,
{
    let planning = open(store, frontier, "open attachment planning snapshot")?;
    let bound: BoundAttachment<M> = bind_attached(&planning, attached)?;
    let parent = bound.parent.handle();
    let mut scope = BTreeSet::from([parent, attached.handle()]);
    scope.extend(bound.siblings.iter().copied());
    let index = index_of(&planning, &scope)?;
    let coverage = index.published().clone();
    let signer = Inline::new(signing_key.verifying_key().to_bytes());
    let host = index.host();
    walk(&coverage, parent, |node, _| {
        if usable_attachment::<_, M::Target>(&planning, &coverage, attached.handle(), node)?
            .is_some()
        {
            return Ok(true);
        }
        // A MAP another key signed is believed nowhere: building one here
        // would be work nothing reads. Refused before anything is mapped or
        // fetched; a pass with nothing to attach needs no host.
        if host != Some(signer) {
            return Err(CollectionRealizationError::HostMismatch { host, signer });
        }
        let mut siblings = Vec::with_capacity(bound.siblings.len());
        for sibling in &bound.siblings {
            match resident_attachment(&planning, &coverage, *sibling, node)? {
                Some(attachment) => siblings.push(attachment),
                None => return Ok(false),
            }
        }
        let snapshot = open(store, frontier, "open attachment mapping snapshot")?;
        let handle = Handle::<SimpleArchive>::from_hash(node);
        let held = snapshot
            .metadata(handle)
            .map_err(|error| {
                CollectionRealizationError::storage("inspect a parent node's residency", error)
            })?
            .is_some();
        if !held {
            return Ok(false);
        }
        let input: Blob<SimpleArchive> = snapshot.get(handle).map_err(|error| {
            CollectionRealizationError::storage("load a parent node to attach", error)
        })?;
        let output = bound.mapping.map(&input, &siblings, &snapshot);
        drop(snapshot);
        match output {
            Ok(output) => {
                let attachment = data_identity::<M::Target>(&output);
                store.put::<M::Target, _>(output).map_err(|error| {
                    CollectionRealizationError::storage("store an attachment", error)
                })?;
                publish(
                    store,
                    frontier,
                    CollectionRecord::Map(CollectionMap::sign(
                        signing_key,
                        attached.handle(),
                        node,
                        attachment,
                    )),
                    "publish attachment MAP",
                )?;
                Ok(true)
            }
            Err(CollectionOperationError::Capacity(_)) => Ok(false),
            Err(CollectionOperationError::MissingDependency(member))
                if unavailable.contains(&member) =>
            {
                Ok(false)
            }
            Err(CollectionOperationError::MissingDependency(member)) => {
                Err(CollectionRealizationError::MissingDependency { member })
            }
            Err(CollectionOperationError::Fatal(reason)) => {
                Err(CollectionRealizationError::Derive {
                    input: node,
                    reason,
                })
            }
        }
    })?;
    Ok(())
}

/// One mapping bound to its target and its immediate source.
struct Bound<M> {
    source: CollectionHandle,
    /// Whether the source is the root of the lineage, whose foundations are
    /// commits rather than images of something further up.
    source_is_root: bool,
    mapping: M,
}

fn bind<R, M>(
    snapshot: &R,
    target: Collection<M::Target>,
) -> Result<Bound<M>, CollectionRealizationError>
where
    R: StoreRead,
    M: DeriveMapping,
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
    Ok(Bound {
        source,
        source_is_root: source == lineage.foundation.handle(),
        mapping,
    })
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
    M: DeriveMapping,
{
    let bound: Bound<M> = bind(&open(store, frontier, "open mapping snapshot")?, target)?;
    let blocked = derive_leaves(
        store,
        target,
        &bound,
        signing_key,
        unavailable,
        frontier,
        aligned,
    )?;
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
/// key owns are its to derive. With `restore` -- maintenance, never the
/// per-write `ensure` -- an own leaf that exists but whose image is not here
/// is fetched too; when it cannot be, the foundation is mapped again to
/// restore the bytes, and a leaf is published only if the image differs.
///
/// Maintenance also derives, after its own, every foundation another key
/// owns that has no leaf at all. A derive is a function anyone can compute,
/// and a reader of the view must not lag behind an owner who is absent (a
/// machine that is offline, or not yet on this version). Two keys deriving the same foundation publish the
/// same output, so a race costs a duplicate record, never a divergent view.
/// That holds only for a mapping every such key computes alike; one that
/// declares [`DeriveMapping::FOREIGN_DERIVABLE`] false leaves each
/// foundation to its owner. Foreign work is offered, never owed:
/// only a key the view admits takes it, only for payloads already here
/// (nothing is fetched for another owner), and whatever the mapping cannot
/// do with one -- a refusal, a capacity limit, a dependency not here -- is
/// that owner's lag, skipped quietly rather than failing this key's pass.
///
/// An own source foundation owed a leaf whose bytes are not here is fetched.
/// When nobody can hand them over, a root commit's payload is reported,
/// because nothing upstream can restore it. A derived source's leaf image is
/// that source's own lag instead: maintaining the source maps it again from
/// what the source derives from, and until then this view lags on it too,
/// the same way a reader of the source does. Downstream work neither
/// requires nor repairs it.
/// Returns the foundations the mapping could not represent.
fn derive_leaves<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    bound: &Bound<M>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    restore: bool,
) -> Result<Vec<(CollectionData, String)>, CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    let key = signing_key.verifying_key();
    let scope = BTreeSet::from([bound.source, target.handle()]);
    let snapshot = open(store, frontier, "open leaf-derivation snapshot")?;
    let coverage = coverage_of(&snapshot, &scope)?;
    let (foundations, _) = coverage.frontier_support(bound.source);
    // Each own foundation, its locator, and the images its existing leaves
    // name: none for a foundation still owed a leaf. Foreign foundations
    // without any leaf follow the own ones, in maintenance only.
    let mut owed = Vec::new();
    let mut foreign = Vec::new();
    let mut derived = Vec::new();
    for raw in foundations.iter_ordered() {
        let foundation: CollectionData = Inline::new(*raw);
        let locator = SourceLocator::of(foundation.raw);
        if !owns(&coverage, bound.source, foundation, &key) {
            if restore && M::FOREIGN_DERIVABLE && !coverage.has_leaf(target.handle(), locator) {
                foreign.push((foundation, locator));
            }
            continue;
        }
        let outputs = coverage.leaf_outputs(target.handle(), locator);
        if outputs.is_empty() {
            owed.push((foundation, locator, outputs, true));
        } else if restore {
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
            owed.push((foundation, locator, outputs, true));
        }
    }
    if owed.is_empty() && foreign.is_empty() {
        return Ok(Vec::new());
    }
    let admitted = producer_is_admitted(&snapshot, target, signing_key)?;
    if new_leaves && !admitted {
        return Err(CollectionRealizationError::UnauthorizedProducer {
            collection: target.handle(),
        });
    }
    // Foreign work is offered, never owed: a key the view does not admit
    // leaves it to the keys it does, and another owner's payload that is not
    // already here is not fetched.
    if admitted && !foreign.is_empty() {
        let mut payloads = FrontierSet::new();
        for (foundation, _) in &foreign {
            payloads.insert(&Entry::new(&foundation.raw));
        }
        let resident = snapshot.resident(&payloads).map_err(|error| {
            CollectionRealizationError::storage("intersect foreign payloads with residency", error)
        })?;
        owed.extend(
            foreign
                .into_iter()
                .filter(|(foundation, _)| resident.get(&foundation.raw).is_some())
                .map(|(foundation, locator)| (foundation, locator, Vec::new(), false)),
        );
    }
    if owed.is_empty() {
        return Ok(Vec::new());
    }
    drop(snapshot);

    let mut blocked = Vec::new();
    for (foundation, locator, existing, own) in owed {
        let snapshot = open(store, frontier, "open leaf mapping snapshot")?;
        let handle = Handle::<M::Source>::from_hash(foundation);
        let resident = snapshot
            .metadata(handle)
            .map_err(|error| {
                CollectionRealizationError::storage("inspect own source foundation", error)
            })?
            .is_some();
        if !resident {
            if !own {
                // Resident when selected; nothing is fetched for another owner.
                continue;
            }
            if unavailable.contains(&foundation) {
                if bound.source_is_root {
                    blocked.push((
                        foundation,
                        "the source commit's payload is not resident and could not be acquired"
                            .to_owned(),
                    ));
                }
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
            // Whatever the mapping cannot do with another owner's foundation
            // is that owner's lag, not this key's failure.
            Err(_) if !own => continue,
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

/// Mirror every source MERGE the key signed and the store drives, bottom-up.
///
/// The walk reads the whole source frontier and descends through the MERGE
/// records that produced each merged node, keeping only those the key signed
/// and the source's coverage drives. The store folds only its host's MERGEs,
/// so on a store hosted by another key nothing is kept and nothing is
/// mirrored; a target MERGE this key signed would not be believed there
/// either. The key's own tops are the frontier nodes it committed and those
/// its kept merges produced.
///
/// The root carry merges every held node, whoever signed the foundations
/// beneath it, so a kept merge can hold another key's foundations. It is
/// mapped from its own bytes like any other only when the mapping declares
/// [`DeriveMapping::FOREIGN_DERIVABLE`]; otherwise it is not mirrored and
/// the view keeps the finer images beneath it, since mapping it would derive
/// another owner's foundations. Likewise a merge holding a foundation the
/// mapping refused has an input without an image and is not mirrored: the
/// view's leaves beneath it stay on its frontier unjoined, however many of
/// them are the key's own. Both widen the view without making it wrong, and
/// both go when a derived collection carries its own leaf images instead of
/// mirroring its source's merges.
///
/// A foundation's image is its leaf. A merged node's image is found, in
/// order: all its inputs share one image, which is then its image too; a
/// target MERGE of exactly its inputs' images is already believed, whose
/// result is its image; or the key owns it, and it is mapped from its own
/// bytes and `MERGE(target; images -> image)` is published. A node the
/// mapping declines is not mirrored, and neither is anything that needs it;
/// its inputs' images stay on the target frontier.
///
/// A foundation can be a merge result too: a join whose union is exactly one
/// input's bytes returns that input, `MERGE(p0, p1, ..) -> p0`. Its image is
/// still its leaf, and each such own MERGE is mirrored onto it without any
/// mapping, the same way an absorption is.
///
/// An own mirror whose image is absent here is reused as it stands; nothing
/// maps it again. A view deriving from this one lags on that node -- it
/// keeps the finer images beneath it -- until the bytes arrive.
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
    M: DeriveMapping,
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
    let everything: Vec<CollectionData> = coverage.frontier(source).collect();
    let mut produced: BTreeMap<CollectionData, Vec<MergeInputs>> = BTreeMap::new();
    let mut pending = everything.clone();
    let mut seen = BTreeSet::new();
    while let Some(node) = pending.pop() {
        if !seen.insert(node) {
            continue;
        }
        // A foundation that stands for itself alone was produced by nothing
        // but its own commit or leaf: no lookup. One that stands for more is
        // a merge result as well.
        if coverage.covers(source, node, node)
            && coverage
                .of(source, node)
                .map_or(true, |support| support.len() <= 1)
        {
            continue;
        }
        let merges: Vec<MergeInputs> = producers(&planning, source, node)?
            .into_iter()
            .filter(|merge| {
                owns_merge(merge, &key)
                    && index.drives_join(source, &merge.merge_inputs(), merge.result())
            })
            .map(|merge| merge.merge_inputs())
            .collect();
        pending.extend(merges.iter().flat_map(|inputs| inputs.iter()));
        produced.insert(node, merges);
    }
    // The key's own source frontier: the foundations it committed and the
    // nodes its own driven merges produced. A join records no owner, and
    // only the host's merges are believed, so the second half is empty
    // unless the key is the store's host.
    let tops: Vec<CollectionData> = everything
        .into_iter()
        .filter(|node| owns(coverage, source, *node, &key) || produced_by_key(&produced, *node))
        .collect();
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

/// Whether one of the key's own driven source merges produces `node`.
fn produced_by_key(
    produced: &BTreeMap<CollectionData, Vec<MergeInputs>>,
    node: CollectionData,
) -> bool {
    produced.get(&node).is_some_and(|merges| !merges.is_empty())
}

/// One pass of aligned mirroring: what it read at the start, and what it has
/// resolved and published since. It holds no store snapshot.
struct Mirror<'a, S, M>
where
    S: Store,
    M: DeriveMapping,
{
    store: &'a mut S,
    frontier: &'a mut OperationFrontier<S::Snapshot>,
    target: Collection<M::Target>,
    bound: &'a Bound<M>,
    signing_key: &'a SigningKey,
    key: VerifyingKey,
    unavailable: &'a BTreeSet<CollectionData>,
    index: CoverageIndex,
    /// The input sets of the key's own driven MERGEs producing each source
    /// node the walk can reach.
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
    M: DeriveMapping,
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
        let foundation = coverage.covers(source, node, node);
        // The key's node: a foundation it committed, or a node one of its own
        // driven merges produced (a join records no owner of its own).
        let owned =
            owns(coverage, source, node, &self.key) || produced_by_key(&self.produced, node);
        let leaf = foundation
            .then(|| {
                coverage
                    .leaf_outputs(target, SourceLocator::of(node.raw))
                    .first()
                    .copied()
            })
            .flatten();
        let (absorbing, proper): (Vec<MergeInputs>, Vec<MergeInputs>) = self
            .produced
            .get(&node)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .partition(|inputs| inputs.contains(node));
        let (image, onto) = if foundation {
            // A foundation's image is its leaf, whoever derived it. Every own
            // MERGE producing it is mirrored onto that image: by homomorphism
            // the image of a join that returned this foundation's bytes is
            // this foundation's image, so nothing is mapped.
            let Some(image) = leaf else {
                return Ok(None);
            };
            (
                image,
                absorbing.into_iter().chain(proper).collect::<Vec<_>>(),
            )
        } else {
            let mut image = None;
            for inputs in &proper {
                let Some(images) = self.input_images(inputs.as_slice(), None)? else {
                    continue;
                };
                // The result is a property of the node, not of the producer:
                // one attempt settles it.
                image = self.join_of(images, node, owned)?;
                break;
            }
            let Some(image) = image else {
                return Ok(None);
            };
            // Every other own producer is mirrored onto that image, as for a
            // foundation: the target's support of it must be the source's,
            // and there is no target carry to finish a missed one. The
            // producer just settled is found by `existing` and skipped.
            (image, absorbing.into_iter().chain(proper).collect())
        };
        // `MERGE(a, node) -> node` in the source is `MERGE(f(a), f(node)) ->
        // f(node)` in the target: an absorption needs no mapping.
        for inputs in onto {
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
        // A mapping that leaves another owner's foundations to that owner
        // must not map them inside a merge either.
        if !M::FOREIGN_DERIVABLE && !self.owns_every_foundation(node) {
            return Ok(None);
        }
        let Some(output) = self.map_merged(node)? else {
            return Ok(None);
        };
        self.publish_mirror(images, output)?;
        Ok(Some(output))
    }

    /// Whether the key owns every source foundation `node` stands for.
    fn owns_every_foundation(&self, node: CollectionData) -> bool {
        let source = self.bound.source;
        let coverage = self.index.published();
        coverage.of(source, node).is_some_and(|support| {
            support
                .iter_ordered()
                .all(|raw| owns(coverage, source, Inline::new(*raw), &self.key))
        })
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
