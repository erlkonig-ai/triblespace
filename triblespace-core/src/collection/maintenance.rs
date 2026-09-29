//! Maintenance planned from the coverage index.
//!
//! Every collection is a set of foundations, and each host joins what it
//! holds of that set into a lattice of its own: join is associative,
//! commutative and idempotent, so two hosts' different trees over the same
//! foundations stand for the same set. The store's fold believes only the
//! host's own MERGEs, so the carry signs with the host's key and merges
//! every held node, whoever signed the foundations beneath it. A merge needs
//! no WRITE: it adds no foundation. There are two kinds of work, and neither
//! compares supports across collections:
//!
//! - A collection carries every frontier node whose bytes are here: a root
//!   its commits, a derived collection its leaf images, each joined in its
//!   own lattice by its own join -- a root's encoding's, a derived
//!   collection's mapping's ([`DeriveMapping::join_images`]). A frontier
//!   node whose support lies inside a held node's is absorbed by it,
//!   `MERGE(node, wider) -> wider`, whether or not its own bytes are here:
//!   an absorption reads none. Whenever one tier -- `floor(log_8
//!   |support|)` -- holds [`MERGE_FAN_IN`] held nodes, the eight lowest
//!   handles are joined by one n-ary MERGE, until no tier holds eight. A
//!   frontier node whose bytes are not here is never joined: nothing is
//!   fetched for it, so an absent payload never stalls or restarts the
//!   carry. A derived collection's carry never reads its source: its
//!   merges are its own, not its source's merges one level down.
//! - A derived collection derives leaves, `DERIVE(target, L(F), f(F))`,
//!   empty images included, scheduled by leaf: any admitted leaf suffices. A
//!   source foundation is owed a leaf only when no believed leaf for its
//!   locator has an output that is here or can be fetched, whoever signed
//!   it, and any key the target admits may derive it on a host that can
//!   compute the mapping. The per-write `ensure` derives the key's own
//!   foundations that have no leaf at all; `maintain` derives every
//!   foundation it can -- the key's own, and another owner's whose payload
//!   is already here -- so a reader never waits on an owner who is offline.
//!   What the mapping cannot do with another owner's foundation stays that
//!   owner's lag. Outputs of leaves that are not here are asked for after
//!   the rest of the work, a bounded number per call, and only through a
//!   store that can reach other holders; each key walks the foundations in
//!   an order of its own, and a foundation whose leaf appears while the
//!   pass runs is left to it.
//!
//! A reader descends from a frontier node to the finer nodes beneath it
//! through the host's driven joins, read from the index by the node's own
//! key ([`Coverage::producers`]); no record is selected for it. The only
//! link between a derived collection and its source is the locator each
//! leaf carries.

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
use crate::trible::Fragment;

use super::coverage::{Coverage, CoverageIndex, CoverageSet, FrontierSet};
use super::exact_derived::{
    data_identity, load_lineage, producer_is_admitted, CollectionRealizationError, Lineage,
};
use super::operation_snapshot::{OperationFrontier, OperationSnapshot};
use super::ownership::owns;
use super::{
    Collection, CollectionData, CollectionDerive, CollectionEncoding, CollectionHandle,
    CollectionMap, CollectionMerge, CollectionOperationError, CollectionRecord, DeriveMapping,
    MapMapping, SourceLocator,
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
/// here and read, each widest first.
///
/// The frontier is every believed foundation, whoever signed it, and the
/// host's own merge results. Only a held node is ever joined or absorbs
/// another. A node whose bytes are not here is not asked for, so a host
/// holding another key's commit or leaf records without their payloads
/// neither fetches them nor restarts the carry once per payload; it can
/// still be absorbed by a held node that covers it, which reads no bytes,
/// and it rejoins the carry proper when its bytes arrive. A node whose bytes
/// are here but do not read -- a store's index may say a blob is present
/// without reading it, as a pile's does -- sits out the same way, instead of
/// failing every carry that would join it.
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
            if resident.get(raw).is_some() && reads(snapshot, node)? {
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

/// Whether a blob's bytes can be read here, which on a store whose index
/// answers presence without reading (a pile's) is more than being resident.
fn reads<R: StoreRead>(
    snapshot: &R,
    blob: CollectionData,
) -> Result<bool, CollectionRealizationError> {
    Ok(snapshot
        .metadata(Handle::<UnknownBlob>::from_hash(blob))
        .map_err(|error| CollectionRealizationError::storage("read a resident blob", error))?
        .is_some())
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

/// Carry every held node of one root to its LSM fixed point, joined by the
/// root encoding's k-way join ([`carry`]).
///
/// A derived collection carries the same way, through its mapping's join
/// ([`maintain_derived`]). One whose encoding happens to be a root's is
/// refused here, where no mapping is bound, rather than joined by a join
/// its mapping may not name.
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
    let lineage = load_lineage(&open(store, frontier, "open root-carry snapshot")?, target)?;
    if lineage.foundation.handle() != target.handle() {
        return Err(CollectionRealizationError::InvalidCover(
            "a derived collection carries through its mapping; maintain it with that mapping"
                .into(),
        ));
    }
    let descriptor = lineage.descriptor(target.handle()).clone();
    carry(store, target, signing_key, frontier, |members, reader| {
        E::join_many(&descriptor, members, reader)
    })
}

/// Carry every held node of one collection's own lattice to its LSM fixed
/// point, joining with `join`.
///
/// Each round reads the frontier from the index, whoever signed the
/// foundations beneath it. A frontier node whose support lies inside a held
/// node's -- one whose bytes are here -- is consumed first, by `MERGE(node,
/// wider) -> wider`: no bytes move, so the absorbed node's own bytes need
/// not be here. Then every tier holding [`MERGE_FAN_IN`] held nodes is
/// carried, the lowest such tier first, eight lowest handles per MERGE,
/// joined by `join`, before the frontier is read again. Each result is
/// stored and published at once, so a later failure keeps the complete
/// successful prefix. A join that answers `Capacity` or `MissingDependency`
/// leaves that group's finer cover standing; `Fatal` fails the carry. A
/// merge needs no WRITE authority, only the store's host key: publishing
/// with any other key is an error
/// ([`CollectionRealizationError::HostMismatch`]). A frontier node whose
/// bytes are not here is never joined and nothing is fetched for it; a host
/// merge result whose bytes are gone and that no held node covers therefore
/// stays on the frontier, and a reader descends it to its inputs. Nothing
/// outside the collection's own lattice is read.
fn carry<S, E, J>(
    store: &mut S,
    target: Collection<E>,
    signing_key: &SigningKey,
    frontier: &mut OperationFrontier<S::Snapshot>,
    mut join: J,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    E: CollectionEncoding,
    J: FnMut(
        &[Blob<E>],
        &OperationSnapshot<S::Snapshot, S::Snapshot>,
    ) -> Result<Blob<E>, CollectionOperationError>,
{
    let scope = BTreeSet::from([target.handle()]);
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
            let joined = join(&blobs, &snapshot);
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
    /// The target's descriptor, which the mapping's join reads.
    target_descriptor: Fragment,
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
        target_descriptor: target_descriptor.clone(),
        mapping,
    })
}

/// Derive leaves into one derived collection and, when `carry`, carry its
/// own lattice.
///
/// `ensure` (`carry` false) derives the key's own foundations that have no
/// leaf yet and publishes no merge. `maintain` derives every foundation this
/// host can derive that has no usable leaf ([`derive_leaves`]), then carries
/// the target's own frontier exactly as a root carries its commits, its leaf
/// images joined by [`DeriveMapping::join_images`]. The carry needs no WRITE
/// and never reads the source: a key the target does not admit derives
/// nothing and still carries, and so does a host that cannot compute the
/// mapping. Outputs of believed leaves that are not here go into `wanted`,
/// for the acquiring loop to ask for once this operation is done.
///
/// What deriving left undone holds nothing back: the carry runs first. A
/// blob an own foundation needs is then asked for
/// ([`CollectionRealizationError::MissingDependency`], which the acquiring
/// loop fetches before running everything again); it is a request, not a
/// report, so it comes before anything reported. What is reported comes in
/// this order: the carry's own failure, then the first own foundation the
/// mapping refused ([`CollectionRealizationError::Derive`]), then, for
/// `ensure` only, a key the target does not admit that owes leaves for
/// foundations of its own
/// ([`CollectionRealizationError::UnauthorizedProducer`]), then own
/// foundations the mapping could not represent
/// ([`CollectionRealizationError::Unmappable`]). The acquiring loop asks for
/// `wanted` before it returns any of these. Only a storage failure ends the
/// operation before the carry.
#[allow(clippy::too_many_arguments)]
pub(super) fn maintain_derived<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    wanted: &mut Vec<Vec<CollectionData>>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    carry_target: bool,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    let bound: Bound<M> = bind(&open(store, frontier, "open mapping snapshot")?, target)?;
    let derived = derive_leaves(
        store,
        target,
        &bound,
        signing_key,
        unavailable,
        wanted,
        frontier,
        carry_target,
    )?;
    let carried = if carry_target {
        carry(store, target, signing_key, frontier, |images, reader| {
            bound
                .mapping
                .join_images(&bound.target_descriptor, images, reader)
        })
    } else {
        Ok(())
    };
    if let Some(member) = derived.missing {
        return Err(CollectionRealizationError::MissingDependency { member });
    }
    carried?;
    if let Some(refusal) = derived.refusal {
        return Err(refusal);
    }
    if derived.unauthorized {
        return Err(CollectionRealizationError::UnauthorizedProducer {
            collection: target.handle(),
        });
    }
    if derived.blocked.is_empty() {
        Ok(())
    } else {
        Err(CollectionRealizationError::Unmappable {
            blocked: derived.blocked,
        })
    }
}

/// What deriving leaves left undone.
#[derive(Default)]
struct Derivation {
    /// The key owes leaves for foundations of its own, and the target does
    /// not admit it to publish them. Only the per-write `ensure` asks.
    unauthorized: bool,
    /// Own foundations the mapping could not represent, and why.
    blocked: Vec<(CollectionData, String)>,
    /// The first blob an own foundation needs that is not here -- its
    /// payload, or a dependency the mapping named -- asked for once
    /// everything else has been derived and carried.
    missing: Option<CollectionData>,
    /// The first own foundation the mapping refused: held until everything
    /// else has been derived and carried, and reported after what the carry
    /// reports.
    refusal: Option<CollectionRealizationError>,
}

/// The order `key` derives foundations in: a hash of the key and the
/// foundation.
///
/// Two hosts that derive one collection at the same time would otherwise
/// walk it in the same order, in step, and derive every foundation twice
/// before either saw the other's leaf. In orders of their own each mostly
/// meets foundations the other has not reached, and one whose leaf the
/// other published meanwhile is skipped ([`derive_leaf`]). This is local
/// scheduling, not ownership: nothing is looked up by it.
fn derive_order(key: &VerifyingKey, foundation: CollectionData) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"triblespace/derive-order");
    hash.update(key.as_bytes());
    hash.update(&foundation.raw);
    *hash.finalize().as_bytes()
}

/// Publish a leaf, `DERIVE(target, L(F), f(F))` with an empty image
/// included, for every source foundation `F` this pass owes one.
///
/// Scheduling is by leaf, and any admitted leaf suffices: a foundation is
/// owed a leaf only when no believed leaf for its locator has an output
/// that is here or can be fetched, whoever signed that leaf. The per-write
/// `ensure` asks this of the foundations the key owns only, and only whether
/// they have a leaf at all; it fetches nothing but their payloads.
/// `maintain` asks it of every foundation this host can derive: the key's
/// own, and another owner's whose payload is already here -- nothing is
/// fetched for another owner, and a reader of the target never waits on an
/// owner who is offline.
///
/// A leaf counts only when its output reads: an output that is here but
/// does not read -- damaged bytes a pile's index still lists -- is treated
/// exactly as an absent one, and a store that asks other holders fetches
/// good bytes for it. An output a believed leaf names that does not read
/// here is not waited for: the outputs of one foundation's leaves go into
/// `wanted` together, as one group any one of which would do, and the
/// acquiring loop asks for them once the rest of the work -- deriving what
/// needs no fetch, and the carry -- is done ([`super::exact_derived`]).
/// Until then its foundation is left alone. When no holder handed over any
/// of a foundation's leaves' outputs (`unavailable`), those leaves do not
/// count and the foundation is mapped again; a fetch that failed outright
/// is no answer about any holder, and the foundation waits. A failed
/// fetch is current unavailability, not loss: a result equal to an output a
/// leaf already names restores those bytes and publishes nothing, and a
/// different one is a second leaf beside the first. When the first output
/// arrives later, both are here, both are joined, and nothing further is
/// derived.
///
/// Foundations are derived own first, each group in the key's own order
/// ([`derive_order`]), and a foundation whose leaf another writer published
/// while the pass ran is skipped ([`derive_leaf`]).
///
/// Nothing is derived on a host that cannot compute the mapping
/// ([`DeriveMapping::computable_here`]): its leaves arrive by replication,
/// and that is no error. A key the target does not admit publishes nothing:
/// under `maintain` it reads nothing of the source either, and under
/// `ensure` it only reports whether it owes leaves for foundations of its
/// own.
///
/// An own source foundation owed a leaf whose bytes are not here is
/// fetched. When nobody can hand them over, a root commit's payload is
/// reported, because nothing upstream can restore it. A derived source's
/// leaf image is that source's own lag instead: maintaining the source maps
/// it again from what the source derives from, and until then this target
/// lags on it too, the same way a reader of the source does. Whatever the
/// mapping cannot do with another owner's foundation -- a refusal, a
/// capacity limit, a dependency not here -- is skipped quietly: it is not
/// this key's failure. What it cannot do with an own foundation is held in
/// the result, and the rest is derived regardless.
#[allow(clippy::too_many_arguments)]
fn derive_leaves<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    bound: &Bound<M>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    wanted: &mut Vec<Vec<CollectionData>>,
    frontier: &mut OperationFrontier<S::Snapshot>,
    maintain: bool,
) -> Result<Derivation, CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    if !bound.mapping.computable_here() {
        return Ok(Derivation::default());
    }
    let key = signing_key.verifying_key();
    let snapshot = open(store, frontier, "open leaf-derivation snapshot")?;
    // Only a key the target admits publishes a leaf. Maintenance by any
    // other key has nothing to derive and nothing to report: its work is
    // the carry, so the source is not even read.
    let admitted = producer_is_admitted(&snapshot, target, signing_key)?;
    if !admitted && maintain {
        return Ok(Derivation::default());
    }
    let scope = BTreeSet::from([bound.source, target.handle()]);
    let coverage = coverage_of(&snapshot, &scope)?;
    let (foundations, _) = coverage.frontier_support(bound.source);
    // Every foundation this pass may derive, with its locator and the
    // outputs its believed leaves name.
    let mut own = Vec::new();
    let mut foreign = Vec::new();
    for raw in foundations.iter_ordered() {
        let foundation: CollectionData = Inline::new(*raw);
        let owned = owns(&coverage, bound.source, foundation, &key);
        if !owned && !maintain {
            continue;
        }
        let locator = SourceLocator::of(foundation.raw);
        let outputs = coverage.leaf_outputs(target.handle(), locator);
        if !maintain && !outputs.is_empty() {
            continue;
        }
        if owned {
            own.push((foundation, locator, outputs));
        } else {
            foreign.push((foundation, locator, outputs));
        }
    }
    if !admitted {
        // `ensure` keeps exactly the key's own foundations with no leaf.
        return Ok(Derivation {
            unauthorized: !own.is_empty(),
            ..Derivation::default()
        });
    }
    if !foreign.is_empty() {
        let mut payloads = FrontierSet::new();
        for (foundation, _, _) in &foreign {
            payloads.insert(&Entry::new(&foundation.raw));
        }
        let resident = snapshot.resident(&payloads).map_err(|error| {
            CollectionRealizationError::storage("intersect foreign payloads with residency", error)
        })?;
        foreign.retain(|(foundation, _, _)| resident.get(&foundation.raw).is_some());
    }
    let mut images = FrontierSet::new();
    for (_, _, outputs) in own.iter().chain(&foreign) {
        for output in outputs {
            images.insert(&Entry::new(&output.raw));
        }
    }
    let resident = if images.is_empty() {
        FrontierSet::new()
    } else {
        snapshot.resident(&images).map_err(|error| {
            CollectionRealizationError::storage("intersect leaf outputs with residency", error)
        })?
    };
    let mut readable = FrontierSet::new();
    for raw in resident.iter_ordered() {
        if reads(&snapshot, Inline::new(*raw))? {
            readable.insert(&Entry::new(raw));
        }
    }
    drop(snapshot);
    own.sort_by_cached_key(|(foundation, _, _)| derive_order(&key, *foundation));
    foreign.sort_by_cached_key(|(foundation, _, _)| derive_order(&key, *foundation));
    // A foundation with a leaf whose output reads here is done, whoever
    // signed the leaf. One whose leaves' outputs do not read here -- absent,
    // or damaged -- waits for them to be asked for, and is owed a leaf only
    // once no holder handed any of them over.
    let mut owed = Vec::new();
    for (entries, owned) in [(own, true), (foreign, false)] {
        for (foundation, locator, outputs) in entries {
            if outputs
                .iter()
                .any(|output| readable.get(&output.raw).is_some())
            {
                continue;
            }
            let unasked = outputs
                .iter()
                .filter(|output| !unavailable.contains(*output))
                .copied()
                .collect::<Vec<_>>();
            if unasked.is_empty() {
                owed.push((foundation, locator, outputs, owned));
            } else {
                wanted.push(unasked);
            }
        }
    }

    let mut derivation = Derivation::default();
    for (foundation, locator, existing, own) in owed {
        match derive_leaf(
            store,
            frontier,
            target,
            bound,
            signing_key,
            foundation,
            locator,
            &existing,
            true,
        )? {
            Mapped::Done | Mapped::Overtaken => {}
            // Resident when selected; nothing is fetched for another owner,
            // and whatever the mapping cannot do with another owner's
            // foundation is not this key's failure.
            Mapped::Absent | Mapped::Refused(_) if !own => {}
            Mapped::Absent if unavailable.contains(&foundation) => {
                if bound.source_is_root {
                    derivation.blocked.push((
                        foundation,
                        "the source commit's payload cannot be read here or acquired".to_owned(),
                    ));
                }
            }
            Mapped::Absent => {
                derivation.missing.get_or_insert(foundation);
            }
            Mapped::Refused(error) => {
                match refused(foundation, error, unavailable, &mut derivation.blocked) {
                    Ok(()) => {}
                    Err(CollectionRealizationError::MissingDependency { member }) => {
                        derivation.missing.get_or_insert(member);
                    }
                    Err(error) => {
                        derivation.refusal.get_or_insert(error);
                    }
                }
            }
        }
    }
    Ok(derivation)
}

/// What mapping one source foundation came to.
enum Mapped {
    /// Its payload is not here.
    Absent,
    /// Its image is stored, and published as a leaf unless a believed leaf
    /// already names that output.
    Done,
    /// While the operation ran, another writer published a leaf for it, or
    /// the output of one of its leaves arrived: nothing was mapped.
    Overtaken,
    /// The mapping could not map it.
    Refused(CollectionOperationError),
}

/// Whether, since the operation's control snapshot, a leaf for `locator`
/// that `existing` does not name was published -- by another host deriving
/// the same collection, say -- or an output `existing` names arrived.
///
/// Read from `now`, a fresh observation of the store, and used only to skip
/// work: an operation otherwise never sees records that arrived while it
/// ran, so two hosts deriving one collection at once would each map every
/// foundation. Skipping is always sound -- the next pass sees the new leaf
/// from its own control snapshot, and asks for its output or maps again by
/// the ordinary rule -- and nothing read here is published or joined.
fn overtaken<R>(
    now: &R,
    target: CollectionHandle,
    locator: SourceLocator,
    existing: &[CollectionData],
) -> Result<bool, CollectionRealizationError>
where
    R: StoreRead,
{
    let coverage = coverage_of(now, &BTreeSet::from([target]))?;
    for output in coverage.leaf_outputs(target, locator) {
        if !existing.contains(&output) {
            return Ok(true);
        }
        if now
            .metadata(Handle::<UnknownBlob>::from_hash(output))
            .map_err(|error| CollectionRealizationError::storage("inspect a leaf output", error))?
            .is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Map one source foundation from its payload, store the image, and publish
/// it as `DERIVE(target, locator, image)` unless `existing` -- the outputs
/// its believed leaves name -- already holds it: then the bytes of a leaf
/// already believed are restored and nothing is published. With `recheck`,
/// a foundation [`overtaken`] while the operation ran is left alone.
#[allow(clippy::too_many_arguments)]
fn derive_leaf<S, M>(
    store: &mut S,
    frontier: &mut OperationFrontier<S::Snapshot>,
    target: Collection<M::Target>,
    bound: &Bound<M>,
    signing_key: &SigningKey,
    foundation: CollectionData,
    locator: SourceLocator,
    existing: &[CollectionData],
    recheck: bool,
) -> Result<Mapped, CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    let now = store.snapshot().map_err(|error| {
        CollectionRealizationError::storage("open leaf mapping snapshot", error)
    })?;
    if recheck && overtaken(&now, target.handle(), locator, existing)? {
        return Ok(Mapped::Overtaken);
    }
    let snapshot = frontier.view(now);
    let handle = Handle::<M::Source>::from_hash(foundation);
    if snapshot
        .metadata(handle)
        .map_err(|error| CollectionRealizationError::storage("inspect a source foundation", error))?
        .is_none()
    {
        return Ok(Mapped::Absent);
    }
    let input: Blob<M::Source> = snapshot
        .get(handle)
        .map_err(|error| CollectionRealizationError::storage("load a source foundation", error))?;
    let output = bound.mapping.map(&input, &snapshot);
    drop(snapshot);
    let output = match output {
        Ok(output) => output,
        Err(error) => return Ok(Mapped::Refused(error)),
    };
    let output_data = data_identity::<M::Target>(&output);
    store
        .put::<M::Target, _>(output)
        .map_err(|error| CollectionRealizationError::storage("store a leaf image", error))?;
    if !existing.contains(&output_data) {
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
    Ok(Mapped::Done)
}

/// Record what the mapping could not do with a foundation this pass was
/// asked to derive: a capacity limit, or a dependency that could not be
/// acquired, is reported with the rest; a dependency not yet asked for is
/// acquired; a refusal fails the pass.
fn refused(
    foundation: CollectionData,
    error: CollectionOperationError,
    unavailable: &BTreeSet<CollectionData>,
    blocked: &mut Vec<(CollectionData, String)>,
) -> Result<(), CollectionRealizationError> {
    match error {
        CollectionOperationError::Capacity(reason) => blocked.push((foundation, reason)),
        CollectionOperationError::MissingDependency(member) if unavailable.contains(&member) => {
            blocked.push((
                foundation,
                format!(
                    "the mapping requires blob {}, which could not be acquired",
                    hex::encode_upper(member.raw)
                ),
            ))
        }
        CollectionOperationError::MissingDependency(member) => {
            return Err(CollectionRealizationError::MissingDependency { member })
        }
        CollectionOperationError::Fatal(reason) => {
            return Err(CollectionRealizationError::Derive {
                input: foundation,
                reason,
            })
        }
    }
    Ok(())
}

/// Map the named source foundations again and publish each result that is
/// not already a leaf's output as another leaf: the explicit supplement to a
/// leaf known to be bad.
///
/// Scheduling never replaces a leaf, and maintenance never derives a
/// foundation that already has a usable one. So a leaf whose output is
/// wrong -- computed by a broken driver, say -- stays, and is supplemented
/// only here, on request: the new leaf stands beside it and the join holds
/// both. A foundation whose result equals an output a believed leaf
/// already names adds nothing. Each foundation must be a believed
/// foundation of `source`, the target's immediate source; its payload is
/// fetched when it is not here, whoever owns it, because re-deriving is
/// asked for, and every payload is asked for before anything is mapped. It
/// needs a key the target admits and a host that can compute the mapping;
/// anything the mapping cannot do with a foundation is an error, because
/// re-deriving it was the request.
///
/// `done` names the foundations an earlier run of the same request already
/// mapped: the acquiring loop runs this again after every fetch, and a
/// mapping that does not reproduce bit for bit must not add a leaf per run.
#[allow(clippy::too_many_arguments)]
pub(super) fn rederive<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    source: CollectionHandle,
    foundations: &BTreeSet<CollectionData>,
    done: &mut BTreeSet<CollectionData>,
    signing_key: &SigningKey,
    unavailable: &BTreeSet<CollectionData>,
    frontier: &mut OperationFrontier<S::Snapshot>,
) -> Result<(), CollectionRealizationError>
where
    S: Store,
    M: DeriveMapping,
{
    let snapshot = open(store, frontier, "open re-derivation snapshot")?;
    let bound: Bound<M> = bind(&snapshot, target)?;
    if !bound.mapping.computable_here() {
        return Err(CollectionRealizationError::Resolution(
            "the mapping is pinned to a class of host this one is not; re-derive on a host \
             that can compute it"
                .to_owned(),
        ));
    }
    if source != bound.source {
        return Err(CollectionRealizationError::InvalidCover(format!(
            "the foundations name collection {}, but the target derives from {}",
            hex::encode_upper(source.raw),
            hex::encode_upper(bound.source.raw),
        )));
    }
    let scope = BTreeSet::from([bound.source, target.handle()]);
    let coverage = coverage_of(&snapshot, &scope)?;
    let (believed, _) = coverage.frontier_support(bound.source);
    if let Some(stranger) = foundations
        .iter()
        .find(|foundation| believed.get(&foundation.raw).is_none())
    {
        return Err(CollectionRealizationError::InvalidCover(format!(
            "{} is not a believed foundation of the target's source",
            hex::encode_upper(stranger.raw),
        )));
    }
    if !producer_is_admitted(&snapshot, target, signing_key)? {
        return Err(CollectionRealizationError::UnauthorizedProducer {
            collection: target.handle(),
        });
    }
    let owed: Vec<_> = foundations
        .iter()
        .filter(|foundation| !done.contains(*foundation))
        .map(|foundation| {
            let locator = SourceLocator::of(foundation.raw);
            (
                *foundation,
                locator,
                coverage.leaf_outputs(target.handle(), locator),
            )
        })
        .collect();
    let mut payloads = FrontierSet::new();
    for (foundation, _, _) in &owed {
        payloads.insert(&Entry::new(&foundation.raw));
    }
    let resident = snapshot.resident(&payloads).map_err(|error| {
        CollectionRealizationError::storage("intersect named payloads with residency", error)
    })?;
    if let Some((member, _, _)) = owed.iter().find(|(foundation, _, _)| {
        resident.get(&foundation.raw).is_none() && !unavailable.contains(foundation)
    }) {
        return Err(CollectionRealizationError::MissingDependency { member: *member });
    }
    drop(snapshot);
    let mut blocked = Vec::new();
    for (foundation, locator, existing) in owed {
        match derive_leaf(
            store,
            frontier,
            target,
            &bound,
            signing_key,
            foundation,
            locator,
            &existing,
            false,
        )? {
            Mapped::Done | Mapped::Overtaken => {
                done.insert(foundation);
            }
            Mapped::Absent if unavailable.contains(&foundation) => blocked.push((
                foundation,
                "the source foundation's payload cannot be read here or acquired".to_owned(),
            )),
            Mapped::Absent => {
                return Err(CollectionRealizationError::MissingDependency { member: foundation })
            }
            Mapped::Refused(error) => refused(foundation, error, unavailable, &mut blocked)?,
        }
    }
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(CollectionRealizationError::Unmappable { blocked })
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
