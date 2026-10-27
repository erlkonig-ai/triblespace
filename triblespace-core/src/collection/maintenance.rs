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
//!   collection's mapping's ([`DeriveMapping::join_images`]). Whenever one
//!   tier -- `floor(log_8 |support|)` -- holds [`MERGE_FAN_IN`] held nodes,
//!   eight distinct handles in canonical order are joined by one MERGE.
//!   Underfull tiers, including nodes covered by another node, may remain;
//!   no binary absorption is emitted. The union may equal an input. A
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
    Unfetched,
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
pub const MERGE_FAN_IN: usize = super::records::MERGE_INPUTS;

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

/// Sign exactly eight distinct, canonically ordered nodes. The historical
/// variable-arity codec and signature remain unchanged; this is a producer
/// restriction, not a record-format migration.
fn sign_merge(
    signing_key: &SigningKey,
    collection: CollectionHandle,
    inputs: [CollectionData; MERGE_FAN_IN],
    result: CollectionData,
) -> Result<CollectionMerge, CollectionRealizationError> {
    if !inputs.windows(2).all(|pair| pair[0].raw < pair[1].raw) {
        return Err(CollectionRealizationError::Resolution(
            "plan a MERGE without eight distinct canonically ordered inputs".into(),
        ));
    }
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

/// Frontier nodes of one collection whose bytes are here and read, widest first.
///
/// The frontier is every believed foundation, whoever signed it, and the
/// host's own merge results. Only a held node is ever joined.
/// A node whose bytes are not here is not asked for, so a host
/// holding another key's commit or leaf records without their payloads
/// neither fetches them nor restarts the carry once per payload. A node
/// rejoins the carry when its bytes arrive. A node whose bytes
/// are here but do not read -- a store's index may say a blob is present
/// without reading it, as a pile's does -- sits out the same way, instead of
/// failing every carry that would join it.
fn held_frontier_nodes<R>(
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
    let mut held = Vec::new();
    for raw in frontier.iter_ordered() {
        let node: CollectionData = Inline::new(*raw);
        if let Some(support) = coverage.of(collection, node) {
            if resident.get(raw).is_some() && reads(snapshot, node)? {
                held.push((node, support.clone()));
            }
        }
    }
    held.sort_by(|left, right| {
        right
            .1
            .len()
            .cmp(&left.1.len())
            .then_with(|| left.0.raw.cmp(&right.0.raw))
    });
    Ok(held)
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

/// A successful publication must become this exact driven witness. Support
/// growth or a different producer for the same output is not evidence of that.
fn require_driven(
    coverage: &Coverage,
    collection: CollectionHandle,
    inputs: &[CollectionData; MERGE_FAN_IN],
    result: CollectionData,
) -> Result<(), CollectionRealizationError> {
    if coverage
        .producers(collection, result)
        .iter()
        .any(|producer| producer.as_slice() == inputs.as_slice())
    {
        Ok(())
    } else {
        Err(CollectionRealizationError::Stalled {
            cover: coverage.frontier(collection).collect(),
        })
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
/// foundations beneath it. Every tier holding [`MERGE_FAN_IN`] held nodes is
/// carried, the lowest such tier first, eight distinct lowest handles per MERGE,
/// joined by `join`, before the frontier is read again. Each result is
/// stored and published at once, so a later failure keeps the complete
/// successful prefix. A join that answers `Capacity` or `MissingDependency`
/// leaves that group's finer cover standing; `Fatal` fails the carry. A
/// merge needs no WRITE authority, only the store's host key: publishing
/// with any other key is an error
/// ([`CollectionRealizationError::HostMismatch`]). A frontier node whose
/// bytes are not here is never joined and nothing is fetched for it. Underfull
/// tiers and dominated nodes may remain on the frontier; readers still select
/// a sufficient cover or descend to finer inputs. A result may equal an input,
/// and unchanged support is not a failure. Each exact group is attempted at
/// most once per invocation, but a published witness must be driven by the
/// next coverage fold. No eventual consumption of all nodes is promised.
/// Nothing outside the collection's own lattice is read.
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
    // Scratch for this invocation only, never retained across observations.
    let mut attempted = BTreeSet::<[CollectionData; MERGE_FAN_IN]>::new();
    let mut published = Vec::<([CollectionData; MERGE_FAN_IN], CollectionData)>::new();
    loop {
        let snapshot = open(store, frontier, "open root-carry snapshot")?;
        let index = index_of(&snapshot, &scope)?;
        for (inputs, result) in published.drain(..) {
            require_driven(index.published(), target.handle(), &inputs, result)?;
        }
        let nodes = held_frontier_nodes(&snapshot, index.published(), target.handle())?;
        if nodes.len() < MERGE_FAN_IN {
            return Ok(());
        }
        // Per-round scratch: grouping does not become a retained catalogue.
        let mut tiers = BTreeMap::<u32, BTreeSet<CollectionData>>::new();
        for (node, support) in &nodes {
            tiers.entry(tier(support.len())).or_default().insert(*node);
        }
        // The lowest tier with a full group; within it, consecutive groups of
        // the lowest handles, each group pairwise disjoint from the others.
        let round: Vec<[CollectionData; MERGE_FAN_IN]> = tiers
            .into_values()
            .map(|members| {
                let members: Vec<CollectionData> = members.into_iter().collect();
                members
                    .chunks_exact(MERGE_FAN_IN)
                    .map(|group| group.try_into().expect("an exact eight-node chunk"))
                    .filter(|group| !attempted.contains(group))
                    .collect::<Vec<_>>()
            })
            .find(|groups| !groups.is_empty())
            .unwrap_or_default();
        if round.is_empty() {
            return Ok(());
        }
        require_host(&index, signing_key)?;
        drop(snapshot);
        for group in round {
            attempted.insert(group);
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
                            group,
                            result,
                        )?),
                        "publish root carry MERGE",
                    )?;
                    published.push((group, result));
                }
                Err(CollectionOperationError::Fatal(reason)) => {
                    return Err(CollectionRealizationError::Merge {
                        inputs: group.to_vec(),
                        reason,
                    });
                }
                Err(CollectionOperationError::Capacity(_))
                | Err(CollectionOperationError::MissingDependency(_)) => {
                    // The finer cover stays the valid result for this group.
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
    attached_lineage_mode(snapshot, attached, false)
}

pub(super) fn attached_lineage_acquiring<R, E>(
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
    attached_lineage_mode(snapshot, attached, true)
}

fn attached_lineage_mode<R, E>(
    snapshot: &R,
    attached: Collection<E>,
    acquire: bool,
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
        if !acquire
            && !snapshot.contains_blob(collection).map_err(|error| {
                CollectionRealizationError::storage(
                    "inspect collection descriptor residency",
                    error,
                )
            })?
        {
            return Err(CollectionRealizationError::MissingDependency {
                member: Handle::<SimpleArchive>::to_hash(collection),
            });
        }
        super::api::load_collection_descriptor(snapshot, collection)
            .map(|loaded| loaded.fragment)
            .map_err(|error| {
                if acquire && crate::repo::is_missing_blob(&error) {
                    return CollectionRealizationError::MissingDependency {
                        member: Handle::<SimpleArchive>::to_hash(collection),
                    };
                }
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
/// frontier node cannot have one. Only frontier nodes are maintained: an
/// interior node a merge has consumed needs no attachment, and one a MAP
/// gave before its merge stays in the store until a compaction collects it.
///
/// A dependency the mapping names that is not here is wanted, not required:
/// it goes into `wanted` as a group of its own, and the node is descended
/// exactly as one whose bytes are not here, so one pass visits every other
/// node and names every node's absence, instead of ending at the first.
/// The acquiring loop asks for them together once the pass is done, within
/// its budget of failed fetches, and runs the operation again if it asked
/// for any ([`super::exact_derived`]). Nothing is lost by not waiting: an
/// attachment is an index of its node and never the only way to read it --
/// what no taken attachment covers is the reader's residual, read from the
/// parent's own foundations -- so an absent dependency costs lag, never a
/// wrong or a falsely complete read. The node itself gets no MAP while its
/// dependency is absent, and its finer nodes are mapped in its place where
/// their own dependencies are here; each such attachment is complete for its
/// own node. A foundation whose own mapping still names an absent blob has
/// no attachment and stays residual. Once the bytes arrive, a later pass
/// meets the node again -- it still has no usable attachment -- and maps
/// it; the reader then takes it, widest first, and the finer attachments
/// beneath it are no longer selected, left in the store like any MAP a
/// merge supersedes. A blob already asked for and not got in this call
/// ([`Unfetched`]) is not wanted again: the node is descended for the rest
/// of the call, and its foundations stay residual until a later call gets
/// the bytes.
///
/// A mapping names one dependency per node and call of `map`, so one pass
/// names at most one absence per node visited; the walk visits each node
/// once, and each blob is named once per pass, so `wanted` holds at most
/// one group per node of the parent's lattice.
pub(super) fn attach_frontier<S, M>(
    store: &mut S,
    attached: Collection<M::Target>,
    signing_key: &SigningKey,
    unfetched: &Unfetched,
    wanted: &mut Vec<Vec<CollectionData>>,
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
    // What this pass has named in `wanted`: a parent and a finer node
    // beneath it often need the same blob, and asking for it once is enough.
    let mut named = BTreeSet::new();
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
            // Wanted, and the node descended meanwhile; once asked for and
            // not got, only descended.
            Err(CollectionOperationError::MissingDependency(member)) => {
                if !unfetched.contains(&member) && named.insert(member) {
                    wanted.push(vec![member]);
                }
                Ok(false)
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
/// storage error ends the operation at once, deriving's before the carry
/// and the carry's own -- a leaf image or MERGE that cannot be stored, a
/// held node that cannot be loaded -- before anything else, and it is the
/// one error the call reports. It is never held behind a request: that
/// would run the operation again, and a retry that went through would lose
/// it. Otherwise a blob an own foundation needs is asked for
/// ([`CollectionRealizationError::MissingDependency`], which the acquiring
/// loop fetches before running everything again); it is a request, not a
/// report, so it comes before anything reported, and a carry that fails the
/// same way on every call -- a join refusing a leaf that reads and does not
/// decode -- hides no payload. What is reported comes in this order: the
/// carry's own failure, then the first own foundation the mapping refused
/// ([`CollectionRealizationError::Derive`]), then, for `ensure` only, a key
/// the target does not admit that owes leaves for foundations of its own
/// ([`CollectionRealizationError::UnauthorizedProducer`]), then own
/// foundations the mapping could not represent
/// ([`CollectionRealizationError::Unmappable`]). The acquiring loop asks for
/// `wanted` before it returns any of these.
#[allow(clippy::too_many_arguments)]
pub(super) fn maintain_derived<S, M>(
    store: &mut S,
    target: Collection<M::Target>,
    signing_key: &SigningKey,
    unfetched: &Unfetched,
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
        unfetched,
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
    if matches!(carried, Err(CollectionRealizationError::Storage { .. })) {
        return carried;
    }
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
/// of a foundation's leaves' outputs ([`Unfetched::unavailable`]), those
/// leaves do not count and the foundation is mapped again. A fetch that
/// failed outright is no answer about any holder, even when it was made for
/// another foundation that needs the same blob: the foundation waits. A
/// failed fetch is current unavailability, not loss: a result equal to an output a
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
    unfetched: &Unfetched,
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
                .filter(|output| !unfetched.unavailable.contains(*output))
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
            Mapped::Absent if unfetched.contains(&foundation) => {
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
                match refused(foundation, error, unfetched, &mut derivation.blocked) {
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
    unfetched: &Unfetched,
    blocked: &mut Vec<(CollectionData, String)>,
) -> Result<(), CollectionRealizationError> {
    match error {
        CollectionOperationError::Capacity(reason) => blocked.push((foundation, reason)),
        CollectionOperationError::MissingDependency(member) if unfetched.contains(&member) => {
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
    unfetched: &Unfetched,
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
        resident.get(&foundation.raw).is_none() && !unfetched.contains(foundation)
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
            Mapped::Absent if unfetched.contains(&foundation) => blocked.push((
                foundation,
                "the source foundation's payload cannot be read here or acquired".to_owned(),
            )),
            Mapped::Absent => {
                return Err(CollectionRealizationError::MissingDependency { member: foundation })
            }
            Mapped::Refused(error) => refused(foundation, error, unfetched, &mut blocked)?,
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
    use super::*;
    use crate::collection::coverage::AdmitEveryRecord;
    use crate::collection::{empty_metadata_handle, CollectionCommit};

    #[test]
    fn a_published_witness_requires_its_exact_driven_inputs_and_result() {
        let host = SigningKey::from_bytes(&[41; 32]);
        let collection = Inline::new([20; 32]);
        let inputs: [CollectionData; MERGE_FAN_IN] =
            std::array::from_fn(|i| Inline::new([i as u8 + 1; 32]));
        let result = inputs[7];
        let mut index = CoverageIndex::for_host(Inline::new(host.verifying_key().to_bytes()));
        for input in inputs {
            index.apply(
                &CollectionRecord::Commit(CollectionCommit::sign(
                    &host,
                    collection,
                    input,
                    empty_metadata_handle(),
                )),
                &AdmitEveryRecord,
            );
        }
        assert!(matches!(
            require_driven(index.published(), collection, &inputs, result),
            Err(CollectionRealizationError::Stalled { .. })
        ));
        // A different driven producer for this output cannot satisfy the check.
        let other = Inline::new([9; 32]);
        index.apply(
            &CollectionRecord::Commit(CollectionCommit::sign(
                &host, collection, other, empty_metadata_handle(),
            )),
            &AdmitEveryRecord,
        );
        let mut different = inputs;
        different[0] = other;
        index.apply(
            &CollectionRecord::Merge(
                CollectionMerge::sign(&host, collection, different, result).unwrap(),
            ),
            &AdmitEveryRecord,
        );
        assert!(matches!(
            require_driven(index.published(), collection, &inputs, result),
            Err(CollectionRealizationError::Stalled { .. })
        ));
        index.apply(
            &CollectionRecord::Merge(sign_merge(&host, collection, inputs, result).unwrap()),
            &AdmitEveryRecord,
        );
        require_driven(index.published(), collection, &inputs, result).unwrap();
        assert!(matches!(
            require_driven(index.published(), collection, &inputs, inputs[0]),
            Err(CollectionRealizationError::Stalled { .. })
        ));
    }

    #[test]
    fn the_producer_refuses_duplicate_or_noncanonical_inputs() {
        let host = SigningKey::from_bytes(&[41; 32]);
        let collection = Inline::new([20; 32]);
        let mut inputs: [CollectionData; MERGE_FAN_IN] =
            std::array::from_fn(|i| Inline::new([i as u8 + 1; 32]));
        let result = inputs[7];
        sign_merge(&host, collection, inputs, result)
            .unwrap()
            .verify_strict()
            .unwrap();
        inputs.swap(0, 1);
        assert!(matches!(
            sign_merge(&host, collection, inputs, result),
            Err(CollectionRealizationError::Resolution(_))
        ));
        inputs[0] = inputs[1];
        assert!(matches!(
            sign_merge(&host, collection, inputs, result),
            Err(CollectionRealizationError::Resolution(_))
        ));
    }

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
