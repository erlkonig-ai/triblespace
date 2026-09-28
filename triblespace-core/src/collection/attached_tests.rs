//! Attached collections: which attachments a reader uses, maintenance of
//! the parent's frontier, the fold's treatment of MAPs, and the
//! cover-query equivalence law for every attachment this crate defines.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use futures::executor::block_on;

use crate::attribute::Attribute;
use crate::blob::encodings::entity_id_set::{EntityIdSet, EntityIdSetBlob};
use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use crate::blob::{Blob, IntoBlob};
use crate::collection::latest::{LatestBlob, LatestIndex};
use crate::collection::lww_register::{LwwIndex, LwwRegisterBlob};
use crate::collection::{
    empty_metadata_handle, simplearchive_union, succinctarchive_union, AdmissionPolicy, Collection,
    CollectionAttachment, CollectionCommit, CollectionData, CollectionDerive, CollectionEncoding,
    CollectionMap, CollectionMerge, CollectionPolicy, CollectionRead, CollectionRealizationError,
    CollectionRecord, CollectionSnapshotExt, CollectionStore, CollectionStoreExt, Cover,
    CoverageRead, SourceLocator, TryFromCover,
};
use crate::id::{ExclusiveId, Id};
use crate::inline::encodings::genid::GenId;
use crate::inline::encodings::hash::Handle;
use crate::inline::encodings::time::{i128_to_ordered_be, NsTAIInterval};
use crate::inline::Inline;
use crate::macros::entity;
use crate::metadata;
use crate::repo::memoryrepo::MemoryRepo;
use crate::repo::{BlobStoreGet, BlobStoreMeta, BlobStorePut, SnapshotSource, StoreRead};
use crate::trible::{Fragment, Trible, TribleSet, TRIBLE_LEN};

fn host() -> SigningKey {
    SigningKey::from_bytes(&[91; 32])
}

fn other() -> SigningKey {
    SigningKey::from_bytes(&[92; 32])
}

fn policy() -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(host().verifying_key()),
        AdmissionPolicy::direct(host().verifying_key()),
    )
}

fn id(byte: u8) -> Id {
    Id::new([byte; 16]).unwrap()
}

fn row(entity: u8, attribute: u8, value: u8) -> TribleSet {
    let mut data = [value; TRIBLE_LEN];
    data[..16].fill(entity);
    data[16..32].fill(attribute);
    [Trible::force_raw(data).unwrap()].into_iter().collect()
}

fn data<E: crate::blob::BlobEncoding>(blob: &Blob<E>) -> CollectionData {
    Handle::<E>::to_hash(blob.get_handle())
}

/// A store hosted by [`host`] with one root and its Succinct attachment.
fn succinct_root(
    name: &str,
) -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    Collection<SuccinctArchiveBlob>,
) {
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let root = store.collection(name, policy()).unwrap();
    let attached = store.attach::<SuccinctArchiveBlob>(root, ()).unwrap();
    (store, root, attached)
}

/// Map `node` through Succinct, store the image and publish `key`'s MAP.
fn map_succinct(
    store: &mut MemoryRepo,
    attached: Collection<SuccinctArchiveBlob>,
    node: CollectionData,
    key: &SigningKey,
) -> CollectionData {
    let snapshot = store.snapshot().unwrap();
    let bytes: Blob<SimpleArchive> = snapshot
        .get(Handle::<SimpleArchive>::from_hash(node))
        .unwrap();
    drop(snapshot);
    let image = succinctarchive_union::derive_element(&bytes).unwrap();
    let attachment = data(&image);
    store.put::<SuccinctArchiveBlob, _>(image).unwrap();
    store
        .insert(CollectionRecord::Map(CollectionMap::sign(
            key,
            attached.handle(),
            node,
            attachment,
        )))
        .unwrap();
    attachment
}

fn commit(
    store: &mut MemoryRepo,
    root: Collection<SimpleArchive>,
    facts: TribleSet,
) -> CollectionData {
    store
        .commit(root, &host(), Fragment::from(facts))
        .unwrap()
        .data()
}

fn members<E: CollectionEncoding>(cover: &Cover<E>) -> BTreeSet<CollectionData> {
    cover
        .members()
        .map(|member| Handle::<E>::to_hash(member))
        .collect()
}

fn residual<R: StoreRead, E: CollectionEncoding>(
    attached: &crate::collection::AttachedSnapshot<R, E>,
) -> BTreeSet<CollectionData> {
    attached.residual().data_members().collect()
}

fn facts_of(snapshot: &impl StoreRead, attached: Collection<SuccinctArchiveBlob>) -> TribleSet {
    snapshot
        .attached(attached)
        .unwrap()
        .view::<UnionArchive<OrderedUniverse>>()
        .unwrap()
        .iter()
        .collect()
}

// ---------------------------------------------------------------------------
// The usable-attachment descent.
// ---------------------------------------------------------------------------

#[test]
fn a_usable_attachment_is_taken() {
    let (mut store, root, attached) = succinct_root("taken");
    let node = commit(&mut store, root, row(1, 2, 3));
    let attachment = map_succinct(&mut store, attached, node, &host());
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert_eq!(members(read.cover()), BTreeSet::from([attachment]));
    assert!(read.residual().is_empty());
    assert_eq!(
        read.support().data_members().collect::<Vec<_>>(),
        vec![node]
    );
    assert_eq!(facts_of(&snapshot, attached), row(1, 2, 3));
}

/// Eight commits carried into one merge, each commit attached, and the
/// merge's attachment given by a MAP whose bytes are not here.
#[test]
fn a_believed_map_whose_bytes_are_absent_is_descended() {
    let (mut store, root, attached) = succinct_root("absent-bytes");
    let mut children = BTreeSet::new();
    let mut expected = TribleSet::new();
    for byte in 1..=8u8 {
        expected += row(byte, 2, 3);
        children.insert(commit(&mut store, root, row(byte, 2, 3)));
    }
    block_on(store.maintain(root, &host())).unwrap();
    let snapshot = store.snapshot().unwrap();
    let merged: Vec<_> = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()]))
        .unwrap()
        .frontier(root.handle())
        .collect();
    drop(snapshot);
    assert_eq!(merged.len(), 1);
    let mut attachments = BTreeSet::new();
    for child in &children {
        attachments.insert(map_succinct(&mut store, attached, *child, &host()));
    }
    store
        .insert(CollectionRecord::Map(CollectionMap::sign(
            &host(),
            attached.handle(),
            merged[0],
            Inline::new([0xAB; 32]),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert_eq!(members(read.cover()), attachments);
    assert!(read.residual().is_empty());
    assert_eq!(facts_of(&snapshot, attached), expected);
}

/// A merged node's Rank9 attachment whose Succinct child is not here is not
/// usable; its children's complete Rank9 attachments are.
#[test]
fn a_resident_rank9_whose_succinct_child_is_absent_is_descended() {
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let root = store.collection("rank9-descent", policy()).unwrap();
    let succinct = store.attach::<SuccinctArchiveBlob>(root, ()).unwrap();
    let rank9 = store
        .attach::<Rank9AcceleratedSuccinctArchiveBlob>(root, succinct)
        .unwrap();
    let mut children = Vec::new();
    for byte in 1..=8u8 {
        children.push(commit(&mut store, root, row(byte, 4, 5)));
    }
    block_on(store.maintain(root, &host())).unwrap();
    let snapshot = store.snapshot().unwrap();
    let merged = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()]))
        .unwrap()
        .frontier(root.handle())
        .next()
        .unwrap();
    let merged_bytes: Blob<SimpleArchive> = snapshot
        .get(Handle::<SimpleArchive>::from_hash(merged))
        .unwrap();
    drop(snapshot);
    // The merged node's accelerator, with its raw child never stored.
    let raw = succinctarchive_union::derive_element(&merged_bytes).unwrap();
    let accelerated =
        crate::blob::encodings::succinctarchive::SuccinctArchive::<OrderedUniverse>::build_accelerated_root(raw)
            .unwrap();
    let merged_attachment = data(&accelerated);
    store
        .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(accelerated)
        .unwrap();
    store
        .insert(CollectionRecord::Map(CollectionMap::sign(
            &host(),
            rank9.handle(),
            merged,
            merged_attachment,
        )))
        .unwrap();
    // Every child complete: its Succinct attachment, then its Rank9 one.
    let mut expected = BTreeSet::new();
    for child in &children {
        let raw = map_succinct(&mut store, succinct, *child, &host());
        let snapshot = store.snapshot().unwrap();
        let node: Blob<SimpleArchive> = snapshot
            .get(Handle::<SimpleArchive>::from_hash(*child))
            .unwrap();
        let image = <Rank9AcceleratedSuccinctArchiveBlob as CollectionAttachment>::map(
            &succinct,
            &node,
            &[raw],
            &snapshot,
        )
        .unwrap();
        drop(snapshot);
        expected.insert(data(&image));
        let attachment = store
            .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(image)
            .unwrap();
        store
            .insert(CollectionRecord::Map(CollectionMap::sign(
                &host(),
                rank9.handle(),
                *child,
                Handle::<Rank9AcceleratedSuccinctArchiveBlob>::to_hash(attachment),
            )))
            .unwrap();
    }
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(rank9).unwrap();
    assert!(!members(read.cover()).contains(&merged_attachment));
    assert_eq!(members(read.cover()), expected);
    assert!(read.residual().is_empty());
    let view: UnionArchive<OrderedUniverse> = read.view().unwrap();
    assert_eq!(view.iter().count(), 8);
}

/// Another key's MAP, arriving by `cat`, is never used, even with its bytes
/// here: the node stays in the residual.
#[test]
fn a_foreign_map_is_never_used() {
    let (mut store, root, attached) = succinct_root("foreign-map");
    let node = commit(&mut store, root, row(1, 2, 3));
    map_succinct(&mut store, attached, node, &other());
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert!(read.cover().is_empty());
    assert_eq!(residual(&read), BTreeSet::from([node]));
    // The fold never believed it at all.
    let coverage = CoverageRead::coverage(&snapshot, &BTreeSet::from([attached.handle()])).unwrap();
    assert!(coverage.attachments(attached.handle(), node).is_empty());
}

/// A MAP for a node the parent's lattice does not reach -- one only another
/// key's merge produced, or no node of the parent at all -- is never used.
#[test]
fn a_map_for_a_node_the_lattice_does_not_reach_is_never_used() {
    let (mut store, root, attached) = succinct_root("unreached");
    let a = commit(&mut store, root, row(1, 2, 3));
    let b = commit(&mut store, root, row(4, 5, 6));
    // Another key merges a and b; this host believes no such node.
    let snapshot = store.snapshot().unwrap();
    let joined = simplearchive_union::join(
        &snapshot.get(Handle::<SimpleArchive>::from_hash(a)).unwrap(),
        &snapshot.get(Handle::<SimpleArchive>::from_hash(b)).unwrap(),
    )
    .unwrap();
    drop(snapshot);
    let foreign = data(&joined);
    store.put::<SimpleArchive, _>(joined).unwrap();
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(&other(), root.handle(), [a, b], foreign).unwrap(),
        ))
        .unwrap();
    let unreached = map_succinct(&mut store, attached, foreign, &host());
    // An unrelated archive, no node of the parent.
    let stray: Blob<SimpleArchive> = row(9, 9, 9).to_blob();
    let stray_node = data(&stray);
    store.put::<SimpleArchive, _>(stray).unwrap();
    let stray_attachment = map_succinct(&mut store, attached, stray_node, &host());

    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    let taken = members(read.cover());
    assert!(!taken.contains(&unreached));
    assert!(!taken.contains(&stray_attachment));
    assert_eq!(residual(&read), BTreeSet::from([a, b]));
}

/// A host join still waiting for an input's support is no producer, and it
/// changes nothing a reader sees: the attached read of a store holding it is
/// the read of the same store without it.
///
/// The join claims `z` is `a + b + y`, where `a` and `b` are attached
/// commits and `y` has no support, so it stays blocked and consumes nothing.
/// That is the whole observable contract. Whether a reader would descend a
/// blocked join cannot be seen through the read at all: every node with a
/// row is reachable through driven joins anyway, and a node without one is
/// never taken, so the walk's own filter is pinned by `producers` alone.
#[test]
fn a_blocked_own_join_changes_nothing_a_reader_sees() {
    fn read_with_join(blocked: bool) -> (BTreeSet<CollectionData>, BTreeSet<CollectionData>) {
        let (mut store, root, attached) = succinct_root("blocked");
        let a = commit(&mut store, root, row(1, 2, 3));
        let b = commit(&mut store, root, row(4, 5, 6));
        let z = commit(&mut store, root, row(7, 8, 9));
        let y: CollectionData = Inline::new([0x31; 32]);
        if blocked {
            store
                .insert(CollectionRecord::Merge(
                    CollectionMerge::sign(&host(), root.handle(), [a, b, y], z).unwrap(),
                ))
                .unwrap();
        }
        map_succinct(&mut store, attached, a, &host());
        map_succinct(&mut store, attached, b, &host());
        let snapshot = store.snapshot().unwrap();
        let coverage = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()])).unwrap();
        assert_eq!(coverage.has_blocked(root.handle()), blocked);
        assert!(
            coverage.producers(root.handle(), z).is_empty(),
            "a blocked join names no producer of its result"
        );
        let read = snapshot.attached(attached).unwrap();
        assert_eq!(residual(&read), BTreeSet::from([z]));
        (members(read.cover()), residual(&read))
    }
    assert_eq!(read_with_join(true), read_with_join(false));
}

/// An absorption `MERGE(c, m) -> m` names its own result among its inputs:
/// descending an unattached `m` skips that self-edge and ends. A cycle of
/// host joins ends too.
#[test]
fn a_self_edge_and_a_cycle_terminate() {
    let (mut store, root, attached) = succinct_root("self-edge");
    let mut children = Vec::new();
    for byte in 1..=8u8 {
        children.push(commit(&mut store, root, row(byte, 2, 3)));
    }
    block_on(store.maintain(root, &host())).unwrap();
    let snapshot = store.snapshot().unwrap();
    let merged = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()]))
        .unwrap()
        .frontier(root.handle())
        .next()
        .unwrap();
    drop(snapshot);
    store
        .insert(CollectionRecord::Merge(
            CollectionMerge::sign(&host(), root.handle(), [children[0], merged], merged).unwrap(),
        ))
        .unwrap();
    let mut attachments = BTreeSet::new();
    for child in &children {
        attachments.insert(map_succinct(&mut store, attached, *child, &host()));
    }
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert_eq!(members(read.cover()), attachments);
    assert!(read.residual().is_empty());
    drop(snapshot);

    // A cycle of host joins over nodes without bytes: g joins f1 and f2, and
    // f2 claims to be the join of g and f1.
    let (mut store, root, attached) = succinct_root("cycle");
    let f1 = commit(&mut store, root, row(1, 1, 1));
    let f2 = commit(&mut store, root, row(2, 2, 2));
    let g: CollectionData = Inline::new([0x77; 32]);
    for (inputs, result) in [([f1, f2], g), ([g, f1], f2)] {
        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&host(), root.handle(), inputs, result).unwrap(),
            ))
            .unwrap();
    }
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert!(read.cover().is_empty());
    // The read terminates. What the parent stands on is the fold's answer:
    // every node of the cycle consumes another, so nothing is left for an
    // attachment to reach or to miss.
    let (believed, _) = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()]))
        .unwrap()
        .frontier_support(root.handle());
    assert_eq!(
        residual(&read),
        believed
            .iter_ordered()
            .map(|raw| Inline::new(*raw))
            .collect::<BTreeSet<CollectionData>>()
    );
    assert!(residual(&read).is_subset(&BTreeSet::from([f1, f2])));
}

/// A foundation without an attachment is the residual, named, whether its
/// bytes are here (read it raw, or build it) or not (a gap).
#[test]
fn a_foundation_without_an_attachment_is_the_residual() {
    let (mut store, root, attached) = succinct_root("residual");
    let here = commit(&mut store, root, row(1, 2, 3));
    // A commit record whose payload never arrived.
    let absent: CollectionData = Inline::new([0x55; 32]);
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &host(),
            root.handle(),
            absent,
            empty_metadata_handle(),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert!(read.cover().is_empty());
    assert_eq!(residual(&read), BTreeSet::from([here, absent]));
    assert!(snapshot
        .metadata(Handle::<SimpleArchive>::from_hash(here))
        .unwrap()
        .is_some());
    assert!(snapshot
        .metadata(Handle::<SimpleArchive>::from_hash(absent))
        .unwrap()
        .is_none());
    // Maintenance attaches what it holds and leaves the gap.
    let after = block_on(store.maintain_attached(attached, &host())).unwrap();
    let read = after.attached(attached).unwrap();
    assert_eq!(read.cover().len(), 1);
    assert_eq!(residual(&read), BTreeSet::from([absent]));
}

/// Supports and usability come from one observation: a MAP arriving, or an
/// attachment's bytes arriving, moves an attached read off current.
#[test]
fn a_map_or_attachment_bytes_arriving_moves_the_read_off_current() {
    let (mut store, root, attached) = succinct_root("current");
    let node = commit(&mut store, root, row(1, 2, 3));
    let before = store.snapshot().unwrap();
    let read = before.attached(attached).unwrap();
    assert!(read.is_current(&store.snapshot().unwrap()));

    // The MAP first, its bytes not yet here.
    let image = succinctarchive_union::derive_element(
        &before
            .get::<Blob<SimpleArchive>, _>(Handle::<SimpleArchive>::from_hash(node))
            .unwrap(),
    )
    .unwrap();
    store
        .insert(CollectionRecord::Map(CollectionMap::sign(
            &host(),
            attached.handle(),
            node,
            data(&image),
        )))
        .unwrap();
    let with_map = store.snapshot().unwrap();
    assert!(!read.is_current(&with_map));
    let read = with_map.attached(attached).unwrap();
    assert!(
        read.cover().is_empty(),
        "the attachment's bytes are not here"
    );
    assert!(read.is_current(&store.snapshot().unwrap()));

    store.put::<SuccinctArchiveBlob, _>(image).unwrap();
    let with_bytes = store.snapshot().unwrap();
    assert!(!read.is_current(&with_bytes));
    let read = with_bytes.attached(attached).unwrap();
    assert_eq!(read.cover().len(), 1);
    assert!(read.residual().is_empty());
}

/// A foundation no attachment reaches is the residual, which a reader may
/// read from its own bytes; those bytes arriving moves the read off current
/// even though no record changed.
#[test]
fn a_residual_foundations_bytes_arriving_moves_the_read_off_current() {
    let (mut store, root, attached) = succinct_root("residual");
    let payload: Blob<SimpleArchive> = row(4, 5, 6).to_blob();
    let node = data(&payload);
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &host(),
            root.handle(),
            node,
            empty_metadata_handle(),
        )))
        .unwrap();
    let before = store.snapshot().unwrap();
    let read = before.attached(attached).unwrap();
    assert_eq!(read.residual().len(), 1);
    assert!(read.is_current(&store.snapshot().unwrap()));

    store.put::<SimpleArchive, _>(payload).unwrap();
    assert!(!read.is_current(&store.snapshot().unwrap()));
}

/// A reader reads what no attachment reaches from its own bytes, and leaves
/// out a residual foundation whose bytes are not here.
#[test]
fn read_attached_reads_the_residual_from_its_bytes() {
    let (mut store, root, attached) = succinct_root("raw");
    let first = commit(&mut store, root, row(1, 2, 3));
    map_succinct(&mut store, attached, first, &host());
    commit(&mut store, root, row(4, 5, 6));
    let absent: Blob<SimpleArchive> = row(7, 8, 9).to_blob();
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &host(),
            root.handle(),
            data(&absent),
            empty_metadata_handle(),
        )))
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert_eq!(read.cover().len(), 1);
    assert_eq!(read.residual().len(), 2);
    let union = succinctarchive_union::read_attached(&read).unwrap();
    assert_eq!(union.segment_count(), 2, "the attachment and one raw read");
    let mut expected = row(1, 2, 3);
    expected += row(4, 5, 6);
    assert_eq!(union.iter().collect::<TribleSet>(), expected);
}

/// A COMMIT, DERIVE or MERGE aimed at an attached collection attests
/// nothing: it is dropped, not parked, and makes no row.
#[test]
fn a_commit_derive_or_merge_aimed_at_an_attached_handle_is_not_parked() {
    let (mut store, _root, attached) = succinct_root("aimed");
    let payload: Blob<SimpleArchive> = row(1, 2, 3).to_blob();
    let node = data(&payload);
    store.put::<SimpleArchive, _>(payload).unwrap();
    let other_node: CollectionData = Inline::new([0x42; 32]);
    for record in [
        CollectionRecord::Commit(CollectionCommit::sign(
            &host(),
            attached.handle(),
            node,
            empty_metadata_handle(),
        )),
        CollectionRecord::Derive(CollectionDerive::sign(
            &host(),
            attached.handle(),
            SourceLocator::of(node.raw),
            other_node,
        )),
        CollectionRecord::Merge(
            CollectionMerge::sign(&host(), attached.handle(), [node, other_node], node).unwrap(),
        ),
    ] {
        store.insert(record).unwrap();
    }
    let snapshot = store.snapshot().unwrap();
    let index = snapshot
        .index(&BTreeSet::from([attached.handle()]))
        .unwrap();
    assert_eq!(index.parked(), 0);
    assert_eq!(index.stored_joins(), 0);
    assert!(index.coverage(attached.handle(), node).is_none());
    assert!(index.coverage(attached.handle(), other_node).is_none());
    assert_eq!(index.published().frontier(attached.handle()).count(), 0);
}

/// A descriptor naming two parents is still attached: a COMMIT aimed at it
/// is dropped like one aimed at any attached collection, never parked
/// waiting for a descriptor that is already here. How many parents it names
/// is no question for the fold; a reader that walks one parent's lattice
/// declines to read it.
#[test]
fn a_descriptor_naming_two_parents_is_attached_and_parks_nothing() {
    use crate::collection::records::{
        collection_mapping, collection_parent, collection_representation,
        KIND_COLLECTION_DESCRIPTOR,
    };
    use crate::metadata::MetaDescribe;
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let first = store.collection("first-parent", policy()).unwrap();
    let second = store.collection("second-parent", policy()).unwrap();
    let descriptor = entity! {
        metadata::tag: KIND_COLLECTION_DESCRIPTOR,
        collection_parent*: [first.handle(), second.handle()],
        collection_representation*: <SuccinctArchiveBlob as MetaDescribe>::describe(),
        collection_mapping*: <SuccinctArchiveBlob as CollectionAttachment>::fragment(&()),
    };
    let handle = crate::collection::descriptor::put_closure(&mut store, &descriptor).unwrap();
    assert_eq!(
        crate::collection::descriptor::parents(descriptor.facts())
            .unwrap()
            .len(),
        2
    );
    let payload: Blob<SimpleArchive> = row(1, 2, 3).to_blob();
    let node = data(&payload);
    store.put::<SimpleArchive, _>(payload).unwrap();
    store
        .insert(CollectionRecord::Commit(CollectionCommit::sign(
            &host(),
            handle,
            node,
            empty_metadata_handle(),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let index = snapshot.index(&BTreeSet::from([handle])).unwrap();
    assert_eq!(index.parked(), 0);
    assert!(index.coverage(handle, node).is_none());
    let attached = Collection::<SuccinctArchiveBlob>::from_handle(handle);
    let refused = snapshot.attached(attached);
    assert!(matches!(
        refused,
        Err(CollectionRealizationError::InvalidCover(_))
    ));
}

/// One maintenance pass carries the parent before it attaches: eight
/// commits become one merge, and only that node is mapped.
#[test]
fn maintenance_attaches_the_frontier_the_carry_leaves() {
    let (mut store, root, attached) = succinct_root("post-carry");
    let mut expected = TribleSet::new();
    for byte in 1..=8u8 {
        expected += row(byte, 2, 3);
        commit(&mut store, root, row(byte, 2, 3));
    }
    let snapshot = block_on(store.maintain_attached(attached, &host())).unwrap();
    let maps: Vec<CollectionMap> = snapshot
        .select_records(&BTreeSet::from([
            crate::collection::CollectionRecordSelector::Collection(attached.handle()),
        ]))
        .unwrap()
        .into_iter()
        .filter_map(|record| match record {
            CollectionRecord::Map(map) => Some(map),
            _ => None,
        })
        .collect();
    assert_eq!(maps.len(), 1, "one MAP, for the merged node only");
    let merged = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()]))
        .unwrap()
        .frontier(root.handle())
        .collect::<Vec<_>>();
    assert_eq!(merged, vec![maps[0].node()]);
    assert_eq!(facts_of(&snapshot, attached), expected);
    // A fixed point: a second pass publishes nothing.
    let again = block_on(store.maintain_attached(attached, &host())).unwrap();
    assert_eq!(
        again.records().unwrap().count(),
        snapshot.records().unwrap().count()
    );
}

/// A key that is not the store's host cannot attach: its MAPs would be
/// believed nowhere here.
#[test]
fn attaching_with_a_key_that_is_not_the_host_is_an_error() {
    let (mut store, root, attached) = succinct_root("not-host");
    commit(&mut store, root, row(1, 2, 3));
    assert!(matches!(
        block_on(store.ensure_attached(attached, &other())),
        Err(CollectionRealizationError::HostMismatch { .. })
    ));
}

/// Rank9 reads the Succinct attachment its descriptor names: maintaining the
/// pair in order makes every fact readable through Rank9.
#[test]
fn rank9_is_built_from_the_named_succinct_attachment() {
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let root = store.collection("rank9-pair", policy()).unwrap();
    let succinct = store.attach::<SuccinctArchiveBlob>(root, ()).unwrap();
    let rank9 = store
        .attach::<Rank9AcceleratedSuccinctArchiveBlob>(root, succinct)
        .unwrap();
    let mut expected = TribleSet::new();
    for byte in 1..=3u8 {
        expected += row(byte, 6, 7);
        commit(&mut store, root, row(byte, 6, 7));
    }
    // Rank9 alone attaches nothing: the Succinct attachments it reads are
    // not there yet.
    let alone = block_on(store.ensure_attached(rank9, &host())).unwrap();
    assert!(alone.attached(rank9).unwrap().cover().is_empty());
    block_on(store.ensure_attached(succinct, &host())).unwrap();
    let snapshot = block_on(store.ensure_attached(rank9, &host())).unwrap();
    let read = snapshot.attached(rank9).unwrap();
    assert_eq!(read.cover().len(), 3);
    assert!(read.residual().is_empty());
    let view: UnionArchive<OrderedUniverse> = read.view().unwrap();
    assert_eq!(view.iter().collect::<TribleSet>(), expected);
}

/// An attached collection is found from the parent, each after the
/// siblings it reads, and the core realizer maintains the pair.
#[test]
fn attached_collections_are_found_from_their_parent_siblings_first() {
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let root = store.collection("upkeep", policy()).unwrap();
    let succinct = store.attach::<SuccinctArchiveBlob>(root, ()).unwrap();
    let rank9 = store
        .attach::<Rank9AcceleratedSuccinctArchiveBlob>(root, succinct)
        .unwrap();
    let node = commit(&mut store, root, row(1, 2, 3));
    // Discovery lists what holds a MAP; seed both.
    map_succinct(&mut store, succinct, node, &host());
    block_on(store.ensure_attached(rank9, &host())).unwrap();
    commit(&mut store, root, row(4, 5, 6));
    let snapshot = store.snapshot().unwrap();
    let found = crate::collection::attached_to(&snapshot, root.handle()).unwrap();
    assert_eq!(
        found
            .iter()
            .map(|attached| attached.handle)
            .collect::<Vec<_>>(),
        vec![succinct.handle(), rank9.handle()]
    );
    assert_eq!(found[1].siblings, vec![succinct.handle()]);
    drop(snapshot);
    let report = block_on(crate::collection::ensure_downstream(
        &mut store,
        root.handle(),
        &host(),
        &mut crate::collection::CoreRealizer,
    ))
    .unwrap();
    assert_eq!(report.realized, vec![succinct.handle(), rank9.handle()]);
    let read = store.snapshot().unwrap().attached(rank9).unwrap();
    assert!(read.residual().is_empty());
    assert_eq!(read.cover().len(), 2);
}

// ---------------------------------------------------------------------------
// Cover-query equivalence.
// ---------------------------------------------------------------------------

/// splitmix64: a deterministic stream for the property tests.
struct Stream(u64);

impl Stream {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0xA24B_AED4_963E_E407).wrapping_add(11))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// One random lattice of a hosted root: the committed fragments, the
/// host's carry or not, and extra host merges over random, possibly
/// overlapping nodes (an absorption, when one picked node covers another).
struct Lattice {
    store: MemoryRepo,
    root: Collection<SimpleArchive>,
    union: TribleSet,
}

fn lattice(name: &str, fragments: Vec<TribleSet>, random: &mut Stream) -> Lattice {
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let root = store.collection(name, policy()).unwrap();
    let mut union = TribleSet::new();
    for fragment in fragments {
        union += fragment.clone();
        store
            .commit(root, &host(), Fragment::from(fragment))
            .unwrap();
    }
    if random.below(2) == 0 {
        block_on(store.maintain(root, &host())).unwrap();
    }
    for _ in 0..random.below(4) {
        let snapshot = store.snapshot().unwrap();
        let nodes = lattice_nodes(&snapshot, root);
        if nodes.len() < 2 {
            break;
        }
        let picked: BTreeSet<CollectionData> = (0..2 + random.below(2))
            .map(|_| nodes[random.below(nodes.len() as u64) as usize])
            .collect();
        if picked.len() < 2 {
            continue;
        }
        let blobs: Vec<Blob<SimpleArchive>> = picked
            .iter()
            .map(|node| {
                snapshot
                    .get(Handle::<SimpleArchive>::from_hash(*node))
                    .unwrap()
            })
            .collect();
        drop(snapshot);
        let joined = blobs.iter().skip(1).fold(blobs[0].clone(), |joined, blob| {
            simplearchive_union::join(&joined, blob).unwrap()
        });
        let result = data(&joined);
        store.put::<SimpleArchive, _>(joined).unwrap();
        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(&host(), root.handle(), picked, result).unwrap(),
            ))
            .unwrap();
    }
    Lattice { store, root, union }
}

/// Every believed node of `root`: the frontier and everything the host's
/// joins name beneath it.
fn lattice_nodes<R: StoreRead>(
    snapshot: &R,
    root: Collection<SimpleArchive>,
) -> Vec<CollectionData> {
    let coverage = CoverageRead::coverage(&snapshot, &BTreeSet::from([root.handle()])).unwrap();
    let mut seen = BTreeSet::new();
    let mut pending: Vec<CollectionData> = coverage.frontier(root.handle()).collect();
    while let Some(node) = pending.pop() {
        if !seen.insert(node) {
            continue;
        }
        for inputs in coverage.producers(root.handle(), node) {
            pending.extend(inputs.iter());
        }
    }
    seen.into_iter().collect()
}

/// Builds the attachment of one node's bytes and stores it, together with
/// anything it needs resident (a Rank9 attachment's raw child).
type Build<T> = fn(&mut MemoryRepo, &Blob<SimpleArchive>) -> Inline<Handle<T>>;

/// Attach `lattice`'s nodes at random, read the attached cover, build the
/// residual in memory, and return that cover beside the cover of the
/// union's single image, both over `attached`.
fn covers<T>(
    lattice: &mut Lattice,
    attached: Collection<T>,
    build: Build<T>,
    random: &mut Stream,
) -> (Cover<T>, Cover<T>)
where
    T: CollectionEncoding,
{
    let snapshot = lattice.store.snapshot().unwrap();
    let nodes = lattice_nodes(&snapshot, lattice.root);
    drop(snapshot);
    for node in nodes {
        if random.below(3) == 0 {
            continue;
        }
        let snapshot = lattice.store.snapshot().unwrap();
        let bytes: Blob<SimpleArchive> = snapshot
            .get(Handle::<SimpleArchive>::from_hash(node))
            .unwrap();
        drop(snapshot);
        let attachment = build(&mut lattice.store, &bytes);
        lattice
            .store
            .insert(CollectionRecord::Map(CollectionMap::sign(
                &host(),
                attached.handle(),
                node,
                Handle::<T>::to_hash(attachment),
            )))
            .unwrap();
    }
    let snapshot = lattice.store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    let mut members: Vec<Inline<Handle<T>>> = read.cover().members().collect();
    let residual: Vec<_> = read.residual().members().collect();
    drop(read);
    for foundation in residual {
        let bytes: Blob<SimpleArchive> = snapshot.get(foundation).unwrap();
        members.push(build(&mut lattice.store, &bytes));
    }
    drop(snapshot);
    let union = build(&mut lattice.store, &lattice.union.clone().to_blob());
    (attached.cover(members), attached.cover([union]))
}

fn view<T, V>(store: &mut MemoryRepo, attached: Collection<T>, cover: &Cover<T>) -> V
where
    T: CollectionEncoding,
    V: TryFromCover<T>,
{
    let snapshot = store.snapshot().unwrap();
    let descriptor: TribleSet = snapshot.get(attached.handle()).unwrap();
    V::try_from_cover(cover, &Fragment::from(descriptor), &snapshot).unwrap()
}

fn random_rows(random: &mut Stream, entities: u8) -> Vec<TribleSet> {
    (0..2 + random.below(20))
        .map(|_| {
            let mut facts = TribleSet::new();
            for _ in 0..1 + random.below(4) {
                facts += row(
                    1 + random.below(entities as u64) as u8,
                    1 + random.below(3) as u8,
                    random.below(4) as u8,
                );
            }
            facts
        })
        .collect()
}

#[test]
fn succinct_covers_answer_like_the_union() {
    fn build(
        store: &mut MemoryRepo,
        bytes: &Blob<SimpleArchive>,
    ) -> Inline<Handle<SuccinctArchiveBlob>> {
        let snapshot = store.snapshot().unwrap();
        let image =
            <SuccinctArchiveBlob as CollectionAttachment>::map(&(), bytes, &[], &snapshot).unwrap();
        drop(snapshot);
        store.put::<SuccinctArchiveBlob, _>(image).unwrap()
    }
    for seed in 0..24 {
        let mut random = Stream::new(seed);
        let fragments = random_rows(&mut random, 8);
        let mut lattice = lattice(&format!("succinct-{seed}"), fragments, &mut random);
        let attached = lattice
            .store
            .attach::<SuccinctArchiveBlob>(lattice.root, ())
            .unwrap();
        let (cover, union) = covers(&mut lattice, attached, build, &mut random);
        let through_cover: UnionArchive<OrderedUniverse> =
            view(&mut lattice.store, attached, &cover);
        let through_union: UnionArchive<OrderedUniverse> =
            view(&mut lattice.store, attached, &union);
        assert_eq!(
            through_cover.iter().collect::<TribleSet>(),
            through_union.iter().collect::<TribleSet>(),
            "seed {seed}"
        );
    }
}

#[test]
fn rank9_covers_answer_like_the_union() {
    fn build(
        store: &mut MemoryRepo,
        bytes: &Blob<SimpleArchive>,
    ) -> Inline<Handle<Rank9AcceleratedSuccinctArchiveBlob>> {
        let raw = succinctarchive_union::derive_element(bytes).unwrap();
        let raw = Handle::<SuccinctArchiveBlob>::to_hash(
            store.put::<SuccinctArchiveBlob, _>(raw).unwrap(),
        );
        let snapshot = store.snapshot().unwrap();
        // The sibling handle is only named, never read, by the mapping.
        let sibling = Collection::from_handle(Inline::new([0; 32]));
        let image = <Rank9AcceleratedSuccinctArchiveBlob as CollectionAttachment>::map(
            &sibling,
            bytes,
            &[raw],
            &snapshot,
        )
        .unwrap();
        drop(snapshot);
        store
            .put::<Rank9AcceleratedSuccinctArchiveBlob, _>(image)
            .unwrap()
    }
    for seed in 0..16 {
        let mut random = Stream::new(seed + 100);
        let fragments = random_rows(&mut random, 8);
        let mut lattice = lattice(&format!("rank9-{seed}"), fragments, &mut random);
        let succinct = lattice
            .store
            .attach::<SuccinctArchiveBlob>(lattice.root, ())
            .unwrap();
        let attached = lattice
            .store
            .attach::<Rank9AcceleratedSuccinctArchiveBlob>(lattice.root, succinct)
            .unwrap();
        let (cover, union) = covers(&mut lattice, attached, build, &mut random);
        let through_cover: UnionArchive<OrderedUniverse> =
            view(&mut lattice.store, attached, &cover);
        let through_union: UnionArchive<OrderedUniverse> =
            view(&mut lattice.store, attached, &union);
        assert_eq!(
            through_cover.iter().collect::<TribleSet>(),
            through_union.iter().collect::<TribleSet>(),
            "seed {seed}"
        );
    }
}

fn state_of() -> Attribute<GenId> {
    Attribute::named("attached-test-state-of")
}

fn written_at() -> Attribute<NsTAIInterval> {
    Attribute::named("attached-test-written-at")
}

fn at(nanos: i128) -> Inline<NsTAIInterval> {
    let bound = i128_to_ordered_be(nanos);
    let mut raw = [0u8; 32];
    raw[0..16].copy_from_slice(&bound);
    raw[16..32].copy_from_slice(&bound);
    Inline::new(raw)
}

fn lww_identity(state: Id, register: Id) -> TribleSet {
    let register: Inline<GenId> = crate::inline::IntoInline::to_inline(register);
    [Trible::force(&state, &state_of().id(), &register)]
        .into_iter()
        .collect()
}

fn lww_order(state: Id, nanos: i128) -> TribleSet {
    [Trible::force(&state, &written_at().id(), &at(nanos))]
        .into_iter()
        .collect()
}

fn build_lww(
    store: &mut MemoryRepo,
    bytes: &Blob<SimpleArchive>,
) -> Inline<Handle<LwwRegisterBlob>> {
    let snapshot = store.snapshot().unwrap();
    let image = <LwwRegisterBlob as CollectionAttachment>::map(
        &(state_of().id(), written_at().id()),
        bytes,
        &[],
        &snapshot,
    )
    .unwrap();
    drop(snapshot);
    store.put::<LwwRegisterBlob, _>(image).unwrap()
}

#[test]
fn lww_covers_answer_like_the_union() {
    for seed in 0..24 {
        let mut random = Stream::new(seed + 200);
        // Each state's identity and order land in independent commits, so
        // rows split between nodes, some attached and some raw.
        let mut fragments = Vec::new();
        for state in 1..=(2 + random.below(10) as u8) {
            let register = id(100 + random.below(3) as u8);
            let mut identity = lww_identity(id(state), register);
            let mut order = lww_order(id(state), (state as i128) * 10);
            if random.below(2) == 0 {
                identity += order;
                order = TribleSet::new();
            }
            fragments.push(identity);
            if !order.is_empty() {
                fragments.push(order);
            }
        }
        let mut lattice = lattice(&format!("lww-{seed}"), fragments, &mut random);
        let attached = lattice
            .store
            .attach::<LwwRegisterBlob>(lattice.root, (state_of().id(), written_at().id()))
            .unwrap();
        let (cover, union) = covers(&mut lattice, attached, build_lww, &mut random);
        let through_cover: LwwIndex = view(&mut lattice.store, attached, &cover);
        let through_union: LwwIndex = view(&mut lattice.store, attached, &union);
        assert_eq!(
            through_cover.query().unwrap(),
            through_union.query().unwrap(),
            "seed {seed}"
        );
    }
}

/// The named case: a register's identity in an attached node, its order in
/// a raw one, paired across the cover.
#[test]
fn lww_rows_split_between_an_attachment_and_a_raw_member_pair_up() {
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let root = store.collection("lww-split", policy()).unwrap();
    let attached = store
        .attach::<LwwRegisterBlob>(root, (state_of().id(), written_at().id()))
        .unwrap();
    let state = id(1);
    let register = id(2);
    let identity = store
        .commit(root, &host(), Fragment::from(lww_identity(state, register)))
        .unwrap()
        .data();
    store
        .commit(root, &host(), Fragment::from(lww_order(state, 42)))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let bytes: Blob<SimpleArchive> = snapshot
        .get(Handle::<SimpleArchive>::from_hash(identity))
        .unwrap();
    drop(snapshot);
    let attachment = build_lww(&mut store, &bytes);
    store
        .insert(CollectionRecord::Map(CollectionMap::sign(
            &host(),
            attached.handle(),
            identity,
            Handle::<LwwRegisterBlob>::to_hash(attachment),
        )))
        .unwrap();
    let snapshot = store.snapshot().unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert_eq!(read.cover().len(), 1);
    let raw: Vec<_> = read.residual().members().collect();
    assert_eq!(raw.len(), 1);
    let raw_bytes: Blob<SimpleArchive> = snapshot.get(raw[0]).unwrap();
    drop(read);
    drop(snapshot);
    let built = build_lww(&mut store, &raw_bytes);
    let cover = attached.cover([attachment, built]);
    let index: LwwIndex = view(&mut store, attached, &cover);
    let query = index.query().unwrap();
    assert_eq!(query.winner(register), Some(state));
    assert!(query.contains(state));
}

fn build_latest(store: &mut MemoryRepo, bytes: &Blob<SimpleArchive>) -> Inline<Handle<LatestBlob>> {
    let snapshot = store.snapshot().unwrap();
    let image = <LatestBlob as CollectionAttachment>::map(
        &metadata::supersedes.id(),
        bytes,
        &[],
        &snapshot,
    )
    .unwrap();
    drop(snapshot);
    store.put::<LatestBlob, _>(image).unwrap()
}

fn supersedes(newer: u8, older: u8) -> TribleSet {
    let newer = id(newer);
    entity! { ExclusiveId::force_ref(&newer) @ metadata::supersedes: id(older) }.into_facts()
}

fn exists(state: u8) -> TribleSet {
    let state = id(state);
    entity! { ExclusiveId::force_ref(&state) @ metadata::tag: id(200) }.into_facts()
}

#[test]
fn latest_covers_answer_like_the_union() {
    for seed in 0..24 {
        let mut random = Stream::new(seed + 300);
        let fragments: Vec<TribleSet> = (0..2 + random.below(16))
            .map(|_| {
                let a = 1 + random.below(10) as u8;
                if random.below(2) == 0 {
                    exists(a)
                } else {
                    supersedes(a, 1 + random.below(10) as u8)
                }
            })
            .collect();
        let mut lattice = lattice(&format!("latest-{seed}"), fragments, &mut random);
        let attached = lattice
            .store
            .attach::<LatestBlob>(lattice.root, metadata::supersedes.id())
            .unwrap();
        let (cover, union) = covers(&mut lattice, attached, build_latest, &mut random);
        let through_cover: LatestIndex = view(&mut lattice.store, attached, &cover);
        let through_union: LatestIndex = view(&mut lattice.store, attached, &union);
        assert_eq!(
            through_cover.states().collect::<BTreeSet<_>>(),
            through_union.states().collect::<BTreeSet<_>>(),
            "seed {seed}"
        );
    }
}

/// The named case: a state live in one node and retired in another stays
/// retired across the cover.
#[test]
fn latest_retirement_in_one_node_and_live_state_in_another() {
    let mut store = MemoryRepo::for_host(host().verifying_key());
    let root = store.collection("latest-split", policy()).unwrap();
    let attached = store
        .attach::<LatestBlob>(root, metadata::supersedes.id())
        .unwrap();
    store
        .commit(root, &host(), Fragment::from(exists(1)))
        .unwrap();
    store
        .commit(root, &host(), Fragment::from(supersedes(2, 1)))
        .unwrap();
    let snapshot = block_on(store.ensure_attached(attached, &host())).unwrap();
    let read = snapshot.attached(attached).unwrap();
    assert_eq!(read.cover().len(), 2);
    let index: LatestIndex = read.view().unwrap();
    assert_eq!(
        index.states().collect::<BTreeSet<_>>(),
        BTreeSet::from([id(2)])
    );
}

#[test]
fn entity_id_set_covers_answer_like_the_union() {
    fn build(
        store: &mut MemoryRepo,
        bytes: &Blob<SimpleArchive>,
    ) -> Inline<Handle<EntityIdSetBlob>> {
        let snapshot = store.snapshot().unwrap();
        let image = <EntityIdSetBlob as CollectionAttachment>::map(
            &metadata::supersedes.id(),
            bytes,
            &[],
            &snapshot,
        )
        .unwrap();
        drop(snapshot);
        store.put::<EntityIdSetBlob, _>(image).unwrap()
    }
    for seed in 0..24 {
        let mut random = Stream::new(seed + 400);
        let fragments: Vec<TribleSet> = (0..2 + random.below(16))
            .map(|_| supersedes(1 + random.below(10) as u8, 1 + random.below(10) as u8))
            .collect();
        let mut lattice = lattice(&format!("ids-{seed}"), fragments, &mut random);
        let attached = lattice
            .store
            .attach::<EntityIdSetBlob>(lattice.root, metadata::supersedes.id())
            .unwrap();
        let (cover, union) = covers(&mut lattice, attached, build, &mut random);
        let through_cover: EntityIdSet = view(&mut lattice.store, attached, &cover);
        let through_union: EntityIdSet = view(&mut lattice.store, attached, &union);
        assert_eq!(
            through_cover.iter().collect::<BTreeSet<_>>(),
            through_union.iter().collect::<BTreeSet<_>>(),
            "seed {seed}"
        );
    }
}
