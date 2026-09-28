//! Attached-collection lifecycle tests for regular-path summaries.

#![cfg(test)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::executor::block_on;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::{Blob, IntoBlob, TryFromBlob};
use triblespace_core::collection::simplearchive_union;
use triblespace_core::collection::{
    Collection, CollectionAttachment, CollectionData, CollectionMap, CollectionMerge,
    CollectionPolicy, CollectionRead, CollectionRecord, CollectionSnapshotExt, CollectionStore,
    CollectionStoreExt, TryFromCover,
};
use triblespace_core::id::ExclusiveId;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::{Inline, RawInline};
use triblespace_core::metadata;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
use triblespace_core::trible::{Fragment, TribleSet};

use crate::{Automaton, PathIndex, PathSummaryBlob, Step, Transition};

fn id(byte: u8) -> triblespace_core::id::Id {
    triblespace_core::id::Id::new([byte; 16]).unwrap()
}

fn host_key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

fn policy(authority: VerifyingKey) -> CollectionPolicy {
    CollectionPolicy::new(
        triblespace_core::collection::AdmissionPolicy::direct(authority),
        triblespace_core::collection::AdmissionPolicy::direct(authority),
    )
}

fn plus() -> Automaton {
    Automaton::new(
        2,
        [0],
        [1],
        [
            Transition::new(0, 1, Step::Forward(metadata::tag.id().into())),
            Transition::new(1, 1, Step::Forward(metadata::tag.id().into())),
        ],
    )
    .unwrap()
}

fn edge(source: u8, target: u8) -> TribleSet {
    let source = id(source);
    entity! { ExclusiveId::force_ref(&source) @ metadata::tag: id(target) }.into_facts()
}

/// A store hosted by the maintaining key, a root and its path summary.
fn attached_paths(
    name: &str,
) -> (
    MemoryRepo,
    Collection<SimpleArchive>,
    Collection<PathSummaryBlob>,
) {
    let key = host_key();
    let mut store = MemoryRepo::for_host(key.verifying_key());
    let root = store.collection(name, policy(key.verifying_key())).unwrap();
    let target = store.attach::<PathSummaryBlob>(root, plus()).unwrap();
    (store, root, target)
}

fn descriptor_for<L>(store: &mut MemoryRepo, collection: Collection<L>) -> Fragment
where
    L: triblespace_core::collection::CollectionEncoding,
{
    let snapshot = store.snapshot().unwrap();
    let blob: Blob<SimpleArchive> = snapshot.get(collection.handle()).unwrap();
    Fragment::from(TribleSet::try_from_blob(blob).unwrap())
}

fn maps(store: &mut MemoryRepo, collection: Collection<PathSummaryBlob>) -> usize {
    store
        .snapshot()
        .unwrap()
        .records()
        .unwrap()
        .map(Result::unwrap)
        .filter(|record| {
            matches!(record, CollectionRecord::Map(map) if map.collection() == collection.handle())
        })
        .count()
}

#[test]
fn an_attached_summary_names_its_parent_and_carries_no_policy() {
    let (mut store, root, target) = attached_paths("edges");
    let descriptor = descriptor_for(&mut store, target);
    assert_eq!(
        triblespace_core::collection::descriptor::parent(descriptor.facts()),
        Ok(Some(root.handle()))
    );
    assert_eq!(
        triblespace_core::collection::descriptor::capability_policies(descriptor.facts(), None)
            .count(),
        0
    );
    let root_descriptor = descriptor_for(&mut store, root);
    assert_eq!(
        <PathSummaryBlob as CollectionAttachment>::bind(&root_descriptor, &descriptor).unwrap(),
        plus()
    );
}

#[test]
fn an_empty_parent_is_bottom_and_maintenance_writes_nothing() {
    let (mut store, _root, target) = attached_paths("empty-edges");
    let snapshot = block_on(store.maintain_attached(target, &host_key())).unwrap();
    assert_eq!(maps(&mut store, target), 0);
    let attached = snapshot.attached(target).unwrap();
    assert!(attached.cover().is_empty());
    assert!(attached.residual().is_empty());
    let index: Arc<PathIndex> = attached.view().unwrap();
    assert_eq!(index.accepted_pair_count(), 0);
}

#[test]
fn a_path_across_two_nodes_closes_over_the_attached_cover() {
    let (mut store, root, target) = attached_paths("split-edges");
    let key = host_key();
    for (source, target_vertex) in [(1, 2), (2, 3)] {
        store
            .commit(root, &key, Fragment::from(edge(source, target_vertex)))
            .unwrap();
    }
    let snapshot = block_on(store.ensure_attached(target, &key)).unwrap();
    assert_eq!(maps(&mut store, target), 2);
    let attached = snapshot.attached(target).unwrap();
    assert_eq!(attached.cover().len(), 2);
    let index: Arc<PathIndex> = attached.view().unwrap();
    assert!(index.contains(&RawInline::from(id(1)), &RawInline::from(id(3))));
    // A second pass has nothing to attach.
    block_on(store.ensure_attached(target, &key)).unwrap();
    assert_eq!(maps(&mut store, target), 2);
}

#[test]
fn a_merged_node_is_attached_once_after_the_carry() {
    let (mut store, root, target) = attached_paths("chain-edges");
    let key = host_key();
    for step in 1..=8u8 {
        store
            .commit(root, &key, Fragment::from(edge(step, step + 1)))
            .unwrap();
    }
    // One pass: the eight commits are carried into one merge, and only that
    // node is attached.
    let snapshot = block_on(store.maintain_attached(target, &key)).unwrap();
    assert_eq!(maps(&mut store, target), 1);
    let attached = snapshot.attached(target).unwrap();
    assert_eq!(attached.cover().len(), 1);
    assert_eq!(attached.support().len(), 8);
    let index: Arc<PathIndex> = attached.view().unwrap();
    assert!(index.contains(&RawInline::from(id(1)), &RawInline::from(id(9))));
}

/// splitmix64: a deterministic stream for the property test.
struct Stream(u64);

impl Stream {
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

/// Every believed node of `root`'s lattice: the frontier and everything the
/// host's joins name beneath it.
fn lattice_nodes<R: triblespace_core::repo::StoreRead>(
    snapshot: &R,
    root: Collection<SimpleArchive>,
) -> Vec<CollectionData> {
    let coverage = snapshot.coverage(&BTreeSet::from([root.handle()])).unwrap();
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

/// Cover-query equivalence: over random lattices (commits, the host's carry,
/// extra host merges with overlapping inputs, absorptions) and random
/// attachment presence, the paths the attached cover closes -- with the
/// residual built in memory -- are exactly the paths of the summary of the
/// union of every foundation.
#[test]
fn attached_covers_answer_like_the_summary_of_the_union() {
    for seed in 0..24u64 {
        let mut random = Stream(seed.wrapping_mul(0x51D7_348D_A7C9_2E11) + 7);
        let (mut store, root, target) = attached_paths(&format!("random-{seed}"));
        let key = host_key();
        let automaton = plus();
        let commits = 2 + random.below(18) as usize;
        let mut union = TribleSet::new();
        for _ in 0..commits {
            let mut facts = TribleSet::new();
            for _ in 0..1 + random.below(3) {
                facts += edge(1 + random.below(6) as u8, 1 + random.below(6) as u8);
            }
            union += facts.clone();
            store.commit(root, &key, Fragment::from(facts)).unwrap();
        }
        if random.below(2) == 0 {
            block_on(store.maintain(root, &key)).unwrap();
        }
        // Host merges over random, possibly overlapping, nodes, and
        // absorptions of a node into one that already covers it.
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
            let result = store.put::<SimpleArchive, _>(joined).unwrap();
            store
                .insert(CollectionRecord::Merge(
                    CollectionMerge::sign(
                        &key,
                        root.handle(),
                        picked.iter().copied(),
                        Handle::<SimpleArchive>::to_hash(result),
                    )
                    .unwrap(),
                ))
                .unwrap();
        }
        // Random attachment presence, at any node.
        let snapshot = store.snapshot().unwrap();
        for node in lattice_nodes(&snapshot, root) {
            if random.below(2) == 0 {
                continue;
            }
            let bytes: Blob<SimpleArchive> = snapshot
                .get(Handle::<SimpleArchive>::from_hash(node))
                .unwrap();
            let image =
                <PathSummaryBlob as CollectionAttachment>::map(&automaton, &bytes, &[], &snapshot)
                    .unwrap();
            let attachment = store.put::<PathSummaryBlob, _>(image).unwrap();
            store
                .insert(CollectionRecord::Map(CollectionMap::sign(
                    &key,
                    target.handle(),
                    node,
                    Handle::<PathSummaryBlob>::to_hash(attachment),
                )))
                .unwrap();
        }
        drop(snapshot);

        let snapshot = store.snapshot().unwrap();
        let attached = snapshot.attached(target).unwrap();
        let mut members: Vec<Inline<Handle<PathSummaryBlob>>> =
            attached.cover().members().collect();
        // The residual, built in memory from the parent's own nodes.
        let residual: Vec<_> = attached.residual().members().collect();
        drop(attached);
        drop(snapshot);
        for foundation in residual {
            let snapshot = store.snapshot().unwrap();
            let bytes: Blob<SimpleArchive> = snapshot.get(foundation).unwrap();
            let image =
                <PathSummaryBlob as CollectionAttachment>::map(&automaton, &bytes, &[], &snapshot)
                    .unwrap();
            drop(snapshot);
            members.push(store.put::<PathSummaryBlob, _>(image).unwrap());
        }
        let expected_image = <PathSummaryBlob as CollectionAttachment>::map(
            &automaton,
            &union.to_blob(),
            &[],
            &store.snapshot().unwrap(),
        )
        .unwrap();
        let expected_member = store.put::<PathSummaryBlob, _>(expected_image).unwrap();

        let descriptor = descriptor_for(&mut store, target);
        let snapshot = store.snapshot().unwrap();
        let through_cover: Arc<PathIndex> =
            TryFromCover::try_from_cover(&target.cover(members), &descriptor, &snapshot).unwrap();
        let through_union: Arc<PathIndex> =
            TryFromCover::try_from_cover(&target.cover([expected_member]), &descriptor, &snapshot)
                .unwrap();
        let pairs = |index: &PathIndex| {
            let mut pairs = BTreeSet::new();
            for source in 1..=6u8 {
                for sink in 1..=6u8 {
                    if index.contains(&RawInline::from(id(source)), &RawInline::from(id(sink))) {
                        pairs.insert((source, sink));
                    }
                }
            }
            pairs
        };
        assert_eq!(
            pairs(&through_cover),
            pairs(&through_union),
            "seed {seed}: a cover of attachments must answer like the union"
        );
    }
}
