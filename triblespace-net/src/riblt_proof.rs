//! Canonical native summary of a typed PATCH union a sparse key-only PATCH.
//! Only overlapping trie paths are visited. Unchanged native subtrees contribute
//! their cached summaries, not a second full key inventory or fake typed values.

use crate::patch_repair::PatchSummary;
use triblespace_core::patch::{Blake3Merkle, IdentitySchema, PATCH, PATCHMerkleNode, PatchHash};

pub(crate) fn union_summary<const N: usize, V>(
    source: &PATCH<N, IdentitySchema, V, Blake3Merkle>,
    additions: &PATCH<N, IdentitySchema, (), Blake3Merkle>,
) -> PatchSummary {
    match (source.merkle_node(&[]), additions.merkle_node(&[])) {
        (None, None) => PatchSummary::new(None, 0).unwrap(),
        (Some(node), None) => summary(node),
        (None, Some(node)) => summary(node),
        (Some(left), Some(right)) => merge(left, right),
    }
}

fn summary<const N: usize, V>(node: PATCHMerkleNode<'_, N, V>) -> PatchSummary {
    PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap()
}

fn merge<const N: usize, V>(
    left: PATCHMerkleNode<'_, N, V>,
    right: PATCHMerkleNode<'_, N, ()>,
) -> PatchSummary {
    if summary(left) == summary(right) {
        return summary(left);
    }
    let a = left.prefix();
    let b = right.prefix();
    let depth = a.iter().zip(b).take_while(|(a, b)| a == b).count();
    // Equal full keys were covered by the equal native summaries above.
    assert!(depth < N);
    let a: Vec<_> = if a.len() == depth {
        left.children().collect()
    } else {
        vec![(a[depth], left)]
    };
    let b: Vec<_> = if b.len() == depth {
        right.children().collect()
    } else {
        vec![(b[depth], right)]
    };
    let mut children = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        match (a.get(i), b.get(j)) {
            (Some((ae, an)), Some((be, bn))) if ae == be => {
                children.push((*ae, merge(*an, *bn)));
                i += 1;
                j += 1;
            }
            (Some((ae, an)), Some((be, _))) if ae < be => {
                children.push((*ae, summary(*an)));
                i += 1;
            }
            (Some((ae, an)), None) => {
                children.push((*ae, summary(*an)));
                i += 1;
            }
            (_, Some((be, bn))) => {
                children.push((*be, summary(*bn)));
                j += 1;
            }
            _ => unreachable!(),
        }
    }
    let count = children.iter().map(|(_, child)| child.leaf_count()).sum();
    let mut representative = [0; N];
    representative[..depth].copy_from_slice(&left.prefix()[..depth]);
    let order: Vec<_> = (0..N).collect();
    let mut state =
        Blake3Merkle::begin_branch(&representative, &order, depth, children.len(), count);
    for (edge, child) in children {
        Blake3Merkle::push_child(&mut state, edge, child.leaf_count(), child.root().unwrap());
    }
    PatchSummary::new(Some(Blake3Merkle::finish_branch(state)), count).unwrap()
}
