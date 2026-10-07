//! Overlay-neutral, root-and-count-proven PATCH nodes.
//!
//! A [`PatchSummary`] pins one immutable trie. A node of it travels as a
//! [`PatchNode`], read from the pinned PATCH by [`patch_node_response`] and
//! checked at the other end by [`validate_patch_node`] against the
//! [`PatchRepairRequest`] that authenticates it: the root, or a child of a
//! branch accepted before. A receiver discharges a subtree it holds only
//! when both digest and leaf count agree; compressed paths need not line up
//! between peers.

use anyhow::{Result, anyhow, bail};

use triblespace_core::patch::{Blake3Merkle, IdentitySchema, PATCH, PatchHash};

/// Canonical root and exact leaf count of one immutable PATCH snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PatchSummary {
    root: Option<[u8; 32]>,
    leaf_count: u64,
}

impl PatchSummary {
    /// Construct one summary, rejecting the only impossible empty/nonempty
    /// combinations.
    pub fn new(root: Option<[u8; 32]>, leaf_count: u64) -> Result<Self> {
        if root.is_none() != (leaf_count == 0) {
            bail!("PATCH root and leaf count disagree");
        }
        Ok(Self { root, leaf_count })
    }

    /// Summarize an immutable canonical BLAKE3 PATCH.
    pub fn from_patch<const KEY_LEN: usize, V>(
        patch: &PATCH<KEY_LEN, IdentitySchema, V, Blake3Merkle>,
    ) -> Self {
        Self {
            root: patch.merkle_root(),
            leaf_count: patch.len(),
        }
    }

    /// Canonical Merkle root; `None` is the unique empty set.
    pub const fn root(self) -> Option<[u8; 32]> {
        self.root
    }

    /// Exact number of leaves committed by the root.
    pub const fn leaf_count(self) -> u64 {
        self.leaf_count
    }
}

/// Exact locator for one node under a pinned PATCH summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PatchRepairRequest {
    summary: PatchSummary,
    /// Prefix relative to the caller-selected PATCH base.
    prefix: Vec<u8>,
    /// Digest authenticated by the root or a previously accepted branch.
    expected_digest: [u8; 32],
}

impl PatchRepairRequest {
    pub(crate) fn new(
        summary: PatchSummary,
        relative_key_len: usize,
        prefix: Vec<u8>,
        expected_digest: [u8; 32],
    ) -> Result<Self> {
        let root = summary
            .root()
            .ok_or_else(|| anyhow!("a PATCH node request cannot pin an empty summary"))?;
        if prefix.len() > relative_key_len {
            bail!(
                "PATCH prefix is {} bytes; relative key is {relative_key_len} bytes",
                prefix.len()
            );
        }
        if prefix.is_empty() && expected_digest != root {
            bail!("PATCH root request digest does not match its pinned root");
        }
        Ok(Self {
            summary,
            prefix,
            expected_digest,
        })
    }

    pub(crate) const fn summary(&self) -> PatchSummary {
        self.summary
    }

    pub(crate) fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    pub(crate) const fn expected_digest(&self) -> [u8; 32] {
        self.expected_digest
    }
}

/// One canonical PATCH leaf. The key is relative to the selected base.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PatchLeaf<V> {
    pub(crate) key: Vec<u8>,
    pub(crate) value: V,
}

/// Authenticated summary of one child edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PatchChild {
    pub(crate) edge: u8,
    pub(crate) digest: [u8; 32],
    pub(crate) leaf_count: u64,
}

/// One canonical compressed PATCH branch, relative to the selected base.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PatchBranch {
    pub(crate) representative: Vec<u8>,
    pub(crate) end_depth: u8,
    pub(crate) children: Vec<PatchChild>,
}

/// One authenticated PATCH node returned by a repair peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PatchNode<V> {
    Leaf {
        digest: [u8; 32],
        leaf: PatchLeaf<V>,
    },
    Branch {
        digest: [u8; 32],
        leaf_count: u64,
        branch: PatchBranch,
    },
}

impl<V> PatchNode<V> {
    pub(crate) const fn digest(&self) -> [u8; 32] {
        match self {
            Self::Leaf { digest, .. } | Self::Branch { digest, .. } => *digest,
        }
    }

    pub(crate) const fn leaf_count(&self) -> u64 {
        match self {
            Self::Leaf { .. } => 1,
            Self::Branch { leaf_count, .. } => *leaf_count,
        }
    }
}

/// Result of looking up one node in a pinned PATCH snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PatchNodeResponse<V> {
    Found(PatchNode<V>),
    /// No node exists at a locator authenticated by an earlier branch.
    PrefixAbsent,
}

/// Construct a protocol-neutral node response from one immutable PATCH.
///
/// `base` is a fixed prefix omitted from the repair protocol (for example a
/// team prefix in the legacy inventory). Both the returned key and compressed
/// branch depth are relative to it.
pub(crate) fn patch_node_response<const KEY_LEN: usize, V, W>(
    patch: &PATCH<KEY_LEN, IdentitySchema, V, Blake3Merkle>,
    base: &[u8],
    relative_prefix: &[u8],
    resolve: impl FnOnce([u8; KEY_LEN], &V) -> Result<W>,
) -> Result<PatchNodeResponse<W>> {
    if base.len() > KEY_LEN || relative_prefix.len() > KEY_LEN - base.len() {
        bail!("PATCH prefix is outside its selected base");
    }
    let mut absolute_prefix = Vec::with_capacity(base.len() + relative_prefix.len());
    absolute_prefix.extend_from_slice(base);
    absolute_prefix.extend_from_slice(relative_prefix);
    let Some(node) = patch.merkle_node(&absolute_prefix) else {
        return Ok(PatchNodeResponse::PrefixAbsent);
    };

    let digest = node.digest();
    if node.is_leaf() {
        let absolute = *node.representative();
        let value = patch
            .get(&absolute)
            .ok_or_else(|| anyhow!("PATCH Merkle leaf has no matching value"))?;
        let value = resolve(absolute, value)?;
        let key = absolute
            .strip_prefix(base)
            .ok_or_else(|| anyhow!("PATCH leaf is outside its selected base"))?
            .to_vec();
        return Ok(PatchNodeResponse::Found(PatchNode::Leaf {
            digest,
            leaf: PatchLeaf { key, value },
        }));
    }

    let representative = node
        .representative()
        .strip_prefix(base)
        .ok_or_else(|| anyhow!("PATCH branch is outside its selected base"))?
        .to_vec();
    let end_depth = node
        .end_depth()
        .checked_sub(base.len())
        .ok_or_else(|| anyhow!("PATCH branch precedes its selected base"))?;
    let end_depth = u8::try_from(end_depth)
        .map_err(|_| anyhow!("PATCH branch depth does not fit the wire frame"))?;
    let children = node
        .children()
        .map(|(edge, child)| PatchChild {
            edge,
            digest: child.digest(),
            leaf_count: child.leaf_count(),
        })
        .collect();
    Ok(PatchNodeResponse::Found(PatchNode::Branch {
        digest,
        leaf_count: node.leaf_count(),
        branch: PatchBranch {
            representative,
            end_depth,
            children,
        },
    }))
}

/// Validate one returned node against its exact request and canonical PATCH
/// hashing rules. The caller supplies only value-specific leaf validation.
pub(crate) fn validate_patch_node<V>(
    request: &PatchRepairRequest,
    key_len: usize,
    base: &[u8],
    node: &PatchNode<V>,
    validate_leaf: impl FnOnce(&[u8], &V) -> Result<()>,
) -> Result<()> {
    if base.len() > key_len {
        bail!("PATCH base exceeds its key length");
    }
    if node.digest() != request.expected_digest() {
        bail!("PATCH node digest does not match the requested digest");
    }
    if node.leaf_count() > request.summary().leaf_count() {
        bail!("PATCH node exceeds its pinned leaf count");
    }
    if request.prefix().is_empty() && node.leaf_count() != request.summary().leaf_count() {
        bail!("PATCH root node count does not match its pinned summary");
    }

    let relative_key_len = key_len - base.len();
    match node {
        PatchNode::Leaf { digest, leaf } => {
            if leaf.key.len() != relative_key_len || !leaf.key.starts_with(request.prefix()) {
                bail!("PATCH leaf key is outside the requested relative prefix");
            }
            let mut absolute = Vec::with_capacity(key_len);
            absolute.extend_from_slice(base);
            absolute.extend_from_slice(&leaf.key);
            let expected = <Blake3Merkle as PatchHash>::leaf(&absolute);
            if digest != &expected {
                bail!("PATCH leaf digest does not bind its full key");
            }
            validate_leaf(&absolute, &leaf.value)?;
        }
        PatchNode::Branch {
            digest,
            leaf_count,
            branch,
        } => {
            let end_depth = branch.end_depth as usize;
            if branch.representative.len() != relative_key_len
                || !branch.representative.starts_with(request.prefix())
            {
                bail!("PATCH branch representative is outside the requested prefix");
            }
            if end_depth < request.prefix().len() || end_depth >= relative_key_len {
                bail!("PATCH branch end depth is outside its relative key");
            }
            if !(2..=256).contains(&branch.children.len()) {
                bail!("PATCH branch fanout is not canonical");
            }
            if branch.children[0].edge != branch.representative[end_depth] {
                bail!("PATCH branch representative is not in its first child");
            }
            let mut previous = None;
            let mut summed_count = 0u64;
            for child in &branch.children {
                if previous.is_some_and(|edge| child.edge <= edge) {
                    bail!("PATCH branch child edges are not strictly ascending");
                }
                if child.leaf_count == 0 {
                    bail!("PATCH branch child has zero leaves");
                }
                previous = Some(child.edge);
                summed_count = summed_count
                    .checked_add(child.leaf_count)
                    .ok_or_else(|| anyhow!("PATCH branch leaf count overflow"))?;
            }
            if summed_count != *leaf_count {
                bail!("PATCH branch child counts do not match its leaf count");
            }

            let mut absolute = Vec::with_capacity(key_len);
            absolute.extend_from_slice(base);
            absolute.extend_from_slice(&branch.representative);
            let absolute_end_depth = base.len() + end_depth;
            // Repair PATCHes use IdentitySchema, so tree depth and key-byte
            // depth are identical.
            let tree_to_key: Vec<usize> = (0..absolute.len()).collect();
            let mut state = <Blake3Merkle as PatchHash>::begin_branch(
                &absolute,
                &tree_to_key,
                absolute_end_depth,
                branch.children.len(),
                *leaf_count,
            );
            for child in &branch.children {
                <Blake3Merkle as PatchHash>::push_child(
                    &mut state,
                    child.edge,
                    child.leaf_count,
                    child.digest,
                );
            }
            let expected = <Blake3Merkle as PatchHash>::finish_branch(state);
            if digest != &expected {
                bail!("PATCH branch digest does not bind its canonical child summaries");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestPatch = PATCH<32, IdentitySchema, (), Blake3Merkle>;

    fn key(bytes: [u8; 4]) -> [u8; 32] {
        let mut key = [0; 32];
        key[..4].copy_from_slice(&bytes);
        key
    }

    fn response(patch: &TestPatch, prefix: &[u8]) -> PatchNodeResponse<()> {
        patch_node_response(patch, &[], prefix, |_, ()| Ok(())).unwrap()
    }

    #[test]
    fn summary_rejects_empty_root_count_disagreement() {
        assert!(PatchSummary::new(None, 1).is_err());
        assert!(PatchSummary::new(Some([1; 32]), 0).is_err());
        assert_eq!(PatchSummary::new(None, 0).unwrap().leaf_count(), 0);
    }

    /// A node whose digest is not the requested one, or whose children's
    /// counts do not add up to its own, is rejected, as is a leaf outside
    /// the requested prefix; the node as the PATCH serves it passes.
    #[test]
    fn a_node_is_rejected_unless_it_binds_its_request() {
        let a = key([1, 2, 3, 0]);
        let b = key([1, 2, 3, 1]);
        let c = key([1, 2, 3, 2]);
        let d = key([1, 2, 4, 0]);
        let remote = TestPatch::from_keys([a, b, c, d]);
        let summary = PatchSummary::from_patch(&remote);
        let root =
            PatchRepairRequest::new(summary, 32, Vec::new(), summary.root().unwrap()).unwrap();
        let PatchNodeResponse::Found(node) = response(&remote, &[]) else {
            unreachable!()
        };
        validate_patch_node(&root, 32, &[], &node, |_, ()| Ok(())).unwrap();

        let mut wrong_digest = node.clone();
        match &mut wrong_digest {
            PatchNode::Leaf { digest, .. } | PatchNode::Branch { digest, .. } => {
                digest[0] ^= 1;
            }
        }
        assert!(validate_patch_node(&root, 32, &[], &wrong_digest, |_, ()| Ok(())).is_err());

        let PatchNode::Branch {
            digest,
            leaf_count,
            mut branch,
        } = node
        else {
            unreachable!()
        };
        assert_eq!(
            branch
                .children
                .iter()
                .map(|child| child.leaf_count)
                .collect::<Vec<_>>(),
            [3, 1]
        );
        let mut child =
            PatchRepairRequest::new(summary, 32, vec![1, 2, 3], branch.children[0].digest).unwrap();
        let PatchNodeResponse::Found(first) = response(&remote, &[1, 2, 3]) else {
            unreachable!()
        };
        validate_patch_node(&child, 32, &[], &first, |_, ()| Ok(())).unwrap();
        // A leaf under another prefix than the one requested.
        child =
            PatchRepairRequest::new(summary, 32, vec![1, 2, 4], branch.children[0].digest).unwrap();
        assert!(validate_patch_node(&child, 32, &[], &first, |_, ()| Ok(())).is_err());

        // Child counts redistributed: the sum still matches, the digest
        // no longer does; a sum that does not match fails first.
        branch.children[0].leaf_count = 2;
        branch.children[1].leaf_count = 2;
        let redistributed = PatchNode::<()>::Branch {
            digest,
            leaf_count,
            branch: branch.clone(),
        };
        assert!(validate_patch_node(&root, 32, &[], &redistributed, |_, ()| Ok(())).is_err());
        branch.children[1].leaf_count = 3;
        let overcounted = PatchNode::<()>::Branch {
            digest,
            leaf_count,
            branch,
        };
        assert!(validate_patch_node(&root, 32, &[], &overcounted, |_, ()| Ok(())).is_err());
    }

    #[test]
    fn fixed_base_preserves_full_key_hashes_and_relative_compression() {
        type BasedPatch = PATCH<4, IdentitySchema, (), Blake3Merkle>;
        let patch = BasedPatch::from_keys([[9, 9, 1, 2], [9, 9, 1, 3]]);
        let response = patch_node_response(&patch, &[9, 9], &[], |_, ()| Ok(())).unwrap();
        let summary = {
            let root = patch.merkle_node(&[9, 9]).unwrap();
            PatchSummary::new(Some(root.digest()), root.leaf_count()).unwrap()
        };
        let request = PatchRepairRequest::new(summary, 2, vec![], summary.root().unwrap()).unwrap();
        let PatchNodeResponse::Found(node) = response else {
            unreachable!()
        };
        validate_patch_node(&request, 4, &[9, 9], &node, |absolute, ()| {
            assert!(absolute.starts_with(&[9, 9]));
            Ok(())
        })
        .unwrap();
    }
}
