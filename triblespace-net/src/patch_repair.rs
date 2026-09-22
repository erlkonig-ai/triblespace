//! Overlay-neutral, root-and-count-proven PATCH reconciliation.
//!
//! A [`PatchSummary`] pins one immutable remote trie. The repair walker treats
//! that authenticated remote shape as its only traversal plan: local state may
//! discharge a subtree only when both digest and leaf count agree. Compressed
//! paths need not line up between peers, responses may arrive out of order,
//! and an unavailable or contradictory pinned snapshot fails closed without
//! discarding leaves already admitted by the caller.

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
pub(crate) struct PatchRepairRequest<S> {
    scope: S,
    summary: PatchSummary,
    /// Prefix relative to the caller-selected PATCH base.
    prefix: Vec<u8>,
    /// Digest authenticated by the root or a previously accepted branch.
    expected_digest: [u8; 32],
}

impl<S> PatchRepairRequest<S> {
    pub(crate) fn new(
        scope: S,
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
            scope,
            summary,
            prefix,
            expected_digest,
        })
    }

    pub(crate) const fn scope(&self) -> &S {
        &self.scope
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
    /// The exact root is no longer retained by the serving peer.
    SnapshotUnavailable,
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
pub(crate) fn validate_patch_node<S, V>(
    request: &PatchRepairRequest<S>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingNode {
    prefix: Vec<u8>,
    digest: [u8; 32],
    leaf_count: u64,
}

/// Count-proven outcome of one completed PATCH repair walk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PatchRepairResult<S> {
    pub(crate) scope: S,
    pub(crate) summary: PatchSummary,
    pub(crate) missing_count: u64,
}

/// Pipelined traversal state for one immutable remote PATCH root.
///
/// The local callbacks must describe one immutable observation for the entire
/// walk. Later admissions can make work redundant, but must not manufacture a
/// subtree equality against a moving snapshot.
#[derive(Clone, Debug)]
pub(crate) struct PatchRepairWalker<S> {
    scope: S,
    summary: PatchSummary,
    relative_key_len: usize,
    frontier: Vec<PendingNode>,
    in_flight: Vec<PendingNode>,
    accounted: u64,
    missing_count: u64,
    failed: bool,
}

impl<S> PatchRepairWalker<S>
where
    S: Clone + Eq,
{
    pub(crate) fn new(scope: S, summary: PatchSummary, relative_key_len: usize) -> Result<Self> {
        // Revalidate at the trust boundary even when a local constructor made
        // the summary.
        let summary = PatchSummary::new(summary.root(), summary.leaf_count())?;
        let frontier = summary
            .root()
            .map(|digest| {
                vec![PendingNode {
                    prefix: Vec::new(),
                    digest,
                    leaf_count: summary.leaf_count(),
                }]
            })
            .unwrap_or_default();
        let walker = Self {
            scope,
            summary,
            relative_key_len,
            frontier,
            in_flight: Vec::new(),
            accounted: 0,
            missing_count: 0,
            failed: false,
        };
        walker.verify_count_invariant()?;
        Ok(walker)
    }

    /// Return the next pinned request, skipping exact local subtrees.
    pub(crate) fn next_request(
        &mut self,
        local_summary: impl FnMut(&S, &[u8]) -> Option<PatchSummary>,
    ) -> Result<Option<PatchRepairRequest<S>>> {
        self.next_request_after(local_summary, None)
    }

    /// Exclude prefix ranges entirely below a lexicographic watermark. Excluded
    /// subtrees are accounted by their authenticated counts, not asserted to
    /// exist locally. The resulting missing count therefore describes this
    /// suffix only, never equality or absence in the excluded range.
    /// A compressed leaf can straddle the prefix bound: the caller must also
    /// discharge leaves at or below the watermark in `accept`'s callback.
    pub(crate) fn next_request_after(
        &mut self,
        mut local_summary: impl FnMut(&S, &[u8]) -> Option<PatchSummary>,
        exclusive_lower_bound: Option<&[u8]>,
    ) -> Result<Option<PatchRepairRequest<S>>> {
        if self.failed {
            bail!("PATCH repair walker is failed");
        }
        if exclusive_lower_bound.is_some_and(|bound| bound.len() != self.relative_key_len) {
            bail!("PATCH traversal watermark has the wrong key length");
        }
        while let Some(pending) = self.frontier.pop() {
            // A prefix covers prefix || 00.. through prefix || FF... Only
            // discard it if even the upper end is at or below the watermark.
            let excluded = exclusive_lower_bound.is_some_and(|bound| {
                let mut upper = pending.prefix.clone();
                upper.resize(self.relative_key_len, u8::MAX);
                upper.as_slice() <= bound
            });
            if excluded
                || local_summary(&self.scope, &pending.prefix)
                    == Some(PatchSummary::new(Some(pending.digest), pending.leaf_count)?)
            {
                self.accounted = self
                    .accounted
                    .checked_add(pending.leaf_count)
                    .ok_or_else(|| anyhow!("PATCH repair accounted count overflow"))?;
                self.verify_count_invariant()?;
                continue;
            }

            let request = PatchRepairRequest::new(
                self.scope.clone(),
                self.summary,
                self.relative_key_len,
                pending.prefix.clone(),
                pending.digest,
            )?;
            self.in_flight.push(pending);
            self.verify_count_invariant()?;
            return Ok(Some(request));
        }

        self.verify_count_invariant()?;
        if self.in_flight.is_empty() && self.accounted != self.summary.leaf_count() {
            self.failed = true;
            bail!(
                "PATCH repair frontier ended after accounting for {} of {} leaves",
                self.accounted,
                self.summary.leaf_count()
            );
        }
        Ok(None)
    }

    /// Consume one response and yield a missing authenticated leaf immediately.
    pub(crate) fn accept<V>(
        &mut self,
        request: &PatchRepairRequest<S>,
        response: PatchNodeResponse<V>,
        mut local_contains: impl FnMut(&S, &[u8]) -> bool,
    ) -> Result<Option<PatchLeaf<V>>> {
        if self.failed {
            bail!("PATCH repair walker is failed");
        }
        let result = self.accept_inner(request, response, &mut local_contains);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn accept_inner<V>(
        &mut self,
        request: &PatchRepairRequest<S>,
        response: PatchNodeResponse<V>,
        local_contains: &mut impl FnMut(&S, &[u8]) -> bool,
    ) -> Result<Option<PatchLeaf<V>>> {
        if request.scope() != &self.scope || request.summary() != self.summary {
            bail!("PATCH response request does not belong to this pinned walk");
        }
        let position = self
            .in_flight
            .iter()
            .position(|pending| {
                pending.prefix == request.prefix() && pending.digest == request.expected_digest()
            })
            .ok_or_else(|| anyhow!("PATCH response has no matching in-flight request"))?;
        let pending = self.in_flight.swap_remove(position);
        let node = match response {
            PatchNodeResponse::SnapshotUnavailable => {
                bail!("pinned PATCH snapshot is unavailable; request a fresh summary")
            }
            PatchNodeResponse::PrefixAbsent => bail!(
                "authenticated PATCH prefix {} is absent",
                hex::encode(&pending.prefix)
            ),
            PatchNodeResponse::Found(node) => node,
        };

        if node.digest() != pending.digest {
            bail!("PATCH node digest does not match its authenticated parent");
        }
        if node.leaf_count() != pending.leaf_count {
            bail!(
                "PATCH node leaf count {} does not match authenticated pending count {}",
                node.leaf_count(),
                pending.leaf_count
            );
        }

        let missing = match node {
            PatchNode::Leaf { leaf, .. } => {
                if pending.leaf_count != 1 || !leaf.key.starts_with(&pending.prefix) {
                    bail!("PATCH leaf does not discharge its authenticated locator");
                }
                let missing = (!local_contains(&self.scope, &leaf.key)).then_some(leaf);
                if missing.is_some() {
                    self.missing_count = self
                        .missing_count
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("PATCH repair missing count overflow"))?;
                }
                self.accounted = self
                    .accounted
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("PATCH repair accounted count overflow"))?;
                missing
            }
            PatchNode::Branch { branch, .. } => {
                let end_depth = usize::from(branch.end_depth);
                if end_depth >= branch.representative.len()
                    || !branch.representative[..end_depth].starts_with(&pending.prefix)
                {
                    bail!("PATCH branch does not extend its authenticated locator");
                }

                let mut previous = None;
                let mut child_total = 0u64;
                for child in &branch.children {
                    if previous.is_some_and(|edge| child.edge <= edge) || child.leaf_count == 0 {
                        bail!("PATCH branch children are not canonical");
                    }
                    previous = Some(child.edge);
                    child_total = child_total
                        .checked_add(child.leaf_count)
                        .ok_or_else(|| anyhow!("PATCH child count overflow"))?;
                }
                if child_total != pending.leaf_count {
                    bail!(
                        "PATCH branch child counts {child_total} do not discharge pending count {}",
                        pending.leaf_count
                    );
                }

                // Reverse push makes the LIFO frontier walk ascending edges.
                // Bytes after end_depth are representative-only routing
                // witnesses and never participate in a child locator.
                for child in branch.children.into_iter().rev() {
                    let mut prefix = branch.representative[..end_depth].to_vec();
                    prefix.push(child.edge);
                    self.frontier.push(PendingNode {
                        prefix,
                        digest: child.digest,
                        leaf_count: child.leaf_count,
                    });
                }
                None
            }
        };
        self.verify_count_invariant()?;
        Ok(missing)
    }

    /// Prove completion and return the exact summary plus bounded counters.
    pub(crate) fn finish(self) -> Result<PatchRepairResult<S>> {
        if self.failed {
            bail!("PATCH repair walker failed before completion");
        }
        if !self.in_flight.is_empty()
            || !self.frontier.is_empty()
            || self.accounted != self.summary.leaf_count()
        {
            bail!(
                "PATCH repair walk is incomplete: accounted {} of {} leaves",
                self.accounted,
                self.summary.leaf_count()
            );
        }
        Ok(PatchRepairResult {
            scope: self.scope,
            summary: self.summary,
            missing_count: self.missing_count,
        })
    }

    fn verify_count_invariant(&self) -> Result<()> {
        let mut total = self.accounted;
        for in_flight in &self.in_flight {
            total = total
                .checked_add(in_flight.leaf_count)
                .ok_or_else(|| anyhow!("PATCH repair count invariant overflow"))?;
        }
        for pending in &self.frontier {
            total = total
                .checked_add(pending.leaf_count)
                .ok_or_else(|| anyhow!("PATCH repair count invariant overflow"))?;
        }
        if total != self.summary.leaf_count() {
            bail!(
                "PATCH repair count invariant accounts for {total} of {} leaves",
                self.summary.leaf_count()
            );
        }
        Ok(())
    }
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

    fn run_walk(
        remote: &TestPatch,
        local: &TestPatch,
    ) -> (PatchRepairResult<()>, Vec<Vec<u8>>, Vec<PatchLeaf<()>>) {
        let mut walker = PatchRepairWalker::new((), PatchSummary::from_patch(remote), 32).unwrap();
        let mut requests = Vec::new();
        let mut missing = Vec::new();
        loop {
            let request = walker
                .next_request(|_, prefix| {
                    local.merkle_node(prefix).map(|node| {
                        PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap()
                    })
                })
                .unwrap();
            let Some(request) = request else {
                break;
            };
            requests.push(request.prefix().to_vec());
            if let Some(leaf) = walker
                .accept(&request, response(remote, request.prefix()), |_, raw| {
                    let key: [u8; 32] = raw.try_into().unwrap();
                    local.get(&key).is_some()
                })
                .unwrap()
            {
                missing.push(leaf);
            }
        }
        (walker.finish().unwrap(), requests, missing)
    }

    fn missing_keys(missing: &[PatchLeaf<()>]) -> Vec<[u8; 32]> {
        missing
            .iter()
            .map(|leaf| leaf.key.as_slice().try_into().unwrap())
            .collect()
    }

    #[test]
    fn summary_rejects_empty_root_count_disagreement() {
        assert!(PatchSummary::new(None, 1).is_err());
        assert!(PatchSummary::new(Some([1; 32]), 0).is_err());
        assert_eq!(PatchSummary::new(None, 0).unwrap().leaf_count(), 0);
    }

    #[test]
    fn remote_split_shallower_than_local_compressed_path() {
        let a = key([1, 2, 3, 0]);
        let b = key([1, 2, 4, 0]);
        let c = key([1, 2, 3, 255]);
        let remote = TestPatch::from_keys([a, b]);
        let local = TestPatch::from_keys([a, c]);

        let (result, _, missing) = run_walk(&remote, &local);
        assert_eq!(result.summary.leaf_count(), 2);
        assert_eq!(result.missing_count, 1);
        assert_eq!(missing_keys(&missing), [b]);
    }

    #[test]
    fn local_split_shallower_than_remote_compressed_path() {
        let a = key([1, 2, 3, 0]);
        let b = key([1, 2, 4, 0]);
        let c = key([1, 2, 3, 255]);
        let remote = TestPatch::from_keys([a, c]);
        let local = TestPatch::from_keys([a, b]);

        let (result, _, missing) = run_walk(&remote, &local);
        assert_eq!(result.summary.leaf_count(), 2);
        assert_eq!(result.missing_count, 1);
        assert_eq!(missing_keys(&missing), [c]);
    }

    #[test]
    fn singleton_and_branch_reconcile_in_both_directions() {
        let a = key([1, 2, 3, 0]);
        let c = key([1, 2, 3, 255]);

        let remote_singleton = TestPatch::from_keys([a]);
        let local_branch = TestPatch::from_keys([a, c]);
        let (singleton, _, singleton_missing) = run_walk(&remote_singleton, &local_branch);
        assert_eq!(singleton.summary.leaf_count(), 1);
        assert_eq!(singleton.missing_count, 0);
        assert!(singleton_missing.is_empty());

        let remote_branch = TestPatch::from_keys([a, c]);
        let local_singleton = TestPatch::from_keys([a]);
        let (branch, _, branch_missing) = run_walk(&remote_branch, &local_singleton);
        assert_eq!(branch.summary.leaf_count(), 2);
        assert_eq!(branch.missing_count, 1);
        assert_eq!(missing_keys(&branch_missing), [c]);
    }

    #[test]
    fn child_locator_may_end_inside_remote_compression() {
        let d = key([0, 7, 8, 1]);
        let e = key([0, 7, 8, 2]);
        let f = key([9, 0, 0, 0]);
        let remote = TestPatch::from_keys([d, e, f]);
        let local = TestPatch::from_keys([d, f]);

        let (result, requests, missing) = run_walk(&remote, &local);
        assert_eq!(result.missing_count, 1);
        assert_eq!(missing_keys(&missing), [e]);
        assert!(requests.iter().any(|prefix| prefix == &[0]));
        assert!(requests.iter().any(|prefix| prefix == &[0, 7, 8, 2]));
    }

    #[test]
    fn independent_frontier_responses_may_arrive_out_of_order() {
        let remote = TestPatch::from_keys((0..32u8).map(|edge| key([edge, 7, 8, 9])));
        let summary = PatchSummary::from_patch(&remote);
        let mut walker = PatchRepairWalker::new((), summary, 32).unwrap();

        let root = walker.next_request(|_, _| None).unwrap().unwrap();
        walker
            .accept(&root, response(&remote, root.prefix()), |_, _| false)
            .unwrap();

        let mut frontier = Vec::new();
        while let Some(request) = walker.next_request(|_, _| None).unwrap() {
            frontier.push(request);
        }
        assert_eq!(frontier.len(), 32);
        assert!(walker.finish().is_err(), "outstanding requests are counted");

        let mut walker = PatchRepairWalker::new((), summary, 32).unwrap();
        let root = walker.next_request(|_, _| None).unwrap().unwrap();
        walker
            .accept(&root, response(&remote, root.prefix()), |_, _| false)
            .unwrap();
        let mut frontier = Vec::new();
        while let Some(request) = walker.next_request(|_, _| None).unwrap() {
            frontier.push(request);
        }

        let mut missing = Vec::new();
        for request in frontier.into_iter().rev() {
            missing.push(
                walker
                    .accept(&request, response(&remote, request.prefix()), |_, _| false)
                    .unwrap()
                    .expect("empty local PATCH misses every leaf"),
            );
        }
        assert!(walker.next_request(|_, _| None).unwrap().is_none());
        let result = walker.finish().unwrap();
        assert_eq!(result.summary.leaf_count(), 32);
        assert_eq!(result.missing_count, 32);
        assert_eq!(missing.len(), 32);
    }

    #[test]
    fn unavailable_or_absent_prefix_never_completes() {
        let remote = TestPatch::from_keys([key([1, 2, 3, 0])]);
        let summary = PatchSummary::from_patch(&remote);
        for response in [
            PatchNodeResponse::<()>::SnapshotUnavailable,
            PatchNodeResponse::<()>::PrefixAbsent,
        ] {
            let mut walker = PatchRepairWalker::new((), summary, 32).unwrap();
            let request = walker.next_request(|_, _| None).unwrap().unwrap();
            assert!(walker.accept(&request, response, |_, _| false).is_err());
            assert!(walker.finish().is_err());
        }

        let branch =
            TestPatch::from_keys([key([0, 7, 8, 1]), key([0, 7, 8, 2]), key([9, 0, 0, 0])]);
        let mut child_absent =
            PatchRepairWalker::new((), PatchSummary::from_patch(&branch), 32).unwrap();
        let root = child_absent.next_request(|_, _| None).unwrap().unwrap();
        child_absent
            .accept(&root, response(&branch, root.prefix()), |_, _| false)
            .unwrap();
        let child = child_absent.next_request(|_, _| None).unwrap().unwrap();
        assert!(!child.prefix().is_empty());
        assert!(
            child_absent
                .accept(&child, PatchNodeResponse::<()>::PrefixAbsent, |_, _| false)
                .is_err()
        );
        assert!(child_absent.finish().is_err());
    }

    #[test]
    fn wrong_digest_or_exact_child_count_never_completes() {
        let a = key([1, 2, 3, 0]);
        let b = key([1, 2, 3, 1]);
        let c = key([1, 2, 3, 2]);
        let d = key([1, 2, 4, 0]);
        let remote = TestPatch::from_keys([a, b, c, d]);
        let summary = PatchSummary::from_patch(&remote);

        let mut wrong_digest = PatchRepairWalker::new((), summary, 32).unwrap();
        let root = wrong_digest.next_request(|_, _| None).unwrap().unwrap();
        let PatchNodeResponse::Found(mut node) = response(&remote, root.prefix()) else {
            unreachable!()
        };
        match &mut node {
            PatchNode::Leaf { digest, .. } | PatchNode::Branch { digest, .. } => {
                digest[0] ^= 1;
            }
        }
        assert!(
            wrong_digest
                .accept(&root, PatchNodeResponse::Found(node), |_, _| false)
                .is_err()
        );
        assert!(wrong_digest.finish().is_err());

        // Blake3Merkle rejects this redistribution at the wire validator. The
        // state machine still fails closed if an internal caller bypasses it.
        let mut wrong_count = PatchRepairWalker::new((), summary, 32).unwrap();
        let root = wrong_count.next_request(|_, _| None).unwrap().unwrap();
        let PatchNodeResponse::Found(PatchNode::Branch {
            digest,
            leaf_count,
            mut branch,
        }) = response(&remote, root.prefix())
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
        branch.children[0].leaf_count = 2;
        branch.children[1].leaf_count = 2;
        wrong_count
            .accept(
                &root,
                PatchNodeResponse::<()>::Found(PatchNode::Branch {
                    digest,
                    leaf_count,
                    branch,
                }),
                |_, _| false,
            )
            .unwrap();
        let child = wrong_count.next_request(|_, _| None).unwrap().unwrap();
        assert!(
            wrong_count
                .accept(&child, response(&remote, child.prefix()), |_, _| false)
                .is_err()
        );
        assert!(wrong_count.finish().is_err());
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
        let request =
            PatchRepairRequest::new((), summary, 2, vec![], summary.root().unwrap()).unwrap();
        let PatchNodeResponse::Found(node) = response else {
            unreachable!()
        };
        validate_patch_node(&request, 4, &[9, 9], &node, |absolute, ()| {
            assert!(absolute.starts_with(&[9, 9]));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn suffix_walk_skips_only_wholly_excluded_prefixes() {
        let keys = [
            key([0, 255, 0, 0]),
            key([1, 0, 0, 0]),
            key([1, 1, 0, 0]),
            key([2, 0, 0, 0]),
        ];
        let patch = TestPatch::from_keys(keys);
        let bound = keys[1];
        let summary = PatchSummary::from_patch(&patch);
        let mut walker = PatchRepairWalker::new((), summary, 32).unwrap();
        let mut received = Vec::new();
        while let Some(request) = walker
            .next_request_after(|_, _| None, Some(&bound))
            .unwrap()
        {
            assert_ne!(request.prefix().first(), Some(&0));
            let response = response(&patch, request.prefix());
            if let PatchNodeResponse::Found(node) = &response {
                validate_patch_node(&request, 32, &[], node, |_, ()| Ok(())).unwrap();
            }
            if let Some(leaf) = walker
                .accept(&request, response, |_, key| key <= bound.as_slice())
                .unwrap()
            {
                received.push(<[u8; 32]>::try_from(leaf.key.as_slice()).unwrap());
            }
        }
        assert_eq!(received, keys[2..]);
        assert_eq!(walker.finish().unwrap().missing_count, 2);
    }
}
