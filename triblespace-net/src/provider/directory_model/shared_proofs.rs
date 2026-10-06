//! Byte-reuse experiment, not a production cache or a new directory protocol.
//!
//! Each root-bound membership still transfers an ordered list of node digests.
//! The receiver asks the selected sender for missing native PATCH node bodies,
//! then passes the reconstructed *whole* proof through the original verifier.
//! This reduces node bytes, not root-to-member associations or verification.
//! Reconstructing the original Vec also deliberately makes no resident-memory
//! or allocation improvement claim. No cache entry carries a lease deadline.
//!
//! The parent's trusted absolute clock/zero-skew and preselected responsibility
//! assumptions remain. Fetch reads only the selected support's existing proof,
//! not a complete provider inventory or a global membership oracle. A partial
//! receiver retains only requested leaf bodies, but branch representatives and
//! sibling summaries can disclose information outside its responsibility, just
//! as in the original independent paths.

use super::*;

const MAX_CACHED_NODES: u64 = 4_096;
type NodeCache = PATCH<32, IdentitySchema, Arc<PatchNode<()>>, Blake3Merkle>;

#[derive(Default, Debug)]
struct TransferCost {
    supports: usize,
    proof_references: usize,
    cache_hits: usize,
    node_requests: usize,
    node_bodies: usize,
    node_body_bytes: usize,
}

impl TransferCost {
    fn proof_bytes(&self) -> usize {
        // One u8 path length (bounded at 65) per support. Each explicit miss
        // requests one 32-byte digest; don't assume sender knowledge of cache.
        self.supports + 32 * (self.proof_references + self.node_requests) + self.node_body_bytes
    }

    fn body(&mut self, node: &PatchNode<()>) {
        self.node_bodies += 1;
        self.node_body_bytes += node_bytes(node);
    }
}

// Concrete native-field byte count, following the node response layout of
// the retired repair/0 stream with the actual key/representative width and an
// empty leaf value:
// found + kind:u8, digest:32; leaf key + value length:u32; or count:u64,
// representative, depth:u8, child count:u32, (edge:u8,digest:32,count:u64)*.
// This is NOT deployed provider wire traffic. Common root/member/lease bodies,
// membership/lease PATCH repair, transport framing, and round-trip latency are
// excluded. Counts use every actually visited node and its actual fanout.
fn node_bytes(node: &PatchNode<()>) -> usize {
    match node {
        PatchNode::Leaf { leaf, .. } => 2 + 32 + leaf.key.len() + 4,
        PatchNode::Branch { branch, .. } => {
            2 + 32 + 8 + branch.representative.len() + 1 + 4 + 41 * branch.children.len()
        }
    }
}

#[derive(Clone)]
struct References {
    member: Member,
    subject: Subject,
    nodes: Vec<[u8; 32]>,
}

impl From<&MembershipSupport> for References {
    fn from(support: &MembershipSupport) -> Self {
        Self {
            member: support.member,
            subject: support.subject.clone(),
            nodes: support.proof.iter().map(PatchNode::digest).collect(),
        }
    }
}

fn receive_references(
    directory: &mut Directory,
    cache: &mut NodeCache,
    references: References,
    mut fetch: impl FnMut([u8; 32]) -> Result<PatchNode<()>>,
    now: u64,
    validation: &mut Cost,
    transfer: &mut TransferCost,
) -> Result<()> {
    ensure!(references.nodes.len() <= MAX_PROOF_NODES, "proof budget");
    transfer.supports += 1;
    transfer.proof_references += references.nodes.len();
    let mut proof = Vec::with_capacity(references.nodes.len());
    for digest in references.nodes {
        let node = if let Some(node) = cache.get(&digest) {
            transfer.cache_hits += 1;
            (**node).clone()
        } else {
            transfer.node_requests += 1;
            let node = fetch(digest)?;
            transfer.body(&node);
            ensure!(node.digest() == digest, "wrong requested node");
            node
        };
        proof.push(node);
    }
    let support = Arc::new(MembershipSupport {
        member: references.member,
        subject: references.subject,
        proof,
    });
    // Presence is not validity or freshness: even all-hit paths must pass the
    // exact live lease, responsibility, provider, key, root, and full node walk.
    directory.receive_content(support.clone(), now, validation)?;
    // A malformed path cannot poison the reusable cache. Capacity merely stops
    // retention; it neither rejects valid membership nor weakens verification.
    for node in &support.proof {
        if cache.len() == MAX_CACHED_NODES {
            break;
        }
        cache.insert(&Entry::with_value(&node.digest(), Arc::new(node.clone())));
    }
    Ok(())
}

fn repair(
    directory: &mut Directory,
    source: &Directory,
    mut cache: Option<&mut NodeCache>,
    now: u64,
) -> (Cost, TransferCost) {
    let mut validation = Cost::default();
    let mut transfer = TransferCost::default();
    directory
        .repair_from_with(source, now, &mut validation, |directory, support, cost| {
            if let Some(cache) = &mut cache {
                receive_references(
                    directory,
                    cache,
                    References::from(support.as_ref()),
                    |digest| {
                        support
                            .proof
                            .iter()
                            .find(|node| node.digest() == digest)
                            .cloned()
                            .ok_or_else(|| anyhow::anyhow!("selected proof lacks requested node"))
                    },
                    now,
                    cost,
                    &mut transfer,
                )
            } else {
                transfer.supports += 1;
                for node in &support.proof {
                    transfer.body(node);
                }
                directory.receive_content(support, now, cost)
            }
        })
        .unwrap();
    (validation, transfer)
}

fn compare(
    phase: &str,
    inline: &mut Directory,
    shared: &mut Directory,
    cache: &mut NodeCache,
    source: &Directory,
    now: u64,
) -> (TransferCost, TransferCost) {
    let (inline_work, inline_bytes) = repair(inline, source, None, now);
    let (shared_work, shared_bytes) = repair(shared, source, Some(cache), now);
    assert_eq!(inline.active(now), shared.active(now));
    assert_eq!(inline.content.merkle_root(), shared.content.merkle_root());
    assert_eq!(inline.leases.merkle_root(), shared.leases.merkle_root());
    assert_eq!(inline_work.content_writes, shared_work.content_writes);
    assert_eq!(inline_work.lease_writes, shared_work.lease_writes);
    assert_eq!(
        inline_work.signatures_verified,
        shared_work.signatures_verified
    );
    assert_eq!(
        inline_work.repair_node_requests,
        shared_work.repair_node_requests
    );
    assert_eq!(
        inline_work.proof_nodes_verified,
        shared_work.proof_nodes_verified
    );
    assert_eq!(
        inline_work.proof_child_summaries_verified,
        shared_work.proof_child_summaries_verified
    );
    eprintln!(
        "shared-proof {phase}: active={} new-root-member-bindings={} leases={} signatures={} \
         repair-requests={} validated-nodes={} validated-children={} \
         inline-bodies={} inline-body-bytes={} inline-proof-bytes={} \
         shared-bodies={} shared-body-bytes={} references={} hits={} miss-requests={} \
         shared-proof-bytes={} cache-nodes={}",
        shared.active(now).len(),
        shared_work.content_writes,
        shared_work.lease_writes,
        shared_work.signatures_verified,
        shared_work.repair_node_requests,
        shared_work.proof_nodes_verified,
        shared_work.proof_child_summaries_verified,
        inline_bytes.node_bodies,
        inline_bytes.node_body_bytes,
        inline_bytes.proof_bytes(),
        shared_bytes.node_bodies,
        shared_bytes.node_body_bytes,
        shared_bytes.proof_references,
        shared_bytes.cache_hits,
        shared_bytes.node_requests,
        shared_bytes.proof_bytes(),
        cache.len(),
    );
    (inline_bytes, shared_bytes)
}

#[test]
fn shared_nodes_reduce_bytes_not_root_bindings_or_validation() {
    const N: usize = 256;
    let (signer, members, inventory) = fixture(N);
    let now = 1_000_000;
    let mut source = publish(
        true,
        &signer,
        &members,
        &inventory,
        now,
        now + 100,
        &mut Cost::default(),
    );
    let mut inline = Directory::new(Range::ALL);
    let mut shared = Directory::new(Range::ALL);
    let mut cache = NodeCache::new();
    let (cold_inline, cold_shared) =
        compare("cold", &mut inline, &mut shared, &mut cache, &source, now);
    assert_eq!(cold_shared.supports, N);
    assert!(cold_shared.node_bodies < cold_inline.node_bodies);
    assert!(cold_shared.proof_bytes() < cold_inline.proof_bytes());
    let cold_cache = cache.clone();

    install_issued(
        &mut source,
        Lease::issue(
            root_subject(&signer, &inventory),
            now + 50,
            now + 200,
            &signer,
            &mut Budget::unlimited(),
            &mut Cost::default(),
        )
        .unwrap(),
    );
    let (_, renewed) = compare(
        "unchanged-renewal",
        &mut inline,
        &mut shared,
        &mut cache,
        &source,
        now + 50,
    );
    assert_eq!(renewed.supports, 0);
    assert_eq!(renewed.proof_bytes(), 0);
    assert_eq!(cache.merkle_root(), cold_cache.merkle_root());
    assert_eq!(shared.expiry(members[0], now + 50), Some(now + 200));

    let (_, grown_members, grown_inventory) = fixture(N + 1);
    assert_eq!(&grown_members[..N], members.as_slice());
    let grown = publish(
        true,
        &signer,
        &grown_members,
        &grown_inventory,
        now + 50,
        now + 250,
        &mut Cost::default(),
    );
    let (growth_inline, growth_shared) = compare(
        "one-member-growth",
        &mut inline,
        &mut shared,
        &mut cache,
        &grown,
        now + 50,
    );
    assert_eq!(growth_shared.supports, N + 1); // NOT one new binding.
    assert!(growth_shared.node_bodies < cold_shared.node_bodies);
    assert!(growth_shared.proof_bytes() < growth_inline.proof_bytes());
    assert_eq!(shared.active(now + 200).len(), N + 1);
    assert!(shared.active(now + 250).is_empty());

    let mut inline = Directory::new(Range::LEFT);
    let mut shared = Directory::new(Range::LEFT);
    let mut cache = NodeCache::new();
    let (_, partial) = compare(
        "partial-cold",
        &mut inline,
        &mut shared,
        &mut cache,
        &source,
        now + 50,
    );
    let selected = members
        .iter()
        .filter(|member| Range::LEFT.contains(member.locator))
        .count();
    assert_eq!(partial.supports, selected);
    assert!(selected > 0 && selected < N);
    // The cache has no leaf payloads outside requested responsibility. Branch
    // representatives/sibling summaries remain the stated disclosure caveat.
    for digest in cache.iter() {
        if let PatchNode::Leaf { leaf, .. } = cache.get(digest).unwrap().as_ref() {
            assert!(Range::LEFT.contains(leaf.key[..32].try_into().unwrap()));
        }
    }
    let (_, partial_growth) = compare(
        "partial-growth",
        &mut inline,
        &mut shared,
        &mut cache,
        &grown,
        now + 50,
    );
    assert_eq!(
        partial_growth.supports,
        grown_members
            .iter()
            .filter(|member| Range::LEFT.contains(member.locator))
            .count()
    );
    for member in shared.active(now + 200) {
        assert_eq!(shared.expiry(member, now + 200), Some(now + 250));
    }
}

#[test]
fn cache_hits_never_renew_expiry_or_supply_a_new_root_binding() {
    let (signer, members, inventory) = fixture(16);
    let source = publish(
        true,
        &signer,
        &members,
        &inventory,
        10,
        100,
        &mut Cost::default(),
    );
    let mut directory = Directory::new(Range::ALL);
    let mut cache = NodeCache::new();
    repair(&mut directory, &source, Some(&mut cache), 20);
    let support = source
        .content
        .get(source.content.iter().next().unwrap())
        .unwrap();
    let mut transfer = TransferCost::default();
    let mut validation = Cost::default();
    let hit = receive_references(
        &mut directory,
        &mut cache,
        References::from(support.as_ref()),
        |_| panic!("all nodes should be cached"),
        99,
        &mut validation,
        &mut transfer,
    );
    assert!(hit.is_ok());
    assert_eq!(directory.expiry(support.member, 99), Some(100));
    assert_eq!(transfer.node_requests, 0);
    assert!(validation.proof_nodes_verified > 0);
    let expired = receive_references(
        &mut directory,
        &mut cache,
        References::from(support.as_ref()),
        |_| panic!("all nodes should be cached"),
        100,
        &mut Cost::default(),
        &mut TransferCost::default(),
    );
    assert!(
        expired
            .unwrap_err()
            .to_string()
            .contains("no live exact inventory lease")
    );
    assert!(directory.active(100).is_empty());

    let (_, _, grown_inventory) = fixture(17);
    let changed = root_subject(&signer, &grown_inventory);
    directory
        .receive_lease(
            Lease::issue(
                changed.clone(),
                100,
                200,
                &signer,
                &mut Budget::unlimited(),
                &mut Cost::default(),
            )
            .unwrap(),
            100,
            &mut Cost::default(),
        )
        .unwrap();
    let mut grafted = References::from(support.as_ref());
    grafted.subject = changed;
    assert!(
        receive_references(
            &mut directory,
            &mut cache,
            grafted,
            |_| panic!("old path is cached"),
            100,
            &mut Cost::default(),
            &mut TransferCost::default()
        )
        .is_err()
    );
    assert!(directory.active(100).is_empty());
}

#[test]
fn invalid_node_bodies_cannot_poison_cache_and_eviction_changes_only_cost() {
    let (signer, members, inventory) = fixture(16);
    let source = publish(
        true,
        &signer,
        &members,
        &inventory,
        10,
        100,
        &mut Cost::default(),
    );
    let mut directory = Directory::new(Range::ALL);
    let lease = source
        .leases
        .get(source.leases.iter().next().unwrap())
        .unwrap()
        .clone();
    directory
        .receive_lease(lease, 20, &mut Cost::default())
        .unwrap();
    let support = source
        .content
        .get(source.content.iter().next().unwrap())
        .unwrap();
    let mut cache = NodeCache::new();
    let result = receive_references(
        &mut directory,
        &mut cache,
        References::from(support.as_ref()),
        |digest| {
            let mut node = support
                .proof
                .iter()
                .find(|node| node.digest() == digest)
                .unwrap()
                .clone();
            if let PatchNode::Leaf { leaf, .. } = &mut node {
                leaf.key[63] ^= 1; // Keep claimed digest: canonical hashing must catch it.
            }
            Ok(node)
        },
        20,
        &mut Cost::default(),
        &mut TransferCost::default(),
    );
    assert!(result.is_err());
    assert!(cache.is_empty());
    assert!(directory.content.is_empty());

    repair(&mut directory, &source, Some(&mut cache), 20);
    let cached_directory = directory.clone();
    cache = NodeCache::new();
    let (_, grown_members, grown_inventory) = fixture(17);
    let grown = publish(
        true,
        &signer,
        &grown_members,
        &grown_inventory,
        30,
        100,
        &mut Cost::default(),
    );
    let (_, after_eviction) = repair(&mut directory, &grown, Some(&mut cache), 30);
    assert!(after_eviction.node_requests > 0);
    assert_eq!(cached_directory.expiry(members[0], 30), Some(100));
    assert_eq!(directory.expiry(members[0], 30), Some(100));
    assert!(directory.active(100).is_empty());
}
