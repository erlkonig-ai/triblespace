//! Wire-free protocol experiment, NOT the deployed provider protocol.
//!
//! This model compares independently signed entry leases with signed immutable
//! inventory roots. It deliberately assumes a trusted, shared absolute test
//! clock (zero skew); it does not solve clock recovery or define a disk format.
//! First-byte ranges stand in for already-selected responsibility, while the
//! separate placement oracle knows a complete synthetic topology. Neither is a
//! proposed distributed membership oracle or production range-routing algorithm.
//!
//! Immutable membership *support* and finite lease evidence have separate
//! Merkle PATCHes. A support key binds (L, provider, token, inventory binding),
//! never an expiry or renewed certificate id. PATCH hashes keys, not values.
//! Root changes therefore need new support proofs; unchanged-root renewal does
//! not touch the membership PATCH. The deliberately unshared inclusion paths
//! make proof-refresh cost visible rather than assuming a proof-forest win.

#[path = "directory_model/shared_proofs.rs"]
mod shared_proofs;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};

use crate::clock::VirtualClock;
use crate::patch_repair::{
    PatchNode, PatchNodeResponse, PatchRepairRequest, PatchSummary, patch_node_response,
    validate_patch_node,
};
use crate::routing::{K, distance_cmp};

// Test-only transcript domains, not stable protocol ids or wire magic.
const BINDING_DOMAIN: &[u8] = b"TEST ONLY provider-directory-model binding\0";
const LEASE_DOMAIN: &[u8] = b"TEST ONLY provider-directory-model lease\0";
const FIXTURE_DOMAIN: &str = "TEST ONLY provider-directory-model opaque fixtures";
const MAX_MODEL_ITEMS: u64 = 1_024;
const MAX_MODEL_NODE_REQUESTS: usize = 4_096;
const MAX_PROOF_NODES: usize = 65;

type InventoryPatch = PATCH<64, IdentitySchema, (), Blake3Merkle>;
type ContentPatch = PATCH<128, IdentitySchema, Arc<MembershipSupport>, Blake3Merkle>;
type LeasePatch = PATCH<32, IdentitySchema, Arc<Lease>, Blake3Merkle>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Member {
    locator: [u8; 32],
    provider: [u8; 32],
    token: [u8; 32],
}

impl Member {
    fn key(self) -> [u8; 96] {
        let mut key = [0; 96];
        key[..32].copy_from_slice(&self.locator);
        key[32..64].copy_from_slice(&self.provider);
        key[64..].copy_from_slice(&self.token);
        key
    }

    fn inventory_key(self) -> [u8; 64] {
        let mut key = [0; 64];
        key[..32].copy_from_slice(&self.locator);
        key[32..].copy_from_slice(&self.token);
        key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Range {
    start: u16,
    end: u16,
}

impl Range {
    const ALL: Self = Self { start: 0, end: 256 };
    const LEFT: Self = Self { start: 0, end: 128 };
    const RIGHT: Self = Self {
        start: 128,
        end: 256,
    };

    fn contains(self, locator: [u8; 32]) -> bool {
        self.start <= u16::from(locator[0]) && u16::from(locator[0]) < self.end
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Subject {
    Entry(Member),
    Root {
        provider: [u8; 32],
        range: Range,
        inventory: PatchSummary,
    },
}

impl Subject {
    fn provider(&self) -> [u8; 32] {
        match self {
            Self::Entry(member) => member.provider,
            Self::Root { provider, .. } => *provider,
        }
    }

    fn members(&self) -> u64 {
        match self {
            Self::Entry(_) => 1,
            Self::Root { inventory, .. } => inventory.leaf_count(),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = BINDING_DOMAIN.to_vec();
        match self {
            Self::Entry(member) => {
                bytes.push(0);
                bytes.extend_from_slice(&member.key());
            }
            Self::Root {
                provider,
                range,
                inventory,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(provider);
                bytes.extend_from_slice(&range.start.to_be_bytes());
                bytes.extend_from_slice(&range.end.to_be_bytes());
                bytes.push(u8::from(inventory.root().is_some()));
                bytes.extend_from_slice(&inventory.root().unwrap_or_default());
                bytes.extend_from_slice(&inventory.leaf_count().to_be_bytes());
            }
        }
        bytes
    }

    fn binding(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes()).as_bytes()
    }
}

#[derive(Clone, Debug)]
struct Lease {
    subject: Subject,
    issued_at: u64,
    expires_at: u64,
    signature: [u8; 64],
}

impl Lease {
    fn transcript(&self) -> Vec<u8> {
        let mut bytes = LEASE_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.subject.bytes());
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes
    }

    fn id(&self) -> [u8; 32] {
        let mut bytes = self.transcript();
        bytes.extend_from_slice(&self.signature);
        *blake3::hash(&bytes).as_bytes()
    }

    fn live(&self, now: u64) -> bool {
        self.issued_at <= now && now < self.expires_at
    }

    fn issue(
        subject: Subject,
        issued_at: u64,
        expires_at: u64,
        signer: &SigningKey,
        budget: &mut Budget,
        cost: &mut Cost,
    ) -> Result<Arc<Self>> {
        ensure!(
            subject.provider() == signer.verifying_key().to_bytes(),
            "wrong issuer"
        );
        ensure!(issued_at < expires_at, "empty lease");
        ensure!(
            expires_at - issued_at <= super::PROVIDER_LEASE_LIFETIME.as_secs(),
            "lease too long"
        );
        ensure!(
            subject.members() != 0,
            "empty inventory needs no announcement"
        );
        // One signature is still an attempt for EVERY covered logical member.
        budget.charge(subject.members())?;
        let mut lease = Self {
            subject,
            issued_at,
            expires_at,
            signature: [0; 64],
        };
        lease.signature = signer.sign(&lease.transcript()).to_bytes();
        cost.signatures_issued += 1;
        Ok(Arc::new(lease))
    }

    fn verify(&self, now: u64, cost: &mut Cost) -> Result<()> {
        ensure!(self.live(now), "lease is not live at this absolute instant");
        ensure!(
            self.expires_at - self.issued_at <= super::PROVIDER_LEASE_LIFETIME.as_secs(),
            "lease too long"
        );
        if let Subject::Root {
            range, inventory, ..
        } = &self.subject
        {
            ensure!(
                range.start < range.end && range.end <= 256,
                "invalid root scope"
            );
            PatchSummary::new(inventory.root(), inventory.leaf_count())?;
        }
        cost.signatures_verified += 1;
        VerifyingKey::from_bytes(&self.subject.provider())?
            .verify_strict(&self.transcript(), &Signature::from_bytes(&self.signature))?;
        Ok(())
    }
}

#[derive(Default, Debug)]
struct Cost {
    signatures_issued: usize,
    signatures_verified: usize,
    content_leaves_sent: usize,
    lease_leaves_sent: usize,
    content_writes: usize,
    lease_writes: usize,
    repair_node_requests: usize,
    proof_nodes_verified: usize,
    proof_child_summaries_verified: usize,
}

struct Budget {
    remaining: Option<u64>,
    charged: u64,
}

impl Budget {
    fn unlimited() -> Self {
        Self {
            remaining: None,
            charged: 0,
        }
    }

    fn charge(&mut self, members: u64) -> Result<()> {
        ensure!(
            self.remaining.is_none_or(|left| left >= members),
            "logical-member budget exhausted"
        );
        if let Some(left) = &mut self.remaining {
            *left -= members;
        }
        self.charged += members;
        Ok(())
    }
}

// An independent VirtualClock avoids installing process-global time in unit
// tests. Reboot starts a new monotonic origin but retains the trusted wall epoch.
struct TestClock {
    base: u64,
    clock: Arc<VirtualClock>,
}

impl TestClock {
    fn at(base: u64) -> Self {
        Self {
            base,
            clock: VirtualClock::new(hifitime::Epoch::from_tai_seconds(base as f64)),
        }
    }

    fn now(&self) -> u64 {
        self.base + self.clock.now_ns() / 1_000_000_000
    }

    fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }
}

#[derive(Clone, Debug)]
struct MembershipSupport {
    member: Member,
    subject: Subject,
    proof: Vec<PatchNode<()>>,
}

impl MembershipSupport {
    fn key(&self) -> [u8; 128] {
        let mut key = [0; 128];
        key[..96].copy_from_slice(&self.member.key());
        key[96..].copy_from_slice(&self.subject.binding());
        key
    }

    fn verify(&self, cost: &mut Cost) -> Result<()> {
        ensure!(
            self.member.provider == self.subject.provider(),
            "provider mismatch"
        );
        match &self.subject {
            Subject::Entry(member) => {
                ensure!(
                    member == &self.member && self.proof.is_empty(),
                    "entry mismatch"
                );
            }
            Subject::Root {
                range, inventory, ..
            } => {
                ensure!(
                    range.contains(self.member.locator),
                    "member outside signed scope"
                );
                verify_inclusion(*inventory, self.member.inventory_key(), &self.proof, cost)?;
            }
        }
        Ok(())
    }
}

fn inclusion(inventory: &InventoryPatch, key: [u8; 64]) -> Result<Vec<PatchNode<()>>> {
    ensure!(inventory.get(&key).is_some(), "absent inventory member");
    let mut prefix = Vec::new();
    let mut proof = Vec::new();
    loop {
        let PatchNodeResponse::Found(node) =
            patch_node_response(inventory, &[], &prefix, |_, ()| Ok(()))?
        else {
            bail!("inventory proof node absent");
        };
        let next = match &node {
            PatchNode::Leaf { .. } => None,
            PatchNode::Branch { branch, .. } => {
                Some(key[..=usize::from(branch.end_depth)].to_vec())
            }
        };
        proof.push(node);
        ensure!(proof.len() <= MAX_PROOF_NODES, "inclusion path budget");
        match next {
            Some(next) => prefix = next,
            None => return Ok(proof),
        }
    }
}

fn verify_inclusion(
    summary: PatchSummary,
    key: [u8; 64],
    proof: &[PatchNode<()>],
    cost: &mut Cost,
) -> Result<()> {
    ensure!(
        !proof.is_empty() && proof.len() <= MAX_PROOF_NODES,
        "inclusion path budget"
    );
    let mut digest = summary
        .root()
        .ok_or_else(|| anyhow::anyhow!("empty inventory"))?;
    let mut count = summary.leaf_count();
    let mut prefix = Vec::new();
    for (index, node) in proof.iter().enumerate() {
        let request = PatchRepairRequest::new(summary, 64, prefix.clone(), digest)?;
        validate_patch_node(&request, 64, &[], node, |raw, ()| {
            ensure!(raw == key.as_slice(), "proof names another member");
            Ok(())
        })?;
        ensure!(node.leaf_count() == count, "inclusion child count mismatch");
        cost.proof_nodes_verified += 1;
        match node {
            PatchNode::Leaf { .. } => {
                ensure!(index + 1 == proof.len(), "trailing inclusion nodes");
                return Ok(());
            }
            PatchNode::Branch { branch, .. } => {
                cost.proof_child_summaries_verified += branch.children.len();
                let depth = usize::from(branch.end_depth);
                ensure!(
                    key[..depth] == branch.representative[..depth],
                    "compressed prefix mismatch"
                );
                let child = branch
                    .children
                    .iter()
                    .find(|child| child.edge == key[depth])
                    .ok_or_else(|| anyhow::anyhow!("inclusion child absent"))?;
                prefix = key[..=depth].to_vec();
                digest = child.digest;
                count = child.leaf_count;
            }
        }
    }
    bail!("inclusion path did not reach a leaf")
}

#[derive(Clone)]
struct Directory {
    range: Range,
    content: ContentPatch,
    leases: LeasePatch,
}

impl Directory {
    fn new(range: Range) -> Self {
        Self {
            range,
            content: ContentPatch::new(),
            leases: LeasePatch::new(),
        }
    }

    fn live_lease(&self, subject: &Subject, now: u64) -> Option<Arc<Lease>> {
        // Deliberately tiny model lookup, not a proposed production scan/index.
        self.leases
            .iter()
            .filter_map(|id| self.leases.get(id))
            .filter(|lease| &lease.subject == subject && lease.live(now))
            .max_by_key(|lease| (lease.expires_at, lease.id()))
            .cloned()
    }

    fn receive_lease(&mut self, lease: Arc<Lease>, now: u64, cost: &mut Cost) -> Result<()> {
        lease.verify(now, cost)?;
        let id = lease.id();
        if self.leases.get(&id).is_none() {
            ensure!(self.leases.len() < MAX_MODEL_ITEMS, "lease capacity");
            self.leases.insert(&Entry::with_value(&id, lease));
            cost.lease_writes += 1;
        }
        Ok(())
    }

    fn receive_content(
        &mut self,
        support: Arc<MembershipSupport>,
        now: u64,
        cost: &mut Cost,
    ) -> Result<()> {
        ensure!(
            self.range.contains(support.member.locator),
            "outside responsibility"
        );
        ensure!(
            self.live_lease(&support.subject, now).is_some(),
            "no live exact inventory lease"
        );
        support.verify(cost)?;
        let key = support.key();
        if self.content.get(&key).is_none() {
            ensure!(self.content.len() < MAX_MODEL_ITEMS, "content capacity");
            self.content.insert(&Entry::with_value(&key, support));
            cost.content_writes += 1;
        }
        Ok(())
    }

    fn active(&self, now: u64) -> BTreeSet<Member> {
        self.content
            .iter()
            .filter_map(|key| self.content.get(key))
            .filter(|support| {
                self.range.contains(support.member.locator)
                    && self.live_lease(&support.subject, now).is_some()
            })
            .map(|support| support.member)
            .collect()
    }

    fn expiry(&self, member: Member, now: u64) -> Option<u64> {
        self.content
            .iter()
            .filter_map(|key| self.content.get(key))
            .filter(|support| support.member == member)
            .filter_map(|support| self.live_lease(&support.subject, now))
            .map(|lease| lease.expires_at)
            .max()
    }

    fn project(&self, range: Range, now: u64) -> Self {
        let mut selected = Self::new(range);
        // Preserve unchanged membership nodes, including during lease-only
        // renewal. This tiny model still scans to select a range; it does not
        // claim a production projection-time complexity bound.
        selected.content = self.content.clone();
        for key in self.content.iter() {
            let support = self.content.get(key).unwrap();
            if !range.contains(support.member.locator) {
                selected.content.remove(key);
                continue;
            }
            if let Some(lease) = self.live_lease(&support.subject, now) {
                selected
                    .leases
                    .insert(&Entry::with_value(&lease.id(), lease));
            } else {
                selected.content.remove(key);
            }
        }
        selected
    }

    fn repair_from(&mut self, source: &Self, now: u64, cost: &mut Cost) -> Result<()> {
        self.repair_from_with(source, now, cost, |directory, support, cost| {
            directory.receive_content(support, now, cost)
        })
    }

    // One test-only transport seam; selection, repair, signed leases, and the
    // final membership verifier remain shared by both proof representations.
    fn repair_from_with(
        &mut self,
        source: &Self,
        now: u64,
        cost: &mut Cost,
        mut receive: impl FnMut(&mut Self, Arc<MembershipSupport>, &mut Cost) -> Result<()>,
    ) -> Result<()> {
        // This pinned projection transfers only the receiver-selected range.
        // Production must locate it structurally; model projection is not timed.
        let pinned = source.project(self.range, now);
        let local_leases = self.project(self.range, now).leases;
        for id in missing(&pinned.leases, &local_leases, cost)? {
            let lease = pinned.leases.get(&id).unwrap().clone();
            ensure!(lease.id() == id, "lease body does not bind leaf key");
            cost.lease_leaves_sent += 1;
            self.receive_lease(lease, now, cost)?;
        }
        for key in missing(&pinned.content, &self.content, cost)? {
            let support = pinned.content.get(&key).unwrap().clone();
            ensure!(support.key() == key, "content body does not bind leaf key");
            cost.content_leaves_sent += 1;
            receive(self, support, cost)?;
        }
        Ok(())
    }

    fn restore(range: Range, checkpoint: &Self, now: u64) -> Result<Self> {
        let mut directory = Self::new(range);
        // Revalidate preserved signed evidence; NEVER use now + lifetime.
        directory.repair_from(checkpoint, now, &mut Cost::default())?;
        Ok(directory)
    }
}

/// The keys of `remote` that `local` lacks, found as a receiver prunes a
/// pushed tree: the remote tree is walked from its root, every subtree
/// `local` holds whole is skipped, and each node visited is one request.
fn missing<const N: usize, V>(
    remote: &PATCH<N, IdentitySchema, V, Blake3Merkle>,
    local: &PATCH<N, IdentitySchema, V, Blake3Merkle>,
    cost: &mut Cost,
) -> Result<Vec<[u8; N]>> {
    ensure!(remote.len() <= MAX_MODEL_ITEMS, "repair inventory budget");
    let summary = |patch: &PATCH<N, IdentitySchema, V, Blake3Merkle>, prefix: &[u8]| {
        patch
            .merkle_node(prefix)
            .map(|node| PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap())
    };
    let pinned = PatchSummary::from_patch(remote);
    let mut result = Vec::new();
    let mut requests = 0;
    let mut pending = vec![Vec::new()];
    while let Some(prefix) = pending.pop() {
        let Some(wanted) = summary(remote, &prefix) else {
            continue;
        };
        if summary(local, &prefix) == Some(wanted) {
            continue;
        }
        requests += 1;
        ensure!(requests <= MAX_MODEL_NODE_REQUESTS, "repair request budget");
        cost.repair_node_requests += 1;
        let PatchNodeResponse::Found(node) =
            patch_node_response(remote, &[], &prefix, |_, _| Ok(()))?
        else {
            bail!("a pinned tree holds the nodes its branches name");
        };
        let request = PatchRepairRequest::new(pinned, N, prefix, wanted.root().unwrap())?;
        validate_patch_node(&request, N, &[], &node, |_, ()| Ok(()))?;
        match node {
            PatchNode::Leaf { leaf, .. } => {
                let key: [u8; N] = leaf.key.as_slice().try_into().unwrap();
                if local.get(&key).is_none() {
                    result.push(key);
                }
            }
            PatchNode::Branch { branch, .. } => {
                let end = usize::from(branch.end_depth);
                for child in branch.children.iter().rev() {
                    let mut locator = branch.representative[..end].to_vec();
                    locator.push(child.edge);
                    pending.push(locator);
                }
            }
        }
    }
    Ok(result)
}

fn fixture(count: usize) -> (SigningKey, Vec<Member>, InventoryPatch) {
    let signer = SigningKey::from_bytes(&[73; 32]);
    let provider = signer.verifying_key().to_bytes();
    let members = (0..count)
        .map(|index| {
            let mut hash = blake3::Hasher::new_derive_key(FIXTURE_DOMAIN);
            hash.update(&(index as u64).to_be_bytes());
            let handle = *hash.finalize().as_bytes();
            // H exists only at the provider fixture boundary; no model message,
            // membership, directory or signature stores/transmits it.
            Member {
                locator: super::blob_locator(handle),
                provider,
                token: super::blob_provider_token(handle, provider),
            }
        })
        .collect::<Vec<_>>();
    let inventory = InventoryPatch::from_keys(members.iter().map(|member| member.inventory_key()));
    (signer, members, inventory)
}

fn root_subject(signer: &SigningKey, inventory: &InventoryPatch) -> Subject {
    Subject::Root {
        provider: signer.verifying_key().to_bytes(),
        range: Range::ALL,
        inventory: PatchSummary::from_patch(inventory),
    }
}

fn install_issued(directory: &mut Directory, lease: Arc<Lease>) {
    // Locally issued certificate already has trusted construction provenance.
    directory
        .leases
        .insert(&Entry::with_value(&lease.id(), lease));
}

fn publish(
    root_mode: bool,
    signer: &SigningKey,
    members: &[Member],
    inventory: &InventoryPatch,
    now: u64,
    expires: u64,
    cost: &mut Cost,
) -> Directory {
    let mut source = Directory::new(Range::ALL);
    let mut budget = Budget::unlimited();
    let root = root_subject(signer, inventory);
    if root_mode {
        install_issued(
            &mut source,
            Lease::issue(root.clone(), now, expires, signer, &mut budget, cost).unwrap(),
        );
    }
    for member in members {
        let subject = if root_mode {
            root.clone()
        } else {
            Subject::Entry(*member)
        };
        if !root_mode {
            install_issued(
                &mut source,
                Lease::issue(subject.clone(), now, expires, signer, &mut budget, cost).unwrap(),
            );
        }
        let proof = if root_mode {
            inclusion(inventory, member.inventory_key()).unwrap()
        } else {
            Vec::new()
        };
        let support = Arc::new(MembershipSupport {
            member: *member,
            subject,
            proof,
        });
        source
            .content
            .insert(&Entry::with_value(&support.key(), support));
    }
    assert_eq!(budget.charged, members.len() as u64);
    source
}

#[test]
fn forwarding_restart_and_expired_replay_never_extend_a_lease() {
    for root_mode in [false, true] {
        let (signer, members, inventory) = fixture(32);
        let clock = TestClock::at(1_000_000);
        let expires = clock.now() + 100;
        let mut source = publish(
            root_mode,
            &signer,
            &members,
            &inventory,
            clock.now(),
            expires,
            &mut Cost::default(),
        );
        for _ in 0..4 {
            clock.advance(20);
            let mut forwarded = Directory::new(Range::ALL);
            forwarded
                .repair_from(&source, clock.now(), &mut Cost::default())
                .unwrap();
            assert_eq!(forwarded.expiry(members[0], clock.now()), Some(expires));
            let restarted_clock = TestClock::at(clock.now());
            source = Directory::restore(Range::ALL, &forwarded, restarted_clock.now()).unwrap();
            assert_eq!(
                source.expiry(members[0], restarted_clock.now()),
                Some(expires)
            );
        }
        let stale_checkpoint = source.clone();
        clock.advance(20);
        assert!(source.active(clock.now()).is_empty());
        let restored = Directory::restore(Range::ALL, &stale_checkpoint, clock.now()).unwrap();
        assert!(restored.content.is_empty() && restored.leases.is_empty());
        let lease = stale_checkpoint
            .leases
            .get(stale_checkpoint.leases.iter().next().unwrap())
            .unwrap()
            .clone();
        assert!(
            source
                .receive_lease(lease, clock.now(), &mut Cost::default())
                .is_err()
        );
        assert_eq!(source.expiry(members[0], clock.now()), None);
    }
}

#[test]
fn unchanged_root_renewal_changes_only_one_lease_leaf() {
    let (signer, members, inventory) = fixture(64);
    let mut issue_cost = Cost::default();
    let mut source = publish(
        true,
        &signer,
        &members,
        &inventory,
        100,
        200,
        &mut issue_cost,
    );
    let mut replica = Directory::new(Range::ALL);
    replica
        .repair_from(&source, 100, &mut Cost::default())
        .unwrap();
    let before = PatchSummary::from_patch(&replica.content);
    let mut identical = Cost::default();
    replica.repair_from(&source, 125, &mut identical).unwrap();
    assert_eq!(identical.repair_node_requests, 0);
    let mut budget = Budget::unlimited();
    let lease = Lease::issue(
        root_subject(&signer, &inventory),
        150,
        250,
        &signer,
        &mut budget,
        &mut issue_cost,
    )
    .unwrap();
    install_issued(&mut source, lease);
    let mut renewal = Cost::default();
    replica.repair_from(&source, 150, &mut renewal).unwrap();
    assert_eq!(PatchSummary::from_patch(&replica.content), before);
    assert_eq!(
        (
            renewal.content_leaves_sent,
            renewal.content_writes,
            renewal.proof_nodes_verified
        ),
        (0, 0, 0)
    );
    assert_eq!(
        (
            renewal.lease_leaves_sent,
            renewal.lease_writes,
            renewal.signatures_verified
        ),
        (1, 1, 1)
    );
    assert_eq!(budget.charged, members.len() as u64);
    assert_eq!(replica.expiry(members[0], 201), Some(250));
}

#[test]
fn changed_inventory_cannot_renew_unproven_historical_members() {
    let (signer, members, inventory) = fixture(16);
    let source = publish(
        true,
        &signer,
        &members,
        &inventory,
        100,
        200,
        &mut Cost::default(),
    );
    let mut replica = Directory::new(Range::ALL);
    replica
        .repair_from(&source, 100, &mut Cost::default())
        .unwrap();
    let changed =
        InventoryPatch::from_keys(members[1..].iter().map(|member| member.inventory_key()));
    let changed_subject = root_subject(&signer, &changed);
    let renewed = Lease::issue(
        changed_subject.clone(),
        150,
        250,
        &signer,
        &mut Budget::unlimited(),
        &mut Cost::default(),
    )
    .unwrap();
    replica
        .receive_lease(renewed, 150, &mut Cost::default())
        .unwrap();
    assert!(
        replica.active(201).is_empty(),
        "new root alone proves none of the old support bindings"
    );
    let retained = Arc::new(MembershipSupport {
        member: members[1],
        subject: changed_subject.clone(),
        proof: inclusion(&changed, members[1].inventory_key()).unwrap(),
    });
    replica
        .receive_content(retained, 201, &mut Cost::default())
        .unwrap();
    assert_eq!(replica.active(201), BTreeSet::from([members[1]]));
    let graft = Arc::new(MembershipSupport {
        member: members[0],
        subject: changed_subject,
        proof: inclusion(&inventory, members[0].inventory_key()).unwrap(),
    });
    assert!(
        replica
            .receive_content(graft, 201, &mut Cost::default())
            .is_err()
    );
    assert_eq!(replica.expiry(members[0], 201), None);
}

#[test]
fn partial_ranges_handoff_and_reseed_keep_original_expiry() {
    let (signer, members, inventory) = fixture(64);
    let provider = publish(
        true,
        &signer,
        &members,
        &inventory,
        100,
        300,
        &mut Cost::default(),
    );
    let mut left = Directory::new(Range::LEFT);
    let mut right = Directory::new(Range::RIGHT);
    left.repair_from(&provider, 100, &mut Cost::default())
        .unwrap();
    right
        .repair_from(&provider, 100, &mut Cost::default())
        .unwrap();
    let left_members = left.active(100);
    let right_members = right.active(100);
    assert!(!left_members.is_empty() && !right_members.is_empty());
    assert!(left_members.is_disjoint(&right_members));
    assert_eq!(
        left_members
            .union(&right_members)
            .copied()
            .collect::<BTreeSet<_>>(),
        members.iter().copied().collect()
    );
    assert!(left.content.len() < inventory.len() && right.content.len() < inventory.len());

    let quarter = Range { start: 0, end: 64 };
    let mut joining = Directory::new(quarter);
    joining
        .repair_from(&left, 150, &mut Cost::default())
        .unwrap();
    assert!(!joining.active(150).is_empty());
    for member in joining.active(150) {
        assert!(quarter.contains(member.locator));
        assert_eq!(joining.expiry(member, 150), Some(300));
    }
    left = left.project(
        Range {
            start: 64,
            end: 128,
        },
        150,
    );
    assert!(left.active(150).is_disjoint(&joining.active(150)));

    // Every holder of the right-hand region crashes. A surviving disjoint
    // shard cannot reconstruct it; the live provider must reseed missing leaves.
    right = Directory::new(Range::RIGHT);
    right.repair_from(&left, 180, &mut Cost::default()).unwrap();
    assert!(right.active(180).is_empty());
    let mut recovery = Cost::default();
    right.repair_from(&provider, 180, &mut recovery).unwrap();
    assert_eq!(right.active(180), right_members);
    assert_eq!(recovery.content_leaves_sent, right_members.len());
    assert!(right.active(300).is_empty());
}

#[test]
fn root_signatures_cannot_bypass_logical_member_budget() {
    let (signer, members, inventory) = fixture(8);
    let root = root_subject(&signer, &inventory);
    for limit in [0, 7] {
        let mut budget = Budget {
            remaining: Some(limit),
            charged: 0,
        };
        let mut cost = Cost::default();
        assert!(Lease::issue(root.clone(), 100, 200, &signer, &mut budget, &mut cost).is_err());
        assert_eq!((budget.charged, cost.signatures_issued), (0, 0));
    }
    let mut budget = Budget {
        remaining: Some(8),
        charged: 0,
    };
    let mut cost = Cost::default();
    Lease::issue(root.clone(), 100, 200, &signer, &mut budget, &mut cost).unwrap();
    assert_eq!((budget.charged, cost.signatures_issued), (8, 1));
    assert!(Lease::issue(root, 150, 250, &signer, &mut budget, &mut cost).is_err());
    assert!(
        Lease::issue(
            Subject::Entry(members[0]),
            150,
            250,
            &signer,
            &mut budget,
            &mut cost
        )
        .is_err()
    );
    // A deliberately smaller inventory can spend the remaining member budget;
    // roots are not an all-or-nothing policy for the entire resident store.
    let small = InventoryPatch::from_keys(members[..3].iter().map(|member| member.inventory_key()));
    let mut small_budget = Budget {
        remaining: Some(3),
        charged: 0,
    };
    Lease::issue(
        root_subject(&signer, &small),
        100,
        200,
        &signer,
        &mut small_budget,
        &mut cost,
    )
    .unwrap();
    assert_eq!(small_budget.charged, 3);
}

#[test]
fn signatures_and_inclusion_bind_provider_token_scope_and_count() {
    let (signer, members, inventory) = fixture(8);
    let source = publish(
        true,
        &signer,
        &members,
        &inventory,
        100,
        200,
        &mut Cost::default(),
    );
    let original = source
        .leases
        .get(source.leases.iter().next().unwrap())
        .unwrap()
        .as_ref()
        .clone();
    let mut tampered = original.clone();
    tampered.expires_at += 1;
    assert!(tampered.verify(100, &mut Cost::default()).is_err());
    let mut tampered = original.clone();
    if let Subject::Root {
        inventory: summary, ..
    } = &mut tampered.subject
    {
        *summary = PatchSummary::new(summary.root(), summary.leaf_count() + 1).unwrap();
    }
    assert!(tampered.verify(100, &mut Cost::default()).is_err());
    let mut tampered = original.clone();
    if let Subject::Root { range, .. } = &mut tampered.subject {
        *range = Range::LEFT;
    }
    assert!(tampered.verify(100, &mut Cost::default()).is_err());
    let mut tampered = original;
    if let Subject::Root { provider, .. } = &mut tampered.subject {
        *provider = SigningKey::from_bytes(&[74; 32]).verifying_key().to_bytes();
    }
    assert!(tampered.verify(100, &mut Cost::default()).is_err());

    let proof = inclusion(&inventory, members[0].inventory_key()).unwrap();
    let mut changed = members[0];
    changed.token[0] ^= 1;
    assert!(
        verify_inclusion(
            PatchSummary::from_patch(&inventory),
            changed.inventory_key(),
            &proof,
            &mut Cost::default()
        )
        .is_err()
    );
    assert!(
        verify_inclusion(
            PatchSummary::from_patch(&inventory),
            members[1].inventory_key(),
            &proof,
            &mut Cost::default()
        )
        .is_err()
    );
}

#[test]
fn deterministic_cost_probe_separates_measured_work_from_analytic_requests() {
    const N: usize = 64;
    let (signer, members, inventory) = fixture(N);
    for root_mode in [false, true] {
        let mut issued = Cost::default();
        let mut source = publish(
            root_mode,
            &signer,
            &members,
            &inventory,
            100,
            200,
            &mut issued,
        );
        let mut replica = Directory::new(Range::ALL);
        let mut cold = Cost::default();
        replica.repair_from(&source, 100, &mut cold).unwrap();
        let subjects = if root_mode {
            vec![root_subject(&signer, &inventory)]
        } else {
            members.iter().copied().map(Subject::Entry).collect()
        };
        let mut renewal_issue = Cost::default();
        let mut budget = Budget::unlimited();
        for subject in subjects {
            install_issued(
                &mut source,
                Lease::issue(subject, 150, 250, &signer, &mut budget, &mut renewal_issue).unwrap(),
            );
        }
        let mut warm = Cost::default();
        replica.repair_from(&source, 150, &mut warm).unwrap();
        let certificates = if root_mode { 1 } else { N };
        assert_eq!(issued.signatures_issued, certificates);
        assert_eq!(renewal_issue.signatures_issued, certificates);
        assert_eq!(cold.content_leaves_sent, N);
        assert_eq!(warm.lease_leaves_sent, certificates);
        assert_eq!(
            (
                warm.content_leaves_sent,
                warm.content_writes,
                warm.proof_nodes_verified
            ),
            (0, 0, 0)
        );
        assert_eq!(replica.active(201).len(), N);
        println!(
            "model_measured mode={} n={N} cold={cold:?} renewal={warm:?} renewal_signatures={} logical_members_charged={}",
            if root_mode { "root" } else { "entry" },
            renewal_issue.signatures_issued,
            budget.charged
        );
        let mut identical = Cost::default();
        replica.repair_from(&source, 175, &mut identical).unwrap();
        assert_eq!(identical.repair_node_requests, 0);

        if root_mode {
            let changed =
                InventoryPatch::from_keys(members[1..].iter().map(|member| member.inventory_key()));
            let changed_source = publish(
                true,
                &signer,
                &members[1..],
                &changed,
                180,
                280,
                &mut Cost::default(),
            );
            let mut refresh = Cost::default();
            replica
                .repair_from(&changed_source, 180, &mut refresh)
                .unwrap();
            // Naive independent inclusion paths need one new support witness
            // per retained member after a global root changes. This is measured
            // cost, not an assumed O(delta) proof-forest implementation.
            assert_eq!(refresh.content_leaves_sent, N - 1);
            assert_eq!(refresh.content_writes, N - 1);
            assert!(refresh.proof_nodes_verified >= N - 1);
            assert_eq!(
                replica.active(201).len(),
                N,
                "old valid root is not revoked"
            );
            assert_eq!(replica.active(251).len(), N - 1);
            println!(
                "model_measured mode=root_changed_one_removal retained={} refresh={refresh:?}",
                N - 1
            );
        }
    }

    // Complete-topology exact placement oracle, NOT a distributed lookup.
    let peers = (1..=64)
        .map(|byte| {
            SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .to_bytes()
        })
        .collect::<Vec<_>>();
    let mut grouped = BTreeMap::<[u8; 32], BTreeSet<Member>>::new();
    for member in &members {
        let mut closest = peers.clone();
        closest.sort_unstable_by(|a, b| distance_cmp(member.locator, *a, *b));
        for peer in closest.into_iter().take(K) {
            grouped.entry(peer).or_default().insert(*member);
        }
    }
    assert_eq!(grouped.values().map(BTreeSet::len).sum::<usize>(), N * K);
    for member in &members {
        assert_eq!(
            grouped
                .values()
                .filter(|batch| batch.contains(member))
                .count(),
            K
        );
    }
    assert!(grouped.values().all(|batch| batch.len() <= N));
    println!(
        "model_oracle n={N} peers={} replicas={K} put_memberships={} grouped_frames={} frame_member_bound={N}; analytic_current_rpc_count=N*q+N*K (q is NOT measured); analytic_unchanged_root_certificates=R (R interested replicas, not global DHT replication)",
        peers.len(),
        N * K,
        grouped.len()
    );
}
