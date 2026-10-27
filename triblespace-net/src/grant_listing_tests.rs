//! The grant exchange around the walks (design: grants gossip by
//! participation): grants a walk kept whose descriptor is not resident wait
//! in bounded memory and land only once they validate. Every negative
//! assertion has a positive control in the same test.

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::TryFromBlob as _;
use triblespace_core::capability::{CapabilityHandle, CapabilityProof};
use triblespace_core::collection::CollectionHandle;
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::{
    BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource, StoreChanges,
};
use triblespace_core::trible::TribleSet;

use super::*;
use crate::grants_index_tests::{deliver, grant, handle_of, id, key, resource};
use crate::host::ActiveCollections;

/// One node's pile and grant exchange.
struct Node {
    key: SigningKey,
    store: MemoryRepo,
    active: ActiveCollections,
    grants: Grants<MemoryRepoSnapshot>,
}

impl Node {
    fn new(byte: u8) -> Self {
        let key = key(byte);
        Self {
            grants: Grants::new(key.verifying_key().to_bytes()),
            key,
            store: MemoryRepo::default(),
            active: ActiveCollections::new(),
        }
    }

    fn put(&mut self, facts: &TribleSet) -> CollectionHandle {
        self.store.put::<SimpleArchive, _>(facts.clone()).unwrap()
    }

    fn snapshot(&mut self) -> StoreSnapshot<MemoryRepoSnapshot> {
        StoreSnapshot::from_store_changes(
            self.store.snapshot().unwrap(),
            &self.active,
            self.key.verifying_key(),
            None,
            None,
            StoreChanges::ALL,
        )
        .unwrap()
    }

    fn observe(&mut self) -> Effects {
        let snapshot = self.snapshot();
        self.grants.observe(snapshot)
    }

    fn proofs(&mut self) -> usize {
        self.store.snapshot().unwrap().proofs().unwrap().count()
    }

    /// Land what the exchange asked to land, as the host's admission does.
    fn land(&mut self, effects: &Effects) {
        for proof in &effects.land {
            self.store.insert_proof(proof.clone()).unwrap();
        }
    }
}

/// A resource rooted at `root` with one delegable definition: its
/// descriptor and definition facts, not yet put anywhere, and its handles.
fn unheld(root: &SigningKey, label: &str) -> (TribleSet, TribleSet, CollectionHandle, CapabilityHandle) {
    let definition = deliver(true);
    let handle = handle_of(&definition);
    let descriptor = resource(&[(root, handle)], label);
    let r = {
        use triblespace_core::blob::IntoBlob;
        CollectionHandle::new(IntoBlob::<SimpleArchive>::to_blob(descriptor.clone()).get_handle().raw)
    };
    (descriptor, definition, r, handle)
}

fn now() -> Mono {
    crate::clock::mono_now()
}

fn pending(peer: PeerId, proof: &CapabilityProof) -> GrantEvent {
    GrantEvent::Pending {
        peer,
        proof: proof.clone(),
    }
}

#[test]
fn a_pending_grant_lands_only_once_its_descriptor_arrives() {
    let [alice, bob_key, carol] = [0xC0, 0xC1, 0xC2].map(key);
    let mut bob = Node::new(0xC1);
    bob.observe();
    let (descriptor, definition, r, handle) = unheld(&alice, "arrives later");
    let proof = grant(r, &alice, handle, &bob_key);

    let effects = bob.grants.walked(pending(id(&carol), &proof), now());
    assert!(effects.land.is_empty(), "no descriptor, no landing");
    assert!(
        effects
            .fetch
            .iter()
            .any(|fetch| fetch.blobs.contains(&r.raw) && fetch.sources.first() == Some(&id(&carol))),
        "the descriptor is fetched from the sender first: {:?}",
        effects.fetch
    );
    assert!(bob.grants.waiting().contains(id(&carol), &proof));
    assert_eq!(bob.proofs(), 0);
    // A waiting grant names no participant and admits nothing.
    let snapshot = bob.snapshot();
    assert!(!snapshot.grants().participates(r, id(&bob_key)));
    assert!(snapshot.grants().grants(r).is_none());

    bob.put(&definition);
    bob.put(&descriptor);
    let effects = bob.observe();
    assert_eq!(effects.land, [proof.clone()], "positive control: it lands");
    assert!(!bob.grants.waiting().contains(id(&carol), &proof));
    bob.land(&effects);
    assert_eq!(bob.proofs(), 1);
}

#[test]
fn a_pending_grant_that_starts_outside_r_s_roots_is_dropped_once_r_arrives() {
    let [alice, bob_key, carol, mallory] = [0xD0, 0xD1, 0xD2, 0xDF].map(key);
    let mut bob = Node::new(0xD1);
    bob.observe();
    let (descriptor, definition, r, handle) = unheld(&alice, "rooted elsewhere");
    let wrong = grant(r, &mallory, handle, &bob_key);
    let valid = grant(r, &alice, handle, &bob_key);
    for proof in [&wrong, &valid] {
        assert!(bob.grants.walked(pending(id(&carol), proof), now()).land.is_empty());
        assert!(bob.grants.waiting().contains(id(&carol), proof));
    }
    bob.put(&definition);
    bob.put(&descriptor);
    let effects = bob.observe();
    assert_eq!(effects.land, [valid.clone()], "only the rooted one lands");
    assert!(!bob.grants.waiting().contains(id(&carol), &wrong));
    assert_eq!(bob.grants.waiting().size().0, 0);
}

/// One more grant than a sender's share evicts exactly that sender's oldest;
/// another sender's grants stay.
#[test]
fn pending_grants_are_bounded_per_sender_and_evict_the_oldest() {
    let [alice, carol, dave] = [0xE0, 0xE2, 0xE3].map(key);
    let mut bob = Node::new(0xE1);
    bob.observe();
    let (_, _, r, handle) = unheld(&alice, "bounded");
    let subject = |index: usize| {
        let mut seed = [0xE5; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        SigningKey::from_bytes(&seed)
    };
    let others = grant(r, &alice, handle, &subject(10_000));
    bob.grants.walked(pending(id(&dave), &others), now());
    let proofs: Vec<_> = (0..=MAX_PENDING_PER_SENDER)
        .map(|index| grant(r, &alice, handle, &subject(index)))
        .collect();
    for proof in &proofs {
        bob.grants.walked(pending(id(&carol), proof), now());
    }
    assert_eq!(bob.grants.waiting().kept(id(&carol)), MAX_PENDING_PER_SENDER);
    assert!(!bob.grants.waiting().contains(id(&carol), &proofs[0]), "the oldest left");
    assert!(bob.grants.waiting().contains(id(&carol), &proofs[1]));
    assert!(bob.grants.waiting().contains(id(&carol), &proofs[MAX_PENDING_PER_SENDER]));
    assert_eq!(bob.grants.waiting().kept(id(&dave)), 1, "another sender's share is its own");
    assert!(bob.grants.waiting().contains(id(&dave), &others));
}

/// The total and byte bounds evict the oldest grant of the sender holding
/// the most, the first to arrive of equals.
#[test]
fn pending_grants_are_bounded_in_all_and_in_bytes() {
    let [alice, carol, dave] = [0xF0, 0xF2, 0xF3].map(key);
    let (_, _, r, handle) = unheld(&alice, "bounded in all");
    let proofs: Vec<_> = (0..6u8)
        .map(|index| grant(r, &alice, handle, &key(0x10 + index)))
        .collect();
    let size = proofs[0].as_bytes().len();
    assert!(proofs.iter().all(|proof| proof.as_bytes().len() == size));

    let mut pending = Pending::new(PendingLimits {
        per_sender: 10,
        total: 3,
        bytes: usize::MAX,
    });
    for (index, proof) in proofs[..4].iter().enumerate() {
        let sender = if index % 2 == 0 { id(&carol) } else { id(&dave) };
        let evicted = pending.insert(sender, proof.clone());
        assert_eq!(evicted.len(), usize::from(index == 3));
    }
    assert_eq!(pending.size(), (3, 3 * size));
    assert!(!pending.contains(id(&carol), &proofs[0]), "the oldest of all left");
    assert!(pending.contains(id(&dave), &proofs[1]));

    let mut pending = Pending::new(PendingLimits {
        per_sender: 10,
        total: 10,
        bytes: 2 * size + size / 2,
    });
    for proof in &proofs[..3] {
        pending.insert(id(&carol), proof.clone());
    }
    assert_eq!(pending.size(), (2, 2 * size), "two fit the byte bound, three do not");
    assert!(!pending.contains(id(&carol), &proofs[0]));
    assert!(pending.contains(id(&carol), &proofs[2]));
}

#[test]
fn a_sender_s_pending_grants_leave_with_its_last_connection() {
    let [alice, bob_key, carol, dave] = [0x20, 0x21, 0x22, 0x23].map(key);
    let mut bob = Node::new(0x21);
    bob.observe();
    let (_, _, r, handle) = unheld(&alice, "leaves");
    let from_carol = grant(r, &alice, handle, &bob_key);
    let from_dave = grant(r, &alice, handle, &key(0x24));
    let (carol_link, _carol_frames) = Link::detached(1, id(&carol));
    let (dave_link, _dave_frames) = Link::detached(2, id(&dave));
    bob.grants.event(&ReconEvent::Opened(carol_link.clone()));
    bob.grants.event(&ReconEvent::Opened(dave_link.clone()));
    bob.grants.walked(pending(id(&carol), &from_carol), now());
    bob.grants.walked(pending(id(&dave), &from_dave), now());
    bob.grants.event(&ReconEvent::Closed(carol_link));
    assert!(!bob.grants.waiting().contains(id(&carol), &from_carol));
    assert!(
        bob.grants.waiting().contains(id(&dave), &from_dave),
        "positive control: a connected sender's grant stays"
    );
}

// ---- GRANT_ROOTS: listing to participants, walks on a root mismatch ----

/// A connection seen from one node: its link and the frames queued on it.
struct Linked {
    link: Link,
    frames: tokio::sync::mpsc::Receiver<Frame>,
}

/// Open a connection from `node` to `peer` with local id `id`.
fn open_to(node: &mut Node, peer: PeerId, id: u64) -> (Linked, Effects) {
    let (link, frames) = Link::detached(id, peer);
    let effects = node.grants.event(&ReconEvent::Opened(link.clone()));
    (Linked { link, frames }, effects)
}

/// Every resource listed on `linked` so far, with its summary.
fn listed(linked: &mut Linked) -> Vec<(CollectionHandle, PatchSummary)> {
    let mut roots = Vec::new();
    while let Ok(frame) = linked.frames.try_recv() {
        if let Frame::GrantRoots(entries) = frame {
            roots.extend(entries);
        }
    }
    roots
}

fn hear(node: &mut Node, linked: &Linked, roots: Vec<(CollectionHandle, PatchSummary)>) -> Effects {
    node.grants
        .event(&ReconEvent::Frame(linked.link.clone(), Frame::GrantRoots(roots)))
}

fn summary(byte: u8) -> PatchSummary {
    PatchSummary::new(Some([byte; 32]), 1).unwrap()
}

fn handle(index: u64) -> CollectionHandle {
    let mut raw = [0x99; 32];
    raw[..8].copy_from_slice(&index.to_be_bytes());
    CollectionHandle::new(raw)
}

/// A node holding R (rooted at `alice`, granted to `bob`) and an Open-READ
/// collection C it may write: (R, C).
fn holding(node: &mut Node, alice: &SigningKey, bob: &SigningKey) -> (CollectionHandle, CollectionHandle) {
    use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
    use triblespace_core::patch::Entry;
    let (descriptor, definition, r, handle) = unheld(alice, "listed");
    node.put(&definition);
    node.put(&descriptor);
    node.store
        .insert_proof(grant(r, alice, handle, bob))
        .unwrap();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(node.key.verifying_key()),
    );
    let c = node.store.collection("open read", policy).unwrap().handle();
    node.active.insert(&Entry::new(&c.raw));
    (r, c)
}

#[test]
fn each_participant_is_listed_its_resources_and_a_stranger_nothing() {
    let [alice, bob, carol, stranger] = [0x30, 0x31, 0x32, 0x3F].map(key);
    let mut host = Node::new(0x3A);
    let (r, c) = holding(&mut host, &alice, &bob);
    host.observe();
    let index = host.snapshot().grants().clone();
    let (mut to_alice, _) = open_to(&mut host, id(&alice), 1);
    let (mut to_bob, _) = open_to(&mut host, id(&bob), 2);
    let (mut to_carol, _) = open_to(&mut host, id(&carol), 3);
    let (mut to_stranger, _) = open_to(&mut host, id(&stranger), 4);
    host.grants.peered([(3, c, true)]);
    host.observe();
    let r_listed = (r, index.summary(r));
    assert_eq!(index.summary(r).leaf_count(), 1);
    assert_eq!(listed(&mut to_alice), [r_listed], "a root of R");
    assert_eq!(listed(&mut to_bob), [r_listed], "a key named on a grant over R");
    assert_eq!(
        listed(&mut to_carol),
        [(c, index.summary(c))],
        "a peer peered for an Open-READ C"
    );
    assert!(listed(&mut to_stranger).is_empty(), "a stranger hears of nothing");
}

#[test]
fn a_host_of_two_teams_lists_only_the_member_s_team() {
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionPolicy, CollectionStoreExt, read_capability,
    };
    use triblespace_core::patch::Entry;
    let [owner_a, member_a, owner_b, member_b] = [0x40, 0x41, 0x42, 0x43].map(key);
    let mut host = Node::new(0x4A);
    let mut team = |owner: &SigningKey, member: &SigningKey, name: &str| {
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(owner.verifying_key()),
            AdmissionPolicy::direct(owner.verifying_key()),
        );
        let collection = host.store.collection(name, policy).unwrap().handle();
        host.active.insert(&Entry::new(&collection.raw));
        host.store
            .insert_proof(grant(collection, owner, read_capability(), member))
            .unwrap();
        collection
    };
    let ca = team(&owner_a, &member_a, "team a");
    let cb = team(&owner_b, &member_b, "team b");
    host.observe();
    let (mut to_a, _) = open_to(&mut host, id(&member_a), 1);
    host.observe();
    let roots = listed(&mut to_a);
    assert!(roots.iter().any(|(resource, _)| *resource == ca), "CA is listed: {roots:?}");
    assert!(roots.iter().all(|(resource, _)| *resource != cb), "CB is not: {roots:?}");
}

#[test]
fn a_differing_root_opens_one_walk_per_link_resource_and_root() {
    let [alice, bob, peer] = [0x50, 0x51, 0x5F].map(key);
    let mut host = Node::new(0x5A);
    let (r, _) = holding(&mut host, &alice, &bob);
    host.observe();
    let local = host.snapshot().grants().summary(r);
    let (linked, _) = open_to(&mut host, id(&peer), 1);
    assert!(hear(&mut host, &linked, vec![(r, local)]).walks.is_empty(), "equal roots");
    assert_eq!(hear(&mut host, &linked, vec![(r, summary(1))]).walks, [(id(&peer), r)]);
    assert!(hear(&mut host, &linked, vec![(r, summary(1))]).walks.is_empty(), "once per root");
    assert_eq!(hear(&mut host, &linked, vec![(r, summary(2))]).walks, [(id(&peer), r)]);
    // Another connection is its own.
    let (other, _) = open_to(&mut host, id(&key(0x5E)), 2);
    assert_eq!(hear(&mut host, &other, vec![(r, summary(2))]).walks, [(id(&key(0x5E)), r)]);
}

#[test]
fn unknown_resources_are_charged_to_a_per_connection_budget() {
    let peer = key(0x6F);
    let mut host = Node::new(0x6A);
    host.observe();
    let (linked, _) = open_to(&mut host, id(&peer), 1);
    let roots = (0..300).map(|index| (handle(index), summary(1))).collect();
    let effects = hear(&mut host, &linked, roots);
    assert_eq!(effects.walks.len(), MAX_UNKNOWN_RESOURCES_PER_LINK, "exactly the budget");
    // A charged resource is still heard; an uncharged one is not.
    assert_eq!(hear(&mut host, &linked, vec![(handle(0), summary(2))]).walks.len(), 1);
    assert!(hear(&mut host, &linked, vec![(handle(299), summary(2))]).walks.is_empty());
    // A new connection has its own budget.
    let (fresh, _) = open_to(&mut host, id(&peer), 2);
    assert_eq!(hear(&mut host, &fresh, vec![(handle(299), summary(2))]).walks.len(), 1);
}

#[test]
fn a_waiting_grant_fetches_its_descriptor_and_every_definition_from_a_lister_first() {
    let [alice, xavier, bob_key, carol] = [0x70, 0x71, 0x72, 0x73].map(key);
    let mut bob = Node::new(0x72);
    let (_, first, r, handle) = unheld(&alice, "cold");
    let second = {
        use triblespace_core::capability::capability_action;
        use triblespace_core::prelude::entity;
        entity! { capability_action: crate::grants_index_tests::ACTION_TEST_DELIVER,
            triblespace_core::metadata::name: "second step" }
        .facts()
        .clone()
    };
    let chain = grant(r, &alice, handle, &xavier)
        .delegate(&xavier, handle_of(&second), bob_key.verifying_key())
        .unwrap();
    bob.store.insert_proof(chain.clone()).unwrap();
    bob.observe();
    let (linked, _) = open_to(&mut bob, id(&carol), 1);
    let mut effects = hear(&mut bob, &linked, vec![(r, summary(1))]);
    let more = bob.observe();
    effects.fetch.extend(more.fetch);
    let wanted = [r.raw, handle.raw, handle_of(&second).raw];
    let fetch = effects
        .fetch
        .iter()
        .find(|fetch| wanted.iter().all(|blob| fetch.blobs.contains(blob)))
        .unwrap_or_else(|| panic!("one fetch of all three: {:?}", effects.fetch));
    assert_eq!(fetch.sources.first(), Some(&id(&carol)), "the lister first");
    let _ = first;
}

#[test]
fn a_grant_over_a_granted_unselected_collection_fetches_its_name() {
    use triblespace_core::blob::IntoBlob;
    use triblespace_core::blob::encodings::utf8string::UTF8String;
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionPolicy, CollectionStoreExt, read_capability,
    };
    let [owner, bob_key, carol] = [0x80, 0x81, 0x82].map(key);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(owner.verifying_key()),
        AdmissionPolicy::direct(owner.verifying_key()),
    );
    let mut source = MemoryRepo::default();
    let c = source.collection("granted", policy).unwrap().handle();
    let descriptor: TribleSet = {
        use triblespace_core::repo::BlobStoreGet;
        source
            .snapshot()
            .unwrap()
            .get::<TribleSet, SimpleArchive>(c)
            .unwrap()
    };
    let mut bob = Node::new(0x81);
    bob.observe();
    let read = grant(c, &owner, read_capability(), &bob_key);
    bob.grants.walked(pending(id(&carol), &read), now());
    bob.put(&descriptor);
    let effects = bob.observe();
    assert_eq!(effects.land, [read], "positive control: the grant lands");
    let name = IntoBlob::<UTF8String>::to_blob("granted").get_handle().raw;
    assert!(
        effects
            .fetch
            .iter()
            .any(|fetch| fetch.blobs.contains(&name) && fetch.sources.first() == Some(&id(&carol))),
        "the name is fetched from the sender: {:?}",
        effects.fetch
    );
}

#[test]
fn peering_for_r_reopens_a_walk_whose_root_still_differs() {
    let [alice, bob, peer] = [0x90, 0x91, 0x9F].map(key);
    let mut host = Node::new(0x9A);
    let (_, c) = holding(&mut host, &alice, &bob);
    host.observe();
    let (linked, _) = open_to(&mut host, id(&peer), 1);
    assert_eq!(hear(&mut host, &linked, vec![(c, summary(3))]).walks, [(id(&peer), c)]);
    assert!(hear(&mut host, &linked, vec![(c, summary(3))]).walks.is_empty());
    assert_eq!(
        host.grants.peered([(1, c, true)]).walks,
        [(id(&peer), c)],
        "a walk whose grants were skipped before peering opens again"
    );
    assert!(host.grants.peered([(1, c, true)]).walks.is_empty(), "only when peering starts");
}

#[test]
fn an_evicted_pending_grant_lets_the_next_listing_reopen_its_walk() {
    let [alice, peer] = [0xA0, 0xAF].map(key);
    let mut bob = Node::new(0xA1);
    bob.observe();
    let (_, _, r, handle) = unheld(&alice, "evicted");
    let (linked, _) = open_to(&mut bob, id(&peer), 1);
    assert_eq!(hear(&mut bob, &linked, vec![(r, summary(4))]).walks, [(id(&peer), r)]);
    assert!(hear(&mut bob, &linked, vec![(r, summary(4))]).walks.is_empty(), "control");
    for index in 0..=MAX_PENDING_PER_SENDER {
        let mut seed = [0xA5; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let subject = SigningKey::from_bytes(&seed);
        bob.grants
            .walked(pending(id(&peer), &grant(r, &alice, handle, &subject)), now());
    }
    assert_eq!(
        hear(&mut bob, &linked, vec![(r, summary(4))]).walks,
        [(id(&peer), r)],
        "eviction cleared what was opened"
    );
}

/// Grants over a resident blob larger than any descriptor make a walk's
/// gate decode none of it; over one within the bound, once per walk.
#[test]
fn a_stranger_cannot_make_a_grant_walk_decode_a_large_blob_or_one_per_proof() {
    use triblespace_core::blob::IntoBlob as _;
    use triblespace_core::trible::Trible;
    let stranger = key(0xB9);
    let mut node = Node::new(0xB1);
    let mut archive = |count: u64| {
        let mut facts = TribleSet::new();
        for index in 0..count {
            let mut raw = [1_u8; 64];
            raw[..8].copy_from_slice(&index.to_be_bytes());
            facts.insert(&Trible::force_raw(raw).unwrap());
        }
        let blob: triblespace_core::blob::Blob<SimpleArchive> = facts.to_blob();
        let handle = CollectionHandle::new(blob.get_handle().raw);
        node.store.put::<SimpleArchive, _>(blob.clone()).unwrap();
        let started = std::time::Instant::now();
        let _ = TribleSet::try_from_blob(blob).unwrap();
        (handle, started.elapsed())
    };
    let (large, large_decode) = archive(1 << 15);
    let (resident, resident_decode) = archive(1 << 12);
    let snapshot = node.snapshot();
    let walk = |resource: CollectionHandle| {
        let mut gate = Gate::new(resource, true);
        let proofs: Vec<_> = (0..32)
            .map(|_| grant(resource, &stranger, handle_of(&deliver(false)), &stranger))
            .collect();
        let started = std::time::Instant::now();
        for proof in proofs {
            assert!(matches!(gate.admit(&snapshot, proof), Gated::Skip));
        }
        started.elapsed()
    };
    let over_large = walk(large);
    assert!(over_large < large_decode, "{over_large:?} against one decode {large_decode:?}");
    let over_resident = walk(resident);
    assert!(
        over_resident < 4 * resident_decode,
        "{over_resident:?} against one decode {resident_decode:?}"
    );
}

// ---- walk ends, retries and backoff ----

fn ended(peer: &SigningKey, resource: CollectionHandle, outcome: GrantOutcome) -> GrantEvent {
    GrantEvent::Ended(GrantWalkEnd {
        peer: id(peer),
        resource,
        outcome,
        skipped: 0,
    })
}

fn after(base: Mono, seconds: u64) -> Mono {
    base + std::time::Duration::from_secs(seconds)
}

fn confirmed() -> GrantOutcome {
    GrantOutcome::Confirmed {
        agreed: PatchSummary::new(None, 0).unwrap(),
    }
}

/// A host connected to `peer`, which listed `summary` for R: the walk it
/// opened is the first.
fn listed_to(peer: &SigningKey, resource: CollectionHandle, summary: PatchSummary) -> (Node, Linked) {
    let mut host = Node::new(0x01);
    host.observe();
    let (linked, _) = open_to(&mut host, id(peer), 7);
    assert_eq!(hear(&mut host, &linked, vec![(resource, summary)]).walks, [(id(peer), resource)]);
    (host, linked)
}

#[test]
fn a_failed_grant_walk_reopens_after_a_backoff_on_the_same_connection() {
    let peer = key(0xB0);
    let r = handle(1);
    let (mut host, linked) = listed_to(&peer, r, summary(5));
    let base = now();
    host.grants.walked(ended(&peer, r, confirmed()), base);
    assert_eq!(host.grants.deadline(), None, "control: a confirmed walk is not retried");
    assert!(host.grants.retry(after(base, 600)).walks.is_empty());

    host.grants
        .walked(ended(&peer, r, GrantOutcome::Unconfirmed(None)), base);
    assert_eq!(host.grants.deadline(), Some(after(base, 1)));
    assert!(host.grants.retry(base).walks.is_empty(), "not before the backoff");
    assert_eq!(
        host.grants.retry(after(base, 1)).walks,
        [(id(&peer), r)],
        "the same connection, no new listing"
    );
    for outcome in [
        GrantOutcome::Replaced,
        GrantOutcome::NotStarted(NotStarted::Queued),
    ] {
        host.grants.walked(ended(&peer, r, outcome), after(base, 1));
        assert_eq!(host.grants.deadline(), None, "{outcome:?} changes nothing");
    }
    assert!(hear(&mut host, &linked, vec![(r, summary(5))]).walks.is_empty());
    for outcome in [
        GrantOutcome::Refused,
        GrantOutcome::NotStarted(NotStarted::NoConnection),
        GrantOutcome::NotStarted(NotStarted::StartDeclined),
        GrantOutcome::NotStarted(NotStarted::AlreadyRunning),
    ] {
        let mut host = listed_to(&peer, r, summary(5)).0;
        host.grants.walked(ended(&peer, r, outcome), base);
        assert_eq!(host.grants.retry(after(base, 1)).walks, [(id(&peer), r)], "{outcome:?}");
    }
}

/// A peer that refuses every walk is asked again at 1, 3, 7, 15, 31 and
/// 63 s, then once a minute: 15 walks in ten minutes, never more.
#[test]
fn a_refusing_peer_is_walked_on_the_backoff_schedule_only() {
    let peer = key(0xB1);
    let r = handle(2);
    let (mut host, _linked) = listed_to(&peer, r, summary(6));
    let base = now();
    let mut walks = 1;
    host.grants
        .walked(ended(&peer, r, GrantOutcome::Refused), base);
    while let Some(at) = host.grants.deadline() {
        if at > after(base, 600) {
            break;
        }
        for (_, resource) in host.grants.retry(at).walks {
            walks += 1;
            host.grants
                .walked(ended(&peer, resource, GrantOutcome::Refused), at);
        }
    }
    assert_eq!(walks, 15);
}

#[test]
fn a_root_change_resets_the_backoff() {
    let peer = key(0xB2);
    let r = handle(3);
    let (mut host, linked) = listed_to(&peer, r, summary(7));
    let base = now();
    let mut at = base;
    for _ in 0..4 {
        host.grants
            .walked(ended(&peer, r, GrantOutcome::Unconfirmed(None)), at);
        at = host.grants.deadline().unwrap();
        assert_eq!(host.grants.retry(at).walks.len(), 1);
    }
    host.grants
        .walked(ended(&peer, r, GrantOutcome::Unconfirmed(None)), at);
    assert_eq!(host.grants.deadline(), Some(after(at, 16)), "grown to 16 s");
    assert_eq!(
        hear(&mut host, &linked, vec![(r, summary(8))]).walks,
        [(id(&peer), r)],
        "a new root opens at once"
    );
    host.grants
        .walked(ended(&peer, r, GrantOutcome::Unconfirmed(None)), at);
    assert_eq!(host.grants.deadline(), Some(after(at, 1)), "and starts again at 1 s");
}

/// The walk confirmed while the grant it delivered waited for its
/// descriptor; when that grant is evicted, the walk opens again on the
/// same connection although the peer lists nothing new.
#[test]
fn a_confirmed_walk_whose_pending_grant_is_evicted_reopens_without_a_new_listing() {
    let [alice, peer] = [0xC8, 0xCF].map(key);
    let (_, _, r, handle) = unheld(&alice, "evicted after confirming");
    let (mut host, _linked) = listed_to(&peer, r, summary(9));
    let base = now();
    let first = grant(r, &alice, handle, &key(0xC9));
    host.grants.walked(pending(id(&peer), &first), base);
    host.grants.walked(ended(&peer, r, confirmed()), base);
    assert_eq!(host.grants.deadline(), None, "control: nothing to retry yet");
    for index in 0..MAX_PENDING_PER_SENDER {
        let mut seed = [0xCA; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let other = grant(r, &alice, handle, &SigningKey::from_bytes(&seed));
        host.grants.walked(pending(id(&peer), &other), base);
    }
    assert!(!host.grants.waiting().contains(id(&peer), &first), "evicted");
    let due = host.grants.deadline().expect("a retry is scheduled");
    assert!(due <= after(base, 1));
    assert_eq!(host.grants.retry(due).walks, [(id(&peer), r)]);
}

/// The same when the pending grant's descriptor cannot be fetched.
#[test]
fn a_confirmed_walk_whose_descriptor_fetch_fails_reopens_without_a_new_listing() {
    let [alice, peer] = [0xD8, 0xDF].map(key);
    let (_, _, r, handle) = unheld(&alice, "never fetched");
    let (mut host, _linked) = listed_to(&peer, r, summary(10));
    let base = now();
    let proof = grant(r, &alice, handle, &key(0xD9));
    host.grants.walked(pending(id(&peer), &proof), base);
    host.grants.walked(ended(&peer, r, confirmed()), base);
    assert_eq!(host.grants.deadline(), None, "control: nothing to retry yet");
    host.grants.fetch_failed(r.raw, base);
    assert!(!host.grants.waiting().contains(id(&peer), &proof), "given up");
    assert_eq!(host.grants.deadline(), Some(after(base, 1)));
    assert_eq!(host.grants.retry(after(base, 1)).walks, [(id(&peer), r)]);
}

/// A stored grant whose definition could not be fetched has it fetched
/// again from the lister when the retry falls due.
#[test]
fn a_stored_grant_whose_definition_fetch_fails_is_fetched_again_at_the_retry() {
    let [alice, bob_key, peer] = [0xE8, 0xE9, 0xEF].map(key);
    let (descriptor, _, r, handle) = unheld(&alice, "definition missing");
    let mut host = Node::new(0xE9);
    host.put(&descriptor);
    host.store
        .insert_proof(grant(r, &alice, handle, &bob_key))
        .unwrap();
    host.observe();
    let (linked, _) = open_to(&mut host, id(&peer), 3);
    let base = now();
    let heard = hear(&mut host, &linked, vec![(r, summary(11))]);
    assert!(heard.fetch.iter().any(|fetch| fetch.blobs.contains(&handle.raw)));
    host.grants.walked(ended(&peer, r, confirmed()), base);
    host.grants.fetch_failed(handle.raw, base);
    let due = host.grants.deadline().expect("a retry is scheduled");
    let retried = host.grants.retry(due);
    assert!(
        retried
            .fetch
            .iter()
            .any(|fetch| fetch.blobs.contains(&handle.raw) && fetch.sources.first() == Some(&id(&peer))),
        "{:?}",
        retried.fetch
    );
}

// ---- health: grant agreement from the index and the peer's listing ----

/// An empty record frontier: health's view of a collection with no records.
fn no_records() -> crate::health::RepairFrontier {
    let empty = PatchSummary::new(None, 0).unwrap();
    crate::health::RepairFrontier {
        wake_root: [0; 32],
        commits: empty,
        derives: empty,
    }
}

/// Health reads grant agreement from the grant index, never from C's
/// admission evidence. C holds a valid grant, a junk-delegated proof and a
/// waiting one here: the evidence holds all three, the index only the
/// first. A peer listing the index's root for C agrees with this side, and
/// the pair reads current; the listing goes with the connection.
#[test]
fn health_reports_the_grant_index_root_and_the_peer_s_listing() {
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionPolicy, CollectionStoreExt, read_capability,
    };
    use triblespace_core::patch::Entry;

    use crate::health::{CollectionHealth, Health, PairState, PeeringHealth};
    use crate::walk::WalkKind;

    let [owner, g, z, y] = [0xC1, 0xC2, 0xC3, 0xC4].map(key);
    let mut host = Node::new(0xC0);
    let direct = AdmissionPolicy::direct(owner.verifying_key());
    let c = host
        .store
        .collection("agreement", CollectionPolicy::new(direct.clone(), direct))
        .unwrap()
        .handle();
    host.active.insert(&Entry::new(&c.raw));
    let to_g = grant(c, &owner, read_capability(), &g);
    let junk = to_g.delegate(&g, read_capability(), z.verifying_key()).unwrap();
    let absent = handle_of(&{
        use triblespace_core::metadata;
        use triblespace_core::prelude::entity;
        entity! { metadata::name: "never stored" }.facts().clone()
    });
    let waiting = grant(c, &owner, absent, &y);
    for proof in [&to_g, &junk, &waiting] {
        host.store.insert_proof(proof.clone()).unwrap();
    }
    host.observe();
    let snapshot = host.snapshot();
    let index = snapshot.grants().summary(c);
    let evidence = snapshot
        .collection(c)
        .unwrap()
        .repair()
        .authorization_evidence()
        .summary();
    assert_eq!((index.leaf_count(), evidence.leaf_count()), (1, 3));

    let health = Health::new(iroh_base::EndpointId::from_bytes(&id(&host.key)).unwrap());
    let (linked, _) = open_to(&mut host, id(&owner), 1);
    hear(&mut host, &linked, vec![(c, index)]);
    assert!(host.grants.publish(&health));
    let published = health.snapshot();
    let entry = published
        .grants
        .iter()
        .find(|entry| entry.resource == c)
        .expect("C's grant agreement is published");
    assert_eq!(entry.local, index, "the index's root, not the evidence's");
    assert_eq!(entry.peers.len(), 1);
    assert_eq!(entry.peers[0].peer, id(&owner));
    assert_eq!(entry.peers[0].listed, Some(index));

    let now = crate::clock::mono_now();
    health.update(|sample| {
        sample.started_at = Some(now);
        sample.observed_at = Some(now);
        sample.store.serving_snapshot = true;
        sample.store.last_snapshot_observed_at = Some(now);
        sample.collections.push(CollectionHealth {
            collection: c,
            local_frontier: Some(no_records()),
            last_local_change_at: Some(now),
            peers: Vec::new(),
        });
        sample.peerings.push(PeeringHealth {
            collection: c,
            peer: id(&owner),
            asked: true,
            peered: true,
            sends: true,
            receives: true,
            refused_by_me: false,
            refused_by_them: false,
        });
    });
    health.with_peer(c, id(&owner), |pair| {
        let empty = no_records();
        pair.pushed(now, WalkKind::Commit, empty.commits, true);
        pair.pushed(now, WalkKind::Derive, empty.derives, true);
        pair.received(now, WalkKind::Commit, Some(empty.commits), true);
        pair.received(now, WalkKind::Derive, Some(empty.derives), true);
    });
    let age = std::time::Duration::from_secs(180);
    assert_eq!(health.snapshot().pair(c, id(&owner), now, age), PairState::Current);

    host.grants.event(&ReconEvent::Closed(linked.link.clone()));
    assert!(host.grants.publish(&health));
    let entry = health
        .snapshot()
        .grants
        .iter()
        .find(|entry| entry.resource == c)
        .cloned()
        .expect("an active C stays published");
    assert!(entry.peers.is_empty(), "a listing goes with its connection");
    assert_ne!(health.snapshot().pair(c, id(&owner), now, age), PairState::Current);
}

/// One peer's published agreement on R.
fn agreement(health: &crate::health::Health, resource: CollectionHandle, peer: PeerId) -> (PatchSummary, crate::health::GrantPeerHealth) {
    let published = health.snapshot();
    let entry = published
        .grants
        .iter()
        .find(|entry| entry.resource == resource)
        .expect("R's agreement is published");
    let peer = entry
        .peers
        .iter()
        .find(|listing| listing.peer == peer)
        .cloned()
        .expect("the peer's listing is published");
    (entry.local, peer)
}

fn health_of(node: &Node) -> crate::health::Health {
    crate::health::Health::new(iroh_base::EndpointId::from_bytes(&id(&node.key)).unwrap())
}

/// While the peer's grants over R differ, its listing and the agreement
/// differ from this side's root (the fields move); after a confirmed walk
/// and the peer's new listing, local, listed and agreed are equal. The walk
/// end is counted, and so are the proofs it skipped.
#[test]
fn grant_health_reports_local_listed_agreed_and_walk_ends() {
    let [alice, bob] = [0x50, 0x51].map(key);
    let mut host = Node::new(0x5B);
    let (r, _) = holding(&mut host, &alice, &bob);
    host.observe();
    let local = host.snapshot().grants().summary(r);
    let health = health_of(&host);
    let (linked, _) = open_to(&mut host, id(&bob), 1);
    assert_eq!(hear(&mut host, &linked, vec![(r, summary(1))]).walks, [(id(&bob), r)]);
    host.grants.publish(&health);
    let (published, in_flight) = agreement(&health, r, id(&bob));
    assert_eq!(published, local);
    assert_eq!(in_flight.listed, Some(summary(1)));
    assert_eq!(in_flight.agreed, None, "positive control: nothing agreed yet");
    assert_eq!(in_flight.ends.ok + in_flight.ends.failed, 0);

    host.grants.walked(
        GrantEvent::Ended(GrantWalkEnd {
            peer: id(&bob),
            resource: r,
            outcome: GrantOutcome::Confirmed { agreed: local },
            skipped: 1,
        }),
        now(),
    );
    hear(&mut host, &linked, vec![(r, local)]);
    host.grants.publish(&health);
    let (published, settled) = agreement(&health, r, id(&bob));
    assert_eq!((settled.listed, settled.agreed), (Some(published), Some(published)));
    assert_eq!(published, local);
    assert_eq!((settled.ends.ok, settled.ends.failed), (1, 0));
    assert!(settled.ends.last_ok);
    assert_eq!(settled.skipped, 1, "a skipped junk proof leaves agreed == local");

    host.grants.walked(
        GrantEvent::Ended(GrantWalkEnd {
            peer: id(&bob),
            resource: r,
            outcome: GrantOutcome::Unconfirmed(None),
            skipped: 0,
        }),
        now(),
    );
    host.grants.publish(&health);
    let (_, failed) = agreement(&health, r, id(&bob));
    assert_eq!((failed.ends.ok, failed.ends.failed), (1, 1));
    assert_eq!(failed.agreed, Some(local), "the last confirmed agreement stays");
}

/// A grant the peer delivered that waits for its descriptor counts as
/// pending; once evicted, the walk that opens again counts as a retry.
#[test]
fn an_evicted_pending_grant_counts_as_pending_then_as_a_retry() {
    let [alice, peer] = [0xF0, 0xFF].map(key);
    let (_, _, r, handle) = unheld(&alice, "counted");
    let (mut host, _linked) = listed_to(&peer, r, summary(12));
    let health = health_of(&host);
    let base = now();
    let first = grant(r, &alice, handle, &key(0xF1));
    host.grants.walked(pending(id(&peer), &first), base);
    host.grants.walked(ended(&peer, r, confirmed()), base);
    host.grants.publish(&health);
    let (_, counted) = agreement(&health, r, id(&peer));
    assert_eq!((counted.pending, counted.retries), (1, 0));
    for index in 0..MAX_PENDING_PER_SENDER {
        let mut seed = [0xF2; 32];
        seed[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let other = grant(r, &alice, handle, &SigningKey::from_bytes(&seed));
        host.grants.walked(pending(id(&peer), &other), base);
    }
    assert!(!host.grants.waiting().contains(id(&peer), &first), "evicted");
    let due = host.grants.deadline().expect("a retry is scheduled");
    assert_eq!(host.grants.retry(due).walks, [(id(&peer), r)]);
    host.grants.publish(&health);
    let (_, retried) = agreement(&health, r, id(&peer));
    assert_eq!(retried.pending, 1 + MAX_PENDING_PER_SENDER as u64);
    assert_eq!(retried.retries, 1);
}

/// A collection an indexed grant names this node on, that it holds but has
/// not selected, is published as granted and unselected; selecting it
/// removes it. A non-collection resource granted to it never is, nor a
/// collection granted only to someone else.
#[test]
fn a_granted_unselected_collection_is_published_until_selected() {
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionPolicy, CollectionStoreExt, read_capability,
    };
    use triblespace_core::collection::selection::{CONFIG_COLLECTION_NAME, write_sync_selection};
    use triblespace_core::collection::private_policy;
    use triblespace_core::patch::Entry;

    let [owner, other] = [0x21, 0x22].map(key);
    let mut host = Node::new(0x20);
    let me = host.key.clone();
    let direct = AdmissionPolicy::direct(owner.verifying_key());
    let granted = host
        .store
        .collection("granted", CollectionPolicy::new(direct.clone(), direct.clone()))
        .unwrap()
        .handle();
    let elsewhere = host
        .store
        .collection("not mine", CollectionPolicy::new(direct.clone(), direct))
        .unwrap()
        .handle();
    host.store
        .insert_proof(grant(granted, &owner, read_capability(), &me))
        .unwrap();
    host.store
        .insert_proof(grant(elsewhere, &owner, read_capability(), &other))
        .unwrap();
    let (r, _) = holding(&mut host, &owner, &me);
    let config = host
        .store
        .collection(CONFIG_COLLECTION_NAME, private_policy(me.verifying_key()))
        .unwrap();
    for collection in [granted, elsewhere] {
        host.active.insert(&Entry::new(&collection.raw));
    }
    let health = health_of(&host);
    host.observe();
    host.grants.publish(&health);
    assert_eq!(health.snapshot().named_unselected, [granted]);
    assert!(host.snapshot().grants().participates(r, id(&me)), "R names me too");

    write_sync_selection(&mut host.store, config, &me, granted, true).unwrap();
    host.observe();
    host.grants.publish(&health);
    assert!(health.snapshot().named_unselected.is_empty(), "selected now");
}

// ---- review fixes: bounds, recovery and re-opening ----

/// A grant that waits for its descriptor has only that descriptor fetched:
/// its definitions are asked for once it validated and landed (positive
/// control), never before a root has been checked.
#[test]
fn a_pending_grant_fetches_only_its_descriptor_until_it_lands() {
    let [alice, bob_key, carol] = [0x14, 0x15, 0x16].map(key);
    let mut bob = Node::new(0x15);
    bob.observe();
    let (descriptor, _, r, handle) = unheld(&alice, "descriptor first");
    let proof = grant(r, &alice, handle, &bob_key);
    let effects = bob.grants.walked(pending(id(&carol), &proof), now());
    assert!(
        effects.fetch.iter().any(|fetch| fetch.blobs.contains(&r.raw)),
        "the descriptor is fetched: {:?}",
        effects.fetch
    );
    assert!(
        effects.fetch.iter().all(|fetch| !fetch.blobs.contains(&handle.raw)),
        "no definition before the root is checked: {:?}",
        effects.fetch
    );
    bob.put(&descriptor);
    let landed = bob.observe();
    assert_eq!(landed.land, [proof.clone()]);
    assert!(
        landed
            .fetch
            .iter()
            .any(|fetch| fetch.blobs.contains(&handle.raw) && fetch.sources.first() == Some(&id(&carol))),
        "positive control: once it lands its definition is fetched from the sender: {:?}",
        landed.fetch
    );
}

/// When every sender together fills the pending bounds, the sender holding
/// the most gives up its oldest: a sender with few waiting grants is not
/// starved by one with many, in count or in bytes.
#[test]
fn a_sender_filling_the_pending_bounds_evicts_its_own_oldest() {
    let [alice, carol, dave] = [0x17, 0x18, 0x19].map(key);
    let (_, _, r, handle) = unheld(&alice, "fair");
    let proofs: Vec<_> = (0..5u8)
        .map(|index| grant(r, &alice, handle, &key(0x60 + index)))
        .collect();
    let size = proofs[0].as_bytes().len();
    for limits in [
        PendingLimits { per_sender: 10, total: 4, bytes: usize::MAX },
        PendingLimits { per_sender: 10, total: 10, bytes: 4 * size },
    ] {
        let mut pending = Pending::new(limits);
        assert!(pending.insert(id(&dave), proofs[0].clone()).is_empty());
        for proof in &proofs[1..4] {
            assert!(pending.insert(id(&carol), proof.clone()).is_empty());
        }
        let evicted = pending.insert(id(&carol), proofs[4].clone());
        assert_eq!(evicted, [(id(&carol), r)], "{limits:?}");
        assert!(pending.contains(id(&dave), &proofs[0]), "the small sender keeps its grant");
        assert!(!pending.contains(id(&carol), &proofs[1]), "the large sender's oldest left");
        assert!(pending.contains(id(&carol), &proofs[4]), "positive control: the newest waits");
        assert_eq!(pending.kept(id(&carol)), 3);
    }
}

/// A peering on which this side does not send C (the peer may write C but
/// not read it) lists C to nobody; a peering on which it sends does
/// (positive control). Either one widens what a walk over C keeps, so both
/// open a walk again whose root still differs.
#[test]
fn a_write_only_peering_is_listed_no_grants() {
    use triblespace_core::collection::{
        AdmissionPolicy, CollectionPolicy, CollectionStoreExt, read_capability,
    };
    use triblespace_core::patch::Entry;
    let [reader, writer, neighbour] = [0x1B, 0x1C, 0x1D].map(key);
    let mut host = Node::new(0x1A);
    let owner = host.key.clone();
    let c = host
        .store
        .collection(
            "private read, open write",
            CollectionPolicy::new(AdmissionPolicy::direct(owner.verifying_key()), AdmissionPolicy::Open),
        )
        .unwrap()
        .handle();
    host.active.insert(&Entry::new(&c.raw));
    host.store
        .insert_proof(grant(c, &owner, read_capability(), &reader))
        .unwrap();
    host.observe();
    let local = host.snapshot().grants().summary(c);
    let (mut to_writer, _) = open_to(&mut host, id(&writer), 3);
    let (mut to_neighbour, _) = open_to(&mut host, id(&neighbour), 4);
    assert_eq!(hear(&mut host, &to_writer, vec![(c, summary(5))]).walks, [(id(&writer), c)]);
    assert!(hear(&mut host, &to_writer, vec![(c, summary(5))]).walks.is_empty());
    let effects = host.grants.peered([(3, c, false), (4, c, true)]);
    assert_eq!(effects.walks, [(id(&writer), c)], "a receiving peering widens the gate");
    host.observe();
    assert!(listed(&mut to_writer).is_empty(), "the reader set is not disclosed");
    assert_eq!(listed(&mut to_neighbour), [(c, local)], "positive control");
}

/// A pending grant given up before its walk's end arrived: the walk still
/// opens again after the backoff, whatever the confirmed end says.
#[test]
fn a_give_up_before_the_walk_confirms_still_reopens_it() {
    let [alice, peer] = [0x26, 0x27].map(key);
    let (_, _, r, handle) = unheld(&alice, "given up first");
    let (mut host, _linked) = listed_to(&peer, r, summary(30));
    let base = now();
    let proof = grant(r, &alice, handle, &key(0x28));
    host.grants.walked(pending(id(&peer), &proof), base);
    host.grants.fetch_failed(r.raw, base);
    assert_eq!(host.grants.deadline(), Some(after(base, 1)), "control: scheduled");
    host.grants.walked(ended(&peer, r, confirmed()), base);
    assert_eq!(host.grants.deadline(), Some(after(base, 1)), "the confirmed end keeps it");
    assert_eq!(host.grants.retry(after(base, 1)).walks, [(id(&peer), r)]);
}

/// A peer whose pending grants are given up after every confirmed walk is
/// walked again on a growing backoff: 1, 2, 4, then 8 s.
#[test]
fn a_pending_grant_given_up_after_every_confirmed_walk_backs_off() {
    let [alice, peer] = [0x29, 0x2A].map(key);
    let (_, _, r, handle) = unheld(&alice, "given up again");
    let (mut host, _linked) = listed_to(&peer, r, summary(31));
    let proof = grant(r, &alice, handle, &key(0x2B));
    let mut at = now();
    for delay in [1, 2, 4, 8] {
        host.grants.walked(pending(id(&peer), &proof), at);
        host.grants.walked(ended(&peer, r, confirmed()), at);
        host.grants.fetch_failed(r.raw, at);
        let due = host.grants.deadline().expect("a retry is scheduled");
        assert_eq!(due, after(at, delay), "after {delay} s");
        assert_eq!(host.grants.retry(due).walks, [(id(&peer), r)]);
        at = due;
    }
}

/// A stored grant's definition that no source has is asked for again on a
/// growing backoff, not every second.
#[test]
fn a_definition_found_nowhere_is_asked_for_again_on_a_growing_backoff() {
    let [alice, bob_key, peer] = [0x2C, 0x2D, 0x2E].map(key);
    let (descriptor, _, r, handle) = unheld(&alice, "never found");
    let mut host = Node::new(0x2D);
    host.put(&descriptor);
    host.store
        .insert_proof(grant(r, &alice, handle, &bob_key))
        .unwrap();
    host.observe();
    let (linked, _) = open_to(&mut host, id(&peer), 3);
    hear(&mut host, &linked, vec![(r, summary(32))]);
    let mut at = now();
    host.grants.walked(ended(&peer, r, confirmed()), at);
    for delay in [1, 2, 4, 8] {
        host.grants.fetch_failed(handle.raw, at);
        let due = host.grants.deadline().expect("a retry is scheduled");
        assert_eq!(due, after(at, delay), "after {delay} s");
        let retried = host.grants.retry(due);
        assert!(
            retried.fetch.iter().any(|fetch| fetch.blobs.contains(&handle.raw)),
            "positive control: asked again: {:?}",
            retried.fetch
        );
        at = due;
    }
}

/// A node that becomes a participant of R (its own grant landed) walks R
/// again with each peer that listed a differing root, so it receives the
/// grants it skipped while it took no part; once.
#[test]
fn becoming_a_participant_walks_again_what_it_skipped() {
    let [alice, bob_key, carol] = [0x33, 0x34, 0x35].map(key);
    let mut bob = Node::new(0x34);
    bob.observe();
    let (descriptor, definition, r, handle) = unheld(&alice, "joins later");
    let to_bob = grant(r, &alice, handle, &bob_key);
    let (linked, _) = open_to(&mut bob, id(&carol), 1);
    assert_eq!(hear(&mut bob, &linked, vec![(r, summary(33))]).walks, [(id(&carol), r)]);
    bob.grants.walked(pending(id(&carol), &to_bob), now());
    bob.grants.walked(ended(&carol, r, confirmed()), now());
    assert!(bob.observe().walks.is_empty(), "control: nothing changed");
    bob.put(&definition);
    bob.put(&descriptor);
    let landed = bob.observe();
    assert_eq!(landed.land, [to_bob.clone()]);
    bob.land(&landed);
    let joined = bob.observe();
    assert!(bob.snapshot().grants().participates(r, id(&bob_key)));
    assert_eq!(joined.walks, [(id(&carol), r)], "walked again on becoming a participant");
    assert!(bob.observe().walks.is_empty(), "once");
}

/// A listing heard while a walk over the same resource runs with that peer
/// is walked after the backoff, although that walk then confirms: it may
/// have walked an older root. A confirmed end with nothing heard meanwhile
/// schedules nothing (control).
#[test]
fn a_listing_heard_while_its_walk_runs_is_walked_after_that_walk_ends() {
    let peer = key(0x36);
    let r = handle(36);
    let (mut host, linked) = listed_to(&peer, r, summary(34));
    let base = now();
    host.grants.walked(ended(&peer, r, confirmed()), base);
    assert_eq!(host.grants.deadline(), None, "control: nothing heard meanwhile");
    assert_eq!(hear(&mut host, &linked, vec![(r, summary(35))]).walks, [(id(&peer), r)]);
    let running = GrantOutcome::NotStarted(NotStarted::AlreadyRunning);
    assert!(host.grants.walked(ended(&peer, r, running), base).walks.is_empty());
    host.grants.walked(ended(&peer, r, confirmed()), base);
    let due = host.grants.deadline().expect("the root heard meanwhile is walked");
    assert_eq!(due, after(base, 1));
    assert_eq!(host.grants.retry(due).walks, [(id(&peer), r)]);
}

// ---- a grant landed through a peering is completed ----

/// A collection C whose READ is Open and whose WRITE is rooted at `owner`,
/// with a delegable WRITE definition P also bound to `owner`, and the chain
/// owner -> X (P) -> Y (Q), where Q is an attenuated WRITE definition C does
/// not bind. Built in a pile of its own: nothing is resident anywhere else.
struct Delegated {
    c: CollectionHandle,
    descriptor: TribleSet,
    p: TribleSet,
    q: TribleSet,
    q_handle: CapabilityHandle,
    chain: CapabilityProof,
}

fn delegated(owner: &SigningKey, x: &SigningKey, y: &SigningKey) -> Delegated {
    use triblespace_core::capability::{capability_action, capability_delegate_action};
    use triblespace_core::collection::{
        ACTION_WRITE, AdmissionPolicy, CollectionPolicy, CollectionStoreExt,
    };
    use triblespace_core::metadata;
    use triblespace_core::prelude::entity;
    use triblespace_core::repo::BlobStoreGet;
    let p = entity! {
        capability_action: ACTION_WRITE,
        capability_delegate_action: ACTION_WRITE,
        metadata::name: "delegable write",
    };
    let q = entity! { capability_action: ACTION_WRITE, metadata::name: "attenuated write" }
        .facts()
        .clone();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(owner.verifying_key()),
    )
    .with_capability(p.clone(), AdmissionPolicy::direct(owner.verifying_key()));
    let mut source = MemoryRepo::default();
    let c = source.collection("delegated write", policy).unwrap().handle();
    let descriptor: TribleSet = source
        .snapshot()
        .unwrap()
        .get::<TribleSet, SimpleArchive>(c)
        .unwrap();
    let p = p.facts().clone();
    let q_handle = handle_of(&q);
    let chain = grant(c, owner, handle_of(&p), x)
        .delegate(x, q_handle, y.verifying_key())
        .unwrap();
    Delegated {
        c,
        descriptor,
        p,
        q,
        q_handle,
        chain,
    }
}

/// Whether `effects` fetch `blob`, and from whom first.
fn fetched_from(effects: &Effects, blob: RawHash) -> Option<PeerId> {
    effects
        .fetch
        .iter()
        .find(|fetch| fetch.blobs.contains(&blob))
        .map(|fetch| fetch.sources[0])
}

/// A grant over C that names neither this node nor a participant lands
/// through a peering for C (the walk gate keeps it for the peering alone),
/// with C's descriptor and its bound definition P already resident: the
/// warm case. Its second step's definition Q, which C does not bind, is
/// fetched from the peer that listed C, on observation and again on its next
/// listing; once Q arrives the grant is indexed, its keys join C's
/// participants, and C's new root is listed to a peer this side sends C to
/// and to C's root, never to the peer it only receives C from.
#[test]
fn a_grant_landed_through_a_peering_has_its_unbound_definition_fetched_and_is_listed() {
    let [owner, x, y, sender, neighbour] = [0x61, 0x62, 0x63, 0x64, 0x65].map(key);
    let d = delegated(&owner, &x, &y);
    let mut bob = Node::new(0x66);
    assert_eq!(bob.put(&d.descriptor), d.c);
    bob.put(&d.p);
    bob.active
        .insert(&triblespace_core::patch::Entry::new(&d.c.raw));
    bob.observe();
    let (mut to_sender, _) = open_to(&mut bob, id(&sender), 1);
    let (mut to_neighbour, _) = open_to(&mut bob, id(&neighbour), 2);
    let (mut to_owner, _) = open_to(&mut bob, id(&owner), 3);
    bob.grants.peered([(1, d.c, false), (2, d.c, true)]);
    bob.observe();
    for linked in [&mut to_sender, &mut to_neighbour, &mut to_owner] {
        listed(linked);
    }
    assert_eq!(
        hear(&mut bob, &to_sender, vec![(d.c, summary(0x61))]).walks,
        [(id(&sender), d.c)]
    );

    let snapshot = bob.snapshot();
    assert!(!snapshot.grants().participates(d.c, bob.grants.local));
    assert!(
        matches!(Gate::new(d.c, false).admit(&snapshot, d.chain.clone()), Gated::Skip),
        "control: without the peering the gate skips it"
    );
    let Gated::Land(landed) = Gate::new(d.c, true).admit(&snapshot, d.chain.clone()) else {
        panic!("the peering keeps it, and C's descriptor is resident: it lands");
    };
    bob.store.insert_proof(landed).unwrap();

    let observed = bob.observe();
    assert!(
        matches!(
            bob.snapshot().grants().verdict(d.chain.id()),
            Some(Verdict::Waiting(missing)) if missing[..] == [d.q_handle.raw]
        ),
        "it waits for Q alone"
    );
    assert_eq!(
        fetched_from(&observed, d.q_handle.raw),
        Some(id(&sender)),
        "Q is fetched from the lister: {:?}",
        observed.fetch
    );
    let relisted = hear(&mut bob, &to_sender, vec![(d.c, summary(0x62))]);
    assert_eq!(
        fetched_from(&relisted, d.q_handle.raw),
        Some(id(&sender)),
        "and again on the next listing: {:?}",
        relisted.fetch
    );

    bob.put(&d.q);
    bob.observe();
    let snapshot = bob.snapshot();
    assert_eq!(
        snapshot.grants().verdict(d.chain.id()),
        Some(&Verdict::Indexed(d.c))
    );
    assert!(snapshot.grants().participates(d.c, id(&y)));
    let local = snapshot.grants().summary(d.c);
    assert_eq!(local.leaf_count(), 1);
    assert!(
        listed(&mut to_neighbour).contains(&(d.c, local)),
        "listed to a peer this side sends C to"
    );
    assert!(listed(&mut to_owner).contains(&(d.c, local)), "and to C's root");
    assert!(
        listed(&mut to_sender).iter().all(|(resource, _)| *resource != d.c),
        "never to a peer this side only receives C from"
    );
}

/// The cold case, a positive control that passed before the warm case did:
/// the same grant arriving before C's descriptor waits in memory with only
/// the descriptor fetched; once the descriptor and P arrive it lands and Q
/// is fetched from its sender, and once Q arrives it is indexed.
#[test]
fn a_grant_pending_its_descriptor_under_a_peering_has_its_unbound_definition_fetched_on_landing() {
    let [owner, x, y, sender] = [0x74, 0x75, 0x76, 0x77].map(key);
    let d = delegated(&owner, &x, &y);
    let mut bob = Node::new(0x78);
    bob.active
        .insert(&triblespace_core::patch::Entry::new(&d.c.raw));
    bob.observe();
    let (to_sender, _) = open_to(&mut bob, id(&sender), 1);
    bob.grants.peered([(1, d.c, false)]);
    hear(&mut bob, &to_sender, vec![(d.c, summary(0x74))]);

    let snapshot = bob.snapshot();
    let Gated::Pending(waiting) = Gate::new(d.c, true).admit(&snapshot, d.chain.clone()) else {
        panic!("no descriptor yet: it waits");
    };
    let effects = bob.grants.walked(pending(id(&sender), &waiting), now());
    assert_eq!(fetched_from(&effects, d.c.raw), Some(id(&sender)));
    assert_eq!(
        fetched_from(&effects, d.q_handle.raw),
        None,
        "nothing a step names before the grant starts at one of C's roots"
    );

    bob.put(&d.descriptor);
    bob.put(&d.p);
    let effects = bob.observe();
    assert_eq!(effects.land, [d.chain.clone()]);
    assert_eq!(
        fetched_from(&effects, d.q_handle.raw),
        Some(id(&sender)),
        "landing fetches Q from the sender: {:?}",
        effects.fetch
    );
    bob.land(&effects);
    bob.put(&d.q);
    bob.observe();
    assert_eq!(
        bob.snapshot().grants().verdict(d.chain.id()),
        Some(&Verdict::Indexed(d.c))
    );
}

/// A stranger's grant over C, offered on a connection not peered for C, to a
/// node that takes no part in C and is not named on it, is skipped: nothing
/// lands (positive control: the same grant on a peered connection lands).
/// The same grant stored here by other means (a merged pile) has nothing
/// fetched, neither on observation nor when the stranger lists C; a grant
/// naming this node, waiting the same way for its own definition, is fetched
/// for in the same observation (positive control).
#[test]
fn a_grant_this_node_is_neither_named_on_nor_peered_for_fetches_nothing() {
    use triblespace_core::capability::capability_action;
    use triblespace_core::collection::ACTION_WRITE;
    use triblespace_core::prelude::entity;
    let [owner, x, y, stranger] = [0x83, 0x84, 0x85, 0x86].map(key);
    let d = delegated(&owner, &x, &y);
    let mut bob = Node::new(0x88);
    bob.put(&d.descriptor);
    bob.put(&d.p);
    bob.active
        .insert(&triblespace_core::patch::Entry::new(&d.c.raw));
    bob.observe();
    let (to_stranger, _) = open_to(&mut bob, id(&stranger), 1);
    let heard = hear(&mut bob, &to_stranger, vec![(d.c, summary(0x83))]);
    assert!(heard.fetch.is_empty(), "nothing waits here yet: {:?}", heard.fetch);

    let snapshot = bob.snapshot();
    assert!(matches!(
        Gate::new(d.c, false).admit(&snapshot, d.chain.clone()),
        Gated::Skip
    ));
    assert!(
        matches!(Gate::new(d.c, true).admit(&snapshot, d.chain.clone()), Gated::Land(_)),
        "positive control: a peered connection keeps it"
    );
    assert_eq!(bob.proofs(), 0, "a skipped grant lands nothing");

    let own = entity! { capability_action: ACTION_WRITE, triblespace_core::metadata::name: "bob's write" }
        .facts()
        .clone();
    let named = grant(d.c, &owner, handle_of(&d.p), &x)
        .delegate(&x, handle_of(&own), bob.key.verifying_key())
        .unwrap();
    bob.store.insert_proof(d.chain.clone()).unwrap();
    bob.store.insert_proof(named).unwrap();
    let observed = bob.observe();
    assert!(
        matches!(
            bob.snapshot().grants().verdict(d.chain.id()),
            Some(Verdict::Waiting(_))
        ),
        "it waits for Q"
    );
    assert_eq!(fetched_from(&observed, d.q_handle.raw), None, "not wanted: {:?}", observed.fetch);
    assert!(
        fetched_from(&observed, handle_of(&own).raw).is_some(),
        "positive control: a grant naming this node is: {:?}",
        observed.fetch
    );
    let heard = hear(&mut bob, &to_stranger, vec![(d.c, summary(0x84))]);
    assert_eq!(
        fetched_from(&heard, d.q_handle.raw),
        None,
        "a stranger's listing fetches nothing for it: {:?}",
        heard.fetch
    );
}

/// A stored grant over C waiting for Q, on a node that takes no part in C,
/// is asked for once a connection becomes peered for C, from that peer
/// first, without waiting for another observation or listing; a peering for
/// another resource asks for nothing (control).
#[test]
fn a_new_peering_for_c_asks_for_what_a_stored_grant_over_c_waits_for() {
    let [owner, x, y, partner] = [0x89, 0x8A, 0x8B, 0x8C].map(key);
    let d = delegated(&owner, &x, &y);
    let mut bob = Node::new(0x8D);
    bob.put(&d.descriptor);
    bob.put(&d.p);
    bob.active
        .insert(&triblespace_core::patch::Entry::new(&d.c.raw));
    bob.store.insert_proof(d.chain.clone()).unwrap();
    assert!(bob.observe().fetch.is_empty(), "not wanted yet");
    let (to_partner, _) = open_to(&mut bob, id(&partner), 2);
    hear(&mut bob, &to_partner, vec![(d.c, summary(0x89))]);
    let elsewhere = bob.grants.peered([(2, handle(0x89), false)]);
    assert!(elsewhere.fetch.is_empty(), "control: {:?}", elsewhere.fetch);
    let peered = bob.grants.peered([(2, handle(0x89), false), (2, d.c, false)]);
    assert_eq!(
        fetched_from(&peered, d.q_handle.raw),
        Some(id(&partner)),
        "peered for C, Q is asked of that peer first: {:?}",
        peered.fetch
    );
}
