//! The grant exchange around the walks (design: grants gossip by
//! participation): grants a walk kept whose descriptor is not resident wait
//! in bounded memory and land only once they validate. Every negative
//! assertion has a positive control in the same test.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::TryFromBlob as _;
use triblespace_core::capability::{CapabilityHandle, CapabilityProof};
use triblespace_core::collection::CollectionHandle;
use triblespace_core::repo::memoryrepo::MemoryRepo;
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
    grants: Grants,
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

    fn snapshot(&mut self) -> Arc<StoreSnapshot> {
        Arc::new(
            StoreSnapshot::from_store_changes(
                self.store.snapshot().unwrap(),
                &self.active,
                self.key.verifying_key(),
                None,
                None,
                StoreChanges::ALL,
            )
            .unwrap(),
        )
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

/// The total and byte bounds evict the oldest grant whoever sent it.
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
    host.grants.peered([(3, c)]);
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
        host.grants.peered([(1, c)]).walks,
        [(id(&peer), c)],
        "a walk whose grants were skipped before peering opens again"
    );
    assert!(host.grants.peered([(1, c)]).walks.is_empty(), "only when peering starts");
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
        GrantOutcome::NotStarted(NotStarted::AlreadyRunning),
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
