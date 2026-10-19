//! The grant exchange around the walks (design: grants gossip by
//! participation): grants a walk kept whose descriptor is not resident wait
//! in bounded memory and land only once they validate. Every negative
//! assertion has a positive control in the same test.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
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

    let effects = bob.grants.walked(pending(id(&carol), &proof));
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
        assert!(bob.grants.walked(pending(id(&carol), proof)).land.is_empty());
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
    bob.grants.walked(pending(id(&dave), &others));
    let proofs: Vec<_> = (0..=MAX_PENDING_PER_SENDER)
        .map(|index| grant(r, &alice, handle, &subject(index)))
        .collect();
    for proof in &proofs {
        bob.grants.walked(pending(id(&carol), proof));
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
    bob.grants.walked(pending(id(&carol), &from_carol));
    bob.grants.walked(pending(id(&dave), &from_dave));
    bob.grants.event(&ReconEvent::Closed(carol_link));
    assert!(!bob.grants.waiting().contains(id(&carol), &from_carol));
    assert!(
        bob.grants.waiting().contains(id(&dave), &from_dave),
        "positive control: a connected sender's grant stays"
    );
}
