//! The grant index: every stored grant over any resource R, keyed R | proof
//! id, with R's participants, built incrementally (design: grants gossip by
//! participation). Every negative assertion here carries a positive control
//! in the same test, so "not indexed" is never satisfied by nothing being
//! indexed at all.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::capability::policy::resource_policy;
use triblespace_core::capability::{
    CapabilityHandle, CapabilityProof, CapabilityResource, capability_action,
    capability_delegate_action,
};
use triblespace_core::collection::{
    AdmissionPolicy, CollectionHandle, CollectionPolicy, CollectionStoreExt, read_capability,
};
use triblespace_core::id::Id;
use triblespace_core::macros::id_hex;
use triblespace_core::metadata;
use triblespace_core::patch::Entry as PatchEntry;
use triblespace_core::prelude::entity;
use triblespace_core::repo::memoryrepo::{MemoryRepo, MemoryRepoSnapshot};
use triblespace_core::repo::{
    BlobStoreList, BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
    StoreChanges, StoreSnapshot as _,
};
use triblespace_core::trible::TribleSet;

use crate::grants::{GrantIndex, Junk, Verdict};
use crate::host::{ActiveCollections, StoreSnapshot};
use crate::patch_repair::PatchSummary;

/// The retired routing backlink, declared here so an old-shape resource
/// descriptor can be written. Anchored: anchor and encoding reproduce the
/// published id 926F34A0A81715F0C44F77C691A42468.
pub(crate) mod retired {
    use triblespace_core::macros::attributes;
    use triblespace_core::prelude::*;

    attributes! {
        "62E951EC3ABB7F9B7F123BB7DE2F9F99" as pub resource_collection: inlineencodings::Handle<blobencodings::SimpleArchive>;
    }
}

/// Tag of the test's non-collection resource descriptors, standing in for a
/// Secrets version. Minted with `trible genid` on 2026-10-19 for the grant
/// gossip scenarios and reused here.
pub(crate) const KIND_TEST_RESOURCE: Id = id_hex!("6F0A88AB3F0B3C732CB85805DA09D148");
/// The action the test definitions grant. Minted with `trible genid` on
/// 2026-10-19 for the grant gossip scenarios and reused here.
pub(crate) const ACTION_TEST_DELIVER: Id = id_hex!("5766257B997431DDEC2AC40CC3E3B682");

pub(crate) fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

pub(crate) fn id(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// A definition that invokes the test action and, when `delegable`, may
/// delegate it.
pub(crate) fn deliver(delegable: bool) -> TribleSet {
    if delegable {
        entity! {
            capability_action: ACTION_TEST_DELIVER,
            capability_delegate_action: ACTION_TEST_DELIVER,
        }
        .facts()
        .clone()
    } else {
        entity! { capability_action: ACTION_TEST_DELIVER }.facts().clone()
    }
}

/// A definition naming no action at all.
fn empty_definition() -> TribleSet {
    entity! { metadata::name: "names no action" }.facts().clone()
}

pub(crate) fn handle_of(facts: &TribleSet) -> CapabilityHandle {
    use triblespace_core::blob::IntoBlob;
    IntoBlob::<SimpleArchive>::to_blob(facts.clone()).get_handle()
}

/// A Secrets-shaped resource descriptor: one entity tagged with the test
/// kind, not a collection, with one direct binding per `(root, definition)`.
pub(crate) fn resource(bindings: &[(&SigningKey, CapabilityHandle)], label: &str) -> TribleSet {
    let entity = triblespace_core::id::rngid();
    let mut facts = entity! { &entity @
        metadata::tag: KIND_TEST_RESOURCE,
        metadata::name: label,
    };
    for (root, definition) in bindings {
        facts += entity! { &entity @
            resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(*definition),
        };
    }
    facts.facts().clone()
}

/// An invoke-only definition with its own handle.
fn labelled(label: &str) -> TribleSet {
    entity! { capability_action: ACTION_TEST_DELIVER, metadata::name: label }
        .facts()
        .clone()
}

pub(crate) fn grant(
    over: CollectionHandle,
    issuer: &SigningKey,
    definition: CapabilityHandle,
    subject: &SigningKey,
) -> CapabilityProof {
    CapabilityProof::new(
        CapabilityResource::from(over),
        issuer,
        definition,
        subject.verifying_key(),
    )
}

/// One store and its index, observed incrementally.
#[derive(Default)]
struct Pile {
    store: MemoryRepo,
    active: ActiveCollections,
    last: Option<(MemoryRepoSnapshot, Arc<GrantIndex>)>,
}

impl Pile {
    fn put(&mut self, facts: &TribleSet) -> CollectionHandle {
        self.store.put::<SimpleArchive, _>(facts.clone()).unwrap()
    }

    fn insert(&mut self, proofs: &[&CapabilityProof]) {
        for proof in proofs {
            self.store.insert_proof((*proof).clone()).unwrap();
        }
    }

    /// Observe the store, from the previous index when there is one.
    fn observe(&mut self) -> Arc<GrantIndex> {
        let snapshot = self.store.snapshot().unwrap();
        let (previous, changes) = match &self.last {
            Some((before, index)) => (Some(index), snapshot.changes_since(before)),
            None => (None, StoreChanges::ALL),
        };
        let index = GrantIndex::observe(&snapshot, &self.active, previous, changes).unwrap();
        self.last = Some((snapshot, index.clone()));
        index
    }

    fn counts(&mut self) -> (usize, usize) {
        let snapshot = self.store.snapshot().unwrap();
        (
            snapshot.proofs().unwrap().count(),
            snapshot.blobs().count(),
        )
    }
}

fn participants(index: &GrantIndex, resource: CollectionHandle) -> BTreeSet<[u8; 32]> {
    index
        .grants(resource)
        .map(|grants| {
            grants
                .participants
                .iter_ordered()
                .map(|key| *key)
                .collect()
        })
        .unwrap_or_default()
}

fn indexed(index: &GrantIndex, resource: CollectionHandle) -> BTreeSet<[u8; 32]> {
    index
        .grants(resource)
        .map(|grants| {
            grants
                .proofs
                .iter_ordered()
                .map(|key| key[32..].try_into().unwrap())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_valid_grant_is_indexed_and_a_wrong_root_grant_is_junk() {
    let [alice, stranger, xavier, yves] = [0x10, 0x11, 0x12, 0x13].map(key);
    let mut pile = Pile::default();
    let definition = deliver(true);
    let handle = handle_of(&definition);
    pile.put(&definition);
    let r = pile.put(&resource(&[(&alice, handle)], "a resource"));
    let valid = grant(r, &alice, handle, &xavier);
    let wrong_root = grant(r, &stranger, handle, &yves);
    pile.insert(&[&valid, &wrong_root]);
    let index = pile.observe();
    assert_eq!(index.verdict(valid.id()), Some(&Verdict::Indexed(r)));
    assert_eq!(index.verdict(wrong_root.id()), Some(&Verdict::Junk(Junk::Root)));
    assert_eq!(index.get(r, valid.id()), Some(&valid));
    assert_eq!(index.get(r, wrong_root.id()), None);
    assert_eq!(indexed(&index, r), BTreeSet::from([valid.id().raw]));
    assert!(index.participates(r, id(&alice)) && index.participates(r, id(&xavier)));
    assert!(!index.participates(r, id(&stranger)) && !index.participates(r, id(&yves)));
    assert_eq!(index.resources().collect::<Vec<_>>(), vec![r]);
    // Exact stored bytes (I1).
    assert_eq!(index.get(r, valid.id()).unwrap().as_bytes(), valid.as_bytes());
}

/// G holds an invoke-only grant and signs G→Z anyway: the chain fails core
/// delegation, is skipped, and Z takes no part. G's own grant stays indexed
/// and G takes part (control); a delegable grantee H does add W (control).
#[test]
fn an_undelegated_extension_is_junk_and_adds_no_participant() {
    let [alice, g, z, h, w] = [0x20, 0x21, 0x22, 0x23, 0x24].map(key);
    let mut pile = Pile::default();
    let (invoke, delegable) = (deliver(false), deliver(true));
    let (invoke_handle, delegable_handle) = (handle_of(&invoke), handle_of(&delegable));
    pile.put(&invoke);
    pile.put(&delegable);
    let r = pile.put(&resource(
        &[(&alice, invoke_handle), (&alice, delegable_handle)],
        "delegations",
    ));
    let to_g = grant(r, &alice, invoke_handle, &g);
    let junk = to_g.delegate(&g, invoke_handle, z.verifying_key()).unwrap();
    let to_h = grant(r, &alice, delegable_handle, &h);
    let onward = to_h.delegate(&h, invoke_handle, w.verifying_key()).unwrap();
    pile.insert(&[&to_g, &junk, &to_h, &onward]);
    let index = pile.observe();
    assert_eq!(index.verdict(junk.id()), Some(&Verdict::Junk(Junk::Delegation)));
    assert_eq!(index.verdict(to_g.id()), Some(&Verdict::Indexed(r)));
    assert_eq!(index.verdict(onward.id()), Some(&Verdict::Indexed(r)));
    assert!(!index.participates(r, id(&z)), "an undelegated extension named a participant");
    assert!(index.participates(r, id(&g)));
    assert!(index.participates(r, id(&w)), "a valid delegation names its subject");
    assert_eq!(
        participants(&index, r),
        BTreeSet::from([id(&alice), id(&g), id(&h), id(&w)])
    );
}

/// D4: an extension through a definition that names no action passes core's
/// delegation check (no action to compare, which this test documents) and
/// still adds no participant.
#[test]
fn an_extension_through_an_empty_definition_is_junk_for_participation() {
    let [alice, g, z] = [0x30, 0x31, 0x32].map(key);
    let mut pile = Pile::default();
    let (invoke, empty) = (deliver(false), empty_definition());
    let (invoke_handle, empty_handle) = (handle_of(&invoke), handle_of(&empty));
    pile.put(&invoke);
    pile.put(&empty);
    let r = pile.put(&resource(&[(&alice, invoke_handle)], "empty step"));
    let to_g = grant(r, &alice, invoke_handle, &g);
    let junk = to_g.delegate(&g, empty_handle, z.verifying_key()).unwrap();
    pile.insert(&[&to_g, &junk]);
    let snapshot = pile.store.snapshot().unwrap();
    assert_eq!(
        junk.validate_delegation(&snapshot),
        Ok(()),
        "core accepts a step that names no action"
    );
    let index = pile.observe();
    assert_eq!(index.verdict(junk.id()), Some(&Verdict::Junk(Junk::NoActionStep)));
    assert_eq!(index.verdict(to_g.id()), Some(&Verdict::Indexed(r)));
    assert!(!index.participates(r, id(&z)));
    assert!(index.participates(r, id(&g)));
}

/// A proof missing its resource descriptor and two definitions waits on all
/// three at once. One blob-only change carrying the three indexes it with
/// one evaluation; its indexed siblings are not evaluated again.
#[test]
fn a_waiting_proof_names_every_missing_handle_and_is_evaluated_once_more() {
    let [alice, g, z] = [0x40, 0x41, 0x42].map(key);
    let mut pile = Pile::default();
    let (first, second) = (deliver(true), deliver(false));
    let (first_handle, second_handle) = (handle_of(&first), handle_of(&second));
    let descriptor = resource(&[(&alice, first_handle)], "arrives late");
    let r = handle_of(&descriptor);
    let chain = grant(r, &alice, first_handle, &g)
        .delegate(&g, second_handle, z.verifying_key())
        .unwrap();
    // Siblings over a resident resource.
    let sibling_definition = labelled("sibling");
    let sibling_handle = handle_of(&sibling_definition);
    pile.put(&sibling_definition);
    let resident = pile.put(&resource(&[(&alice, sibling_handle)], "resident"));
    let siblings = [0x44, 0x45, 0x46].map(|byte| grant(resident, &alice, sibling_handle, &key(byte)));
    pile.insert(&[&chain]);
    pile.insert(&siblings.iter().collect::<Vec<_>>());
    let waiting = pile.observe();
    let missing = BTreeSet::from([r.raw, first_handle.raw, second_handle.raw]);
    assert_eq!(waiting.verdict(chain.id()), Some(&Verdict::Waiting(missing.clone())));
    assert_eq!(
        waiting.waiting().map(|(proof, handles)| (proof, handles.clone())).collect::<Vec<_>>(),
        vec![(chain.id(), missing)]
    );
    for sibling in &siblings {
        assert_eq!(waiting.verdict(sibling.id()), Some(&Verdict::Indexed(resident)));
    }
    assert!(!waiting.participates(r, id(&g)) && !waiting.participates(r, id(&z)));
    let before = waiting.evaluations();
    assert_eq!(before, 4);

    pile.put(&descriptor);
    pile.put(&first);
    pile.put(&second);
    let changes = pile.store.snapshot().unwrap().changes_since(&pile.last.as_ref().unwrap().0);
    assert_eq!(changes, StoreChanges::BLOBS, "a blob-only change");
    let arrived = pile.observe();
    assert_eq!(arrived.verdict(chain.id()), Some(&Verdict::Indexed(r)));
    assert_eq!(arrived.waiting().count(), 0);
    assert!(arrived.participates(r, id(&g)) && arrived.participates(r, id(&z)));
    assert_eq!(arrived.evaluations() - before, 1, "only the waiting proof was evaluated");
}

/// Roots come from any descriptor's generic policy fields: a non-collection
/// resource's direct and quorum roots take part; an Open binding names no
/// root.
#[test]
fn roots_of_a_non_collection_descriptor_are_participants() {
    let [alice, bob, carol, dave, xavier] = [0x50, 0x51, 0x52, 0x53, 0x54].map(key);
    let mut pile = Pile::default();
    let definition = deliver(true);
    let handle = handle_of(&definition);
    pile.put(&definition);
    let entity = triblespace_core::id::rngid();
    let quorum = AdmissionPolicy::quorum([bob.verifying_key(), carol.verifying_key()], 2, None)
        .unwrap();
    let descriptor = (entity! { &entity @
        metadata::tag: KIND_TEST_RESOURCE,
        resource_policy*: AdmissionPolicy::direct(alice.verifying_key()).binding(handle),
    } + entity! { &entity @
        resource_policy*: quorum.binding(handle),
    } + entity! { &entity @
        resource_policy*: AdmissionPolicy::Open.binding(handle),
    })
    .facts()
    .clone();
    let r = pile.put(&descriptor);
    let proof = grant(r, &alice, handle, &xavier);
    pile.insert(&[&proof]);
    let index = pile.observe();
    assert_eq!(index.verdict(proof.id()), Some(&Verdict::Indexed(r)));
    assert_eq!(
        participants(&index, r),
        BTreeSet::from([id(&alice), id(&bob), id(&carol), id(&xavier)])
    );
    assert!(!index.participates(r, id(&dave)));
}

/// An old resource descriptor that still carries the retired backlink and a
/// new one without it are indexed alike; their handles differ (I7).
#[test]
fn old_and_new_resource_descriptors_are_indexed_alike() {
    let [alice, xavier] = [0x60, 0x61].map(key);
    let mut pile = Pile::default();
    let definition = deliver(false);
    let handle = handle_of(&definition);
    pile.put(&definition);
    let collection = pile
        .store
        .collection("named by an old descriptor", CollectionPolicy::new(
            AdmissionPolicy::direct(alice.verifying_key()),
            AdmissionPolicy::direct(alice.verifying_key()),
        ))
        .unwrap()
        .handle();
    let entity = triblespace_core::id::rngid();
    let binding = AdmissionPolicy::direct(alice.verifying_key()).binding(handle);
    let new = (entity! { &entity @ metadata::tag: KIND_TEST_RESOURCE, resource_policy*: binding.clone() })
        .facts()
        .clone();
    let old = (entity! { &entity @
        metadata::tag: KIND_TEST_RESOURCE,
        resource_policy*: binding,
        retired::resource_collection: collection,
    })
    .facts()
    .clone();
    let (r_new, r_old) = (pile.put(&new), pile.put(&old));
    assert_ne!(r_new, r_old);
    let proofs = [r_new, r_old].map(|r| grant(r, &alice, handle, &xavier));
    pile.insert(&proofs.iter().collect::<Vec<_>>());
    let index = pile.observe();
    for (r, proof) in [r_new, r_old].into_iter().zip(&proofs) {
        assert_eq!(index.verdict(proof.id()), Some(&Verdict::Indexed(r)));
        assert_eq!(participants(&index, r), BTreeSet::from([id(&alice), id(&xavier)]));
    }
}

/// summary(R) depends only on R's grants: equal across arrival orders and
/// stores, unchanged by grants over other resources, and moved by a grant
/// over R (control).
#[test]
fn summaries_are_canonical_and_scoped_to_their_resource() {
    let [alice] = [0x70].map(key);
    let definition = deliver(false);
    let handle = handle_of(&definition);
    let r1 = resource(&[(&alice, handle)], "one");
    let r2 = resource(&[(&alice, handle)], "two");
    let (h1, h2) = (handle_of(&r1), handle_of(&r2));
    let over_r1 = [0x71, 0x72, 0x73].map(|byte| grant(h1, &alice, handle, &key(byte)));
    let over_r2 = grant(h2, &alice, handle, &key(0x74));
    let mut forward = Pile::default();
    let mut backward = Pile::default();
    for pile in [&mut forward, &mut backward] {
        pile.put(&definition);
        pile.put(&r1);
        pile.put(&r2);
    }
    for proof in &over_r1 {
        forward.insert(&[proof]);
        forward.observe();
    }
    backward.insert(&over_r1.iter().rev().collect::<Vec<_>>());
    let (one, other) = (forward.observe(), backward.observe());
    assert_eq!(one.summary(h1), other.summary(h1));
    assert_eq!(one.summary(h1).leaf_count(), 3);
    let empty = PatchSummary::new(None, 0).unwrap();
    assert_eq!(one.summary(h2), empty);
    forward.insert(&[&over_r2]);
    let more = forward.observe();
    assert_eq!(more.summary(h1), one.summary(h1), "a grant over R2 moved R1");
    assert_ne!(more.summary(h2), empty, "control: the grant over R2 moved R2");
    let late = grant(h1, &alice, handle, &key(0x75));
    forward.insert(&[&late]);
    assert_ne!(forward.observe().summary(h1), one.summary(h1), "control: R1 moves");
}

/// An unrelated change keeps every untouched resource's entry shared.
#[test]
fn an_unrelated_change_shares_every_untouched_resource() {
    let alice = key(0x80);
    let mut pile = Pile::default();
    let definition = deliver(false);
    let handle = handle_of(&definition);
    pile.put(&definition);
    let r1 = pile.put(&resource(&[(&alice, handle)], "untouched"));
    let r2 = pile.put(&resource(&[(&alice, handle)], "touched"));
    pile.insert(&[&grant(r1, &alice, handle, &key(0x81)), &grant(r2, &alice, handle, &key(0x82))]);
    let before = pile.observe();
    pile.insert(&[&grant(r2, &alice, handle, &key(0x83))]);
    let after = pile.observe();
    assert!(Arc::ptr_eq(&before.grants(r1).unwrap(), &after.grants(r1).unwrap()));
    assert!(
        !Arc::ptr_eq(&before.grants(r2).unwrap(), &after.grants(r2).unwrap()),
        "control: the touched resource changed"
    );
    // A blob nothing waits for changes no entry either.
    pile.put(&entity! { metadata::name: "an unrelated blob" }.facts().clone());
    let unrelated = pile.observe();
    for r in [r1, r2] {
        assert!(Arc::ptr_eq(&after.grants(r).unwrap(), &unrelated.grants(r).unwrap()));
    }
}

/// I8: a waiting proof's keys take no part, and evaluation writes nothing:
/// the store's proof and blob counts are unchanged by an observation. Once
/// the definition arrives, the key takes part (control).
#[test]
fn a_waiting_proof_names_no_participant_and_evaluation_writes_nothing() {
    let [alice, quinn] = [0x90, 0x91].map(key);
    let mut pile = Pile::default();
    let definition = deliver(false);
    let handle = handle_of(&definition);
    let r = pile.put(&resource(&[(&alice, handle)], "definition later"));
    let proof = grant(r, &alice, handle, &quinn);
    pile.insert(&[&proof]);
    let counts = pile.counts();
    let index = pile.observe();
    assert_eq!(pile.counts(), counts);
    assert!(matches!(index.verdict(proof.id()), Some(Verdict::Waiting(_))));
    assert!(!index.participates(r, id(&quinn)));
    assert!(!index.participates(r, id(&alice)), "a resource with no indexed grant has no entry");
    pile.put(&definition);
    let arrived = pile.observe();
    assert!(arrived.participates(r, id(&quinn)) && arrived.participates(r, id(&alice)));
}

/// Through the host's serving snapshot. For an active collection C the
/// admission evidence (signature and root only) holds every grant the index
/// holds, plus a junk-delegated and a waiting proof the index does not (D1:
/// the admission input is unchanged). An active C with no grant still has
/// its roots as participants.
#[test]
fn collection_evidence_is_a_superset_of_its_indexed_grants() {
    let [owner, g, z, y, lonely_owner] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4].map(key);
    let mut store = MemoryRepo::default();
    let direct = AdmissionPolicy::direct(owner.verifying_key());
    let c = store
        .collection("evidence", CollectionPolicy::new(direct.clone(), direct))
        .unwrap()
        .handle();
    let lonely_direct = AdmissionPolicy::direct(lonely_owner.verifying_key());
    let lonely = store
        .collection("no grants", CollectionPolicy::new(lonely_direct.clone(), lonely_direct))
        .unwrap()
        .handle();
    let to_g = grant(c, &owner, read_capability(), &g);
    let junk = to_g.delegate(&g, read_capability(), z.verifying_key()).unwrap();
    let absent = handle_of(&entity! { metadata::name: "never stored" }.facts().clone());
    let waiting = grant(c, &owner, absent, &y);
    for proof in [&to_g, &junk, &waiting] {
        store.insert_proof(proof.clone()).unwrap();
    }
    let mut active = ActiveCollections::new();
    active.insert(&PatchEntry::new(&c.raw));
    active.insert(&PatchEntry::new(&lonely.raw));
    let snapshot = StoreSnapshot::from_store_changes(
        store.snapshot().unwrap(),
        &active,
        owner.verifying_key(),
        None,
        None,
        StoreChanges::ALL,
    )
    .unwrap();
    let index = snapshot.grants();
    let evidence: BTreeSet<[u8; 32]> = snapshot
        .collection(c)
        .unwrap()
        .repair()
        .authorization_evidence()
        .proofs()
        .map(|proof| proof.id().raw)
        .collect();
    let grants = indexed(index, c);
    assert_eq!(grants, BTreeSet::from([to_g.id().raw]), "positive: the valid grant is indexed");
    assert!(evidence.is_superset(&grants));
    assert!(evidence.contains(&junk.id().raw) && evidence.contains(&waiting.id().raw));
    assert_eq!(index.verdict(junk.id()), Some(&Verdict::Junk(Junk::Delegation)));
    assert!(matches!(index.verdict(waiting.id()), Some(Verdict::Waiting(_))));
    assert!(index.participates(lonely, id(&lonely_owner)), "an active C's roots take part");
    assert_eq!(index.summary(lonely), PatchSummary::new(None, 0).unwrap());
    assert!(!index.participates(c, id(&z)) && !index.participates(c, id(&y)));
    assert!(index.participates(c, id(&owner)) && index.participates(c, id(&g)));
}

/// One landing costs one evaluation at the measured live scale: 2,215 proofs
/// over 929 resources, at most 7 per resource (sky's live pile on
/// 2026-10-19). Framing: evaluations per landing, unit test, synthetic store,
/// sky.
#[test]
fn one_landing_costs_one_evaluation_at_live_scale() {
    const PROOFS: usize = 2_215;
    const RESOURCES: usize = 929;
    let alice = key(0xB0);
    let mut pile = Pile::default();
    let definition = deliver(false);
    let handle = handle_of(&definition);
    pile.put(&definition);
    let resources: Vec<CollectionHandle> = (0..RESOURCES)
        .map(|n| pile.put(&resource(&[(&alice, handle)], &format!("resource {n}"))))
        .collect();
    let subject = |n: usize| -> VerifyingKey {
        let mut seed = [0xC0; 32];
        seed[..8].copy_from_slice(&(n as u64).to_le_bytes());
        SigningKey::from_bytes(&seed).verifying_key()
    };
    for n in 0..PROOFS {
        let r = if n < 7 { resources[0] } else { resources[1 + (n - 7) % (RESOURCES - 1)] };
        pile.store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(r),
                &alice,
                handle,
                subject(n),
            ))
            .unwrap();
    }
    let index = pile.observe();
    assert_eq!(index.evaluations(), PROOFS as u64);
    assert_eq!(index.resources().count(), RESOURCES);
    assert_eq!(index.summary(resources[0]).leaf_count(), 7);
    pile.store
        .insert_proof(CapabilityProof::new(
            CapabilityResource::from(resources[3]),
            &alice,
            handle,
            subject(PROOFS),
        ))
        .unwrap();
    let landed = pile.observe();
    assert_eq!(landed.evaluations() - index.evaluations(), 1);
    let unchanged = pile.observe();
    assert_eq!(unchanged.evaluations(), landed.evaluations(), "no change, no evaluation");
}
