//! The per-resource grant walk (design: grants gossip by participation).
//!
//! A walk of kind Authorization reconciles the grants over any resource R
//! from the grant index, not a collection's evidence. The sender sends to a
//! participant of R (a peering counts only where it sends R); the receiver
//! receives and keeps a proof only when a prefix names it, it takes part in
//! R, or the link is peered for R either way.
//! Anything else is skipped and the walk still confirms. Every negative
//! assertion has a positive control in the same test.

use ed25519_dalek::SigningKey;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::capability::CapabilityProof;
use triblespace_core::collection::{
    AdmissionPolicy, CollectionHandle, CollectionPolicy, write_capability,
};
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
use triblespace_core::repo::{
    BlobStorePut, CapabilityProofRead, CapabilityProofStore, SnapshotSource,
};
use triblespace_core::trible::TribleSet;

use crate::exchange::tests::{Side, carry};
use crate::exchange::{Exchange, Failure, Outcome, Pinned};
use crate::grants_index_tests::{deliver, grant, handle_of, id, key, resource};
use crate::health::PeeringHealth;
use crate::patch_repair::PatchSummary;
use crate::transport::PeerId;
use crate::walk::tests::walking::Node;
use crate::walk::{KEY_BYTES, WalkKind};
use crate::walk_stream::{Algorithm, Frame, OfferRole};

const AUTH: WalkKind = WalkKind::Authorization;

fn empty() -> PatchSummary {
    PatchSummary::new(None, 0).unwrap()
}

fn root(summary: PatchSummary) -> Frame {
    Frame::Subtree {
        prefix: Vec::new(),
        summary,
    }
}

/// Put `facts` into `node`'s store.
fn put(node: &mut Node, facts: &TribleSet) -> CollectionHandle {
    node.store.put::<SimpleArchive, _>(facts.clone()).unwrap()
}

fn insert(node: &mut Node, proofs: &[&CapabilityProof]) {
    for proof in proofs {
        node.store.insert_proof((*proof).clone()).unwrap();
    }
    node.observe();
}

/// The stored proof with `proof`'s id, if any.
fn stored(node: &mut Node, proof: &CapabilityProof) -> Option<CapabilityProof> {
    node.store
        .snapshot()
        .unwrap()
        .proofs()
        .unwrap()
        .map(Result::unwrap)
        .find(|held| held.id() == proof.id())
}

fn proof_count(node: &mut Node) -> usize {
    node.store.snapshot().unwrap().proofs().unwrap().count()
}

/// Mark `peer` as peered for `collection` in `node`'s health.
fn peer_with(node: &Node, collection: CollectionHandle, peer: PeerId) {
    peer_sending(node, collection, peer, true);
}

/// Mark `peer` as peered for `collection` in `node`'s health, with this side
/// sending C to it or not.
fn peer_sending(node: &Node, collection: CollectionHandle, peer: PeerId, sends: bool) {
    node.health.update(|health| {
        health.peerings.push(PeeringHealth {
            collection,
            peer,
            asked: false,
            peered: true,
            sends,
            receives: true,
            refused_by_me: false,
            refused_by_them: false,
        })
    });
}

/// A non-collection resource rooted at `root` with one delegable definition,
/// put into each of `nodes`: (R, the definition's handle).
fn rooted(
    root: &SigningKey,
    label: &str,
    nodes: &mut [&mut Node],
) -> (CollectionHandle, triblespace_core::capability::CapabilityHandle) {
    let definition = deliver(true);
    let handle = handle_of(&definition);
    let descriptor = resource(&[(root, handle)], label);
    let mut resource = None;
    for node in nodes.iter_mut() {
        put(node, &definition);
        resource = Some(put(node, &descriptor));
        node.observe();
    }
    (resource.unwrap(), handle)
}

/// Drive `side` against a scripted sender that announces exactly `values`
/// as R's delta (the root and every leaf), answers each value request with
/// the bytes given, says DONE, and sends LANDED once `side` said DONE.
fn scripted(side: &mut Side, resource: CollectionHandle, values: &[([u8; KEY_BYTES], Vec<u8>)]) {
    let mut tree = PATCH::<64, IdentitySchema, (), Blake3Merkle>::new();
    for (key, _) in values {
        let mut full = [0; 64];
        full[..32].copy_from_slice(&resource.raw);
        full[32..].copy_from_slice(key);
        tree.insert(&Entry::new(&full));
    }
    let declared = tree
        .merkle_node(&resource.raw)
        .map(|node| PatchSummary::new(Some(node.digest()), node.leaf_count()).unwrap())
        .unwrap_or_else(empty);
    side.hear(root(declared));
    for (key, _) in values {
        let leaf = tree.merkle_node(&[&resource.raw[..], &key[..]].concat()).unwrap();
        side.hear(Frame::Subtree {
            prefix: key.to_vec(),
            summary: PatchSummary::new(Some(leaf.digest()), 1).unwrap(),
        });
    }
    let mut done = false;
    loop {
        let mut moved = false;
        while let Some(frame) = side.next() {
            moved = true;
            if let Frame::ValueRequest { key } = frame
                && let Some((_, bytes)) = values.iter().find(|(wanted, _)| *wanted == key)
            {
                side.hear(Frame::Value {
                    key,
                    bytes: bytes.clone(),
                });
            }
        }
        if !done {
            done = true;
            moved = true;
            side.hear(Frame::Done);
        } else if side.sent.contains(&Frame::Done)
            && side.sent.contains(&Frame::Landed)
            && !side.heard.contains(&Frame::Landed)
        {
            moved = true;
            side.hear(Frame::Landed);
        }
        if !moved || side.outcome().is_some() {
            return;
        }
    }
}

fn value(proof: &CapabilityProof) -> ([u8; KEY_BYTES], Vec<u8>) {
    (proof.id().raw, proof.as_bytes().to_vec())
}

#[test]
fn two_grant_pins_converge_to_their_union_with_the_exact_bytes() {
    let [alice, bob, carol] = [0x30, 0x31, 0x32].map(key);
    let mut a = Node::new(0x30);
    let mut b = Node::new(0x31);
    let (r, handle) = rooted(&alice, "walked", &mut [&mut a, &mut b]);
    let to_bob = grant(r, &alice, handle, &bob);
    let to_carol = grant(r, &alice, handle, &carol);
    insert(&mut a, &[&to_bob]);
    insert(&mut b, &[&to_carol]);

    let opened = a
        .walks
        .start(b.id(), r, AUTH)
        .expect("a walk over any resource R starts from the grant index");
    assert_eq!(opened.algorithm(), Algorithm::Prefix);
    assert_eq!(opened.offer_role(), None, "both take part in R: two-way");
    let joined = b
        .walks
        .start_incoming(a.id(), r, AUTH, opened.algorithm(), opened.offer_role())
        .unwrap();
    let mut a = Side::with(a, opened);
    let mut b = Side::with(b, joined);
    carry(&mut a, &mut b);
    assert_eq!(a.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.outcome(), Some(Outcome::Confirmed));
    for side in [&mut a, &mut b] {
        for proof in [&to_bob, &to_carol] {
            let held = stored(&mut side.node, proof).expect("the union landed");
            assert_eq!(held.as_bytes(), proof.as_bytes(), "the exact bytes travel");
            assert_eq!(held.id(), proof.id());
        }
    }
    assert_eq!(
        a.node.serving().grants().summary(r),
        b.node.serving().grants().summary(r)
    );
    assert_eq!(a.node.serving().grants().summary(r).leaf_count(), 2);
}

#[test]
fn a_walk_to_a_non_participant_sends_nothing_and_to_a_participant_sends_r() {
    let [alice, bob, stranger] = [0x40, 0x41, 0x4F].map(key);
    let mut a = Node::new(0x40);
    let (r, handle) = rooted(&alice, "disclosed", &mut [&mut a]);
    insert(&mut a, &[&grant(r, &alice, handle, &bob)]);

    let mut to_stranger = a.walks.start(id(&stranger), r, AUTH).unwrap();
    assert_eq!(to_stranger.offer_role(), Some(OfferRole::Receive));
    assert_eq!(to_stranger.next_delta(), Some(root(empty())));
    assert_eq!(to_stranger.next_delta(), Some(Frame::Done));
    assert!(to_stranger.next_body().is_none());

    // Positive control: the same R to a participant carries its grants.
    let mut to_bob = a.walks.start(id(&bob), r, AUTH).unwrap();
    assert_eq!(to_bob.offer_role(), None);
    let local = a.serving().grants().summary(r);
    assert_eq!(local.leaf_count(), 1);
    assert_eq!(to_bob.next_delta(), Some(root(local)));
}

#[test]
fn an_open_read_reader_peered_for_c_keeps_a_late_write_grant_and_an_unpeered_one_skips_it() {
    let [alice, xavier] = [0x50, 0x5A].map(key);
    for peered in [true, false] {
        let mut writer = Node::new(0x50);
        let mut reader = Node::new(0x51);
        let policy = CollectionPolicy::new(
            AdmissionPolicy::Open,
            AdmissionPolicy::direct(alice.verifying_key()),
        );
        let c = writer.hold("open read", policy.clone());
        assert_eq!(reader.hold("open read", policy), c);
        let late = grant(c, &alice, write_capability(), &xavier);
        insert(&mut writer, &[&late]);
        reader.observe();
        peer_with(&writer, c, reader.id());
        if peered {
            peer_with(&reader, c, writer.id());
        }
        let opened = writer.walks.start(reader.id(), c, AUTH).unwrap();
        let joined = reader
            .walks
            .start_incoming(writer.id(), c, AUTH, opened.algorithm(), opened.offer_role())
            .unwrap();
        let mut writer = Side::with(writer, opened);
        let mut reader = Side::with(reader, joined);
        carry(&mut writer, &mut reader);
        assert_eq!(writer.outcome(), Some(Outcome::Confirmed), "peered={peered}");
        assert_eq!(reader.outcome(), Some(Outcome::Confirmed), "peered={peered}");
        assert_eq!(
            stored(&mut reader.node, &late).is_some(),
            peered,
            "only a reader peered for C keeps a grant naming neither it nor a participant"
        );
    }
}

/// A proof over another resource, offered in C's walk, is skipped; a valid
/// grant over C naming the receiver lands in the same walk, which confirms.
/// Undecodable bytes still fail the walk.
#[test]
fn a_proof_over_another_resource_is_skipped_and_the_walk_confirms() {
    let [alice, stranger] = [0x60, 0x6F].map(key);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(alice.verifying_key()),
    );
    let mut bob = Node::new(0x61);
    let bob_key = key(0x61);
    let c = bob.hold("skips foreign", policy.clone());
    let elsewhere = CollectionHandle::new([0x77; 32]);
    let foreign = grant(elsewhere, &alice, write_capability(), &bob_key);
    let valid = grant(c, &alice, write_capability(), &bob_key);
    let before = proof_count(&mut bob);
    let joined = bob
        .walks
        .start_incoming(id(&stranger), c, AUTH, Algorithm::Prefix, None)
        .unwrap();
    let mut side = Side::with(bob, joined);
    scripted(&mut side, c, &[value(&foreign), value(&valid)]);
    assert_eq!(side.outcome(), Some(Outcome::Confirmed));
    assert!(stored(&mut side.node, &foreign).is_none());
    assert!(stored(&mut side.node, &valid).is_some(), "positive control");
    assert_eq!(proof_count(&mut side.node), before + 1);

    // Skip, never fail: but bytes that are no proof still fail.
    let mut bob = Node::new(0x61);
    bob.hold("skips foreign", policy);
    let joined = bob
        .walks
        .start_incoming(id(&stranger), c, AUTH, Algorithm::Prefix, None)
        .unwrap();
    let mut side = Side::with(bob, joined);
    scripted(&mut side, c, &[([0x55; KEY_BYTES], vec![1, 2, 3])]);
    assert_eq!(side.outcome(), Some(Outcome::Failed(Failure::BadValue)));
}

#[test]
fn a_wrong_root_proof_over_an_unknown_r_is_skipped_and_the_agreement_is_the_receivers() {
    let [alice, stranger, zed] = [0x70, 0x7E, 0x7F].map(key);
    let mut far = Node::new(0x7D);
    let (r, handle) = rooted(&alice, "unknown here", &mut [&mut far]);
    let wrong = grant(r, &stranger, handle, &zed);
    let mut bob = Node::new(0x71);
    bob.observe();
    let before = proof_count(&mut bob);
    let joined = bob
        .walks
        .start_incoming(id(&stranger), r, AUTH, Algorithm::Prefix, None)
        .expect("an R absent here is walked from an empty pin");
    let mut side = Side::with(bob, joined);
    scripted(&mut side, r, &[value(&wrong)]);
    assert_eq!(side.outcome(), Some(Outcome::Confirmed));
    assert_eq!(proof_count(&mut side.node), before);
    let local = side.node.serving().grants().summary(r);
    let Side { exchange, .. } = side;
    let agreed = exchange.end().agreed.expect("confirmed").summary();
    assert_eq!(agreed, local, "the agreement is what the receiver holds");
    assert_ne!(agreed.leaf_count(), 1, "never the sender's root");
}

/// A walk counts the proofs it skipped, and only those: a foreign proof is
/// counted, the valid grant landing beside it is not, and the agreement is
/// what the receiver holds.
#[test]
fn a_walk_counts_what_it_skipped_and_not_what_it_landed() {
    let [alice, stranger] = [0x64, 0x6E].map(key);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(alice.verifying_key()),
    );
    let mut bob = Node::new(0x65);
    let bob_key = key(0x65);
    let c = bob.hold("counts skips", policy);
    let foreign = grant(CollectionHandle::new([0x78; 32]), &alice, write_capability(), &bob_key);
    let valid = grant(c, &alice, write_capability(), &bob_key);
    let joined = bob
        .walks
        .start_incoming(id(&stranger), c, AUTH, Algorithm::Prefix, None)
        .unwrap();
    let mut side = Side::with(bob, joined);
    scripted(&mut side, c, &[value(&foreign), value(&valid)]);
    assert_eq!(side.outcome(), Some(Outcome::Confirmed));
    assert!(stored(&mut side.node, &valid).is_some(), "positive control: it landed");
    side.node.observe();
    let local = side.node.serving().grants().summary(c);
    assert_eq!(local.leaf_count(), 1);
    let Side { exchange, .. } = side;
    let ended = exchange.end();
    assert_eq!(ended.skipped, 1, "the foreign proof, not the landed one");
    assert_eq!(ended.agreed.expect("confirmed").summary(), local);
}

#[test]
fn an_incoming_walk_over_an_absent_r_starts_empty_and_receives() {
    let mut bob = Node::new(0x81);
    bob.observe();
    let absent = CollectionHandle::new([0x88; 32]);
    let mut joined = bob
        .walks
        .start_incoming(id(&key(0x80)), absent, AUTH, Algorithm::Prefix, None)
        .expect("Bob's case: nothing about R is held yet");
    assert!(joined.receives());
    assert_eq!(joined.next_delta(), Some(root(empty())));
}

#[test]
fn a_cached_riblt_grant_walk_is_refused_and_a_prefix_one_accepted() {
    let mut bob = Node::new(0x91);
    let c = bob.hold("prefix only", crate::walk::tests::walking::open());
    let peer = id(&key(0x90));
    assert!(
        bob.walks
            .start_incoming(peer, c, AUTH, Algorithm::CachedRiblt, None)
            .is_none()
    );
    assert!(
        bob.walks
            .start_selected(peer, c, AUTH, Some(Algorithm::CachedRiblt))
            .is_none()
    );
    assert!(
        bob.walks
            .start_incoming(peer, c, AUTH, Algorithm::Prefix, None)
            .is_some(),
        "positive control"
    );
}

/// A cold grantee opens receive-only; its sender joins as a one-way sender;
/// a proof naming the grantee whose descriptor it lacks does not land, and
/// the agreement excludes it. A receive-only opener is refused only by a
/// side that does not send to it.
#[test]
fn a_cold_grantee_receives_one_way_and_a_proof_it_cannot_validate_does_not_land() {
    let [alice, bob_key, stranger] = [0xA0, 0xA1, 0xAF].map(key);
    let mut a = Node::new(0xA0);
    let (r, handle) = rooted(&alice, "cold", &mut [&mut a]);
    let to_bob = grant(r, &alice, handle, &bob_key);
    insert(&mut a, &[&to_bob]);
    let mut bob = Node::new(0xA1);
    bob.observe();

    let opened = bob.walks.start(a.id(), r, AUTH).unwrap();
    assert_eq!(opened.offer_role(), Some(OfferRole::Receive));
    assert!(
        a.walks
            .start_incoming(id(&stranger), r, AUTH, Algorithm::Prefix, Some(OfferRole::Receive))
            .is_none(),
        "nobody would send"
    );
    let joined = a
        .walks
        .start_incoming(bob.id(), r, AUTH, opened.algorithm(), opened.offer_role())
        .expect("positive control: Alice sends to a participant");
    assert_eq!(joined.offer_role(), Some(OfferRole::Send));
    let mut bob = Side::with(bob, opened);
    let mut a = Side::with(a, joined);
    carry(&mut a, &mut bob);
    assert_eq!(a.outcome(), Some(Outcome::Confirmed));
    assert_eq!(bob.outcome(), Some(Outcome::Confirmed));
    assert!(stored(&mut bob.node, &to_bob).is_none(), "no descriptor, no landing");
    let local = bob.node.serving().grants().summary(r);
    let Side { exchange, .. } = bob;
    assert_eq!(exchange.end().agreed.unwrap().summary(), local);
}

/// A walk keeps the peer's delta as a membership proof over keys, so a grant
/// it does not keep costs a leaf, not its bytes: every skipped grant shares
/// one stand-in value. The grant it keeps holds its own bytes (positive
/// control), and the walk still confirms.
#[test]
fn a_walk_keeps_no_bytes_of_the_grants_it_does_not_keep() {
    let [alice, stranger] = [0x68, 0x6D].map(key);
    let policy = CollectionPolicy::new(
        AdmissionPolicy::Open,
        AdmissionPolicy::direct(alice.verifying_key()),
    );
    let mut bob = Node::new(0x69);
    let bob_key = key(0x69);
    let c = bob.hold("keeps no skipped bytes", policy);
    let foreign: Vec<CapabilityProof> = (0..4u8)
        .map(|index| {
            let elsewhere = CollectionHandle::new([0x40 + index; 32]);
            grant(elsewhere, &alice, write_capability(), &bob_key)
        })
        .collect();
    let valid = grant(c, &alice, write_capability(), &bob_key);
    let joined = bob
        .walks
        .start_incoming(id(&stranger), c, AUTH, Algorithm::Prefix, None)
        .unwrap();
    let mut side = Side::with(bob, joined);
    let mut values: Vec<_> = foreign.iter().map(value).collect();
    values.push(value(&valid));
    scripted(&mut side, c, &values);
    assert_eq!(side.outcome(), Some(Outcome::Confirmed));
    assert!(stored(&mut side.node, &valid).is_some(), "positive control: it landed");
    assert_eq!(
        side.exchange.peer_bytes(valid.id().raw),
        Some(valid.as_bytes().to_vec()),
        "positive control: a kept grant holds its own bytes"
    );
    let held: std::collections::BTreeSet<Vec<u8>> = foreign
        .iter()
        .map(|proof| side.exchange.peer_bytes(proof.id().raw).expect("each is a leaf"))
        .collect();
    assert_eq!(held.len(), 1, "four skipped grants share one stand-in");
    let Side { exchange, .. } = side;
    let ended = exchange.end();
    assert_eq!(ended.skipped, 4);
}

/// A peering on which this side does not send C (the peer may write C but
/// not read it) makes the peer no participant: a walk with it over C sends
/// none of C's grants and a receive-only opener is refused. Positive
/// control: a peering on which this side sends C does both.
#[test]
fn a_write_only_peering_is_sent_no_grants() {
    let [owner, reader, writer] = [0xB0, 0xB1, 0xBF].map(key);
    for sends in [false, true] {
        let mut a = Node::new(0xB0);
        let c = a.hold(
            "private read, open write",
            CollectionPolicy::new(
                AdmissionPolicy::direct(owner.verifying_key()),
                AdmissionPolicy::Open,
            ),
        );
        insert(&mut a, &[&grant(c, &owner, triblespace_core::collection::read_capability(), &reader)]);
        let local = a.serving().grants().summary(c);
        assert_eq!(local.leaf_count(), 1);
        peer_sending(&a, c, id(&writer), sends);

        let mut opened = a.walks.start(id(&writer), c, AUTH).unwrap();
        let joined = a.walks.start_incoming(
            id(&writer),
            c,
            AUTH,
            Algorithm::Prefix,
            Some(OfferRole::Receive),
        );
        if sends {
            assert_eq!(opened.offer_role(), None, "positive control: both ways");
            assert_eq!(opened.next_delta(), Some(root(local)));
            assert!(joined.is_some(), "positive control: a sender joins a receiver");
        } else {
            assert_eq!(opened.offer_role(), Some(OfferRole::Receive));
            assert_eq!(opened.next_delta(), Some(root(empty())), "no reader is disclosed");
            assert!(joined.is_none(), "nobody would send");
        }
    }
}

/// A one-way grant offer's coarse HAVE certifies only grants the receiver's
/// ORIGINAL pin holds: proofs its grant index judged and indexed. The same
/// indexed grants on both sides are acknowledged by one root HAVE and nothing
/// is resent. A private extra grant, or the same proof BYTES stored but not
/// indexed (no descriptor here), yields no coarse HAVE, and the walk still
/// confirms leaf by leaf.
#[test]
fn a_one_way_grant_offer_coarse_have_certifies_only_indexed_grants() {
    let [alice, bob, carol, dave, erin] = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4].map(key);
    for case in ["indexed", "private extra", "stored unindexed"] {
        let mut a = Node::new(0xC0);
        let mut b = Node::new(0xC5);
        let (r, handle) = if case == "stored unindexed" {
            rooted(&alice, "coarse grants", &mut [&mut a])
        } else {
            rooted(&alice, "coarse grants", &mut [&mut a, &mut b])
        };
        let grants: Vec<_> = [&bob, &carol, &dave]
            .into_iter()
            .map(|subject| grant(r, &alice, handle, subject))
            .collect();
        let refs: Vec<_> = grants.iter().collect();
        insert(&mut a, &refs);
        insert(&mut b, &refs);
        if case == "private extra" {
            insert(&mut b, &[&grant(r, &alice, handle, &erin)]);
        }
        let pin = |node: &Node| {
            Pinned::Grants(r, node.serving().grants().grants(r).unwrap_or_default())
        };
        let indexed = b.serving().grants().summary(r);
        let offered = a.serving().grants().summary(r);
        match case {
            "indexed" => assert_eq!(indexed, offered),
            "private extra" => assert_eq!(indexed.leaf_count(), 4),
            _ => {
                assert_eq!(indexed, empty(), "held bytes, but nothing indexed");
                assert!(grants.iter().all(|proof| stored(&mut b, proof).is_some()));
            }
        }
        let sender = Exchange::start_one_way(r, AUTH, pin(&a), None, true, false);
        let receiver = Exchange::start_one_way(r, AUTH, pin(&b), None, false, true);
        let mut a = Side::with(a, sender);
        let mut b = Side::with(b, receiver);
        // The root receipt, if any, reaches the writer before its descendants.
        let root = a.next().unwrap();
        b.hear(root);
        while let Some(frame) = b.next() {
            a.hear(frame);
        }
        carry(&mut a, &mut b);
        assert_eq!(a.outcome(), Some(Outcome::Confirmed), "{case}");
        assert_eq!(b.outcome(), Some(Outcome::Confirmed), "{case}");
        let coarse: Vec<_> = b
            .sent
            .iter()
            .filter_map(|frame| match frame {
                Frame::Have { prefix, summary } if prefix.len() < KEY_BYTES => {
                    Some((prefix.clone(), *summary))
                }
                _ => None,
            })
            .collect();
        let values = a.count(|frame| matches!(frame, Frame::Value { .. }));
        if case == "indexed" {
            assert_eq!(coarse, vec![(Vec::new(), offered)], "one exact root HAVE");
            assert_eq!(a.count(|frame| matches!(frame, Frame::Subtree { .. })), 1);
            assert_eq!(values, 0, "no held grant is resent");
            assert_eq!(b.count(|frame| matches!(frame, Frame::Have { .. })), 1);
        } else {
            assert!(
                coarse.iter().all(|(prefix, _)| !prefix.is_empty()),
                "{case}: no root HAVE"
            );
            if case == "stored unindexed" {
                assert!(coarse.is_empty(), "unindexed bytes certify nothing");
                assert_eq!(values, 3, "every body is offered");
            }
            let haves = b.count(|frame| matches!(frame, Frame::Have { .. }));
            assert!(haves >= 1, "{case}: leaf receipts continue");
        }
    }
}
