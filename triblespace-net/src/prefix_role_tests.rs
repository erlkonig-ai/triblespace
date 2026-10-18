//! OPEN commits to the typed body protocol independently of local preferences.
use super::tests::walking::{Node, open};
use super::*;
use crate::walk_stream::{Algorithm, FRAME_OPEN, OfferRole};
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};

#[test]
fn prefix_offer_open_roles_roundtrip_and_reject_wrong_components() {
    for (offer, byte) in [
        (None, 0),
        (Some(OfferRole::Send), 2),
        (Some(OfferRole::Receive), 3),
    ] {
        for kind in [WalkKind::Commit, WalkKind::Authorization] {
            let frame = Frame::Open {
                collection: CollectionHandle::new([9; 32]),
                kind,
                algorithm: Algorithm::Prefix,
                offer,
            };
            let (tag, mut bytes) = frame.encode();
            assert_eq!(bytes.len(), 34);
            assert_eq!(bytes[33], byte);
            assert_eq!(Frame::decode(tag, &bytes).unwrap(), Some(frame));
            if offer.is_some() {
                bytes[32] = WalkKind::References.wire();
                assert!(Frame::decode(tag, &bytes).is_err());
            }
            bytes[33] = 4;
            assert!(Frame::decode(FRAME_OPEN, &bytes).is_err());
        }
    }
}

#[test]
fn prefix_offer_open_role_mismatch_refused_and_pull_never_infers_eager() {
    for receive_only in [false, true] {
        let mut local = Node::new(221);
        let peer = Node::new(222);
        let owner = AdmissionPolicy::direct(local.key.verifying_key());
        let policy = if receive_only {
            CollectionPolicy::new(owner, AdmissionPolicy::Open)
        } else {
            CollectionPolicy::new(AdmissionPolicy::Open, owner)
        };
        let collection = local.hold("explicit-prefix-body-role", policy);
        let incoming = if receive_only {
            OfferRole::Send
        } else {
            OfferRole::Receive
        };
        let wrong = if receive_only {
            OfferRole::Receive
        } else {
            OfferRole::Send
        };
        for kind in [WalkKind::Commit, WalkKind::Authorization] {
            let outgoing = local.walks.start(peer.id(), collection, kind).unwrap();
            assert_eq!(outgoing.offer_role(), Some(wrong));
            assert!(
                local
                    .walks
                    .start_incoming(peer.id(), collection, kind, Algorithm::Prefix, Some(wrong))
                    .is_none()
            );
            let accepted = local
                .walks
                .start_incoming(
                    peer.id(),
                    collection,
                    kind,
                    Algorithm::Prefix,
                    Some(incoming),
                )
                .unwrap();
            assert_eq!(accepted.offer_role(), Some(wrong));
            let pull = local
                .walks
                .start_incoming(peer.id(), collection, kind, Algorithm::Prefix, None)
                .unwrap();
            assert_eq!(
                pull.offer_role(),
                None,
                "wire mode 0 never infers eager acceptance"
            );
            assert!(
                local
                    .walks
                    .start_incoming(
                        peer.id(),
                        collection,
                        kind,
                        Algorithm::CachedRiblt,
                        Some(incoming)
                    )
                    .is_none()
            );
        }
        assert!(
            local
                .walks
                .start_incoming(
                    peer.id(),
                    collection,
                    WalkKind::References,
                    Algorithm::Prefix,
                    Some(incoming)
                )
                .is_none()
        );
    }
    let mut local = Node::new(223);
    let peer = Node::new(224);
    let collection = local.hold("two-way-prefix-remains-pull", open());
    for role in [OfferRole::Send, OfferRole::Receive] {
        assert!(
            local
                .walks
                .start_incoming(
                    peer.id(),
                    collection,
                    WalkKind::Commit,
                    Algorithm::Prefix,
                    Some(role)
                )
                .is_none()
        );
    }
}
