//! Selection defaults, with native authorization and nonempty private holdings.

use super::tests::walking::{Node, open};
use super::*;
use crate::exchange::Failure;
use crate::walk_stream::Algorithm;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy};

#[test]
fn default_two_way_walks_use_cached_riblt_and_explicit_prefix_still_works() {
    let mut local = Node::new(181);
    let peer = Node::new(182);
    let collection = local.hold("default two-way selection", open());
    local.commit(collection, 7);
    local.observe();
    let mut walks = Walks::new(local.health.clone());
    walks.observe(local.snapshot());

    for kind in [WalkKind::Commit, WalkKind::Derive, WalkKind::References] {
        assert_eq!(
            walks
                .start(peer.id(), collection, kind)
                .unwrap()
                .algorithm(),
            Algorithm::CachedRiblt,
        );
        for requested in [Algorithm::Prefix, Algorithm::CachedRiblt] {
            assert_eq!(
                walks
                    .start_selected(peer.id(), collection, kind, Some(requested))
                    .unwrap()
                    .algorithm(),
                requested,
                "incoming explicit selection is independent of the opening default",
            );
        }
    }

    // Grant walks are Prefix only, whatever the default or the request.
    assert_eq!(
        walks
            .start(peer.id(), collection, WalkKind::Authorization)
            .unwrap()
            .algorithm(),
        Algorithm::Prefix,
    );
    assert!(
        walks
            .start_selected(
                peer.id(),
                collection,
                WalkKind::Authorization,
                Some(Algorithm::CachedRiblt),
            )
            .is_none()
    );

    let prefix = walks.with_algorithm(Algorithm::Prefix);
    assert_eq!(
        prefix
            .start(peer.id(), collection, WalkKind::Commit)
            .unwrap()
            .algorithm(),
        Algorithm::Prefix,
    );
    assert_eq!(
        prefix
            .start_selected(
                peer.id(),
                collection,
                WalkKind::Commit,
                Some(Algorithm::CachedRiblt),
            )
            .unwrap()
            .algorithm(),
        Algorithm::CachedRiblt,
    );
}

#[test]
fn default_one_way_walks_use_prefix_without_disclosing_receive_only_holdings() {
    for receive_only in [true, false] {
        let mut local = Node::new(183);
        let peer = Node::new(184);
        let owner = AdmissionPolicy::direct(local.key.verifying_key());
        let policy = if receive_only {
            CollectionPolicy::new(owner, AdmissionPolicy::Open)
        } else {
            CollectionPolicy::new(AdmissionPolicy::Open, owner)
        };
        let collection = local.hold("default one-way selection", policy);
        let private_key = local.commit(collection, 9).fingerprint().raw();
        local.observe();
        let mut walks = Walks::new(local.health.clone());
        walks.observe(local.snapshot());

        // Grant walks always receive (grant_walk_tests).
        for kind in [WalkKind::Commit, WalkKind::Derive, WalkKind::References] {
            assert!(
                walks
                    .start_selected(peer.id(), collection, kind, Some(Algorithm::CachedRiblt))
                    .is_none(),
                "one-way authority refuses an incoming symmetric equation",
            );
            for requested in [None, Some(Algorithm::Prefix)] {
                let mut exchange = walks
                    .start_selected(peer.id(), collection, kind, requested)
                    .unwrap();
                assert_eq!(exchange.algorithm(), Algorithm::Prefix);
                assert_eq!(exchange.receives(), receive_only);
                if receive_only {
                    assert_eq!(
                        exchange.next_delta(),
                        Some(Frame::Subtree {
                            prefix: Vec::new(),
                            summary: PatchSummary::new(None, 0).unwrap(),
                        }),
                        "even a nonempty private source advertises only the empty delta",
                    );
                    assert_eq!(exchange.next_delta(), Some(Frame::Done));
                    assert!(exchange.next_body().is_none());
                    if kind == WalkKind::Commit {
                        let outs = exchange.on_frame(
                            Frame::ValueRequest { key: private_key },
                            Some(local.snapshot()),
                        );
                        assert!(outs.is_empty(), "private bodies are not served on request");
                        assert_eq!(exchange.outcome(), Some(Outcome::Failed(Failure::Protocol)));
                    }
                }
            }
        }
    }
}
