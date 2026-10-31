//! Selection defaults, with native authorization and nonempty private holdings.

use super::tests::walking::{Node, open};
use super::*;
use crate::exchange::Failure;
use crate::walk_stream::Algorithm;
use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, HeldStore};

/// Captured log output of the current thread while `f` runs.
fn logged(f: impl FnOnce()) -> String {
    #[derive(Clone, Default)]
    struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = Buffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap()
}

#[test]
fn two_way_walks_are_cached_riblt_without_configuration() {
    let mut local = Node::new(181);
    let peer = Node::new(182);
    let collection = local.hold("default two-way selection", open());
    local.commit(collection, 7);
    // A references tree is exchanged only once its held set is published.
    local.store.track_held([collection]);
    local.observe();
    let mut walks = Walks::new(local.health.clone());
    walks.observe(local.snapshot());

    for kind in [WalkKind::Commit, WalkKind::Derive, WalkKind::References] {
        let exchange = walks.start(peer.id(), collection, kind).unwrap();
        assert_eq!(exchange.algorithm(), Algorithm::CachedRiblt);
        assert_eq!(exchange.offer_role(), None);
        assert_eq!(
            walks
                .start_incoming(peer.id(), collection, kind, Algorithm::CachedRiblt, None)
                .unwrap()
                .algorithm(),
            Algorithm::CachedRiblt,
        );
    }

    // Grant walks are Prefix, the deliberate exception (grant_walk_tests).
    assert_eq!(
        walks
            .start(peer.id(), collection, WalkKind::Authorization)
            .unwrap()
            .algorithm(),
        Algorithm::Prefix,
    );
}

#[test]
fn an_incoming_two_way_prefix_walk_of_data_is_refused_and_logged() {
    let mut local = Node::new(185);
    let peer = Node::new(186);
    let collection = local.hold("two-way prefix refused", open());
    local.commit(collection, 3);
    local.store.track_held([collection]);
    local.observe();
    let mut walks = Walks::new(local.health.clone());
    walks.observe(local.snapshot());

    for kind in [WalkKind::Commit, WalkKind::Derive, WalkKind::References] {
        let mut joined = None;
        let log = logged(|| {
            joined = Some(
                walks
                    .start_incoming(peer.id(), collection, kind, Algorithm::Prefix, None)
                    .is_some(),
            );
        });
        assert_eq!(joined, Some(false), "{kind:?}: two-way Prefix of data is refused");
        assert!(
            log.contains("refused walk: two-way Prefix of a data tree"),
            "{kind:?}: the refusal is logged: {log:?}"
        );
    }

    // A grant walk asking for the same profile is joined as before.
    let log = logged(|| {
        assert!(
            walks
                .start_incoming(peer.id(), collection, WalkKind::Authorization, Algorithm::Prefix, None)
                .is_some()
        );
    });
    assert!(!log.contains("refused walk"));
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
        local.store.track_held([collection]);
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
