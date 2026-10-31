//! Offer-only feedback and bounded eager admission, through the real codec.
use super::*;
use crate::walk::tests::walking::{Node, open};
use triblespace_core::collection::CollectionStore;
use triblespace_core::repo::memoryrepo::MemoryRepoSnapshot;

struct Side {
    node: Node,
    exchange: Exchange<MemoryRepoSnapshot>,
    replies: VecDeque<Frame>,
    sent: Vec<Frame>,
    held: Vec<Vec<NetEvent>>,
    hold: bool,
    landed: usize,
}

impl Side {
    fn new(
        node: Node,
        collection: CollectionHandle,
        sends: bool,
        agreed: Option<Arc<Tree>>,
    ) -> Self {
        let exchange = Exchange::start_one_way(
            collection,
            WalkKind::Commit,
            node.pinned(collection),
            agreed,
            sends,
            !sends,
        );
        Self {
            node,
            exchange,
            replies: VecDeque::new(),
            sent: Vec::new(),
            held: Vec::new(),
            hold: false,
            landed: 0,
        }
    }
    fn outputs(&mut self, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Send(frame) => self.replies.push_back(frame),
                Out::Land(events) if self.hold => self.held.push(events),
                Out::Land(events) => self.land(events),
                Out::Fetch(_) => panic!("records need no fetch"),
                Out::Pending(_) => panic!("records are never pending"),
            }
        }
    }
    fn land(&mut self, events: Vec<NetEvent>) {
        self.landed += events.len();
        let (landed, failed) = self.node.insert(events);
        self.node.observe();
        let outs = self.exchange.on_landed_ack(landed, failed);
        self.outputs(outs);
    }
    fn hear(&mut self, frame: Frame) {
        let (tag, bytes) = frame.encode();
        let frame = Frame::decode(tag, &bytes).unwrap().unwrap();
        let outs = self.exchange.on_frame(frame, Some(self.node.snapshot()));
        self.outputs(outs);
    }
    fn next(&mut self) -> Option<Frame> {
        let frame = self
            .replies
            .pop_front()
            .or_else(|| self.exchange.next_body())
            .or_else(|| self.exchange.next_delta())?;
        self.sent.push(frame.clone());
        Some(frame)
    }
}

fn fixture(
    n: u64,
    shared: usize,
    private: bool,
) -> (Side, Side, CollectionHandle, Vec<CollectionRecord>) {
    let mut a = Node::new(201);
    let mut b = Node::new(202);
    let collection = a.hold("prefix-offer-regressions", open());
    assert_eq!(b.hold("prefix-offer-regressions", open()), collection);
    let records: Vec<_> = (0..n).map(|i| a.commit(collection, i)).collect();
    for record in records.iter().take(shared) {
        b.store.insert(*record).unwrap();
    }
    if private {
        b.commit(collection, n + 100);
    }
    a.observe();
    b.observe();
    (
        Side::new(a, collection, true, None),
        Side::new(b, collection, false, None),
        collection,
        records,
    )
}

fn drain(a: &mut Side, b: &mut Side) {
    for _ in 0..10_000 {
        let mut moved = false;
        if let Some(frame) = a.next() {
            b.hear(frame);
            moved = true;
        }
        if let Some(frame) = b.next() {
            a.hear(frame);
            moved = true;
        }
        if !moved {
            return;
        }
    }
    panic!("bounded fixture did not quiesce");
}

#[test]
fn prefix_offer_all_missing_three_windows_no_requests_exact_landings() {
    let (mut a, mut b, collection, _) = fixture(131, 0, false);
    // Delay all return traffic until the sender spends its complete window.
    let mut windows = 0;
    for _ in 0..10 {
        while let Some(frame) = a.next() {
            b.hear(frame);
        }
        if a.exchange.offers.as_ref().unwrap().full() {
            windows += 1;
        }
        while let Some(frame) = b.next() {
            a.hear(frame);
        }
        if a.exchange.outcome().is_some() && b.exchange.outcome().is_some() {
            break;
        }
    }
    drain(&mut a, &mut b);
    assert!(windows >= 2);
    assert_eq!(a.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.node.records(collection).len(), 131);
    assert_eq!(b.landed, 131);
    assert_eq!(
        a.sent
            .iter()
            .filter(|f| matches!(f, Frame::Value { .. }))
            .count(),
        131
    );
    assert_eq!(
        b.sent
            .iter()
            .filter(|f| matches!(f, Frame::Have { .. }))
            .count(),
        131
    );
    assert!(
        !a.sent
            .iter()
            .chain(&b.sent)
            .any(|f| matches!(f, Frame::ValueRequest { .. }))
    );
    eprintln!(
        "PREFIX_OFFER all_missing=131 window=64 values=131 landings=131 have=131 value_requests=0"
    );
}

fn haves(side: &Side) -> Vec<(Vec<u8>, PatchSummary)> {
    side.sent
        .iter()
        .filter_map(|f| match f {
            Frame::Have { prefix, summary } => Some((prefix.clone(), *summary)),
            _ => None,
        })
        .collect()
}

fn count(side: &Side, same: impl Fn(&Frame) -> bool) -> usize {
    side.sent.iter().filter(|f| same(f)).count()
}

/// Cold, with no shared G: a receiver whose ORIGINAL pin holds exactly the
/// offered subtree acknowledges it with one coarse HAVE, and the writer prunes
/// the whole subtree. The reply discloses membership, never contents.
#[test]
fn prefix_offer_cold_exact_pin_sends_one_coarse_have_and_writer_prunes() {
    let (mut a, mut b, collection, _) = fixture(20, 20, false);
    assert!(b.exchange.agreed.is_none() && a.exchange.agreed.is_none());
    let root = a.next().unwrap();
    b.hear(root);
    // Deliver the root receipt before the writer emits any descendant.
    while let Some(frame) = b.next() {
        a.hear(frame);
    }
    assert_eq!(
        haves(&b),
        vec![(Vec::new(), a.exchange.delta.summary())],
        "one coarse HAVE repeating the exact offered root commitment"
    );
    assert!(a.exchange.queue.is_empty(), "the writer pruned every descendant");
    drain(&mut a, &mut b);
    assert_eq!(a.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(count(&a, |f| matches!(f, Frame::Subtree { .. })), 1);
    assert_eq!(count(&a, |f| matches!(f, Frame::Value { .. })), 0, "no held body resent");
    assert_eq!(count(&b, |f| matches!(f, Frame::Have { .. })), 1);
    assert_eq!(b.landed, 0);
    assert_eq!(b.node.records(collection).len(), 20);
}

/// A receiver whose pin differs at a prefix -- a private extra, or keys it
/// lacks -- sends no coarse HAVE there. Every coarse HAVE it does send names
/// a prefix where its pin equals the exact offer; leaves keep their per-leaf
/// receipts, on possession or after landing.
#[test]
fn prefix_offer_unequal_or_private_extra_subtree_sends_no_coarse_have_there() {
    for (shared, private) in [(20, true), (10, false)] {
        let (mut a, mut b, collection, records) = fixture(20, shared, private);
        let extra = private.then(|| {
            b.node
                .records(collection)
                .into_iter()
                .map(|record| record.fingerprint().raw())
                .find(|key| records.iter().all(|r| r.fingerprint().raw() != *key))
                .unwrap()
        });
        let pin = b.exchange.pinned.clone();
        drain(&mut a, &mut b);
        assert_eq!(a.exchange.outcome(), Some(Outcome::Confirmed));
        assert_eq!(b.exchange.outcome(), Some(Outcome::Confirmed));
        let haves = haves(&b);
        assert!(!haves.is_empty());
        for (prefix, summary) in &haves {
            assert_eq!(a.exchange.delta.at(prefix), Some(*summary), "an exact offer");
            if prefix.len() < KEY_BYTES {
                assert_eq!(pin.at(prefix), Some(*summary), "held exactly by the original pin");
            }
            if let Some(extra) = extra {
                assert!(!extra.starts_with(prefix), "no HAVE over the private extra");
            }
        }
        assert!(!haves.iter().any(|(prefix, _)| prefix.is_empty()), "the roots differ");
        // Every offered leaf is acknowledged once, coarsely or by itself.
        for record in &records {
            let key = record.fingerprint().raw();
            assert_eq!(
                haves.iter().filter(|(prefix, _)| key.starts_with(prefix)).count(),
                1,
                "shared={shared} private={private}"
            );
        }
        assert_eq!(b.landed, 20 - shared, "only missing bodies land");
        assert_eq!(
            b.node.records(collection).len(),
            20 + usize::from(private)
        );
    }
}

/// The peer proof is never custody evidence: here it already holds a full
/// graft equal to the offer while the receiver's pin and G hold nothing. No
/// coarse HAVE follows; the bodies are taken and land as for any cold receiver.
#[test]
fn prefix_offer_coarse_have_never_comes_from_the_peer_proof() {
    let (mut a, mut b, collection, _) = fixture(20, 0, false);
    b.exchange.peer = Tree::pinned(WalkKind::Commit, a.node.pinned(collection).repair());
    assert_eq!(b.exchange.peer.summary(), a.exchange.delta.summary());
    drain(&mut a, &mut b);
    assert_eq!(a.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.exchange.outcome(), Some(Outcome::Confirmed));
    assert!(
        haves(&b).iter().all(|(prefix, _)| prefix.len() == KEY_BYTES),
        "no coarse HAVE from a proof graft"
    );
    assert_eq!(count(&b, |f| matches!(f, Frame::Have { .. })), 20);
    assert_eq!(b.landed, 20);
    assert_eq!(b.node.records(collection).len(), 20);
}

/// References are handle-only and never enter HAVE mode: no offer role, no
/// HAVE even when the receiver holds exactly the offered handles, and a
/// HAVE sent to a References writer is a protocol error.
#[test]
fn prefix_offer_references_never_send_or_accept_have() {
    let held = |numbers: std::ops::Range<u64>| {
        let mut patch = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
        for number in numbers {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&number.to_be_bytes());
            patch.insert(&Entry::new(&key));
        }
        patch
    };
    let (a, b, collection, _) = fixture(1, 0, false);
    let kind = WalkKind::References;
    let start = |node: &Node, sends: bool| {
        Exchange::<MemoryRepoSnapshot>::start_one_way(
            collection,
            kind,
            node.pinned(collection).with_inventory(held(0..40)),
            None,
            sends,
            !sends,
        )
    };
    let mut writer = start(&a.node, true);
    let mut reader = start(&b.node, false);
    assert!(writer.offers.is_none() && reader.offers.is_none());
    assert_eq!((writer.offer_role(), reader.offer_role()), (None, None));
    let root = writer.next_delta().unwrap();
    let Frame::Subtree { summary, .. } = root.clone() else {
        unreachable!()
    };
    assert_eq!(reader.pinned.at(&[]), Some(summary), "an exactly equal held set");
    let outs = reader.on_frame(root, Some(b.node.snapshot()));
    assert!(
        !outs
            .iter()
            .any(|out| matches!(out, Out::Send(Frame::Have { .. }))),
        "References never acknowledge by HAVE"
    );
    assert_eq!(reader.outcome(), None);
    writer.on_frame(
        Frame::Have {
            prefix: Vec::new(),
            summary,
        },
        Some(a.node.snapshot()),
    );
    assert_eq!(writer.outcome(), Some(Outcome::Failed(Failure::Protocol)));
}

#[test]
fn prefix_offer_shared_g_prunes_root_even_with_private_extras() {
    let (mut a, mut b, collection, _) = fixture(20, 20, true);
    let shared = Arc::new(Tree::pinned(
        WalkKind::Commit,
        a.node.pinned(collection).repair(),
    ));
    b.exchange = Exchange::start_one_way(
        collection,
        WalkKind::Commit,
        b.node.pinned(collection),
        Some(shared),
        false,
        true,
    );
    let root = a.next().unwrap();
    b.hear(root);
    // Drain the root HAVE before the sender emits descendants.
    while let Some(frame) = b.next() {
        a.hear(frame);
    }
    assert!(a.exchange.queue.is_empty());
    drain(&mut a, &mut b);
    assert_eq!(a.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(
        a.sent
            .iter()
            .filter(|f| matches!(f, Frame::Subtree { .. }))
            .count(),
        1
    );
    assert_eq!(b.landed, 0);
    assert_eq!(b.node.records(collection).len(), 21);
}

#[test]
fn prefix_offer_held_have_cancels_unsent_body_and_late_body_lands_once() {
    let (mut a, mut b, _, _) = fixture(1, 1, false);
    b.hear(a.exchange.next_delta().unwrap());
    let leaf = a.exchange.next_delta().unwrap();
    b.hear(leaf);
    let pending = a.exchange.next_body().unwrap();
    for have in b
        .replies
        .drain(..)
        .filter(|f| matches!(f, Frame::Have { .. }))
    {
        a.hear(have.clone());
        a.hear(have); // A late duplicate cannot release another credit.
    }
    assert!(!a.exchange.keep_pending(&pending));
    assert!(a.exchange.next_body().is_none());
    b.hear(pending.clone());
    b.hear(pending);
    assert_eq!(b.landed, 0, "already-held racing bodies never reland");

    let (mut a, mut b, _, _) = fixture(1, 0, false);
    b.hold = true;
    b.hear(a.exchange.next_delta().unwrap());
    b.hear(a.exchange.next_delta().unwrap());
    let body = a.exchange.next_body().unwrap();
    b.hear(body.clone());
    b.hear(body);
    assert_eq!(b.held.len(), 1);
    assert!(
        !b.replies
            .iter()
            .any(|f| matches!(f, Frame::Have { .. } | Frame::Landed))
    );
    b.hear(a.exchange.next_delta().unwrap()); // DONE, but landing is owed.
    assert!(
        !b.replies
            .iter()
            .any(|f| matches!(f, Frame::Have { .. } | Frame::Landed))
    );
    b.hold = false;
    for events in std::mem::take(&mut b.held) {
        b.land(events);
    }
    assert_eq!(b.landed, 1);
    assert_eq!(
        b.replies
            .iter()
            .filter(|f| matches!(f, Frame::Have { .. }))
            .count(),
        1
    );
    assert!(b.replies.contains(&Frame::Landed));
    eprintln!(
        "PREFIX_OFFER duplicate_missing_values=2 canonical_landings=1 held_racing_values=2 canonical_landings=0"
    );
}

#[test]
fn prefix_offer_no_receipts_bounds_speculation_without_false_completion() {
    let (mut a, _, _, _) = fixture(131, 0, false);
    while a.next().is_some() {}
    assert_eq!(
        a.sent
            .iter()
            .filter(|f| matches!(f, Frame::Value { .. }))
            .count(),
        prefix_offer::WINDOW
    );
    assert!(a.exchange.awaits());
    assert_eq!(a.exchange.outcome(), None);
    assert!(!a.sent.contains(&Frame::Done));
}

#[test]
fn prefix_offer_unoffered_value_receipt_and_failed_landing_refused() {
    let (mut a, mut b, _, records) = fixture(1, 0, false);
    let key = records[0].fingerprint().raw();
    let bytes = Value::from_record_view(&records[0].into()).unwrap()
        .bytes(a.exchange.collection)
        .unwrap();
    b.hear(Frame::Value { key, bytes });
    assert_eq!(
        b.exchange.outcome(),
        Some(Outcome::Failed(Failure::Protocol))
    );
    let summary = a.exchange.delta.summary();
    a.hear(Frame::Have {
        prefix: Vec::new(),
        summary,
    });
    assert_eq!(
        a.exchange.outcome(),
        Some(Outcome::Failed(Failure::Protocol))
    );

    let (mut a, mut b, _, _) = fixture(1, 0, false);
    b.hold = true;
    b.hear(a.exchange.next_delta().unwrap());
    b.hear(a.exchange.next_delta().unwrap());
    b.hear(a.exchange.next_body().unwrap());
    let outs = b.exchange.on_landed_ack(0, 1);
    assert!(outs.is_empty());
    assert_eq!(
        b.exchange.outcome(),
        Some(Outcome::Failed(Failure::InsertFailed))
    );
    assert!(
        !b.replies
            .iter()
            .any(|f| matches!(f, Frame::Have { .. } | Frame::Landed))
    );
}

#[test]
fn prefix_offer_codec_requires_exact_nonempty_canonical_commitment() {
    let (a, _, _, records) = fixture(1, 0, false);
    let frame = Frame::Have {
        prefix: records[0].fingerprint().raw().to_vec(),
        summary: a.exchange.delta.summary(),
    };
    let (tag, bytes) = frame.encode();
    assert_eq!(Frame::decode(tag, &bytes).unwrap(), Some(frame));
    let (tag, empty_bytes) = Frame::Have {
        prefix: Vec::new(),
        summary: empty(),
    }
    .encode();
    assert!(Frame::decode(tag, &empty_bytes).is_err());
    let mut padded = bytes;
    padded[0] = 0;
    assert!(Frame::decode(tag, &padded).is_err());
}

#[test]
fn prefix_offer_coarse_have_racing_child_uses_shared_g_when_live_lags() {
    let (mut a, mut b, collection, _) = fixture(1, 0, false);
    let shared = Arc::new(Tree::pinned(
        WalkKind::Commit,
        a.node.pinned(collection).repair(),
    ));
    b.exchange = Exchange::start_one_way(
        collection,
        WalkKind::Commit,
        b.node.pinned(collection),
        Some(shared),
        false,
        true,
    );
    let parent = a.exchange.next_delta().unwrap();
    let child = a.exchange.next_delta().unwrap(); // Already generated/queued.
    let speculative = a.exchange.next_body().unwrap();
    b.hear(parent);
    let coarse = b.replies.pop_front().unwrap();
    assert!(matches!(&coarse, Frame::Have { prefix, .. } if prefix.is_empty()));
    a.hear(coarse);
    assert!(!a.exchange.keep_pending(&speculative));
    b.hear(child);
    assert!(
        b.exchange.requests.is_empty(),
        "G already certified this child; its body was canceled"
    );
    assert!(b.exchange.wanted.is_empty());
    drain(&mut a, &mut b);
    assert_eq!(a.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.landed, 0);
}

#[test]
fn prefix_offer_wrong_commitment_and_invalid_repeated_value_are_errors() {
    let (mut a, _, _, _) = fixture(1, 0, false);
    let Frame::Subtree { prefix, summary } = a.next().unwrap() else {
        unreachable!()
    };
    a.hear(Frame::Have {
        prefix,
        summary: PatchSummary::new(summary.root(), 2).unwrap(),
    });
    assert_eq!(
        a.exchange.outcome(),
        Some(Outcome::Failed(Failure::Protocol))
    );
    let (mut a, mut b, _, _) = fixture(1, 0, false);
    b.hold = true;
    b.hear(a.exchange.next_delta().unwrap());
    b.hear(a.exchange.next_delta().unwrap());
    let body = a.exchange.next_body().unwrap();
    b.hear(body.clone());
    let Frame::Value { key, mut bytes } = body else {
        unreachable!()
    };
    bytes[0] ^= 0xff;
    b.hear(Frame::Value { key, bytes });
    assert_eq!(
        b.exchange.outcome(),
        Some(Outcome::Failed(Failure::BadValue))
    );
    assert_eq!(b.held.len(), 1);
    assert!(
        b.exchange.on_landed_ack(1, 0).is_empty(),
        "late ACK cannot resurrect a failed stream"
    );
}
