//! Offer-only feedback and bounded eager admission, through the real codec.
use super::*;
use crate::walk::tests::walking::{Node, open};
use triblespace_core::collection::CollectionStore;

struct Side {
    node: Node,
    exchange: Exchange,
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

#[test]
fn prefix_offer_private_extras_do_not_change_cold_receipts() {
    fn receipts(private: bool) -> Vec<Frame> {
        let (mut a, mut b, _, _) = fixture(20, 20, private);
        // The exact private-root graft in the no-extras arm must remain proof-only.
        while let Some(frame) = a.exchange.next_delta() {
            b.hear(frame);
        }
        let receipts: Vec<_> = b
            .replies
            .into_iter()
            .filter(|f| matches!(f, Frame::Have { .. }))
            .collect();
        assert_eq!(receipts.len(), 20);
        assert!(
            receipts
                .iter()
                .all(|f| matches!(f, Frame::Have { prefix, .. } if prefix.len()==KEY_BYTES))
        );
        receipts
    }
    assert_eq!(receipts(false), receipts(true));
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
