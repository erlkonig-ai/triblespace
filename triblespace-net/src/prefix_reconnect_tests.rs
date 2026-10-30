//! What one-way Prefix (sender only -> receiver only) puts on the wire after
//! a reconnect, when the agreed tree G was forgotten, against the same sync
//! with G still held. Measurement, not a fix.
//!
//! The pump follows the walk driver's frame order (walk.rs: answers, then an
//! eager body, then the next delta) and models a link whose round trip is
//! long against a frame's write time: in each round the sender writes
//! everything it may, then the receiver hears all of it and its replies
//! reach the sender together. A round is one round trip. Every frame is
//! counted through the real codec with the 5-byte walk frame header
//! (connection.rs write_frame).
use super::*;
use crate::walk::tests::walking::{Node, key, open};
use std::collections::BTreeSet;
use triblespace_core::collection::{
    CollectionCommit, CollectionData, CollectionStore, empty_metadata_handle,
};
use triblespace_core::repo::memoryrepo::MemoryRepoSnapshot;

const HEADER: usize = 5;
const WRITER: u8 = 211;
const HUB: u8 = 212;
const NAME: &str = "prefix-reconnect";

#[derive(Default, Clone, Copy, Debug)]
struct Wire {
    frames: usize,
    bytes: usize,
    nodes: usize,
    leaves: usize,
    values: usize,
    haves: usize,
    requests: usize,
}

impl Wire {
    fn count(&mut self, frame: &Frame) {
        let (_, payload) = frame.encode();
        self.frames += 1;
        self.bytes += HEADER + payload.len();
        match frame {
            Frame::Subtree { prefix, .. } if prefix.len() == KEY_BYTES => self.leaves += 1,
            Frame::Subtree { .. } => self.nodes += 1,
            Frame::Value { .. } => self.values += 1,
            Frame::Have { .. } => self.haves += 1,
            Frame::ValueRequest { .. } => self.requests += 1,
            _ => {}
        }
    }
}

struct Side {
    node: Node,
    exchange: Exchange<MemoryRepoSnapshot>,
    replies: VecDeque<Frame>,
    wire: Wire,
    /// Keys whose landing is useful here (records new to this side).
    useful: BTreeSet<[u8; KEY_BYTES]>,
    useful_landed: usize,
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
            wire: Wire::default(),
            useful: BTreeSet::new(),
            useful_landed: 0,
        }
    }
    fn outputs(&mut self, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Send(frame) => self.replies.push_back(frame),
                Out::Land(events) => self.land(events),
                Out::Fetch(_) => panic!("records need no fetch"),
                Out::Pending(_) => panic!("records are never pending"),
            }
        }
    }
    fn land(&mut self, events: Vec<NetEvent>) {
        for event in &events {
            if let NetEvent::CollectionRecord(record) = event
                && self.useful.contains(&record.fingerprint().raw())
            {
                self.useful_landed += 1;
            }
        }
        let (landed, failed) = self.node.insert(events);
        // The landing task publishes in batches; one observation per landing
        // batch is what the walk sees at most.
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
    /// The driver's order: answers, then an eager body, then the delta.
    fn next(&mut self) -> Option<Frame> {
        let frame = self
            .replies
            .pop_front()
            .or_else(|| self.exchange.next_body())
            .or_else(|| self.exchange.next_delta())?;
        self.wire.count(&frame);
        Some(frame)
    }
}

#[derive(Debug)]
struct Run {
    w: Wire,
    h: Wire,
    rounds: usize,
    /// (round, writer bytes sent) when the first / last useful record landed.
    first_useful: Option<(usize, usize)>,
    all_useful: Option<(usize, usize)>,
    landed: usize,
}

/// Long-RTT pump: per round the writer writes all it may, the hub hears it
/// all, then the hub's replies all reach the writer.
fn pump(w: &mut Side, h: &mut Side, useful: usize) -> Run {
    let mut rounds = 0;
    let mut first_useful = None;
    let mut all_useful = None;
    loop {
        rounds += 1;
        assert!(rounds < 1_000_000, "did not quiesce");
        let mut moved = false;
        while let Some(frame) = w.next() {
            moved = true;
            h.hear(frame);
            if first_useful.is_none() && h.useful_landed >= 1.min(useful) && useful > 0 {
                first_useful = Some((rounds, w.wire.bytes));
            }
            if all_useful.is_none() && h.useful_landed >= useful {
                all_useful = Some((rounds, w.wire.bytes));
            }
        }
        while let Some(frame) = h.next() {
            moved = true;
            w.hear(frame);
        }
        if !moved {
            break;
        }
    }
    assert_eq!(w.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(h.exchange.outcome(), Some(Outcome::Confirmed));
    Run {
        w: w.wire,
        h: h.wire,
        rounds: rounds - 1,
        first_useful,
        all_useful,
        landed: h.useful_landed,
    }
}

/// Pre-signed records, so each run only inserts.
struct Records {
    collection: CollectionHandle,
    shared: Vec<CollectionRecord>,
    hub_only: Vec<CollectionRecord>,
    new: Vec<CollectionRecord>,
}

fn sign(byte: u8, collection: CollectionHandle, data: u64) -> CollectionRecord {
    CollectionRecord::Commit(CollectionCommit::sign(
        &key(byte),
        collection,
        CollectionData::new(*blake3::hash(&data.to_be_bytes()).as_bytes()),
        empty_metadata_handle(),
    ))
}

fn records(shared: u64, hub_only: u64, new: u64) -> Records {
    let collection = Node::new(WRITER).hold(NAME, open());
    Records {
        collection,
        shared: (0..shared).map(|i| sign(WRITER, collection, i)).collect(),
        hub_only: (0..hub_only)
            .map(|i| sign(HUB, collection, 1_000_000_000 + i))
            .collect(),
        new: (0..new)
            .map(|i| sign(WRITER, collection, 2_000_000_000 + i))
            .collect(),
    }
}

/// Writer: shared + first `d` new. Hub: shared + hub-only. G, when held, is
/// what a prior one-way W->H exchange confirmed: the writer's shared records
/// (a receive-only side advertises the empty delta, so hub-only records
/// never enter G).
fn run(r: &Records, d: usize, agreement: bool) -> Run {
    let mut w = Node::new(WRITER);
    let mut h = Node::new(HUB);
    assert_eq!(w.hold(NAME, open()), r.collection);
    assert_eq!(h.hold(NAME, open()), r.collection);
    for record in r.shared.iter().chain(&r.hub_only) {
        h.store.insert(*record).unwrap();
    }
    for record in &r.shared {
        w.store.insert(*record).unwrap();
    }
    w.observe();
    let agreed = agreement.then(|| {
        Arc::new(Tree::pinned(
            WalkKind::Commit,
            w.pinned(r.collection).repair(),
        ))
    });
    for record in &r.new[..d] {
        w.store.insert(*record).unwrap();
    }
    w.observe();
    h.observe();
    let mut w = Side::new(w, r.collection, true, agreed.clone());
    let mut h = Side::new(h, r.collection, false, agreed);
    h.useful = r.new[..d].iter().map(|r| r.fingerprint().raw()).collect();
    let run = pump(&mut w, &mut h, d);
    assert_eq!(run.landed, d);
    assert_eq!(
        h.node.records(r.collection).len(),
        r.shared.len() + r.hub_only.len() + d
    );
    run
}

fn row(label: &str, n: usize, extra: usize, d: usize, agreement: bool, run: &Run) {
    let at = |x: Option<(usize, usize)>| x.map_or("-".into(), |(r, b)| format!("r{r}/{b}B"));
    eprintln!(
        "PREFIX_RECONNECT {label} w={n} hub_only={extra} d={d} G={} | W->H bytes={} frames={} nodes={} leaves={} values={} requests={} | H->W bytes={} haves={} requests={} | rounds={} first_useful={} all_useful={}",
        if agreement { "held" } else { "forgotten" },
        run.w.bytes,
        run.w.frames,
        run.w.nodes,
        run.w.leaves,
        run.w.values,
        run.w.requests,
        run.h.bytes,
        run.h.haves,
        run.h.requests,
        run.rounds,
        at(run.first_useful),
        at(run.all_useful),
    );
}

/// The regression-sized claim: after a reconnect a write-only sender
/// re-announces and re-sends every record it holds; with G it sends d.
#[test]
fn prefix_reconnect_without_agreement_resends_the_whole_writer_collection() {
    let r = records(1_000, 0, 10);
    let forgotten = run(&r, 10, false);
    let held = run(&r, 10, true);
    row("symmetric", 1_000, 0, 10, false, &forgotten);
    row("symmetric", 1_000, 0, 10, true, &held);
    assert_eq!(forgotten.w.leaves, 1_010);
    assert_eq!(forgotten.w.values, 1_010, "every body goes out before its HAVE");
    assert_eq!(forgotten.h.haves, 1_010);
    assert_eq!(held.w.leaves, 10);
    assert_eq!(held.w.values, 10);
    assert!(forgotten.rounds >= 1_010 / prefix_offer::WINDOW);
}

/// Hub holds the writer's records plus many of its own: without G the hub's
/// extras cost nothing extra, but the writer's whole collection is resent.
#[test]
fn prefix_reconnect_hub_superset_without_agreement() {
    let r = records(1_000, 9_000, 10);
    let forgotten = run(&r, 10, false);
    let held = run(&r, 10, true);
    row("superset", 1_000, 9_000, 10, false, &forgotten);
    row("superset", 1_000, 9_000, 10, true, &held);
    assert_eq!(forgotten.w.values, 1_010);
    assert_eq!(held.w.values, 10);
}

/// The full table. `cargo test -p triblespace-net prefix_reconnect_table --
/// --ignored --nocapture`.
#[test]
#[ignore = "measurement table, minutes at n = 100k"]
fn prefix_reconnect_table() {
    for n in [1_000u64, 10_000, 100_000] {
        let r = records(n, 0, 100);
        for d in [1, 10, 100] {
            for agreement in [true, false] {
                row("symmetric", n as usize, 0, d, agreement, &run(&r, d, agreement));
            }
        }
    }
    for extra in [9_000u64, 99_000] {
        let r = records(1_000, extra, 10);
        for d in [1, 10] {
            for agreement in [true, false] {
                row("superset", 1_000, extra as usize, d, agreement, &run(&r, d, agreement));
            }
        }
    }
}
