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
    agreed: usize,
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
            Frame::Agreed { .. } => self.agreed += 1,
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
    fn with(node: Node, exchange: Exchange<MemoryRepoSnapshot>) -> Self {
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
    let run = pump_any(w, h, useful);
    assert_eq!(w.exchange.outcome(), Some(Outcome::Confirmed));
    assert_eq!(h.exchange.outcome(), Some(Outcome::Confirmed));
    run
}

/// As [`pump`], but an exchange may fail: the pump stops when either side
/// failed (its stream is reset) or nothing moves.
fn pump_any(w: &mut Side, h: &mut Side, useful: usize) -> Run {
    let failed = |side: &Side| matches!(side.exchange.outcome(), Some(Outcome::Failed(_)));
    let mut rounds = 0;
    let mut first_useful = None;
    let mut all_useful = None;
    loop {
        rounds += 1;
        assert!(rounds < 1_000_000, "did not quiesce");
        let mut moved = false;
        while !failed(w)
            && !failed(h)
            && let Some(frame) = w.next()
        {
            moved = true;
            h.hear(frame);
            if first_useful.is_none() && h.useful_landed >= 1.min(useful) && useful > 0 {
                first_useful = Some((rounds, w.wire.bytes));
            }
            if all_useful.is_none() && h.useful_landed >= useful {
                all_useful = Some((rounds, w.wire.bytes));
            }
        }
        while !failed(w)
            && !failed(h)
            && let Some(frame) = h.next()
        {
            moved = true;
            w.hear(frame);
        }
        if !moved || failed(w) || failed(h) {
            break;
        }
    }
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
    assert_eq!(
        forgotten.w.values, 1_010,
        "every body goes out before its HAVE"
    );
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
                row(
                    "symmetric",
                    n as usize,
                    0,
                    d,
                    agreement,
                    &run(&r, d, agreement),
                );
            }
        }
    }
    for extra in [9_000u64, 99_000] {
        let r = records(1_000, extra, 10);
        for d in [1, 10] {
            for agreement in [true, false] {
                row(
                    "superset",
                    1_000,
                    extra as usize,
                    d,
                    agreement,
                    &run(&r, d, agreement),
                );
            }
        }
    }
}

/// The agreement carried over a closed connection, through the walks: the
/// writer and the hub each keep what they confirmed in memory when the
/// connection closes, and the reconnect's exchange is taken against it
/// only once the hub has seen the writer's AGREED and holds the same tree.
mod persisted {
    use super::*;
    use crate::walk_stream::{Algorithm, OfferRole};

    /// The writer only sends C to the hub; the hub only receives it.
    fn node(byte: u8, peer: u8, sends: bool) -> (Node, CollectionHandle) {
        let mut node = Node::new(byte);
        let collection = node.hold(NAME, open());
        let peer = Node::new(peer).id();
        node.health.update(|health| {
            health.peerings.push(crate::health::PeeringHealth {
                collection,
                peer,
                asked: false,
                peered: true,
                sends,
                receives: !sends,
                refused_by_me: false,
                refused_by_them: false,
            })
        });
        node.observe();
        (node, collection)
    }

    struct Lane {
        w: Node,
        h: Node,
        collection: CollectionHandle,
    }

    struct Synced {
        run: Run,
        w: Option<Outcome>,
        h: Option<Outcome>,
        /// The hub's walks asked to exchange again at once.
        again: bool,
    }

    impl Lane {
        fn new(r: &Records, writer: usize, hub: usize) -> Self {
            let (mut w, collection) = node(WRITER, HUB, true);
            let (mut h, _) = node(HUB, WRITER, false);
            assert_eq!(collection, r.collection);
            for record in &r.shared[..writer] {
                w.store.insert(*record).unwrap();
            }
            for record in &r.shared[..hub] {
                h.store.insert(*record).unwrap();
            }
            w.observe();
            h.observe();
            Self { w, h, collection }
        }

        /// One exchange the writer opens, as the walks start it on both
        /// sides, ended into both walks. A side that failed resets the
        /// stream as failed, which its peer reads.
        fn sync(self, useful: &[CollectionRecord]) -> (Self, Synced) {
            let Self { w, h, collection } = self;
            let (wid, hid) = (w.id(), h.id());
            let we = w.walks.start(hid, collection, WalkKind::Commit).unwrap();
            assert_eq!(we.offer_role(), Some(OfferRole::Send));
            let he = h
                .walks
                .start_incoming(
                    wid,
                    collection,
                    WalkKind::Commit,
                    Algorithm::Prefix,
                    Some(OfferRole::Send),
                )
                .unwrap();
            let mut ws = Side::with(w, we);
            let mut hs = Side::with(h, he);
            hs.useful = useful.iter().map(|r| r.fingerprint().raw()).collect();
            let run = pump_any(&mut ws, &mut hs, useful.len());
            let (wo, ho) = (ws.exchange.outcome(), hs.exchange.outcome());
            let failed = |o: Option<Outcome>| matches!(o, Some(Outcome::Failed(_)));
            let now = crate::clock::mono_now();
            let end = |side: Side, peer, peer_failed| {
                let mut node = side.node;
                let mut ended = side.exchange.end();
                ended.peer_failed = peer_failed;
                let again = node
                    .walks
                    .ended(peer, collection, WalkKind::Commit, ended, now);
                (node, again)
            };
            let (w, _) = end(ws, hid, failed(ho));
            let (h, again) = end(hs, wid, failed(wo));
            (
                Self { w, h, collection },
                Synced {
                    run,
                    w: wo,
                    h: ho,
                    again,
                },
            )
        }

        /// The connection closes: both sides carry their agreement over.
        fn close(&mut self) {
            let (wid, hid) = (self.w.id(), self.h.id());
            self.w.walks.closed(hid);
            self.h.walks.closed(wid);
        }

        fn write(&mut self, records: &[CollectionRecord]) {
            for record in records {
                self.w.store.insert(*record).unwrap();
            }
            self.w.observe();
            self.h.observe();
        }

        fn confirmed(
            node: &Node,
            peer: crate::transport::PeerId,
            collection: CollectionHandle,
        ) -> Option<PatchSummary> {
            node.health
                .snapshot()
                .collections
                .iter()
                .find(|entry| entry.collection == collection)?
                .peers
                .iter()
                .find(|pair| pair.peer == peer)?
                .confirmed
                .commits
        }

        /// Both sides confirmed the same agreed root, the writer's tree.
        fn agree(&self) {
            let w = Self::confirmed(&self.w, self.h.id(), self.collection);
            let h = Self::confirmed(&self.h, self.w.id(), self.collection);
            assert_eq!(w, h);
            assert_eq!(
                w,
                Some(
                    Tree::pinned(WalkKind::Commit, self.w.pinned(self.collection).repair())
                        .summary()
                )
            );
        }
    }

    fn after(label: &str, n: usize, d: usize, run: &Run) {
        eprintln!(
            "PREFIX_RECONNECT_PERSISTED {label} w={n} d={d} | W->H bytes={} frames={} agreed={} nodes={} leaves={} values={} | H->W bytes={} haves={} | rounds={} all_useful={}",
            run.w.bytes,
            run.w.frames,
            run.w.agreed,
            run.w.nodes,
            run.w.leaves,
            run.w.values,
            run.h.bytes,
            run.h.haves,
            run.rounds,
            run.all_useful
                .map_or("-".into(), |(r, b)| format!("r{r}/{b}B")),
        );
    }

    /// First sync, close, d new records, reconnect: the reconnect costs what
    /// a kept agreement costs, not the whole collection.
    fn reconnect(r: &Records, d: usize) -> (Lane, Run) {
        let n = r.shared.len();
        // The hub already holds the writer's records (as after any earlier
        // sync); the first exchange is still the full walk that agrees G.
        let (mut lane, first) = Lane::new(r, n, n).sync(&[]);
        assert_eq!(first.w, Some(Outcome::Confirmed));
        assert_eq!(first.h, Some(Outcome::Confirmed));
        assert_eq!(first.run.w.values, n);
        lane.agree();
        lane.close();
        lane.write(&r.new[..d]);
        let (mut lane, again) = lane.sync(&r.new[..d]);
        assert_eq!(again.w, Some(Outcome::Confirmed));
        assert_eq!(again.h, Some(Outcome::Confirmed));
        assert_eq!(again.run.landed, d);
        assert_eq!(again.run.w.agreed, 1, "a carried G is announced");
        lane.agree();
        assert_eq!(lane.h.records(lane.collection).len(), n + d);
        (lane, again.run)
    }

    #[test]
    fn prefix_reconnect_reuses_the_carried_agreement() {
        let r = records(1_000, 0, 10);
        let (_, run) = reconnect(&r, 10);
        let held = super::run(&r, 10, true);
        let forgotten = super::run(&r, 10, false);
        after("carried", 1_000, 10, &run);
        row("symmetric", 1_000, 0, 10, true, &held);
        row("symmetric", 1_000, 0, 10, false, &forgotten);
        assert_eq!(run.w.values, 10);
        assert_eq!(run.w.leaves, 10);
        assert_eq!(run.h.haves, held.h.haves);
        // The only extra is the 45-byte AGREED frame.
        assert_eq!(run.w.bytes, held.w.bytes + HEADER + 40);
        assert_eq!(run.rounds, held.rounds);
    }

    /// The hub restarted (its walks forgot every agreement) with its store
    /// intact: it refuses the writer's AGREED, both forget G, the hub asks
    /// to exchange again at once, and that full walk converges. The next
    /// reconnect is cheap again.
    #[test]
    fn a_restarted_hub_refuses_the_carried_agreement_and_the_full_walk_converges() {
        let r = records(1_000, 0, 20);
        let (mut lane, first) = Lane::new(&r, 1_000, 0).sync(&r.shared);
        assert_eq!(first.h, Some(Outcome::Confirmed));
        lane.close();
        let (mut hub, _) = node(HUB, WRITER, false);
        for record in lane.h.records(lane.collection) {
            hub.store.insert(record).unwrap();
        }
        hub.observe();
        lane.h = hub;
        lane.write(&r.new[..10]);
        let (lane, refused) = lane.sync(&r.new[..10]);
        assert_eq!(refused.h, Some(Outcome::Failed(Failure::StaleAgreement)));
        assert!(refused.again, "a stale agreement is followed at once");
        assert_eq!(refused.run.landed, 0);
        assert!(
            refused.run.w.bytes < 64 * 1_024,
            "refused within the first window"
        );
        let (mut lane, full) = lane.sync(&r.new[..10]);
        assert_eq!(full.w, Some(Outcome::Confirmed));
        assert_eq!(full.h, Some(Outcome::Confirmed));
        assert_eq!(full.run.w.agreed, 0);
        assert_eq!(full.run.w.values, 1_010, "the full walk");
        assert_eq!(lane.h.records(lane.collection).len(), 1_010);
        lane.agree();
        lane.close();
        lane.write(&r.new[10..20]);
        let (mut lane, cheap) = lane.sync(&r.new[10..20]);
        assert_eq!(cheap.h, Some(Outcome::Confirmed));
        assert_eq!(cheap.run.w.values, 10);
        assert_eq!(lane.h.records(lane.collection).len(), 1_020);
    }

    /// The hub's store was restored from an older backup while its walks
    /// kept the carried agreement: it no longer holds every key in G, so it
    /// does not offer G, refuses the writer's, and the full walk restores
    /// what it lost.
    #[test]
    fn a_hub_restored_from_an_older_backup_gets_back_what_it_lost() {
        let r = records(1_000, 0, 10);
        let (mut lane, first) = Lane::new(&r, 1_000, 0).sync(&r.shared);
        assert_eq!(first.h, Some(Outcome::Confirmed));
        let g = Arc::new(Tree::pinned(
            WalkKind::Commit,
            lane.w.pinned(lane.collection).repair(),
        ));
        lane.close();
        // Restored from a backup holding half the records, its walks
        // carrying the agreement over from before.
        let (mut hub, _) = node(HUB, WRITER, false);
        for record in &r.shared[..500] {
            hub.store.insert(*record).unwrap();
        }
        hub.observe();
        let wid = lane.w.id();
        hub.walks.ended(
            wid,
            lane.collection,
            WalkKind::Commit,
            Ended {
                sends: false,
                receives: true,
                confirmed: true,
                landed: true,
                root: g.summary(),
                peer_root: Some(g.summary()),
                retain_agreement: true,
                agreed: Some(g.clone()),
                failure: None,
                refused: false,
                peer_failed: false,
                skipped: 0,
            },
            crate::clock::mono_now(),
        );
        hub.walks.closed(wid);
        lane.h = hub;
        lane.write(&r.new[..10]);
        let (lane, refused) = lane.sync(&r.new[..10]);
        assert_eq!(refused.h, Some(Outcome::Failed(Failure::StaleAgreement)));
        let (mut lane, full) = lane.sync(&r.new[..10]);
        assert_eq!(full.h, Some(Outcome::Confirmed));
        assert_eq!(full.w, Some(Outcome::Confirmed));
        assert_eq!(
            lane.h.records(lane.collection).len(),
            1_010,
            "nothing stays lost"
        );
        lane.agree();
    }

    /// The writer restarted with its store intact, the hub carrying G: the
    /// writer walks against nothing, the hub's AGREED is only information to
    /// a side that does not receive, and both end on the writer's tree, so
    /// the following reconnect is cheap.
    #[test]
    fn a_restarted_writer_walks_in_full_once_and_then_reconnects_cheaply() {
        let r = records(1_000, 0, 20);
        let (mut lane, _) = Lane::new(&r, 1_000, 0).sync(&r.shared);
        lane.close();
        let (mut writer, _) = node(WRITER, HUB, true);
        for record in lane.w.records(lane.collection) {
            writer.store.insert(record).unwrap();
        }
        writer.observe();
        lane.w = writer;
        lane.write(&r.new[..10]);
        let (mut lane, full) = lane.sync(&r.new[..10]);
        assert_eq!(full.w, Some(Outcome::Confirmed));
        assert_eq!(full.h, Some(Outcome::Confirmed));
        assert_eq!(full.run.w.agreed, 0, "the writer has nothing to announce");
        assert_eq!(full.run.h.agreed, 1);
        // The writer announces its whole tree; the hub's carried G, which it
        // still holds, certifies coarse HAVEs that prune most eager bodies.
        assert_eq!(full.run.landed, 10);
        assert!(full.run.w.values < 1_010, "{}", full.run.w.values);
        assert_eq!(lane.h.records(lane.collection).len(), 1_010);
        lane.agree();
        lane.close();
        lane.write(&r.new[10..20]);
        let (_, cheap) = lane.sync(&r.new[10..20]);
        assert_eq!(cheap.h, Some(Outcome::Confirmed));
        assert_eq!(cheap.run.w.values, 10);
    }

    /// Before and after. `cargo test -p triblespace-net
    /// prefix_reconnect_persisted_table -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement table, minutes at n = 100k"]
    fn prefix_reconnect_persisted_table() {
        for n in [1_000u64, 10_000, 100_000] {
            let r = records(n, 0, 100);
            for d in [1, 10, 100] {
                let (_, run) = reconnect(&r, d);
                after("carried", n as usize, d, &run);
            }
        }
    }
}
