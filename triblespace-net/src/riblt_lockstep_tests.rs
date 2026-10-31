//! A balanced cached exchange in deterministic lockstep, through the codec.
//!
//! The production driver's `select!` is unbiased, so its transcripts vary
//! from run to run. This loop has no scheduler: each side writes one frame
//! per turn (an answer, an eager body, or the next of its delta), the
//! writer receipt follows at once, and FIN follows a side's readiness once it
//! has nothing left to write. Its transcript digests were pinned from the
//! symmetric protocol before cached roles existed (b08c83c7), so equal
//! counts must keep exactly that exchange.

use std::collections::VecDeque;

use triblespace_core::repo::memoryrepo::MemoryRepoSnapshot;

use crate::channel::NetEvent;
use crate::exchange::{Exchange, Out, Outcome};
use crate::walk::WalkKind;
use crate::walk::tests::walking::{Node, open};
use crate::walk_stream::Frame;

struct End {
    node: Node,
    exchange: Exchange<MemoryRepoSnapshot>,
    outbox: VecDeque<Frame>,
    cells: usize,
    sent: Vec<u8>,
    fin: bool,
}

impl End {
    fn handle(&mut self, outs: Vec<Out>) {
        let mut outs = VecDeque::from(outs);
        while let Some(out) = outs.pop_front() {
            match out {
                Out::Send(frame) => self.outbox.push_back(frame),
                Out::Land(events) => {
                    let (landed, failed) = self.node.insert(events);
                    outs.extend(self.exchange.on_landed_ack(landed, failed));
                }
                other => panic!("unexpected work: {other:?}"),
            }
        }
    }
}

fn lockstep(a_n: u64, shared: u64, foreign: u64) -> (String, String, usize, usize) {
    let mut a = Node::new(251);
    let mut b = Node::new(252);
    let collection = a.hold("riblt-lockstep", open());
    assert_eq!(b.hold("riblt-lockstep", open()), collection);
    let mut records = Vec::new();
    for i in 0..a_n {
        let record = a.commit(collection, i);
        if i < shared {
            records.push(NetEvent::CollectionRecord(record));
        }
    }
    assert_eq!(b.insert(records).1, 0);
    for i in 0..foreign {
        b.commit(collection, 1_000_000 + i);
    }
    a.observe();
    b.observe();
    let end = |node: Node| End {
        exchange: Exchange::start_riblt(collection, WalkKind::Commit, node.pinned(collection)),
        node,
        outbox: VecDeque::new(),
        cells: 0,
        sent: Vec::new(),
        fin: false,
    };
    let mut ends = [end(a), end(b)];
    loop {
        let mut moved = false;
        for from in [0, 1] {
            let [first, second] = &mut ends;
            let (src, dst) = if from == 0 {
                (first, second)
            } else {
                (second, first)
            };
            let next = src
                .outbox
                .pop_front()
                .or_else(|| src.exchange.next_body())
                .or_else(|| src.exchange.next_delta());
            if let Some(frame) = next {
                moved = true;
                let (kind, bytes) = frame.encode();
                src.sent.push(kind);
                src.sent
                    .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                src.sent.extend_from_slice(&bytes);
                let receipt = match &frame {
                    Frame::RibltCell { .. } => {
                        src.cells += 1;
                        src.exchange.on_written(src.cells)
                    }
                    Frame::RibltRoot { .. } => src.exchange.on_root_written(),
                    _ => Vec::new(),
                };
                src.handle(receipt);
                let frame = Frame::decode(kind, &bytes).unwrap().unwrap();
                let snapshot = dst.node.snapshot();
                let outs = dst.exchange.on_frame(frame, Some(snapshot));
                dst.handle(outs);
            } else if src.exchange.ready_to_finish() && !src.fin {
                moved = true;
                src.fin = true;
                let outs = dst.exchange.on_fin();
                dst.handle(outs);
            }
        }
        if !moved {
            break;
        }
    }
    for end in &ends {
        assert_eq!(end.exchange.outcome(), Some(Outcome::Confirmed));
        assert!(end.fin);
    }
    let digest = |bytes: &[u8]| blake3::hash(bytes).to_hex()[..16].to_string();
    (
        digest(&ends[0].sent),
        digest(&ends[1].sent),
        ends[0].cells,
        ends[1].cells,
    )
}

#[test]
fn riblt_asym_balanced_lockstep_transcript_is_byte_identical_to_the_symmetric_protocol() {
    let run = lockstep(1000, 900, 100);
    eprintln!("RIBLT_LOCKSTEP balanced_1000 {run:?}");
    assert_eq!((run.0.as_str(), run.1.as_str(), run.2, run.3), PINNED);
    // Deterministic: a second run is the same exchange.
    assert_eq!(lockstep(1000, 900, 100), run);
}

/// From b08c83c7, the symmetric protocol before roles.
const PINNED: (&str, &str, usize, usize) = ("c17898bfdf78117b", "52e6d50cde87dc99", 281, 338);
