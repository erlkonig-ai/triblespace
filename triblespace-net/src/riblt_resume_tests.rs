//! Resuming a cut-off cached RIBLT exchange (ALPN 36), at the exchange level.
//! Every frame crosses as its wire bytes: cell runs are split into their
//! RIBLT_CELL frames and decoded from the cached bytes themselves.

use std::collections::{BTreeSet, VecDeque};

use anybytes::Bytes;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::Blob;

use super::*;
use triblespace_core::repo::memoryrepo::MemoryRepoSnapshot;
use crate::riblt_resume::{RESUME_BUDGET_BYTES, ResumeCache};
use crate::riblt_store::CHUNK;
use crate::walk::tests::walking::{Node, open};

const KIND: WalkKind = WalkKind::References;

fn blob(n: u64) -> Blob<UnknownBlob> {
    Blob::new(Bytes::from_source(n.to_be_bytes().to_vec()))
}

fn handle(n: u64) -> [u8; 32] {
    blob(n).get_handle().raw
}

/// The fixture blob whose handle this is.
fn body(fetched: [u8; 32]) -> Blob<UnknownBlob> {
    static NUMBERS: std::sync::OnceLock<std::collections::HashMap<[u8; 32], u64>> =
        std::sync::OnceLock::new();
    let numbers = NUMBERS.get_or_init(|| (0..10_000).map(|n| (handle(n), n)).collect());
    blob(numbers[&fetched])
}

fn held(numbers: impl IntoIterator<Item = u64>) -> PATCH<32, IdentitySchema, (), Blake3Merkle> {
    let mut patch = PATCH::new();
    for n in numbers {
        patch.insert(&Entry::new(&handle(n)));
    }
    patch
}

/// Two hosts of one collection; each side's held set is chosen per run.
struct Fixture {
    a: Node,
    b: Node,
    collection: CollectionHandle,
}

impl Fixture {
    fn new() -> Self {
        let mut a = Node::new(241);
        let mut b = Node::new(242);
        let collection = a.hold("riblt-resume", open());
        assert_eq!(b.hold("riblt-resume", open()), collection);
        a.observe();
        b.observe();
        Self { a, b, collection }
    }

    fn side(
        &self,
        node: &Node,
        numbers: &[u64],
        cache: Option<&Arc<ResumeCache>>,
    ) -> Exchange<MemoryRepoSnapshot> {
        let pin = node
            .pinned(self.collection)
            .with_inventory(held(numbers.iter().copied()));
        let exchange = Exchange::start_riblt(self.collection, KIND, pin);
        match cache {
            Some(cache) => exchange.resuming(cache.clone()),
            None => exchange,
        }
    }
}

/// What one side did in one run.
#[derive(Debug, Default)]
struct Seen {
    /// Indices of the cells this side wrote, in order.
    cells: Vec<u32>,
    /// The RESUME this side sent, if any.
    resume: Option<(u32, PatchSummary)>,
    /// Its ROOT's resume flag.
    announced: bool,
    /// Blobs fetched and landed: the remote-only keys it decoded.
    landed: BTreeSet<[u8; 32]>,
}

struct Run {
    a: Seen,
    b: Seen,
    ended: Option<(Ended, Ended)>,
}

/// A frame as the peer reads it off the wire.
fn wire(frame: Frame) -> Vec<Frame> {
    match frame {
        Frame::RibltCells { frames, .. } => frames
            .chunks(crate::riblt_cache::CELL_FRAME_BYTES)
            .map(|bytes| {
                let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
                assert_eq!(length + 5, bytes.len());
                Frame::decode(bytes[0], &bytes[5..]).unwrap().unwrap()
            })
            .collect(),
        frame => {
            let (kind, payload) = frame.encode();
            vec![Frame::decode(kind, &payload).unwrap().unwrap()]
        }
    }
}

/// Drive both exchanges to completion, or stop once each side has heard at
/// least `cut` cells and end both there, as a dropped connection does.
fn run(
    mut a: Exchange<MemoryRepoSnapshot>,
    mut b: Exchange<MemoryRepoSnapshot>,
    fixture: &Fixture,
    cut: Option<usize>,
) -> Run {
    let snapshots = [fixture.a.snapshot(), fixture.b.snapshot()];
    let mut seen = [Seen::default(), Seen::default()];
    let mut outboxes = [VecDeque::new(), VecDeque::new()];
    let mut fetches = [VecDeque::new(), VecDeque::new()];
    let mut heard = [0usize, 0usize];
    let mut fin = [false, false];
    let mut sides = [&mut a, &mut b];
    loop {
        let mut moved = false;
        for from in 0..2 {
            let to = 1 - from;
            // Answers first: the exchange itself orders RESUME after ROOT.
            let frame = outboxes[from]
                .pop_front()
                .or_else(|| sides[from].next_body())
                .or_else(|| sides[from].next_delta());
            let Some(frame) = frame else { continue };
            moved = true;
            match &frame {
                Frame::RibltRoot { resume, .. } => {
                    seen[from].announced = *resume;
                    assert!(sides[from].on_root_written().is_empty());
                }
                Frame::RibltResume { held, root } => seen[from].resume = Some((*held, *root)),
                _ => {}
            }
            let frames = wire(frame);
            for frame in frames {
                if let Frame::RibltCell { index, .. } = frame {
                    seen[from].cells.push(index);
                    heard[to] += 1;
                    for out in sides[from].on_written(index as usize + 1) {
                        if let Out::Send(frame) = out {
                            outboxes[from].push_back(frame);
                        }
                    }
                }
                for out in sides[to].on_frame(frame, Some(snapshots[to].clone())) {
                    match out {
                        Out::Send(frame) => outboxes[to].push_back(frame),
                        Out::Fetch(handle) => fetches[to].push_back(handle),
                        other => panic!("unexpected discovery work: {other:?}"),
                    }
                }
            }
            assert_eq!(sides[from].outcome(), None, "side {from}");
            assert_eq!(sides[to].outcome(), None, "side {to}");
        }
        if let Some(cut) = cut
            && heard.iter().all(|heard| *heard >= cut)
        {
            assert!(
                !sides[0].discovery_stopped() && !sides[1].discovery_stopped(),
                "cut before decoding"
            );
            let [a_seen, b_seen] = seen;
            let _ = (a.end(), b.end());
            return Run {
                a: a_seen,
                b: b_seen,
                ended: None,
            };
        }
        for side in 0..2 {
            while let Some(fetched) = fetches[side].pop_front() {
                moved = true;
                let mut outs = VecDeque::from(sides[side].on_fetched(fetched, Some(body(fetched))));
                while let Some(out) = outs.pop_front() {
                    match out {
                        Out::Fetch(handle) => fetches[side].push_back(handle),
                        Out::Land(events) => {
                            seen[side].landed.insert(fetched);
                            outs.extend(sides[side].on_landed_ack(events.len() as u64, 0));
                        }
                        Out::Send(frame) => outboxes[side].push_back(frame),
                        other => panic!("unexpected completion work: {other:?}"),
                    }
                }
            }
            if sides[side].ready_to_finish() && outboxes[side].is_empty() && !fin[side] {
                fin[side] = true;
                moved = true;
                for out in sides[1 - side].on_fin() {
                    if let Out::Fetch(handle) = out {
                        fetches[1 - side].push_back(handle);
                    }
                }
            }
        }
        if !moved {
            break;
        }
    }
    assert_eq!(a.outcome(), Some(Outcome::Confirmed));
    assert_eq!(b.outcome(), Some(Outcome::Confirmed));
    let [a_seen, b_seen] = seen;
    Run {
        a: a_seen,
        b: b_seen,
        ended: Some((a.end(), b.end())),
    }
}

const SHARED: u64 = 2_000;
const A_ONLY: std::ops::Range<u64> = 2_000..2_300;
const B_ONLY: std::ops::Range<u64> = 2_300..2_600;
const CUT: usize = 200;

fn a_set() -> Vec<u64> {
    (0..SHARED).chain(A_ONLY).collect()
}

fn b_set() -> Vec<u64> {
    (0..SHARED).chain(B_ONLY).collect()
}

fn keys(range: impl IntoIterator<Item = u64>) -> BTreeSet<[u8; 32]> {
    range.into_iter().map(handle).collect()
}

fn agreed(run: &Run) -> PatchSummary {
    let (a, b) = run.ended.as_ref().unwrap();
    let summary = a.agreed.as_ref().unwrap().summary();
    assert_eq!(summary, b.agreed.as_ref().unwrap().summary());
    summary
}

/// The reference: one uninterrupted exchange between the given sets.
fn uninterrupted(fixture: &Fixture, a: &[u64], b: &[u64]) -> Run {
    run(fixture.side(&fixture.a, a, None), fixture.side(&fixture.b, b, None), fixture, None)
}

#[test]
fn a_cut_exchange_resumes_where_it_stopped_and_lands_the_same() {
    let fixture = Fixture::new();
    let (a_cache, b_cache) = (
        ResumeCache::new(RESUME_BUDGET_BYTES),
        ResumeCache::new(RESUME_BUDGET_BYTES),
    );
    let reference = uninterrupted(&fixture, &a_set(), &b_set());
    assert_eq!(reference.a.landed, keys(B_ONLY));
    assert_eq!(reference.b.landed, keys(A_ONLY));

    let a = fixture.side(&fixture.a, &a_set(), Some(&a_cache));
    let b = fixture.side(&fixture.b, &b_set(), Some(&b_cache));
    let (a_root, b_root) = (a.delta.summary(), b.delta.summary());
    let profile = a.riblt.as_ref().unwrap().profile;
    let cut = run(a, b, &fixture, Some(CUT));
    assert!(!cut.a.announced && !cut.b.announced, "nothing was cached yet");
    assert_eq!(cut.a.resume, None);
    // Each side kept exactly the cells it heard, keyed by the PEER's root.
    let b_holds = b_cache.held(&(profile, a_root));
    let a_holds = a_cache.held(&(profile, b_root));
    assert_eq!(b_holds, cut.a.cells.len());
    assert_eq!(a_holds, cut.b.cells.len());
    assert!(b_holds >= CUT && a_holds >= CUT);

    let resumed = run(
        fixture.side(&fixture.a, &a_set(), Some(&a_cache)),
        fixture.side(&fixture.b, &b_set(), Some(&b_cache)),
        &fixture,
        None,
    );
    assert!(resumed.a.announced && resumed.b.announced);
    assert_eq!(resumed.b.resume, Some((b_holds as u32, a_root)));
    assert_eq!(resumed.a.resume, Some((a_holds as u32, b_root)));
    // Zero cells below what the peer holds, and the stream continues there.
    assert_eq!(resumed.a.cells.first(), Some(&(b_holds as u32)));
    assert_eq!(resumed.b.cells.first(), Some(&(a_holds as u32)));
    assert!(resumed.a.cells.iter().all(|index| *index as usize >= b_holds));
    assert!(resumed.b.cells.iter().all(|index| *index as usize >= a_holds));
    // The same difference decoded, the same records landed, the same union.
    assert_eq!(resumed.a.landed, reference.a.landed);
    assert_eq!(resumed.b.landed, reference.b.landed);
    assert_eq!(agreed(&resumed), agreed(&reference));
    // Both together sent no more cells than the uninterrupted run did,
    // counting the cut run's cells, beyond one run each of overshoot.
    let total = cut.a.cells.len() + cut.b.cells.len() + resumed.a.cells.len() + resumed.b.cells.len();
    let reference_total = reference.a.cells.len() + reference.b.cells.len();
    assert!(total <= reference_total + 4 * CELL_RUN, "{total} vs {reference_total}");
    // Success drops the entries.
    assert_eq!((a_cache.len(), b_cache.len()), (0, 0));
}

#[test]
fn a_peer_root_changed_between_connections_starts_from_zero() {
    let fixture = Fixture::new();
    let (a_cache, b_cache) = (
        ResumeCache::new(RESUME_BUDGET_BYTES),
        ResumeCache::new(RESUME_BUDGET_BYTES),
    );
    let a = fixture.side(&fixture.a, &a_set(), Some(&a_cache));
    let b = fixture.side(&fixture.b, &b_set(), Some(&b_cache));
    let a_root = a.delta.summary();
    let profile = a.riblt.as_ref().unwrap().profile;
    run(a, b, &fixture, Some(CUT));
    assert!(b_cache.held(&(profile, a_root)) >= CUT);

    // A gained a key: B holds cells of A's OLD root only.
    let mut grown = a_set();
    grown.push(9_000);
    let a = fixture.side(&fixture.a, &grown, Some(&a_cache));
    let new_root = a.delta.summary();
    assert_ne!(new_root, a_root);
    let resumed = run(a, fixture.side(&fixture.b, &b_set(), Some(&b_cache)), &fixture, None);
    assert!(resumed.b.announced, "B holds a prefix of this profile");
    assert_eq!(resumed.b.resume, Some((0, new_root)), "B claims nothing for A's new root");
    assert_eq!(resumed.a.cells.first(), Some(&0), "A's stream starts from 0");
    let reference = uninterrupted(&fixture, &grown, &b_set());
    assert_eq!(resumed.a.landed, reference.a.landed);
    assert_eq!(resumed.b.landed, reference.b.landed);
    assert_eq!(agreed(&resumed), agreed(&reference));
}

#[test]
fn our_own_set_changed_between_connections_rebuilds_the_residual() {
    let fixture = Fixture::new();
    let (a_cache, b_cache) = (
        ResumeCache::new(RESUME_BUDGET_BYTES),
        ResumeCache::new(RESUME_BUDGET_BYTES),
    );
    let a = fixture.side(&fixture.a, &a_set(), Some(&a_cache));
    let b = fixture.side(&fixture.b, &b_set(), Some(&b_cache));
    let a_root = a.delta.summary();
    let profile = a.riblt.as_ref().unwrap().profile;
    run(a, b, &fixture, Some(CUT));
    let b_holds = b_cache.held(&(profile, a_root));
    assert!(b_holds >= CUT);

    // B's own set changed: it lost ten shared keys and gained twenty of A's.
    // A's root is unchanged, so B's cached cells of A's stream still hold;
    // the residual against B's NEW cells is a different one.
    let changed: Vec<u64> = (10..SHARED).chain(B_ONLY).chain(2_000..2_020).collect();
    let b = fixture.side(&fixture.b, &changed, Some(&b_cache));
    let resumed = run(fixture.side(&fixture.a, &a_set(), Some(&a_cache)), b, &fixture, None);
    assert_eq!(resumed.b.resume, Some((b_holds as u32, a_root)), "B resumes A's stream");
    assert_eq!(resumed.a.cells.first(), Some(&(b_holds as u32)));
    // A's cached cells were of B's OLD root: B's own stream starts from 0.
    assert_eq!(resumed.a.resume.map(|(held, _)| held), Some(0));
    assert_eq!(resumed.b.cells.first(), Some(&0));
    let reference = uninterrupted(&fixture, &a_set(), &changed);
    assert_eq!(resumed.a.landed, reference.a.landed);
    assert_eq!(resumed.b.landed, reference.b.landed);
    assert_eq!(resumed.b.landed, keys((0..10).chain(2_020..2_300)));
    assert_eq!(agreed(&resumed), agreed(&reference));
}

#[test]
fn an_entry_evicted_by_the_budget_starts_from_zero() {
    let fixture = Fixture::new();
    // One chunk of budget: room for one entry at a time.
    let one_chunk = CHUNK * crate::riblt_cache::CELL_FRAME_BYTES;
    let (a_cache, b_cache) = (ResumeCache::new(one_chunk), ResumeCache::new(one_chunk));
    let a = fixture.side(&fixture.a, &a_set(), Some(&a_cache));
    let b = fixture.side(&fixture.b, &b_set(), Some(&b_cache));
    let a_root = a.delta.summary();
    let profile = a.riblt.as_ref().unwrap().profile;
    run(a, b, &fixture, Some(CUT));
    assert!(b_cache.held(&(profile, a_root)) >= CUT);

    // A later cut exchange with another peer's root takes the whole budget.
    let other = PatchSummary::new(Some([0xAB; 32]), 77).unwrap();
    let mut cells = Records::default();
    cells.push(&CellFrame { index: 0, cell: Cell::default() }).unwrap();
    b_cache.keep((profile, other), cells);
    assert_eq!(b_cache.held(&(profile, a_root)), 0, "the older entry is evicted");
    assert_eq!(b_cache.held(&(profile, other)), 1);

    let resumed = run(
        fixture.side(&fixture.a, &a_set(), Some(&a_cache)),
        fixture.side(&fixture.b, &b_set(), Some(&b_cache)),
        &fixture,
        None,
    );
    assert_eq!(resumed.b.resume, Some((0, a_root)));
    assert_eq!(resumed.a.cells.first(), Some(&0), "a budget miss starts from 0");
    let reference = uninterrupted(&fixture, &a_set(), &b_set());
    assert_eq!(resumed.a.landed, reference.a.landed);
    assert_eq!(resumed.b.landed, reference.b.landed);
    assert_eq!(agreed(&resumed), agreed(&reference));
}

#[test]
fn the_cache_keeps_verbatim_frames_and_evicts_oldest_first() {
    let cache = ResumeCache::new(2 * CHUNK * crate::riblt_cache::CELL_FRAME_BYTES);
    let profile = [7; 16];
    let root = |n: u8| PatchSummary::new(Some([n; 32]), n as u64).unwrap();
    let entry = |cells: usize| {
        let mut records = Records::default();
        for index in 0..cells {
            let cell = Cell {
                symbol: KeySymbol([index as u8; 32]),
                hash: index as u64,
                count: 1,
            };
            records.push(&CellFrame { index: index as u32, cell }).unwrap();
        }
        records
    };
    cache.keep((profile, root(1)), entry(3));
    cache.keep((profile, root(2)), entry(5));
    assert!(cache.holds(&profile) && !cache.holds(&[8; 16]));
    cache.keep((profile, root(3)), entry(1));
    assert_eq!(cache.held(&(profile, root(1))), 0, "oldest evicted");
    assert_eq!(cache.held(&(profile, root(2))), 5);
    // An entry larger than the whole budget is not kept at all.
    cache.keep((profile, root(4)), entry(2 * CHUNK + 1));
    assert_eq!(cache.held(&(profile, root(4))), 0);
    // Taken entries are the exact RIBLT_CELL frames, contiguous from 0.
    let taken = cache.take(&(profile, root(2))).unwrap();
    assert_eq!(cache.held(&(profile, root(2))), 0);
    for index in 0..5 {
        let frame = taken.get(index).unwrap();
        let expected = crate::riblt_cache_tests::encoded_cell_frame(index, &frame.cell);
        assert_eq!(frame.index as usize, index);
        let mut stored = vec![0; crate::riblt_cache::CELL_FRAME_BYTES];
        crate::riblt_store::Record::store(&frame, &mut stored);
        assert_eq!(stored, expected);
    }
}

#[test]
fn a_resume_the_root_did_not_promise_or_a_second_one_fails() {
    let fixture = Fixture::new();
    let root = |exchange: &Exchange<MemoryRepoSnapshot>| exchange.delta.summary();
    for promised in [false, true] {
        let mut a = fixture.side(&fixture.a, &a_set(), None);
        let b = fixture.side(&fixture.b, &b_set(), None);
        let b_root = root(&b);
        let a_root = root(&a);
        a.next_delta();
        a.on_frame(Frame::RibltRoot { summary: b_root, resume: promised }, Some(fixture.a.snapshot()));
        if promised {
            assert_eq!(a.next_delta(), None, "no cell before the promised RESUME");
            a.on_frame(Frame::RibltResume { held: 5, root: a_root }, Some(fixture.a.snapshot()));
            assert_eq!(a.outcome(), None);
            assert!(matches!(a.next_delta(), Some(Frame::RibltCells { first: 5, .. })));
        }
        a.on_frame(Frame::RibltResume { held: 0, root: a_root }, Some(fixture.a.snapshot()));
        assert_eq!(a.outcome(), Some(Outcome::Failed(Failure::Protocol)));
    }
}

/// Equal roots, and the peer's FIN confirms the exchange before our promised
/// RESUME was taken: it is still sent, and readiness waits for it.
#[test]
fn a_promised_resume_is_sent_even_after_an_equal_root_confirmation() {
    let fixture = Fixture::new();
    let cache = ResumeCache::new(RESUME_BUDGET_BYTES);
    let mut a = fixture.side(&fixture.a, &a_set(), None);
    let profile = a.riblt.as_ref().unwrap().profile;
    let other = PatchSummary::new(Some([0xCD; 32]), 9).unwrap();
    let mut cells = Records::default();
    cells.push(&CellFrame { index: 0, cell: Cell::default() }).unwrap();
    cache.keep((profile, other), cells);
    a = a.resuming(cache.clone());
    let root = a.delta.summary();
    assert_eq!(a.next_delta(), Some(Frame::RibltRoot { summary: root, resume: true }));
    assert!(a.on_root_written().is_empty());
    a.on_frame(Frame::RibltRoot { summary: root, resume: false }, Some(fixture.a.snapshot()));
    assert!(!a.ready_to_finish(), "the RESUME is still owed");
    a.on_fin();
    assert_eq!(a.outcome(), Some(Outcome::Confirmed));
    assert_eq!(a.next_delta(), Some(Frame::RibltResume { held: 0, root }));
    assert_eq!(a.next_delta(), None);
    assert!(a.ready_to_finish());
    assert_eq!(cache.held(&(profile, other)), 1, "an unrelated entry stays");
}
