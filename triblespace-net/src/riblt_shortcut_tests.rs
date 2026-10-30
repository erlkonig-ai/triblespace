//! Cell and byte receipts for the asymmetric shortcut against today's
//! symmetric cached discovery. Every mode runs on the production cell cache
//! and residual decoder; only the wire between them is a model.
//!
//! The model is lockstep: each tick, every side still sending writes one
//! cell, and a cell or STOP written at tick t is read at tick t + lag. Lag is
//! the in-flight window in cells; 2026-10-10 saw one arm decode after 14
//! cells while 2,322 were sent, i.e. a lag in the low thousands. Bytes are
//! framed sizes (kind byte, u32 length, payload) of the frames that differ
//! between modes: ROOT, CELL, STOP and VALUE_REQUEST. OPEN and VALUE bodies
//! are identical in every mode and are counted, not priced.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use riblt::Symbol;
use triblespace_core::collection::CollectionHandle;
use triblespace_core::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};

use crate::exchange::Tree;
use crate::patch_repair::PatchSummary;
use crate::riblt_cache::{Cell, Generation, KeySymbol};
use crate::riblt_decode::ResidualDecoder;
use crate::riblt_shortcut::{Shortcut, eligible};
use crate::walk::WalkKind;

const ROOT: usize = 5 + 40;
const CELL: usize = 5 + 52;
const STOP: usize = 5;
const REQUEST: usize = 5 + 32;

type Key = [u8; 32];

fn key(seed: u64, n: u64) -> Key {
    let mut hash = blake3::Hasher::new();
    hash.update(&seed.to_be_bytes());
    hash.update(&n.to_be_bytes());
    *hash.finalize().as_bytes()
}

fn tree(keys: &[Key]) -> Tree {
    let mut patch = PATCH::<32, IdentitySchema, (), Blake3Merkle>::new();
    for key in keys {
        patch.insert(&Entry::new(key));
    }
    Tree::References(patch)
}

struct Fixture {
    a: Arc<Generation>,
    b: Arc<Generation>,
    a_only: BTreeSet<Key>,
    b_only: BTreeSet<Key>,
}

/// A holds `shared` plus `a_only` keys, B holds `shared` plus `b_only`.
fn fixture(seed: u64, shared: usize, a_only: usize, b_only: usize) -> Fixture {
    let collection = CollectionHandle::new([0x5a; 32]);
    let mut n = 0;
    let mut take = |count: usize| -> Vec<Key> {
        (0..count)
            .map(|_| {
                n += 1;
                key(seed, n)
            })
            .collect()
    };
    let shared = take(shared);
    let ao = take(a_only);
    let bo = take(b_only);
    let a: Vec<_> = shared.iter().chain(&ao).copied().collect();
    let b: Vec<_> = shared.iter().chain(&bo).copied().collect();
    let generation = |keys: &[Key]| {
        Generation::advance(collection, WalkKind::References, tree(keys), None).unwrap()
    };
    Fixture {
        a: generation(&a),
        b: generation(&b),
        a_only: ao.into_iter().collect(),
        b_only: bo.into_iter().collect(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    /// Today: both sides stream cells and each decodes the residual.
    Symmetric,
    /// The proposal: the larger side also streams cells, additionally
    /// peels the smaller side's raw cells, and sends STOP if that proves
    /// before its residual decoder does.
    Race,
    /// Variant: the larger side streams no cells at all. It already decodes
    /// both its residual and the raw set from the smaller side's cells
    /// alone, so its own cells only ever fed the peer's decoder, which the
    /// STOP makes moot. It STOPs on whichever of its decoders proves first.
    Silent,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Wire {
    cells: usize,
    bytes: usize,
    requests: usize,
    bodies: usize,
}

#[derive(Debug)]
struct Run {
    a: Wire,
    b: Wire,
    /// The raw decode proved and STOP went out.
    shortcut: bool,
    /// Peer cells the deciding decoder consumed.
    frontier: usize,
    /// Wall time inside the decoders, summed over both sides.
    decode: Duration,
}

impl Run {
    fn cells(&self) -> usize {
        self.a.cells + self.b.cells
    }

    fn bytes(&self) -> usize {
        self.a.bytes + self.b.bytes
    }
}

fn subtract(peer: &Cell, own: &Cell) -> Cell {
    Cell {
        symbol: peer.symbol.xor(&own.symbol),
        hash: peer.hash ^ own.hash,
        count: peer.count.checked_sub(own.count).unwrap(),
    }
}

fn keys(records: &crate::riblt_store::Records<riblt::HashedSymbol<KeySymbol>>) -> BTreeSet<Key> {
    records.iter().map(|symbol| symbol.symbol.0).collect()
}

/// One cached discovery between A (side 0) and B (side 1). `corrupt` flips a
/// symbol bit in the named raw cell as the shortcut sees it, and `lie`
/// replaces the ROOT the shortcut checks against.
fn exchange(
    f: &Fixture,
    mode: Mode,
    lag: usize,
    corrupt: Option<usize>,
    lie: Option<PatchSummary>,
) -> Run {
    let generations = [&f.a, &f.b];
    let roots = [f.a.summary(), f.b.summary()];
    let counts = [roots[0].leaf_count(), roots[1].leaf_count()];
    let racer = (0..2).find(|&s| mode != Mode::Symmetric && eligible(counts[s], counts[1 - s]));
    let mut shortcut =
        racer.map(|s| Shortcut::new(generations[s].key(), lie.unwrap_or(roots[1 - s])));
    let mut residual = [
        ResidualDecoder::with_key(f.a.key()),
        ResidualDecoder::with_key(f.b.key()),
    ];
    let mut wire = [Wire::default(); 2];
    let mut sending = [true; 2];
    if mode == Mode::Silent && let Some(s) = racer {
        sending[s] = false;
    }
    if roots[0] == roots[1] {
        sending = [false; 2];
    }
    let mut written = [0; 2];
    let mut history = [vec![0], vec![0]];
    let mut received = [0; 2];
    let mut decoded: [Option<usize>; 2] = [None; 2];
    let mut stopped: Option<usize> = None;
    let mut split = None;
    let mut frontier = 0;
    let mut decode = Duration::ZERO;
    let mut tick = 0;
    while sending[0] || sending[1] {
        tick += 1;
        assert!(tick < 1_000_000, "the model must terminate");
        for s in 0..2 {
            if sending[s] {
                written[s] += 1;
            }
            history[s].push(written[s]);
        }
        for s in 0..2 {
            let peer = 1 - s;
            if let Some(at) = stopped
                && Some(s) != racer
                && tick >= at + lag
            {
                sending[s] = false;
            }
            let arrived = tick.checked_sub(lag).map_or(0, |t| history[peer][t]);
            while received[s] < arrived {
                let index = received[s];
                received[s] += 1;
                if stopped.is_some() {
                    continue; // In flight past STOP: read and dropped.
                }
                let theirs = generations[peer].cell(index).unwrap();
                if decoded[s].is_none() {
                    let own = generations[s].cell(index).unwrap();
                    let start = Instant::now();
                    residual[s].add(subtract(&theirs, &own)).unwrap();
                    decode += start.elapsed();
                    if residual[s].decoded() {
                        decoded[s] = Some(index + 1);
                        frontier = frontier.max(index + 1);
                        if Some(s) == racer && mode == Mode::Silent {
                            // The residual won: the same split, no STOP race.
                            stopped = Some(tick);
                        }
                    }
                }
                if Some(s) == racer && decoded[s].is_none() {
                    let mut raw = theirs;
                    if corrupt == Some(index) {
                        raw.symbol.0[0] ^= 1;
                    }
                    let start = Instant::now();
                    let proven = shortcut.as_mut().unwrap().add(raw, generations[s].source());
                    decode += start.elapsed();
                    if let Some(proven) = proven {
                        frontier = proven.cells;
                        split = Some(proven);
                        stopped = Some(tick);
                        sending[s] = false;
                    }
                }
            }
            // Today's rule: stop once decoded and the written prefix reaches
            // the decoded one. In lockstep the written prefix always does.
            if decoded[s].is_some_and(|at| written[s] >= at) {
                sending[s] = false;
            }
        }
    }
    for s in 0..2 {
        wire[s].cells = written[s];
        wire[s].bytes = ROOT + written[s] * CELL;
    }
    wire[0].bodies = f.a_only.len();
    wire[1].bodies = f.b_only.len();
    let (racer_only, peer_only) = if racer == Some(1) {
        (&f.b_only, &f.a_only)
    } else {
        (&f.a_only, &f.b_only)
    };
    if let Some(split) = &split {
        let s = racer.unwrap();
        wire[s].bytes += STOP + split.remote_only.len() * REQUEST;
        wire[s].requests = split.remote_only.len();
        let mut local = BTreeSet::new();
        split.local_only.for_each_key(|key| {
            local.insert(key);
        });
        assert_eq!(&local, racer_only, "the raw split pushes exactly what the peer lacks");
        let remote: BTreeSet<_> = split.remote_only.iter().copied().collect();
        assert_eq!(&remote, peer_only, "the raw split requests exactly what it lacks");
    } else if let Some(s) = racer.filter(|_| stopped.is_some()) {
        // Silent mode's residual win: STOP and requests still go out.
        wire[s].bytes += STOP + peer_only.len() * REQUEST;
        wire[s].requests = peer_only.len();
        assert_eq!(&keys(residual[s].local()), racer_only);
        assert_eq!(&keys(residual[s].remote()), peer_only);
    } else if roots[0] != roots[1] {
        assert!(decoded[0].is_some() && decoded[1].is_some(), "symmetric decode completes");
        assert_eq!(keys(residual[0].local()), f.a_only);
        assert_eq!(keys(residual[0].remote()), f.b_only);
    }
    Run {
        a: wire[0],
        b: wire[1],
        shortcut: split.is_some(),
        frontier,
        decode,
    }
}

fn row(label: &str, before: &Run, after: &Run, silent: &Run) {
    eprintln!(
        "{label:<28} | sym A {:>6} B {:>6} = {:>8} B | race A {:>6} B {:>6} = {:>8} B{} | silent A {:>6} B {:>6} = {:>8} B | req {:>4} | decode {:>6.1} / {:>6.1} / {:>6.1} ms",
        before.a.cells,
        before.b.cells,
        before.bytes(),
        after.a.cells,
        after.b.cells,
        after.bytes(),
        if after.shortcut { "*" } else { " " },
        silent.a.cells,
        silent.b.cells,
        silent.bytes(),
        after.a.requests.max(silent.a.requests),
        before.decode.as_secs_f64() * 1e3,
        after.decode.as_secs_f64() * 1e3,
        silent.decode.as_secs_f64() * 1e3,
    );
}

fn all(f: &Fixture, lag: usize) -> (Run, Run, Run) {
    (
        exchange(f, Mode::Symmetric, lag, None, None),
        exchange(f, Mode::Race, lag, None, None),
        exchange(f, Mode::Silent, lag, None, None),
    )
}

/// |A| = 10,000 and B a subset, or B with 10% of its records foreign to A.
#[test]
fn riblt_shortcut_small_peer_costs_its_own_size_not_the_difference() {
    for lag in [0, 256] {
        eprintln!(
            "lag {lag} cells; cells per side and framed ROOT/CELL/STOP/REQUEST bytes per exchange"
        );
        for b in [0, 10, 100, 1000] {
            let foreigns = if b == 0 { vec![0] } else { vec![0, b / 10] };
            for foreign in foreigns {
                let f = fixture(7 + b as u64, b - foreign, 10_000 - (b - foreign), foreign);
                let (before, after, silent) = all(&f, lag);
                row(&format!("|A|=10k |B|={b} foreign={foreign}"), &before, &after, &silent);
                assert!(!before.shortcut);
                assert!(after.shortcut, "B is small enough for the raw decode to win");
                assert!(after.cells() < before.cells());
                assert!(silent.cells() <= after.cells());
                // About 1.4 |B| raw cells, never the ~1.4 x 10k difference.
                let budget = 2 * b + 16;
                assert!(after.frontier <= budget, "raw frontier {} > {budget}", after.frontier);
                assert!(after.a.cells <= budget + lag);
                assert!(after.b.cells <= budget + 2 * lag);
                assert_eq!(after.a.requests, foreign);
                if b == 0 {
                    // A bootstrap ends after one cell.
                    assert_eq!(after.frontier, 1);
                    assert_eq!(after.a.cells, 1 + lag);
                }
            }
        }
    }
}

/// Equal counts never race; one-sided small differences race and lose,
/// so their cells and bytes are exactly today's.
#[test]
fn riblt_shortcut_balanced_exchanges_do_not_regress() {
    for lag in [0, 256] {
        for d in [10, 100] {
            for (label, f) in [
                ("both ways", fixture(11 + d as u64, 10_000 - d / 2, d / 2, d / 2)),
                ("A ahead", fixture(13 + d as u64, 10_000 - d, d, 0)),
            ] {
                let (before, after, silent) = all(&f, lag);
                row(&format!("|A|~|B|~10k d={d} {label} lag {lag}"), &before, &after, &silent);
                assert!(!after.shortcut, "the residual decode must win at d={d}");
                assert_eq!(after.a, before.a);
                assert_eq!(after.b, before.b);
                assert!(silent.cells() <= before.cells());
            }
        }
    }
}

/// The threshold sweep: |B| fixed, |A| / |B| rising, B a subset or with 25%
/// foreign records, at lag 0 and 256. Means over seeds: the residual decode
/// needs about 1.4 d cells, the raw decode about 1.4 |B|. Racing costs no
/// cells at lag 0; with lag, a narrow raw win can cost B's extra in-flight
/// window, while the silent variant never costs cells.
#[test]
fn riblt_shortcut_threshold_sweep() {
    let seeds = 5;
    for lag in [0, 256] {
        for b in [100usize, 1000] {
            for foreign_pct in [0usize, 25] {
                for ratio_pct in [110usize, 150, 175, 200, 225, 300, 500] {
                    let a = b * ratio_pct / 100;
                    let foreign = b * foreign_pct / 100;
                    let shared = b - foreign;
                    let (mut residual, mut raw, mut wins) = (0, 0, 0);
                    let mut cells = [0; 3];
                    let mut times = [Duration::ZERO; 3];
                    for seed in 0..seeds {
                        let f = fixture(1000 + seed, shared, a - shared, foreign);
                        let before = exchange(&f, Mode::Symmetric, lag, None, None);
                        let after = exchange(&f, Mode::Race, lag, None, None);
                        let silent = exchange(&f, Mode::Silent, lag, None, None);
                        residual += before.frontier;
                        raw += if after.shortcut { after.frontier } else { 0 };
                        wins += usize::from(after.shortcut);
                        for (i, run) in [&before, &after, &silent].into_iter().enumerate() {
                            cells[i] += run.cells();
                            times[i] += run.decode;
                        }
                        if lag == 0 {
                            assert!(after.cells() <= before.cells(), "racing costs no cells");
                        }
                        assert!(silent.cells() <= before.cells(), "silent never costs cells");
                    }
                    let mean = |n: usize| n as f64 / seeds as f64;
                    let ms = |t: Duration| t.as_secs_f64() * 1e3 / seeds as f64;
                    eprintln!(
                        "lag {lag:>3} |B|={b:>4} foreign={foreign_pct:>2}% |A|/|B|={:.2} d={:>5}: residual frontier {:>7.1}, raw wins {wins}/{seeds} (raw frontier {:>7.1}); cells sym {:>7.1} race {:>7.1} silent {:>7.1}; decode ms {:.1} / {:.1} / {:.1}",
                        ratio_pct as f64 / 100.0,
                        (a - shared) + foreign,
                        mean(residual),
                        if wins > 0 { raw as f64 / wins as f64 } else { f64::NAN },
                        mean(cells[0]),
                        mean(cells[1]),
                        mean(cells[2]),
                        ms(times[0]),
                        ms(times[1]),
                        ms(times[2]),
                    );
                }
            }
        }
    }
}

/// A raw decode that does not match ROOT, or that a corrupted cell derails,
/// is abandoned and the symmetric decode finishes exactly as today.
#[test]
fn riblt_shortcut_unproven_raw_decodes_fall_back_to_symmetric() {
    let f = fixture(17, 100, 9_900, 0);
    let before = exchange(&f, Mode::Symmetric, 0, None, None);
    // A ROOT that claims another set of the same count.
    let other = fixture(18, 100, 0, 0).b.summary();
    assert_eq!(other.leaf_count(), f.b.summary().leaf_count());
    let lied = exchange(&f, Mode::Race, 0, None, Some(other));
    assert!(!lied.shortcut);
    assert_eq!((lied.a, lied.b), (before.a, before.b));
    for corrupt in [0, 1, 5, 40, 120] {
        let run = exchange(&f, Mode::Race, 0, Some(corrupt), None);
        assert!(!run.shortcut, "corrupted cell {corrupt} must not prove");
        assert_eq!((run.a, run.b), (before.a, before.b));
        // Silent: the larger side's own residual decoder still decides.
        let run = exchange(&f, Mode::Silent, 0, Some(corrupt), None);
        assert!(!run.shortcut);
        assert_eq!((run.a.cells, run.b.cells), (0, before.frontier));
    }
}

fn raw_cells(f: &Fixture, count: usize) -> Vec<Cell> {
    (0..count).map(|index| f.b.cell(index).unwrap()).collect()
}

/// A stream that ends before B's set peels proves nothing: no split, and the
/// shortcut is not abandoned either, it simply never decided.
#[test]
fn riblt_shortcut_too_short_a_stream_never_splits() {
    let f = fixture(19, 100, 9_900, 0);
    let mut whole = Shortcut::new(f.a.key(), f.b.summary());
    let cells = raw_cells(&f, 1024);
    let at = cells
        .iter()
        .position(|cell| whole.add(cell.clone(), f.a.source()).is_some())
        .expect("the honest raw stream peels")
        + 1;
    let mut short = Shortcut::new(f.a.key(), f.b.summary());
    for cell in &cells[..at - 1] {
        assert!(short.add(cell.clone(), f.a.source()).is_none());
    }
    assert!(!short.abandoned());
}

/// Raw cells hold B's own members only: a symbol that peels with a negative
/// count, or a count that cell 0 cannot account for, never proves.
#[test]
fn riblt_shortcut_rejects_negative_members_and_wrong_counts() {
    let f = fixture(23, 10, 9_990, 0);
    let cells = raw_cells(&f, 256);

    // Cell 0 counts every member: one more than B holds.
    let mut shortcut = Shortcut::new(f.a.key(), f.b.summary());
    let mut padded = cells[0].clone();
    padded.count += 1;
    assert!(shortcut.add(padded, f.a.source()).is_none());
    for cell in &cells[1..] {
        assert!(shortcut.add(cell.clone(), f.a.source()).is_none());
    }

    // A pure negative cell: some other key, subtracted.
    let mut shortcut = Shortcut::new(f.a.key(), f.b.summary());
    let stray = riblt::HashedSymbol::new_keyed(KeySymbol(key(99, 99)), &f.a.key());
    let negative = Cell {
        symbol: stray.symbol,
        hash: stray.hash,
        count: -1,
    };
    assert!(shortcut.add(negative, f.a.source()).is_none());
    assert!(shortcut.abandoned());
    for cell in &cells {
        assert!(shortcut.add(cell.clone(), f.a.source()).is_none());
    }

    // An empty B ends after one zero cell; a nonzero one claiming emptiness
    // does not.
    let empty = fixture(29, 0, 10, 0);
    let mut shortcut = Shortcut::new(empty.a.key(), empty.b.summary());
    let split = shortcut
        .add(empty.b.cell(0).unwrap(), empty.a.source())
        .expect("one zero cell proves the empty set");
    assert_eq!(split.cells, 1);
    assert!(split.remote_only.is_empty());
    let mut shortcut = Shortcut::new(f.a.key(), empty.b.summary());
    assert!(shortcut.add(cells[0].clone(), f.a.source()).is_none());
}
