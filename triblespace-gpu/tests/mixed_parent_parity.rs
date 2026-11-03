//! GPU-vs-CPU confirm parity over **mixed-parent** regions.
//!
//! `batch_confirm_parity.rs` pins every routed arm against a frontier of one,
//! where all parent tags are 0 and a region's row band collapses to a single
//! scalar. This file covers the case the frontier protocol actually
//! introduced: one region spanning many parent bindings, where candidate `i`
//! must be checked against *its own* parent's bound values.
//!
//! A heterogeneous frontier cannot be built from outside `triblespace-core`
//! (a [`BindingStore`] holds one index row, and [`Frontier::with_select`] can
//! only repeat it), so the regions here come from the engine itself. A
//! [`Probe`] constraint sits where the archive pattern would, mirrors every
//! region onto a scratch buffer, runs the canonical CPU confirm on the mirror
//! and the device-routed confirm on the real region, and asserts the two
//! liveness word arrays are identical — for every confirm the query makes.
//!
//! Coverage is *constructed*, not hoped for: [`Pool`] proposers pin the
//! variable order so the query walks a known sequence of arms, and each test
//! asserts on the recorded arm histogram that mixed-parent regions really
//! occurred in the shapes it claims to cover.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, SuccinctArchive, SuccinctArchiveConstraint, Universe,
};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::RawInline;
use triblespace_core::query::intersectionconstraint::IntersectionConstraint;
use triblespace_core::query::{
    Binding, Candidates, Constraint, Frontier, ProposalBuffer, Query, Variable, VariableContext,
    VariableId, VariableSet,
};
use triblespace_core::trible::{Trible, TribleSet};
use triblespace_gpu::{WgpuSuccinctArchive, WgpuSuccinctArchiveConstraint};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn make_id(tag: u8, ordinal: u32) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0x80 | tag;
    id[12..].copy_from_slice(&ordinal.to_be_bytes());
    id
}

fn id_value(id: &[u8; 16]) -> RawInline {
    let mut value = [0u8; 32];
    value[16..].copy_from_slice(id);
    value
}

fn free_value(tag: u8, ordinal: u32) -> RawInline {
    let mut value = [0u8; 32];
    value[0] = tag;
    value[1] = 0x55;
    value[28..].copy_from_slice(&ordinal.to_be_bytes());
    value
}

struct Fixture {
    gpu: WgpuSuccinctArchive<OrderedUniverse>,
    entities: Vec<RawInline>,
    attributes: Vec<RawInline>,
    values: Vec<RawInline>,
    /// Values carried by *every* entity, so a candidate pool can guarantee
    /// survivors at each level however sparse the rest of the archive is.
    hubs: Vec<RawInline>,
    absent: Vec<RawInline>,
}

/// `entities` × `attributes` over a value pool, sparse enough that plenty of
/// (entity, attribute) and (entity, value) pairs are missing — so the
/// confirms actually kill — plus four hub values every entity carries.
fn fixture(entities: u32, attributes: u32, values: u32) -> Fixture {
    let entity_ids: Vec<[u8; 16]> = (0..entities).map(|k| make_id(0x01, k)).collect();
    let attribute_ids: Vec<[u8; 16]> = (0..attributes).map(|k| make_id(0x02, k)).collect();
    let value_pool: Vec<RawInline> = (0..values).map(|k| free_value(0x10, k)).collect();
    let hubs: Vec<RawInline> = (0..4).map(|k| free_value(0x11, k)).collect();

    let mut state = 0x5EED_1234u64;
    let mut set = TribleSet::new();
    for entity in &entity_ids {
        for attribute in &attribute_ids {
            if splitmix(&mut state) % 3 == 0 {
                continue;
            }
            let fanout = 1 + (splitmix(&mut state) % 3) as usize;
            for _ in 0..fanout {
                let value = value_pool[(splitmix(&mut state) % value_pool.len() as u64) as usize];
                let mut data = [0u8; 64];
                data[..16].copy_from_slice(entity);
                data[16..32].copy_from_slice(attribute);
                data[32..].copy_from_slice(&value);
                set.insert(&Trible::force_raw(data).expect("non-nil entity and attribute"));
            }
        }
        // Hubs, one per hub value under a rotating attribute.
        for (k, hub) in hubs.iter().enumerate() {
            let mut data = [0u8; 64];
            data[..16].copy_from_slice(entity);
            data[16..32].copy_from_slice(&attribute_ids[k % attribute_ids.len()]);
            data[32..].copy_from_slice(hub);
            set.insert(&Trible::force_raw(data).expect("non-nil entity and attribute"));
        }
    }

    let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
    let gpu = WgpuSuccinctArchive::new(archive)
        .expect("resident wrap succeeds")
        .with_min_confirm_batch(0);
    Fixture {
        gpu,
        entities: entity_ids.iter().map(id_value).collect(),
        attributes: attribute_ids.iter().map(id_value).collect(),
        values: value_pool,
        hubs,
        absent: (0..24)
            .map(|k| free_value(0x20, k))
            .chain((0..8).map(|k| id_value(&make_id(0x03, k))))
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// The parity probe
// ---------------------------------------------------------------------------

/// What one confirm call looked like, keyed by how many of the pattern's
/// *other* positions carried a value — 0 is the membership arm, 1 and 2 are
/// the two range shapes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ArmLog {
    confirms: usize,
    /// Confirms whose region carried more than one distinct parent tag.
    mixed: usize,
    /// Largest number of distinct parent tags seen in one region.
    max_parents: usize,
    /// Largest number of *distinct bound-value tuples* among the parents of
    /// one region — the bar that says the parents disagreed about the row
    /// band, not merely about their tag.
    max_distinct_bands: usize,
    candidates: usize,
    cpu: Duration,
    gpu: Duration,
}

#[derive(Clone, Debug, Default)]
struct Log {
    arms: [ArmLog; 3],
}

impl Log {
    fn total_confirms(&self) -> usize {
        self.arms.iter().map(|a| a.confirms).sum()
    }

    fn merge(&mut self, other: &Log) {
        for (target, entry) in self.arms.iter_mut().zip(other.arms.iter()) {
            target.confirms += entry.confirms;
            target.mixed += entry.mixed;
            target.max_parents = target.max_parents.max(entry.max_parents);
            target.max_distinct_bands = target.max_distinct_bands.max(entry.max_distinct_bands);
            target.candidates += entry.candidates;
            target.cpu += entry.cpu;
            target.gpu += entry.gpu;
        }
    }
}

/// The log handle a test keeps while the query owns the probe itself.
type LogHandle = Arc<Mutex<Log>>;

/// Stands in for one archive pattern and checks both confirm paths on every
/// region the engine hands it.
struct Probe<'a, U>
where
    U: Universe,
{
    positions: [VariableId; 3],
    cpu: SuccinctArchiveConstraint<'a, U>,
    gpu: WgpuSuccinctArchiveConstraint<'a, U>,
    log: LogHandle,
    /// Kill every seventh entry before confirming, so already-dead entries
    /// are covered on both paths.
    prekill: bool,
}

impl<'a, U> Probe<'a, U>
where
    U: Universe,
{
    fn new(
        e: Variable<GenId>,
        a: Variable<GenId>,
        v: Variable<UnknownInline>,
        gpu: &'a WgpuSuccinctArchive<U>,
        prekill: bool,
    ) -> (Self, LogHandle) {
        let log: LogHandle = Arc::new(Mutex::new(Log::default()));
        (
            Probe {
                positions: [e.index, a.index, v.index],
                cpu: SuccinctArchiveConstraint::new(e, a, v, gpu.archive()),
                gpu: WgpuSuccinctArchiveConstraint::new(e, a, v, gpu),
                log: Arc::clone(&log),
                prekill,
            },
            log,
        )
    }

    /// The arm shape: how many of the pattern's other positions are bound.
    fn arm(&self, variable: VariableId, frontier: &Frontier<'_>) -> usize {
        self.positions
            .iter()
            .filter(|&&p| p != variable && frontier.bound().is_set(p))
            .count()
    }

    /// The bound values of the pattern's other positions in `binding` — the
    /// tuple that determines this parent's row band.
    fn band_key(&self, variable: VariableId, binding: &Binding<'_>) -> Vec<RawInline> {
        self.positions
            .iter()
            .filter(|&&p| p != variable)
            .filter_map(|&p| binding.get(p).copied())
            .collect()
    }
}

impl<'a, U> Constraint<'a> for Probe<'a, U>
where
    U: Universe,
{
    fn variables(&self) -> VariableSet {
        self.cpu.variables()
    }

    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        self.cpu.estimate(variable, binding)
    }

    fn propose(&self, variable: VariableId, frontier: &Frontier<'_>, out: &mut ProposalBuffer) {
        self.cpu.propose(variable, frontier, out)
    }

    fn confirm(&self, variable: VariableId, frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if cands.is_empty() || frontier.is_empty() {
            return;
        }
        if self.prekill {
            for i in (0..cands.len()).step_by(7) {
                cands.kill(i);
            }
        }

        let before: Vec<bool> = (0..cands.len()).map(|i| cands.is_live(i)).collect();
        // Replay the region — values *and* parent tags — onto a scratch
        // buffer so the CPU verdict is computed over exactly the same input.
        let mut scratch = ProposalBuffer::new();
        for i in 0..cands.len() {
            scratch.open(cands.parent(i));
            scratch.push(cands.values()[i]);
        }
        let mut mirror = scratch.region(0);
        // Copy liveness by *index*, not by word: `cands` starts wherever its
        // proposer left off in the level buffer while the mirror starts at
        // index 0, and packed liveness words only line up when the two
        // regions share a bit offset. Everything the mirror holds is live to
        // begin with, so replaying the kills is enough.
        for (i, live) in before.iter().enumerate() {
            if !*live {
                mirror.kill(i);
            }
        }

        let started = Instant::now();
        self.cpu.confirm(variable, frontier, &mut mirror);
        let cpu_elapsed = started.elapsed();
        let expected: Vec<bool> = (0..mirror.len()).map(|i| mirror.is_live(i)).collect();

        let started = Instant::now();
        self.gpu.confirm(variable, frontier, cands);
        let gpu_elapsed = started.elapsed();
        let actual: Vec<bool> = (0..cands.len()).map(|i| cands.is_live(i)).collect();

        let arm = self.arm(variable, frontier);
        let mut parents: Vec<u32> = cands.parents().to_vec();
        parents.sort_unstable();
        parents.dedup();
        let mut bands: Vec<Vec<RawInline>> = parents
            .iter()
            .map(|&p| self.band_key(variable, &frontier.row(p as usize)))
            .collect();
        bands.sort();
        bands.dedup();

        assert_eq!(
            actual,
            expected,
            "GPU and CPU liveness diverge (arm {arm}, {} candidates over {} parents / {} bands)",
            cands.len(),
            parents.len(),
            bands.len(),
        );
        for (i, &was_live) in before.iter().enumerate() {
            if !was_live {
                assert!(!actual[i], "entry {i} was revived (arm {arm})");
            }
        }

        let mut log = self.log.lock().unwrap();
        let entry = &mut log.arms[arm];
        entry.confirms += 1;
        entry.mixed += usize::from(parents.len() > 1);
        entry.max_parents = entry.max_parents.max(parents.len());
        entry.max_distinct_bands = entry.max_distinct_bands.max(bands.len());
        entry.candidates += cands.len();
        entry.cpu += cpu_elapsed;
        entry.gpu += gpu_elapsed;
    }

    fn satisfied(&self, binding: &Binding) -> bool {
        self.cpu.satisfied(binding)
    }

    fn influence(&self, variable: VariableId) -> VariableSet {
        self.cpu.influence(variable)
    }
}

// ---------------------------------------------------------------------------
// A proposer that pins the variable order and owns the candidate pool
// ---------------------------------------------------------------------------

/// Proposes a fixed pool for one variable, but only once `after` is fully
/// bound — which is what lets a test dictate the order the engine binds
/// variables in, and therefore which archive arm each confirm exercises.
///
/// Its `estimate` is `Some` for its variable *unconditionally* (only the
/// magnitude varies with `after`), so it never changes a confirmer's
/// relevance across a frontier.
struct Pool {
    variable: VariableId,
    after: Vec<VariableId>,
    values: Vec<RawInline>,
}

impl<'a> Constraint<'a> for Pool {
    fn variables(&self) -> VariableSet {
        let mut set = VariableSet::new_empty();
        set.set(self.variable);
        set
    }

    fn estimate(&self, variable: VariableId, binding: &Binding) -> Option<usize> {
        if variable != self.variable {
            return None;
        }
        // Magnitude 0 once the prerequisites are bound, so this variable wins
        // the engine's smallest-magnitude choice and this constraint wins the
        // intersection's tightest-proposer choice.
        if self.after.iter().all(|&v| binding.bound.is_set(v)) {
            Some(0)
        } else {
            Some(usize::MAX)
        }
    }

    fn propose(&self, variable: VariableId, frontier: &Frontier<'_>, out: &mut ProposalBuffer) {
        if variable != self.variable {
            return;
        }
        for row in 0..frontier.len() {
            out.open(row as u32);
            out.extend_from_slice(&self.values);
        }
    }

    fn confirm(&self, variable: VariableId, _frontier: &Frontier<'_>, cands: &mut Candidates<'_>) {
        if variable == self.variable {
            cands.retain(|value| self.values.contains(value));
        }
    }

    fn satisfied(&self, _binding: &Binding) -> bool {
        true
    }

    fn influence(&self, variable: VariableId) -> VariableSet {
        if variable == self.variable {
            self.variables()
        } else {
            VariableSet::new_empty()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

type Dyn<'a> = Box<dyn Constraint<'a> + Send + Sync + 'a>;

struct Vars {
    e: Variable<GenId>,
    a: Variable<GenId>,
    v: Variable<UnknownInline>,
}

fn vars() -> Vars {
    let mut context = VariableContext::new();
    Vars {
        e: context.next_variable(),
        a: context.next_variable(),
        v: context.next_variable(),
    }
}

/// A candidate pool mixing the three kinds a confirm has to tell apart: a hub
/// value (present for every parent, so every parent keeps a survivor), values
/// present in the universe but usually outside the parent's band, and values
/// absent from the universe entirely. Duplicates are guaranteed.
fn mixed_pool(fixture: &Fixture, seed: u64, len: usize) -> Vec<RawInline> {
    let mut state = seed;
    let mut pool = Vec::with_capacity(len);
    for i in 0..len {
        pool.push(if i == 0 {
            fixture.hubs[(splitmix(&mut state) % fixture.hubs.len() as u64) as usize]
        } else if splitmix(&mut state) % 4 == 0 {
            fixture.absent[(splitmix(&mut state) % fixture.absent.len() as u64) as usize]
        } else {
            fixture.values[(splitmix(&mut state) % fixture.values.len() as u64) as usize]
        });
    }
    if len >= 4 {
        // Guaranteed duplicates, including one straddling a segment boundary.
        pool[len / 2] = pool[0];
        pool[len - 1] = pool[0];
    }
    pool
}

/// The three-level pinned query: entity at the root, then value against a
/// bound entity (single-bound range arm, mixed parents), then attribute
/// against a bound entity *and* value (double-bound range arm, mixed
/// parents).
fn pinned_arms(fixture: &Fixture, width: usize, pool: Vec<RawInline>, prekill: bool) -> Log {
    let v = vars();
    let (probe, log) = Probe::new(v.e, v.a, v.v, &fixture.gpu, prekill);
    let constraint = IntersectionConstraint::new(vec![
        // Pools first: on an estimate tie the intersection keeps the earlier
        // child as proposer, which is what pins the arms.
        Box::new(Pool {
            variable: v.e.index,
            after: vec![],
            values: fixture.entities.clone(),
        }) as Dyn,
        Box::new(Pool {
            variable: v.v.index,
            after: vec![v.e.index],
            values: pool,
        }),
        Box::new(Pool {
            variable: v.a.index,
            after: vec![v.e.index, v.v.index],
            values: fixture.attributes.clone(),
        }),
        Box::new(probe),
    ]);

    let rows: usize = Query::new(constraint, |binding: &Binding| {
        Some((
            *binding.get(v.e.index)?,
            *binding.get(v.a.index)?,
            *binding.get(v.v.index)?,
        ))
    })
    .with_frontier_width(width)
    .count();
    assert!(rows > 0, "pinned query produced no rows");
    let log = log.lock().unwrap().clone();
    log
}

#[test]
fn mixed_parent_range_arms_match_cpu() {
    let fixture = fixture(512, 8, 96);
    let pool = mixed_pool(&fixture, 0xA11CE, 12);
    let log = pinned_arms(&fixture, 256, pool, false);
    println!("pinned arms: {log:?}");

    assert!(
        log.arms[1].mixed > 0,
        "no mixed-parent single-bound confirm: {log:?}"
    );
    assert!(
        log.arms[1].max_distinct_bands > 1,
        "single-bound parents all shared one row band: {log:?}"
    );
    assert!(
        log.arms[2].mixed > 0,
        "no mixed-parent double-bound confirm: {log:?}"
    );
    assert!(
        log.arms[2].max_distinct_bands > 1,
        "double-bound parents all shared one row band: {log:?}"
    );
    let stats = fixture.gpu.stats();
    assert_eq!(
        stats.gpu_errors, 0,
        "device errors demoted confirms: {stats:?}"
    );
    assert_eq!(
        stats.cpu_fallback_confirms, 0,
        "a confirm skipped the device: {stats:?}"
    );
    // The parent table the device resolved really was a batch: the two range
    // arms alone contributed more rows than they made confirm calls.
    assert!(
        stats.gpu_parents > (log.arms[1].confirms + log.arms[2].confirms) as u64,
        "parent tables were width-1: {stats:?}"
    );
}

/// The threshold still governs a mixed-parent region: raised above every
/// region the query produces, nothing reaches the device and the rows are
/// unchanged.
#[test]
fn mixed_parent_regions_fall_back_below_threshold() {
    let mut fixture = fixture(512, 8, 96);
    let pool = mixed_pool(&fixture, 0xFA11, 12);

    let routed = pinned_arms(&fixture, 256, pool.clone(), false);
    let routed_stats = fixture.gpu.stats();
    assert!(routed_stats.gpu_confirms > 0, "{routed_stats:?}");

    fixture.gpu.reset_stats();
    fixture.gpu.set_min_confirm_batch(usize::MAX);
    let fallback = pinned_arms(&fixture, 256, pool, false);
    let fallback_stats = fixture.gpu.stats();

    assert_eq!(fallback_stats.gpu_confirms, 0, "{fallback_stats:?}");
    assert_eq!(fallback_stats.gpu_parents, 0, "{fallback_stats:?}");
    assert!(
        fallback_stats.cpu_fallback_confirms > 0,
        "{fallback_stats:?}"
    );
    for (arm, (routed, fallback)) in routed.arms.iter().zip(fallback.arms.iter()).enumerate() {
        assert_eq!(
            (routed.confirms, routed.candidates),
            (fallback.confirms, fallback.candidates),
            "arm {arm}: routing changed the search itself"
        );
    }
}

#[test]
fn mixed_parent_range_arms_match_cpu_with_dead_entries() {
    let fixture = fixture(512, 8, 96);
    let pool = mixed_pool(&fixture, 0xDEAD_BE11, 13);
    let log = pinned_arms(&fixture, 300, pool, true);
    println!("pinned arms (prekilled): {log:?}");
    assert!(log.arms[1].mixed > 0 && log.arms[2].mixed > 0, "{log:?}");
}

/// Frontier widths that do not divide the level's candidate count, so the
/// engine's chunking leaves partial batches and the tag range of a region is
/// not a full `0..width`.
#[test]
fn mixed_parent_parity_survives_ragged_widths() {
    let fixture = fixture(300, 7, 64);
    for width in [1usize, 2, 3, 17, 101, 299, 4096] {
        let pool = mixed_pool(&fixture, 0x5EED ^ width as u64, 9);
        let log = pinned_arms(&fixture, width, pool, width % 2 == 1);
        assert!(log.total_confirms() > 0, "width {width}: no confirms");
    }
}

/// A triangle over three archive patterns — nothing pinned, so the engine's
/// own adaptive choice decides the arms. Broad coverage rather than
/// constructed coverage, and a check that the row bag is width-independent.
#[test]
fn triangle_query_confirms_match_cpu_at_every_width() {
    let fixture = fixture(96, 4, 48);
    let rows = |width: usize| -> (Vec<(RawInline, RawInline, RawInline)>, Log) {
        let mut context = VariableContext::new();
        let x = context.next_variable::<GenId>();
        let y = context.next_variable::<GenId>();
        let z = context.next_variable::<UnknownInline>();
        let a0 = context.next_variable::<GenId>();
        let a1 = context.next_variable::<GenId>();
        let (p0, log0) = Probe::new(x, a0, z, &fixture.gpu, false);
        let (p1, log1) = Probe::new(y, a1, z, &fixture.gpu, false);
        let constraint = IntersectionConstraint::new(vec![Box::new(p0) as Dyn, Box::new(p1)]);
        let mut out: Vec<_> = Query::new(constraint, |binding: &Binding| {
            Some((
                *binding.get(x.index)?,
                *binding.get(y.index)?,
                *binding.get(z.index)?,
            ))
        })
        .with_frontier_width(width)
        .collect();
        out.sort_unstable();
        let mut log = log0.lock().unwrap().clone();
        log.merge(&log1.lock().unwrap());
        (out, log)
    };

    let (narrow, narrow_log) = rows(1);
    assert!(!narrow.is_empty(), "triangle produced no rows");
    println!("triangle width 1: {narrow_log:?}");
    for width in [7usize, 64, 4096] {
        let (wide, wide_log) = rows(width);
        println!("triangle width {width}: {wide_log:?}");
        assert_eq!(wide, narrow, "width {width} changed the row bag");
        assert!(
            wide_log.arms.iter().any(|a| a.mixed > 0),
            "width {width}: no mixed-parent confirm at all: {wide_log:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Crossover sweep
// ---------------------------------------------------------------------------

/// Region-size sweep for the **mixed-parent** confirm shapes, which is what
/// `DEFAULT_MIN_CONFIRM_BATCH` now has to be set from: with a frontier, a
/// routed region's per-candidate work is the same but its per-*parent* work
/// scales with the frontier width.
///
/// Run with:
/// `cargo test -p triblespace-gpu --release --test mixed_parent_parity -- --ignored --nocapture mixed_parent_crossover_sweep`
#[test]
#[ignore = "measurement benchmark; run explicitly with --ignored --nocapture"]
fn mixed_parent_crossover_sweep() {
    let fixture = fixture(16384, 16, 65536);
    println!(
        "archive: {} tribles, {} universe values",
        fixture.gpu.archive().eav_c.len(),
        fixture.gpu.archive().domain.len()
    );

    // Warm the device pipelines outside the measured runs.
    let _ = pinned_arms(&fixture, 64, mixed_pool(&fixture, 1, 4), false);

    println!(
        "\n{:>7} {:>6} {:>8} {:>10} {:>12} {:>12} {:>8}",
        "arm", "width", "fanout", "region", "cpu ms", "gpu ms", "cpu/gpu"
    );
    for width in [256usize, 1024, 4096, 16384] {
        for fanout in [1usize, 4, 16] {
            let pool = mixed_pool(&fixture, 0xC0FFEE ^ (width * fanout) as u64, fanout);
            let log = pinned_arms(&fixture, width, pool, false);
            for (arm, entry) in log.arms.iter().enumerate() {
                if entry.confirms == 0 {
                    continue;
                }
                let region = entry.candidates as f64 / entry.confirms as f64;
                let cpu_ms = entry.cpu.as_secs_f64() * 1e3;
                let gpu_ms = entry.gpu.as_secs_f64() * 1e3;
                println!(
                    "{:>7} {:>6} {:>8} {:>10.0} {:>12.3} {:>12.3} {:>8.2}",
                    arm,
                    width,
                    fanout,
                    region,
                    cpu_ms,
                    gpu_ms,
                    cpu_ms / gpu_ms
                );
            }
        }
    }
    println!(
        "\ncurrent DEFAULT_MIN_CONFIRM_BATCH = {}",
        triblespace_gpu::DEFAULT_MIN_CONFIRM_BATCH
    );
}
