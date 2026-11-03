//! GPU-vs-CPU parity for batched succinct-archive confirm.
//!
//! The acceptance bar: for the same archive, binding, and candidate region,
//! the device-routed [`Constraint::confirm`] must produce liveness identical
//! to the canonical CPU constraint — across every routed arm, including
//! candidates that are already dead (they must stay dead) and duplicated
//! candidate values.
//!
//! # Why every case runs at several region bases
//!
//! A confirm region is `[base..]` of a [`ProposalBuffer`]. Liveness is
//! bit-packed, so that is *not* a word-aligned sub-slice: candidate `i` is
//! bit `base % 32 + i` of the region's words, and the region's first word
//! carries up to 31 bits belonging to the entries *before* `base`. A device
//! kernel that packs verdicts has to place its bits at that offset, and must
//! leave the neighbours' bits alone. Both mistakes are silent — wrong query
//! answers, no diagnostic — and a suite that only ever builds
//! `buffer.region(0)` has `bit_offset == 0` everywhere and structurally cannot
//! see either.
//!
//! So every parity case runs at all of [`BASES`], and asserts three things:
//!
//! * the region's verdicts match the CPU arm's, at each base;
//! * the region's verdicts do not depend on the base — they are a function of
//!   the candidate values and the binding and of nothing else;
//! * every entry *below* the base comes back exactly as it went in: live ones
//!   live, pre-killed ones dead. That is the bug class that matters, and it is
//!   only observable from outside the region.
//!
//! Liveness is read back through `ProposalBuffer::is_live`, never through
//! `live_words`, so nothing in this file spells a word layout and the suite
//! would keep its meaning against a different one.

use std::collections::HashSet;

use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, SuccinctArchive, SuccinctArchiveConstraint,
};
use triblespace_core::inline::encodings::genid::GenId;
use triblespace_core::inline::encodings::UnknownInline;
use triblespace_core::inline::RawInline;
use triblespace_core::query::{
    BindingStore, Constraint, Frontier, ProposalBuffer, Variable, VariableContext, VariableId,
};
use triblespace_core::trible::{Trible, TribleSet};
use triblespace_gpu::WgpuSuccinctArchive;

/// Buffer indices the confirmed region is made to start at.
///
/// Packed, the region's bit offset is `base % 32`, so these cover offset 0
/// (aligned), 1 (just past the boundary), 5 (interior), and 31 (the region's
/// first word holds exactly one of its candidates and 31 of a neighbour's) —
/// each of them once at a base below a word and once at a base past one, plus
/// a base far enough in that whole words precede the region.
const BASES: [usize; 9] = [0, 1, 5, 31, 32, 33, 63, 64, 1000];

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// A 16-byte id with a tag byte and ordinal, high bit set.
fn make_id(tag: u8, ordinal: u32) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0x80 | tag;
    id[12..].copy_from_slice(&ordinal.to_be_bytes());
    id
}

/// The 32-byte raw value of a 16-byte id (id in the low half, zero prefix).
fn id_value(id: &[u8; 16]) -> RawInline {
    let mut value = [0u8; 32];
    value[16..].copy_from_slice(id);
    value
}

/// An arbitrary non-id 32-byte value with a tag byte and ordinal.
fn free_value(tag: u8, ordinal: u32) -> RawInline {
    let mut value = [0u8; 32];
    value[0] = tag;
    value[1] = 0x55;
    value[28..].copy_from_slice(&ordinal.to_be_bytes());
    value
}

/// The entries placed *before* the confirmed region — the neighbouring
/// region's candidates, which this confirm has no business deciding about.
fn prefix_entries(base: usize) -> Vec<RawInline> {
    (0..base).map(|i| free_value(0x30, i as u32)).collect()
}

/// Which prefix entries are pre-killed. A confirm must neither revive these
/// nor kill the others; both directions are checked, because a whole-word
/// write gets one of them wrong whichever way it goes.
fn prefix_is_dead(i: usize) -> bool {
    i % 7 == 3
}

struct Fixture {
    gpu: WgpuSuccinctArchive<OrderedUniverse>,
    /// Raw values of the entity ids, ascending ordinal.
    entities: Vec<RawInline>,
    /// Raw values of the attribute ids, ascending ordinal.
    attributes: Vec<RawInline>,
    /// Raw values occurring in V position.
    values: Vec<RawInline>,
    /// Raw values absent from the archive's universe entirely.
    absent: Vec<RawInline>,
}

/// A small archive with deliberate sharing: every entity carries several
/// attributes, values are drawn from a shared pool (so V-side fanout exists),
/// and one attribute/value pair is common to most entities.
fn fixture() -> Fixture {
    let entity_ids: Vec<[u8; 16]> = (0..24).map(|k| make_id(0x01, k)).collect();
    let attribute_ids: Vec<[u8; 16]> = (0..6).map(|k| make_id(0x02, k)).collect();
    let value_pool: Vec<RawInline> = (0..40).map(|k| free_value(0x10, k)).collect();

    let mut state = 0xF1D0_57A7u64;
    let mut set = TribleSet::new();
    for (i, entity) in entity_ids.iter().enumerate() {
        for (j, attribute) in attribute_ids.iter().enumerate() {
            // Sparse: each (entity, attribute) present with ~2/3 probability.
            if splitmix(&mut state) % 3 == 0 && !(i == 0 && j == 0) {
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
    }
    assert!(set.len() > 100, "fixture must be non-trivial");

    let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
    let gpu = WgpuSuccinctArchive::new(archive)
        .expect("resident wrap succeeds")
        .with_min_confirm_batch(0);
    Fixture {
        gpu,
        entities: entity_ids.iter().map(id_value).collect(),
        attributes: attribute_ids.iter().map(id_value).collect(),
        values: value_pool,
        absent: (0..16)
            .map(|k| free_value(0x20, k))
            .chain((0..8).map(|k| id_value(&make_id(0x03, k))))
            .collect(),
    }
}

/// Mixed candidate pool: axis hits, universe values from the other axes
/// (present in the universe but usually absent from the probed range),
/// entirely absent values, and duplicates of all three kinds.
fn candidate_pool(fixture: &Fixture, seed: u64, len: usize) -> Vec<RawInline> {
    let mut sources: Vec<&[RawInline]> = vec![
        &fixture.entities,
        &fixture.attributes,
        &fixture.values,
        &fixture.absent,
    ];
    sources.rotate_left((seed % 4) as usize);
    let mut state = seed;
    let mut pool = Vec::with_capacity(len);
    for _ in 0..len {
        let source = sources[(splitmix(&mut state) % sources.len() as u64) as usize];
        pool.push(source[(splitmix(&mut state) % source.len() as u64) as usize]);
    }
    // Guaranteed duplicates.
    if len >= 8 {
        let dup = pool[0];
        pool[len / 2] = dup;
        pool[len - 1] = dup;
    }
    pool
}

fn kills_for(seed: u64, len: usize) -> Vec<usize> {
    let mut state = seed ^ 0xDEAD_BEEF;
    (0..len.div_ceil(5))
        .map(|_| (splitmix(&mut state) % len as u64) as usize)
        .collect()
}

/// The liveness of a whole buffer after one confirm, split at the region's
/// base. Booleans, not words: the point is to say nothing about the layout.
struct Outcome {
    /// Liveness of the confirmed region's candidates, region-relative.
    region: Vec<bool>,
    /// Liveness of the entries below the region's base, buffer-relative.
    prefix: Vec<bool>,
}

/// Builds a buffer of `base` neighbour entries followed by `candidates`,
/// pre-kills part of both, runs one confirm over `[base..]`, and reports the
/// liveness of *every* entry in the buffer.
fn confirm_liveness<'a, C: Constraint<'a>>(
    constraint: &C,
    variable: VariableId,
    frontier: &Frontier<'_>,
    base: usize,
    candidates: &[RawInline],
    kills: &[usize],
) -> Outcome {
    let mut buffer = ProposalBuffer::new();
    buffer.extend_from_slice(&prefix_entries(base));
    buffer.extend_from_slice(candidates);
    {
        // The neighbour's kills, applied through a region that owns them.
        let mut neighbour = buffer.region(0);
        for i in 0..base {
            if prefix_is_dead(i) {
                neighbour.kill(i);
            }
        }
    }
    {
        let mut region = buffer.region(base);
        for &k in kills {
            region.kill(k);
        }
        constraint.confirm(variable, frontier, &mut region);
    }
    Outcome {
        region: (base..buffer.len()).map(|i| buffer.is_live(i)).collect(),
        prefix: (0..base).map(|i| buffer.is_live(i)).collect(),
    }
}

/// Asserts the entries below the region survived the confirm untouched.
fn assert_prefix_undisturbed(prefix: &[bool], arm: &str, context: &str) {
    for (i, live) in prefix.iter().enumerate() {
        assert_eq!(
            *live,
            !prefix_is_dead(i),
            "{arm} confirm disturbed entry {i}, which lies outside the region, for {context}"
        );
    }
}

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

/// One parity check, repeated at every base in [`BASES`]: identical region
/// liveness under the CPU and GPU constraints, dead entries stay dead, every
/// duplicate value pair agrees, the entries outside the region are untouched,
/// and the verdicts are the same whatever the base. Returns the region
/// liveness for arm-coverage assertions.
fn check_arm(
    fixture: &Fixture,
    variable: VariableId,
    frontier: &Frontier<'_>,
    candidates: &[RawInline],
    kills: &[usize],
    context: &str,
) -> Vec<bool> {
    let vars_cpu = vars();
    let cpu_constraint =
        SuccinctArchiveConstraint::new(vars_cpu.e, vars_cpu.a, vars_cpu.v, fixture.gpu.archive());
    let vars_gpu = vars();
    let gpu_constraint = triblespace_gpu::WgpuSuccinctArchiveConstraint::new(
        vars_gpu.e,
        vars_gpu.a,
        vars_gpu.v,
        &fixture.gpu,
    );

    let killed: HashSet<usize> = kills.iter().copied().collect();
    let mut settled: Option<Vec<bool>> = None;
    for base in BASES {
        let context = format!("{context}/base{base}");

        let before = fixture.gpu.stats();
        let cpu = confirm_liveness(&cpu_constraint, variable, frontier, base, candidates, kills);
        let gpu = confirm_liveness(&gpu_constraint, variable, frontier, base, candidates, kills);
        let after = fixture.gpu.stats();

        assert_eq!(
            cpu.region, gpu.region,
            "CPU and GPU liveness diverge for {context}"
        );
        assert_eq!(
            after.gpu_confirms,
            before.gpu_confirms + 1,
            "confirm was not device-routed for {context}"
        );

        assert_prefix_undisturbed(&cpu.prefix, "CPU", &context);
        assert_prefix_undisturbed(&gpu.prefix, "GPU", &context);

        for &k in kills {
            assert!(!gpu.region[k], "killed entry {k} was revived for {context}");
        }
        for i in 0..candidates.len() {
            for j in (i + 1)..candidates.len() {
                if candidates[i] == candidates[j] && !killed.contains(&i) && !killed.contains(&j) {
                    assert_eq!(
                        gpu.region[i], gpu.region[j],
                        "duplicate candidates {i} and {j} disagree for {context}"
                    );
                }
            }
        }

        // A region's verdicts are a function of its candidates and the
        // binding. If they move with the base, some bit landed at the wrong
        // offset.
        if let Some(previous) = &settled {
            assert_eq!(
                previous, &gpu.region,
                "region verdicts changed with the region's base for {context}"
            );
        }
        settled = Some(gpu.region);
    }
    settled.expect("BASES is non-empty")
}

/// Asserts the arm was informative: at least one survivor and at least one
/// non-prekilled kill, so parity is not vacuous.
fn assert_mixed(liveness: &[bool], kills: &[usize], context: &str) {
    let killed: HashSet<usize> = kills.iter().copied().collect();
    let survivors = liveness.iter().filter(|live| **live).count();
    let fresh_kills = liveness
        .iter()
        .enumerate()
        .filter(|(i, live)| !**live && !killed.contains(i))
        .count();
    assert!(survivors > 0, "{context}: no survivors — vacuous parity");
    assert!(fresh_kills > 0, "{context}: no kills — vacuous parity");
}

#[test]
fn membership_confirm_parity_all_axes() {
    let fixture = fixture();
    let v = vars();
    let frontier = Frontier::default();
    for seed in 0..6u64 {
        let candidates = candidate_pool(&fixture, seed, 64 + (seed as usize * 37) % 80);
        let kills = kills_for(seed, candidates.len());
        for (variable, axis) in [
            (v.e.index, "entity"),
            (v.a.index, "attribute"),
            (v.v.index, "value"),
        ] {
            let context = format!("membership/{axis}/seed{seed}");
            let live = check_arm(&fixture, variable, &frontier, &candidates, &kills, &context);
            assert_mixed(&live, &kills, &context);
        }
    }
}

#[test]
fn single_bound_range_confirm_parity() {
    let fixture = fixture();
    let v = vars();
    // (bound variable, confirmed variable, bound raw value pool)
    let arms: [(VariableId, VariableId, &[RawInline], &str); 6] = [
        (v.e.index, v.a.index, &fixture.entities, "e-bound/confirm-a"),
        (v.e.index, v.v.index, &fixture.entities, "e-bound/confirm-v"),
        (
            v.a.index,
            v.e.index,
            &fixture.attributes,
            "a-bound/confirm-e",
        ),
        (
            v.a.index,
            v.v.index,
            &fixture.attributes,
            "a-bound/confirm-v",
        ),
        (v.v.index, v.e.index, &fixture.values, "v-bound/confirm-e"),
        (v.v.index, v.a.index, &fixture.values, "v-bound/confirm-a"),
    ];
    for seed in 0..4u64 {
        let candidates = candidate_pool(&fixture, seed.wrapping_mul(31).wrapping_add(7), 96);
        let kills = kills_for(seed, candidates.len());
        for (bound_var, confirm_var, bound_pool, name) in arms {
            let bound = bound_pool[(seed as usize * 5) % bound_pool.len()];
            let mut binding = BindingStore::new();
            binding.bind(bound_var, &bound);
            let context = format!("range/{name}/seed{seed}");
            check_arm(
                &fixture,
                confirm_var,
                &binding.frontier(),
                &candidates,
                &kills,
                &context,
            );

            // Bound value absent from the archive: the range is empty and
            // every candidate dies on both paths.
            let mut binding = BindingStore::new();
            binding.bind(
                bound_var,
                &fixture.absent[seed as usize % fixture.absent.len()],
            );
            let context = format!("range-empty/{name}/seed{seed}");
            let live = check_arm(
                &fixture,
                confirm_var,
                &binding.frontier(),
                &candidates,
                &kills,
                &context,
            );
            assert!(
                live.iter().all(|survived| !*survived),
                "{context}: empty range must kill everything"
            );
        }
    }
}

#[test]
fn double_bound_range_confirm_parity() {
    let fixture = fixture();
    let v = vars();
    for seed in 0..4u64 {
        let candidates = candidate_pool(&fixture, seed.wrapping_mul(97).wrapping_add(3), 96);
        let kills = kills_for(seed ^ 0x77, candidates.len());
        let entity = fixture.entities[(seed as usize * 3) % fixture.entities.len()];
        let attribute = fixture.attributes[(seed as usize * 2) % fixture.attributes.len()];
        let value = fixture.values[(seed as usize * 11) % fixture.values.len()];

        // (a, v) bound, confirm e.
        let mut binding = BindingStore::new();
        binding.bind(v.a.index, &attribute);
        binding.bind(v.v.index, &value);
        check_arm(
            &fixture,
            v.e.index,
            &binding.frontier(),
            &candidates,
            &kills,
            &format!("range/av-bound/confirm-e/seed{seed}"),
        );

        // (e, v) bound, confirm a.
        let mut binding = BindingStore::new();
        binding.bind(v.e.index, &entity);
        binding.bind(v.v.index, &value);
        check_arm(
            &fixture,
            v.a.index,
            &binding.frontier(),
            &candidates,
            &kills,
            &format!("range/ev-bound/confirm-a/seed{seed}"),
        );

        // (e, a) bound, confirm v.
        let mut binding = BindingStore::new();
        binding.bind(v.e.index, &entity);
        binding.bind(v.a.index, &attribute);
        check_arm(
            &fixture,
            v.v.index,
            &binding.frontier(),
            &candidates,
            &kills,
            &format!("range/ea-bound/confirm-v/seed{seed}"),
        );
    }
}

#[test]
fn all_dead_region_stays_all_dead() {
    let fixture = fixture();
    let v = vars();
    let frontier = Frontier::default();
    let candidates = candidate_pool(&fixture, 41, 32);
    let kills: Vec<usize> = (0..candidates.len()).collect();
    let vars_gpu = vars();
    let constraint = triblespace_gpu::WgpuSuccinctArchiveConstraint::new(
        vars_gpu.e,
        vars_gpu.a,
        vars_gpu.v,
        &fixture.gpu,
    );
    for base in BASES {
        let outcome =
            confirm_liveness(&constraint, v.v.index, &frontier, base, &candidates, &kills);
        assert!(
            outcome.region.iter().all(|live| !*live),
            "an all-dead region gained a survivor at base {base}"
        );
        assert_prefix_undisturbed(&outcome.prefix, "GPU", &format!("all-dead/base{base}"));
    }
}

#[test]
fn below_threshold_falls_back_to_cpu() {
    let mut fixture = fixture();
    fixture.gpu.set_min_confirm_batch(usize::MAX);
    let v = vars();
    let frontier = Frontier::default();
    let candidates = candidate_pool(&fixture, 17, 48);

    let vars_cpu = vars();
    let cpu_constraint =
        SuccinctArchiveConstraint::new(vars_cpu.e, vars_cpu.a, vars_cpu.v, fixture.gpu.archive());
    let vars_gpu = vars();
    let gpu_constraint = triblespace_gpu::WgpuSuccinctArchiveConstraint::new(
        vars_gpu.e,
        vars_gpu.a,
        vars_gpu.v,
        &fixture.gpu,
    );

    for base in BASES {
        let before = fixture.gpu.stats();
        let cpu = confirm_liveness(
            &cpu_constraint,
            v.v.index,
            &frontier,
            base,
            &candidates,
            &[],
        );
        let gpu = confirm_liveness(
            &gpu_constraint,
            v.v.index,
            &frontier,
            base,
            &candidates,
            &[],
        );
        let after = fixture.gpu.stats();

        assert_eq!(
            cpu.region, gpu.region,
            "threshold fallback diverges at base {base}"
        );
        assert_eq!(after.gpu_confirms, before.gpu_confirms);
        assert_eq!(
            after.cpu_fallback_confirms,
            before.cpu_fallback_confirms + 1
        );
        assert_prefix_undisturbed(
            &gpu.prefix,
            "CPU-fallback",
            &format!("threshold/base{base}"),
        );
    }
}

/// Region-size sweep printing the CPU/GPU crossover for both routed confirm
/// shapes. `DEFAULT_MIN_CONFIRM_BATCH`'s doc comment records the measurement.
///
/// Run with:
/// `cargo test -p triblespace-gpu --test batch_confirm_parity -- --ignored --nocapture confirm_crossover_sweep`
#[test]
#[ignore = "measurement benchmark; run explicitly with --ignored --nocapture"]
fn confirm_crossover_sweep() {
    use std::time::Instant;

    // A larger synthetic archive so per-candidate CPU probe costs are
    // realistic: 4096 entities x 64 values over 16 attributes.
    let entity_ids: Vec<[u8; 16]> = (0..4096).map(|k| make_id(0x01, k)).collect();
    let attribute_ids: Vec<[u8; 16]> = (0..16).map(|k| make_id(0x02, k)).collect();
    let value_pool: Vec<RawInline> = (0..65536).map(|k| free_value(0x10, k)).collect();

    let mut state = 0xC0FF_EE00u64;
    let mut set = TribleSet::new();
    for entity in &entity_ids {
        for _ in 0..64 {
            let attribute =
                &attribute_ids[(splitmix(&mut state) % attribute_ids.len() as u64) as usize];
            let value = value_pool[(splitmix(&mut state) % value_pool.len() as u64) as usize];
            let mut data = [0u8; 64];
            data[..16].copy_from_slice(entity);
            data[16..32].copy_from_slice(attribute);
            data[32..].copy_from_slice(&value);
            set.insert(&Trible::force_raw(data).expect("non-nil entity and attribute"));
        }
    }
    let archive: SuccinctArchive<OrderedUniverse> = (&set).into();
    println!(
        "archive: {} tribles, {} universe values",
        archive.eav_c.len(),
        archive.domain.len()
    );
    let gpu = WgpuSuccinctArchive::new(archive)
        .expect("resident wrap succeeds")
        .with_min_confirm_batch(0);

    let absent: Vec<RawInline> = (0..65536).map(|k| free_value(0x20, k)).collect();
    let v = vars();
    let vars_cpu = vars();
    let cpu_constraint =
        SuccinctArchiveConstraint::new(vars_cpu.e, vars_cpu.a, vars_cpu.v, gpu.archive());
    let vars_gpu = vars();
    let gpu_constraint = triblespace_gpu::WgpuSuccinctArchiveConstraint::new(
        vars_gpu.e, vars_gpu.a, vars_gpu.v, &gpu,
    );

    let bench =
        |variable: VariableId, frontier: &Frontier<'_>, candidates: &[RawInline], shape: &str| {
            let mut buffer = ProposalBuffer::new();
            buffer.extend_from_slice(candidates);
            // Layout-agnostic "revive everything": `set_live_words` keeps only
            // the bits the region owns, so all-ones sets exactly those. Sized
            // from `live_word_len`, never from the candidate count.
            let all_live = vec![u32::MAX; buffer.region(0).live_word_len()];
            let reps = 5;

            // Warm up device pipelines outside the timed region.
            {
                let mut region = buffer.region(0);
                gpu_constraint.confirm(variable, frontier, &mut region);
                region.set_live_words(&all_live);
            }

            let mut cpu_best = f64::MAX;
            let mut gpu_best = f64::MAX;
            let mut cpu_live = Vec::new();
            let mut gpu_live = Vec::new();
            for _ in 0..reps {
                let mut region = buffer.region(0);
                region.set_live_words(&all_live);
                let started = Instant::now();
                cpu_constraint.confirm(variable, frontier, &mut region);
                cpu_best = cpu_best.min(started.elapsed().as_secs_f64() * 1e3);
                cpu_live = (0..buffer.len()).map(|i| buffer.is_live(i)).collect();

                let mut region = buffer.region(0);
                region.set_live_words(&all_live);
                let started = Instant::now();
                gpu_constraint.confirm(variable, frontier, &mut region);
                gpu_best = gpu_best.min(started.elapsed().as_secs_f64() * 1e3);
                gpu_live = (0..buffer.len()).map(|i| buffer.is_live(i)).collect();

                buffer.region(0).set_live_words(&all_live);
            }
            assert_eq!(cpu_live, gpu_live, "sweep parity failed for {shape}");
            (cpu_best, gpu_best)
        };

    for (shape, variable, binding_fn) in [
        (
            "membership (confirm v, nothing bound)",
            v.v.index,
            Box::new(BindingStore::new) as Box<dyn Fn() -> BindingStore>,
        ),
        (
            "range (e bound, confirm v)",
            v.v.index,
            Box::new(|| {
                let mut binding = BindingStore::new();
                binding.bind(v.e.index, &id_value(&make_id(0x01, 17)));
                binding
            }),
        ),
    ] {
        println!("\n== {shape} ==");
        println!(
            "{:>8} {:>12} {:>12} {:>8}",
            "region", "cpu ms", "gpu ms", "cpu/gpu"
        );
        let binding = binding_fn();
        for size in [1024usize, 4096, 16384, 65536] {
            let mut state = 0xBEEF ^ size as u64;
            let candidates: Vec<RawInline> = (0..size)
                .map(|_| {
                    if splitmix(&mut state) % 2 == 0 {
                        value_pool[(splitmix(&mut state) % value_pool.len() as u64) as usize]
                    } else {
                        absent[(splitmix(&mut state) % absent.len() as u64) as usize]
                    }
                })
                .collect();
            let (cpu_ms, gpu_ms) = bench(variable, &binding.frontier(), &candidates, shape);
            println!(
                "{:>8} {:>12.3} {:>12.3} {:>8.2}",
                size,
                cpu_ms,
                gpu_ms,
                cpu_ms / gpu_ms
            );
        }
    }
    println!(
        "\ncurrent DEFAULT_MIN_CONFIRM_BATCH = {}",
        triblespace_gpu::DEFAULT_MIN_CONFIRM_BATCH
    );
}
