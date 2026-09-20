//! Evolving-cover maintenance benchmark for canonical Succinct collections.
//!
//! This benchmark compares the two public maintenance paths on
//! geometrically growing source frontiers:
//!
//! - `maintain`: deterministic size-tiered raw-target maintenance followed by
//!   the Rank9-accelerated derivation.
//! - functional snapshot advancement: maintain the Succinct chain, read the
//!   payloads the target newly stands on from the source as the delta, and
//!   return immutable candidates to the caller.
//!
//! Stateless `maintain` gets an independent warm store, a source-identical cold
//! store with no derived evidence, and an immediate unchanged warm no-op. The
//! maintained view gets its own evolving store and immediate no-op. Source
//! commits are appended outside the timers. Store deltas quantify new durable
//! state. One untimed read-only raw attachment records the chosen physical
//! cover and asserts that resident lookup changes no storage. Snapshot support
//! accounting lives entirely in this benchmark rather than production code.
//! No scan or diagnostic touches a measured store before its first timed call
//! at a checkpoint, and the immediate no-op remains adjacent to that call.
//!
//! Final relations are materialized outside the timers into canonical
//! contiguous SimpleArchive bytes. Their cached content handles must match the
//! exact source prefix and the corresponding warm/cold/no-op arms. Stateless
//! raw-cover identities and maintained-view segment counts are reported, but
//! physical covers need not match: optional evidence may choose another exact
//! cover without changing the logical relation.
//!
//! Usage:
//!
//! ```text
//! cargo bench --bench collection_evolution -- \
//!   [--commits 64] [--rows-per-commit 1024] [--warmup 1] [--iters 4]
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace_core::blob::Blob;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionRead, CollectionRecord,
    CollectionSnapshot, CollectionSnapshotExt, CollectionStoreExt, Cover, CoverAdvanceError,
    Support,
};
use triblespace_core::inline::Encodes;
use triblespace_core::prelude::*;
use triblespace_core::repo::memoryrepo::MemoryRepoSnapshot;
use triblespace_core::repo::{BlobStoreGet, BlobStoreList};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StoreShape {
    blobs: u64,
    blob_bytes: u64,
    commits: u64,
    source_merges: u64,
    raw_derives: u64,
    raw_merges: u64,
    accelerated_records: u64,
    other_records: u64,
}

impl StoreShape {
    fn plus(self, other: Self) -> Self {
        Self {
            blobs: self.blobs + other.blobs,
            blob_bytes: self.blob_bytes + other.blob_bytes,
            commits: self.commits + other.commits,
            source_merges: self.source_merges + other.source_merges,
            raw_derives: self.raw_derives + other.raw_derives,
            raw_merges: self.raw_merges + other.raw_merges,
            accelerated_records: self.accelerated_records + other.accelerated_records,
            other_records: self.other_records + other.other_records,
        }
    }

    fn difference(self, before: Self) -> Self {
        Self {
            blobs: self.blobs - before.blobs,
            blob_bytes: self.blob_bytes - before.blob_bytes,
            commits: self.commits - before.commits,
            source_merges: self.source_merges - before.source_merges,
            raw_derives: self.raw_derives - before.raw_derives,
            raw_merges: self.raw_merges - before.raw_merges,
            accelerated_records: self.accelerated_records - before.accelerated_records,
            other_records: self.other_records - before.other_records,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Collections {
    source: Collection<SimpleArchive>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
}

fn store_shape(store: &mut MemoryRepo, collections: &Collections) -> StoreShape {
    let mut shape = StoreShape::default();
    let snapshot = store.snapshot().expect("freeze MemoryRepo snapshot");
    for record in snapshot.records().expect("enumerate collection records") {
        match record.expect("MemoryRepo collection records are infallible") {
            CollectionRecord::Commit(commit)
                if commit.collection() == collections.source.handle() =>
            {
                shape.commits += 1;
            }
            CollectionRecord::Merge(merge) if merge.collection() == collections.source.handle() => {
                shape.source_merges += 1;
            }
            CollectionRecord::Derive(derive) if derive.collection() == collections.raw.handle() => {
                shape.raw_derives += 1;
            }
            CollectionRecord::Merge(merge) if merge.collection() == collections.raw.handle() => {
                shape.raw_merges += 1;
            }
            CollectionRecord::Derive(derive)
                if derive.collection() == collections.accelerated.handle() =>
            {
                shape.accelerated_records += 1;
            }
            CollectionRecord::Merge(merge)
                if merge.collection() == collections.accelerated.handle() =>
            {
                shape.accelerated_records += 1;
            }
            _ => shape.other_records += 1,
        }
    }

    for info in snapshot.blobs() {
        let info = info.expect("MemoryRepo blob listing is infallible");
        shape.blobs += 1;
        shape.blob_bytes += info.length;
    }
    shape
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelationIdentity {
    rows: u64,
    hash: [u8; 32],
}

fn relation_identity(rows: impl IntoIterator<Item = Trible>) -> RelationIdentity {
    let set: TribleSet = rows.into_iter().collect();
    relation_identity_set(&set)
}

fn relation_identity_set(set: &TribleSet) -> RelationIdentity {
    // SimpleArchive is one canonical contiguous EAV sequence. Blob::new has
    // already hashed the complete buffer, so reuse its cached content handle.
    let archive = SimpleArchive::encode(set);
    RelationIdentity {
        rows: set.len() as u64,
        hash: archive.get_handle().raw,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoverIdentity {
    members: u64,
    bytes: u64,
    hash: [u8; 32],
}

fn cover_identity<S>(snapshot: &S, cover: &Cover<SuccinctArchiveBlob>) -> CoverIdentity
where
    S: BlobStoreGet,
{
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0u64;
    for handle in cover.members() {
        hasher.update(&handle.raw);
        let blob: Blob<SuccinctArchiveBlob> =
            snapshot.get(handle).expect("load exact raw cover member");
        bytes += blob.bytes.len() as u64;
    }
    CoverIdentity {
        members: cover.len() as u64,
        bytes,
        hash: *hasher.finalize().as_bytes(),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Arm {
    EnsureWarm,
    EnsureCold,
    EnsureNoop,
    SnapshotAdvance,
    SnapshotNoop,
}

impl Arm {
    fn label(self) -> &'static str {
        match self {
            Self::EnsureWarm => "ensure-warm",
            Self::EnsureCold => "ensure-cold",
            Self::EnsureNoop => "ensure-noop",
            Self::SnapshotAdvance => "snapshot-advance",
            Self::SnapshotNoop => "snapshot-noop",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    arm: Arm,
    commits: usize,
    total_rows: u64,
    basis_rows: u64,
    elapsed: Duration,
    work: StoreShape,
    diagnostic: Diagnostic,
    relation: RelationIdentity,
    cover_members: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Diagnostic {
    StatelessOperation { cover: CoverIdentity },
    Snapshot(SnapshotSupport),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SnapshotSupport {
    cover_members: usize,
    changed_members: usize,
    reused_members: usize,
}

struct TimedOperation {
    elapsed: Duration,
    union: UnionArchive<OrderedUniverse>,
}

struct RunContext<'a> {
    cover: &'a Support,
    signing_key: &'a SigningKey,
    total_rows: u64,
    newly_supported_rows: u64,
    expected: RelationIdentity,
    collections: &'a Collections,
}

fn maintain_succinct(
    store: &mut MemoryRepo,
    collections: &Collections,
    signing_key: &SigningKey,
) -> CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob> {
    block_on(store.maintain(collections.raw, signing_key))
        .expect("maintain raw Succinct collection");
    let snapshot = block_on(store.maintain(collections.accelerated, signing_key))
        .expect("maintain accelerated Succinct collection");
    snapshot
        .collection(collections.accelerated)
        .expect("observe accelerated Succinct collection")
}

fn time_ensure(
    store: &mut MemoryRepo,
    cover: &Support,
    collections: &Collections,
    signing_key: &SigningKey,
) -> TimedOperation {
    let start = Instant::now();
    let attached = maintain_succinct(store, collections, signing_key);
    let elapsed = start.elapsed();
    assert_eq!(
        attached.support().expect("resolve accelerated support"),
        cover,
        "the maintained target stands for the accounting cover",
    );
    let union: UnionArchive<OrderedUniverse> = attached.view().expect("materialize Succinct view");
    black_box(union.segment_count());
    TimedOperation { elapsed, union }
}

fn observe_raw_cover(
    store: &mut MemoryRepo,
    cover: &Support,
    raw: Collection<SuccinctArchiveBlob>,
) -> CoverIdentity {
    // This is outside the timer and must be a zero-write, zero-algebra lookup.
    // The public accelerated phase remains represented by timing and its
    // ordinary DERIVE/MERGE/blob delta.
    let diagnostic_before = store
        .snapshot()
        .expect("freeze pre-diagnostic store snapshot");
    let raw_cover = diagnostic_before
        .collection(raw)
        .expect("observe resident raw cover");
    assert_eq!(
        raw_cover.support().expect("resolve raw support"),
        cover,
        "the raw target stands for the accounting cover",
    );
    let diagnostic_after = store
        .snapshot()
        .expect("freeze post-diagnostic store snapshot");
    let cover = cover_identity(&diagnostic_after, raw_cover.cover());
    assert!(
        diagnostic_after
            .changes_since(&diagnostic_before)
            .is_empty(),
        "post-operation raw mapping diagnostic wrote sync-visible storage"
    );
    cover
}

fn finish_sample(
    arm: Arm,
    context: &RunContext<'_>,
    basis_rows: u64,
    timed: TimedOperation,
    work: StoreShape,
    diagnostic: Diagnostic,
) -> Sample {
    let cover_members = timed.union.segment_count() as u64;
    let relation = relation_identity(timed.union.iter());
    Sample {
        arm,
        commits: context.cover.len(),
        total_rows: context.total_rows,
        basis_rows,
        elapsed: timed.elapsed,
        work,
        diagnostic,
        relation,
        cover_members,
    }
}

fn run_ensure_warm_pair(
    store: &mut MemoryRepo,
    context: &RunContext<'_>,
    before: StoreShape,
) -> ([Sample; 2], StoreShape) {
    let timed_warm = time_ensure(
        store,
        context.cover,
        context.collections,
        context.signing_key,
    );
    let snapshot_after_warm = store
        .snapshot()
        .expect("freeze snapshot between warm and no-op calls");

    // Keep these public calls adjacent. In particular, do not materialize the
    // first result or inspect its raw cover before timing the unchanged call.
    let timed_noop = time_ensure(
        store,
        context.cover,
        context.collections,
        context.signing_key,
    );
    let snapshot_after_noop = store.snapshot().expect("freeze snapshot after no-op call");
    assert!(
        snapshot_after_noop
            .changes_since(&snapshot_after_warm)
            .is_empty(),
        "an unchanged public operation changed sync-visible storage"
    );

    let after = store_shape(store, context.collections);
    let warm_work = after.difference(before);
    let raw_cover = observe_raw_cover(store, context.cover, context.collections.raw);
    let warm = finish_sample(
        Arm::EnsureWarm,
        context,
        context.newly_supported_rows,
        timed_warm,
        warm_work,
        Diagnostic::StatelessOperation { cover: raw_cover },
    );
    assert_eq!(warm.relation, context.expected);

    let noop = finish_sample(
        Arm::EnsureNoop,
        context,
        context.total_rows,
        timed_noop,
        StoreShape::default(),
        Diagnostic::StatelessOperation { cover: raw_cover },
    );
    assert_eq!(noop.relation, context.expected);
    ([warm, noop], after)
}

fn run_ensure_cold(store: &mut MemoryRepo, context: &RunContext<'_>, before: StoreShape) -> Sample {
    let timed = time_ensure(
        store,
        context.cover,
        context.collections,
        context.signing_key,
    );
    let after = store_shape(store, context.collections);
    let raw_cover = observe_raw_cover(store, context.cover, context.collections.raw);
    let cold = finish_sample(
        Arm::EnsureCold,
        context,
        context.total_rows,
        timed,
        after.difference(before),
        Diagnostic::StatelessOperation { cover: raw_cover },
    );
    assert_eq!(cold.relation, context.expected);
    cold
}

fn run_ensure_family(
    iteration: usize,
    warm_store: &mut MemoryRepo,
    cold_store: &mut MemoryRepo,
    context: &RunContext<'_>,
    baselines: [StoreShape; 2],
) -> (Vec<Sample>, StoreShape) {
    let [warm_before, cold_before] = baselines;
    let (warm_pair, warm_after, cold) = if iteration.is_multiple_of(2) {
        let (warm_pair, warm_after) = run_ensure_warm_pair(warm_store, context, warm_before);
        let cold = run_ensure_cold(cold_store, context, cold_before);
        (warm_pair, warm_after, cold)
    } else {
        let cold = run_ensure_cold(cold_store, context, cold_before);
        let (warm_pair, warm_after) = run_ensure_warm_pair(warm_store, context, warm_before);
        (warm_pair, warm_after, cold)
    };
    (vec![warm_pair[0], cold, warm_pair[1]], warm_after)
}

fn time_snapshot(
    state: &mut Option<CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob>>,
    store: &mut MemoryRepo,
    cover: &Support,
    collections: &Collections,
    signing_key: &SigningKey,
) -> (TimedOperation, SnapshotSupport) {
    let start = Instant::now();
    let (candidate, changed_members, reused_members) = match state.as_ref() {
        None => (
            maintain_succinct(store, collections, signing_key),
            cover.len(),
            0,
        ),
        Some(previous) if cover == previous.support().unwrap() => {
            let elapsed = start.elapsed();
            let union: UnionArchive<OrderedUniverse> = previous
                .view()
                .expect("materialize unchanged Succinct snapshot");
            black_box(union.segment_count());
            return (
                TimedOperation { elapsed, union },
                SnapshotSupport {
                    cover_members: cover.len(),
                    changed_members: 0,
                    reused_members: cover.len(),
                },
            );
        }
        Some(previous) => match cover.additions_since(previous.support().unwrap()) {
            Ok(additions) => {
                let next = maintain_succinct(store, collections, signing_key);
                // The delta is a set of source payloads: read them from the
                // source through the same snapshot the target came from.
                let changed: TribleSet = additions
                    .materialize(next.snapshot())
                    .expect("materialize changed source payloads");
                black_box(changed.len());
                (next, additions.len(), previous.support().unwrap().len())
            }
            Err(CoverAdvanceError::ResetRequired { .. }) => (
                maintain_succinct(store, collections, signing_key),
                cover.len(),
                0,
            ),
            Err(error) => {
                panic!("advance maintained Succinct snapshot: {error}")
            }
        },
    };
    let elapsed = start.elapsed();
    let union: UnionArchive<OrderedUniverse> = candidate
        .view()
        .expect("materialize candidate Succinct snapshot");
    black_box(union.segment_count());
    *state = Some(candidate);
    (
        TimedOperation { elapsed, union },
        SnapshotSupport {
            cover_members: cover.len(),
            changed_members,
            reused_members,
        },
    )
}

fn run_snapshot_pair(
    state: &mut Option<CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob>>,
    store: &mut MemoryRepo,
    context: &RunContext<'_>,
    before: StoreShape,
) -> ([Sample; 2], StoreShape) {
    let (timed_advance, advance_work) = time_snapshot(
        state,
        store,
        context.cover,
        context.collections,
        context.signing_key,
    );
    assert_eq!(advance_work.cover_members, context.cover.len());
    assert_eq!(
        advance_work.changed_members + advance_work.reused_members,
        context.cover.len(),
        "snapshot support accounting must cover the exact payload set",
    );
    let snapshot_after_advance = store
        .snapshot()
        .expect("freeze store between snapshot advance and no-op");

    let (timed_noop, noop_work) = time_snapshot(
        state,
        store,
        context.cover,
        context.collections,
        context.signing_key,
    );
    assert_eq!(
        noop_work,
        SnapshotSupport {
            cover_members: context.cover.len(),
            changed_members: 0,
            reused_members: context.cover.len(),
        },
        "an identical snapshot cover must not execute projection work",
    );
    assert!(
        store
            .snapshot()
            .expect("freeze snapshot after view no-op")
            .changes_since(&snapshot_after_advance)
            .is_empty(),
        "an unchanged snapshot changed sync-visible storage",
    );

    let after = store_shape(store, context.collections);
    let advance = finish_sample(
        Arm::SnapshotAdvance,
        context,
        context.newly_supported_rows,
        timed_advance,
        after.difference(before),
        Diagnostic::Snapshot(advance_work),
    );
    let noop = finish_sample(
        Arm::SnapshotNoop,
        context,
        context.total_rows,
        timed_noop,
        StoreShape::default(),
        Diagnostic::Snapshot(noop_work),
    );
    assert_eq!(advance.relation, context.expected);
    assert_eq!(noop.relation, context.expected);
    ([advance, noop], after)
}

fn geometric_checkpoints(commits: usize) -> Vec<usize> {
    let mut checkpoints = Vec::new();
    let mut next = 1usize;
    while next < commits {
        checkpoints.push(next);
        next = next.saturating_mul(2);
    }
    checkpoints.push(commits);
    checkpoints
}

fn make_chunk(commit: usize, rows: usize) -> TribleSet {
    let mut chunk = TribleSet::new();
    for row in 0..rows {
        let ordinal = (commit as u64)
            .checked_mul(rows as u64)
            .and_then(|base| base.checked_add(row as u64))
            .expect("benchmark ordinal fits u64");
        let mut raw = [0u8; 64];
        raw[..8].copy_from_slice(&(ordinal + 1).to_be_bytes());
        raw[8..16].copy_from_slice(&0xE001_0000_0000_0001u64.to_be_bytes());
        raw[16..24].copy_from_slice(&0xA001_0000_0000_0001u64.to_be_bytes());
        raw[24..32].copy_from_slice(&(commit as u64 + 1).to_be_bytes());
        raw[32..40].copy_from_slice(&ordinal.rotate_left(17).to_be_bytes());
        raw[40..48].copy_from_slice(&ordinal.wrapping_mul(31).to_be_bytes());
        raw[48..56].copy_from_slice(&(commit as u64).to_be_bytes());
        raw[56..64].copy_from_slice(&(row as u64).to_be_bytes());
        chunk.insert(&Trible::force_raw(raw).expect("non-nil entity and attribute"));
    }
    chunk
}

fn benchmark_name() -> &'static str {
    "evolving-succinct-benchmark"
}

fn benchmark_authority() -> ed25519_dalek::VerifyingKey {
    SigningKey::from_bytes(&[0x71; 32]).verifying_key()
}

fn benchmark_policy() -> CollectionPolicy {
    CollectionPolicy::new(
        AdmissionPolicy::direct(benchmark_authority()),
        AdmissionPolicy::direct(benchmark_authority()),
    )
}

fn register_collections(store: &mut MemoryRepo) -> Collections {
    let policy = benchmark_policy();
    let source = store
        .collection(benchmark_name(), policy.clone())
        .expect("register benchmark source collection");
    let raw = store
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .expect("register raw Succinct projection");
    let accelerated = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
        .expect("register accelerated Succinct projection");
    Collections {
        source,
        raw,
        accelerated,
    }
}

fn new_source_store(expected: &Collections) -> MemoryRepo {
    let mut store = MemoryRepo::default();
    assert_eq!(&register_collections(&mut store), expected);
    store
}

fn publish_same_chunk(
    chunk: &TribleSet,
    source: Collection<SimpleArchive>,
    signing_key: &SigningKey,
    stores: &mut [&mut MemoryRepo],
) {
    let mut expected = None;
    for store in stores {
        let commit = store
            .commit(source, signing_key, Fragment::from(chunk.clone()))
            .expect("publish source commit");
        match expected {
            None => expected = Some(commit),
            Some(expected) => {
                assert_eq!(
                    commit, expected,
                    "identical source publications must converge"
                )
            }
        }
    }
}

fn run_iteration(
    iteration: usize,
    chunks: &[TribleSet],
    checkpoints: &[usize],
    collections: &Collections,
) -> Vec<Sample> {
    let mut maintained_snapshot = None;
    let source = collections.source;
    let signing_key = SigningKey::from_bytes(&[0x71; 32]);
    let mut source_accounting = new_source_store(collections);
    let mut cold_ensure_source = new_source_store(collections);
    let mut warm_ensure = new_source_store(collections);
    let mut snapshot_source = new_source_store(collections);

    let mut published = 0usize;
    let mut previous_rows = 0u64;
    let mut expected = TribleSet::new();
    let mut samples = Vec::with_capacity(checkpoints.len() * 5);
    let mut ensure_derived_shape = StoreShape::default();
    let mut snapshot_derived_shape = StoreShape::default();
    for &checkpoint in checkpoints {
        for chunk in &chunks[published..checkpoint] {
            expected.union(chunk.clone());
            publish_same_chunk(
                chunk,
                source,
                &signing_key,
                &mut [
                    &mut source_accounting,
                    &mut cold_ensure_source,
                    &mut warm_ensure,
                    &mut snapshot_source,
                ],
            );
        }
        published = checkpoint;

        let source_snapshot = source_accounting
            .snapshot()
            .expect("freeze accounting source snapshot");
        let cover = source
            .admitted(&source_snapshot)
            .expect("freeze accounting source cover");
        assert_eq!(cover.len(), checkpoint);
        let source_shape = store_shape(&mut source_accounting, collections);

        let total_rows = expected.len() as u64;
        let newly_supported_rows = total_rows - previous_rows;
        previous_rows = total_rows;
        let expected_identity = relation_identity_set(&expected);
        let context = RunContext {
            cover: &cover,
            signing_key: &signing_key,
            total_rows,
            newly_supported_rows,
            expected: expected_identity,
            collections,
        };

        let mut cold_ensure = cold_ensure_source.clone();
        let ensure_before = source_shape.plus(ensure_derived_shape);
        let snapshot_before = source_shape.plus(snapshot_derived_shape);
        if iteration.is_multiple_of(2) {
            let (family, warm_after) = run_ensure_family(
                iteration,
                &mut warm_ensure,
                &mut cold_ensure,
                &context,
                [ensure_before, source_shape],
            );
            samples.extend(family);
            ensure_derived_shape = warm_after.difference(source_shape);

            let (pair, after) = run_snapshot_pair(
                &mut maintained_snapshot,
                &mut snapshot_source,
                &context,
                snapshot_before,
            );
            samples.extend(pair);
            snapshot_derived_shape = after.difference(source_shape);
        } else {
            let (pair, after) = run_snapshot_pair(
                &mut maintained_snapshot,
                &mut snapshot_source,
                &context,
                snapshot_before,
            );
            samples.extend(pair);
            snapshot_derived_shape = after.difference(source_shape);

            let (family, warm_after) = run_ensure_family(
                iteration,
                &mut warm_ensure,
                &mut cold_ensure,
                &context,
                [ensure_before, source_shape],
            );
            samples.extend(family);
            ensure_derived_shape = warm_after.difference(source_shape);
        }
    }
    samples
}

#[derive(Default)]
struct Aggregate {
    elapsed_ns: Vec<u128>,
    work: Option<StoreShape>,
    diagnostic: Option<Diagnostic>,
    total_rows: u64,
    basis_rows: u64,
    relation: Option<RelationIdentity>,
    cover_members: u64,
}

impl Aggregate {
    fn push(&mut self, sample: Sample) {
        self.elapsed_ns.push(sample.elapsed.as_nanos());
        match self.work {
            None => self.work = Some(sample.work),
            Some(expected) => assert_eq!(expected, sample.work, "store work changed across runs"),
        }
        match self.diagnostic {
            None => self.diagnostic = Some(sample.diagnostic),
            Some(expected) => assert_eq!(
                expected, sample.diagnostic,
                "diagnostic work changed across runs",
            ),
        }
        if self.total_rows == 0 {
            self.total_rows = sample.total_rows;
            self.basis_rows = sample.basis_rows;
            self.relation = Some(sample.relation);
            self.cover_members = sample.cover_members;
        } else {
            assert_eq!(self.total_rows, sample.total_rows);
            assert_eq!(self.basis_rows, sample.basis_rows);
            assert_eq!(self.relation, Some(sample.relation));
            assert_eq!(self.cover_members, sample.cover_members);
        }
    }
}

fn raw_cover(aggregate: &Aggregate) -> CoverIdentity {
    match aggregate.diagnostic.expect("diagnostic observation") {
        Diagnostic::StatelessOperation { cover, .. } => cover,
        Diagnostic::Snapshot(_) => {
            panic!("snapshot arm has no stateless raw-cover observation")
        }
    }
}

fn median(values: &[u128]) -> u128 {
    let mut values = values.to_vec();
    values.sort_unstable();
    let upper = values.len() / 2;
    if values.len().is_multiple_of(2) {
        values[upper - 1] + (values[upper] - values[upper - 1]) / 2
    } else {
        values[upper]
    }
}

fn short_hash(hash: &[u8; 32]) -> String {
    let mut output = String::with_capacity(12);
    for byte in &hash[..6] {
        write!(&mut output, "{byte:02X}").expect("writing to String is infallible");
    }
    output
}

fn parse_usize(args: &[String], index: &mut usize, option: &str) -> usize {
    *index += 1;
    args.get(*index)
        .unwrap_or_else(|| panic!("{option} needs an integer"))
        .parse()
        .unwrap_or_else(|_| panic!("{option} needs an integer"))
}

fn main() {
    let mut commits = 64usize;
    let mut rows_per_commit = 1_024usize;
    let mut warmup = 1usize;
    let mut iterations = 4usize;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--commits" => commits = parse_usize(&args, &mut index, "--commits"),
            "--rows-per-commit" => {
                rows_per_commit = parse_usize(&args, &mut index, "--rows-per-commit")
            }
            "--warmup" => warmup = parse_usize(&args, &mut index, "--warmup"),
            "--iters" => iterations = parse_usize(&args, &mut index, "--iters"),
            "--bench" => {}
            other => panic!("unknown option {other:?}"),
        }
        index += 1;
    }
    assert!(commits > 0, "--commits must be nonzero");
    assert!(rows_per_commit > 0, "--rows-per-commit must be nonzero");
    assert!(iterations > 0, "--iters must be nonzero");

    let checkpoints = geometric_checkpoints(commits);
    let chunks: Vec<_> = (0..commits)
        .map(|commit| make_chunk(commit, rows_per_commit))
        .collect();
    let mut descriptor_store = MemoryRepo::default();
    let collections = register_collections(&mut descriptor_store);
    println!(
        "config   : commits={commits} rows/commit={rows_per_commit} warmup={warmup} iters={iterations} checkpoints={checkpoints:?}"
    );
    println!(
        "timing   : source publication and all diagnostics excluded; median of {iterations} whole runs"
    );
    println!(
        "cold     : derived-evidence cold, not CPU-cache cold; warm/cold order alternates by measured run"
    );

    for iteration in 0..warmup {
        black_box(run_iteration(
            iteration,
            &chunks,
            &checkpoints,
            &collections,
        ));
    }

    let mut aggregates = BTreeMap::<(usize, Arm), Aggregate>::new();
    for iteration in 0..iterations {
        for sample in run_iteration(iteration, &chunks, &checkpoints, &collections) {
            aggregates
                .entry((sample.commits, sample.arm))
                .or_default()
                .push(sample);
        }
    }

    let arms = [
        Arm::EnsureWarm,
        Arm::EnsureCold,
        Arm::EnsureNoop,
        Arm::SnapshotAdvance,
        Arm::SnapshotNoop,
    ];
    println!(
        "\n{:>7} {:>16} {:>11} {:>14} {:>10} {:>8}",
        "commits", "arm", "median-ms", "ns/basis-row", "basis-rows", "cover",
    );
    for &checkpoint in &checkpoints {
        for arm in arms {
            let aggregate = &aggregates[&(checkpoint, arm)];
            let elapsed = median(&aggregate.elapsed_ns);
            println!(
                "{:>7} {:>16} {:>11.3} {:>14.1} {:>10} {:>8}",
                checkpoint,
                arm.label(),
                elapsed as f64 / 1_000_000.0,
                elapsed as f64 / aggregate.basis_rows.max(1) as f64,
                aggregate.basis_rows,
                aggregate.cover_members,
            );
        }
    }

    println!(
        "\nwork columns: +B=blobs, +bytes=blob payload, +D=raw derives, +M=raw merges, +A=accelerated DERIVE/MERGE records; support=changed/reused foundational members for snapshots"
    );
    println!(
        "{:>7} {:>16} {:>4} {:>10} {:>4} {:>4} {:>4} {:>15}",
        "commits", "arm", "+B", "+bytes", "+D", "+M", "+A", "support",
    );
    for &checkpoint in &checkpoints {
        for arm in arms {
            let aggregate = &aggregates[&(checkpoint, arm)];
            let work = aggregate.work.expect("store work");
            let support = match aggregate.diagnostic.expect("diagnostic observation") {
                Diagnostic::StatelessOperation { .. } => "stateless".to_owned(),
                Diagnostic::Snapshot(work) => {
                    format!("{}/{}", work.changed_members, work.reused_members)
                }
            };
            println!(
                "{:>7} {:>16} {:>4} {:>10} {:>4} {:>4} {:>4} {:>15}",
                checkpoint,
                arm.label(),
                work.blobs,
                work.blob_bytes,
                work.raw_derives,
                work.raw_merges,
                work.accelerated_records,
                support,
            );
            assert_eq!(work.commits, 0, "measured operation wrote a COMMIT");
            assert_eq!(
                work.source_merges, 0,
                "measured operation published a source MERGE",
            );
            assert_eq!(work.other_records, 0, "unclassified record write");
        }
    }

    println!("\nidentity : canonical logical EAV equality verified against every source prefix");
    for &checkpoint in &checkpoints {
        let relation = aggregates[&(checkpoint, Arm::EnsureWarm)]
            .relation
            .expect("relation identity");
        for arm in arms {
            assert_eq!(aggregates[&(checkpoint, arm)].relation, Some(relation));
        }
        let ensure_warm = raw_cover(&aggregates[&(checkpoint, Arm::EnsureWarm)]);
        let ensure_cold = raw_cover(&aggregates[&(checkpoint, Arm::EnsureCold)]);
        let snapshot_members = aggregates[&(checkpoint, Arm::SnapshotAdvance)].cover_members;
        println!(
            "  commits={checkpoint:<7} rows={:<9} logical={} ensure-physical={} ({}/{}) snapshot-members={}",
            relation.rows,
            short_hash(&relation.hash),
            if ensure_warm.hash == ensure_cold.hash {
                "same"
            } else {
                "different"
            },
            ensure_warm.members,
            ensure_cold.members,
            snapshot_members,
        );
    }
}
