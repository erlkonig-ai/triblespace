//! End-to-end incremental-query maintenance over a growing source frontier.
//!
//! The two arms maintain the same application result set over source-identical
//! stores. The incremental arm retains an immutable Succinct snapshot; their
//! query strategy differs:
//!
//! - `full` re-runs the complete query and replaces the result set.
//! - `incremental` reads the payloads the target newly stands on from the
//!   source as one delta, runs `pattern_changes!`, and extends the result set.
//!
//! Every timed observation includes Succinct maintenance, target attachment,
//! and application-side `BTreeSet` maintenance. Source publication, fixture
//! construction, and the seed view are outside timing. Each measured run uses
//! fresh independent stores and advances through every fixed-size commit;
//! geometric checkpoints only control which observations are reported.
//! Strong equality checks run outside each timer but between observations, so
//! results describe an invariant-heavy warm trace rather than isolated
//! cache-cold calls.
//!
//! The fixture deliberately projects every query variable and gives every book
//! a unique binding. This makes the two accumulated result sets comparable. It
//! does not assert that `pattern_changes!` generally computes a projected set
//! difference: hidden witnesses and repeated commit support can legitimately
//! re-emit projected tuples.
//!
//! Usage:
//!
//! ```text
//! cargo bench --bench incremental_collection_queries -- \
//!   [--commits 64] [--books-per-commit 256] [--warmup 1] [--iters 4]
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    OrderedUniverse, Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob, UnionArchive,
};
use triblespace::core::collection::{
    AdmissionPolicy, Collection, CollectionPolicy, CollectionSnapshot, CollectionSnapshotExt,
    CollectionStoreExt,
};
use triblespace::core::examples::literature;
use triblespace::core::repo::memoryrepo::MemoryRepoSnapshot;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;

type Entity = Inline<inlineencodings::GenId>;
type Title = Inline<inlineencodings::ShortString>;
type Row = (Entity, Entity, Title);

/// The seed store holds the author and the registered projections; each arm
/// clones it and publishes the book commits itself, one observation at a time,
/// so the source frontier grows under the arm instead of being replayed
/// against a store which already holds everything.
#[derive(Clone)]
struct Fixture {
    store: MemoryRepo,
    signing_key: SigningKey,
    collection: Collection<SimpleArchive>,
    commits: Vec<Fragment>,
    expected_batches: Vec<Vec<Row>>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
}

fn benchmark_name() -> &'static str {
    "incremental-query-benchmark"
}

fn benchmark_key() -> SigningKey {
    SigningKey::from_bytes(&[0x49; 32])
}

fn build_fixture(commits: usize, books_per_commit: usize) -> Fixture {
    let signing_key = benchmark_key();
    let authority = signing_key.verifying_key();
    let name = benchmark_name();
    let policy = CollectionPolicy::new(
        AdmissionPolicy::direct(authority),
        AdmissionPolicy::direct(authority),
    );
    let mut store = MemoryRepo::default();
    let collection = store
        .collection(name, policy.clone())
        .expect("register benchmark collection");

    let author = entity! {
        literature::firstname: "Frank",
        literature::lastname: "Herbert",
    };
    let author_id = author.root().expect("intrinsic author id");
    store
        .commit(collection, &signing_key, author)
        .expect("publish seed author");
    let snapshot = store.snapshot().expect("freeze seed snapshot");
    assert_eq!(
        collection
            .admitted(&snapshot)
            .expect("freeze seed support")
            .len(),
        1
    );

    let mut fragments = Vec::with_capacity(commits);
    let mut expected_batches = Vec::with_capacity(commits);
    for commit in 0..commits {
        let mut fragment = Fragment::empty();
        let mut expected = Vec::with_capacity(books_per_commit);
        for book in 0..books_per_commit {
            let ordinal = commit
                .checked_mul(books_per_commit)
                .and_then(|base| base.checked_add(book))
                .expect("fixture ordinal fits usize");
            let title = format!("Book {ordinal:020}");
            let entity = entity! {
                literature::title: title.as_str(),
                literature::author: &author_id,
            };
            let book_id = entity.root().expect("intrinsic book id");
            expected.push((
                author_id.to_inline(),
                book_id.to_inline(),
                title.as_str().to_inline(),
            ));
            fragment += entity;
        }
        fragments.push(fragment);
        expected_batches.push(expected);
    }

    let raw = store
        .derive::<SuccinctArchiveBlob>(collection, (), policy.clone())
        .expect("register raw Succinct projection");
    let accelerated = store
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(raw, (), policy)
        .expect("register accelerated Succinct projection");
    Fixture {
        store,
        signing_key,
        collection,
        commits: fragments,
        expected_batches,
        raw,
        accelerated,
    }
}

/// Carry both mapping edges to the source's frontier and attach the
/// accelerated target from the snapshot which observes that work.
fn maintain_succinct(
    store: &mut MemoryRepo,
    signing_key: &SigningKey,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
) -> CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob> {
    block_on(store.maintain(raw, signing_key)).expect("maintain raw Succinct cover");
    let snapshot = block_on(store.maintain(accelerated, signing_key))
        .expect("maintain accelerated Succinct cover");
    snapshot
        .collection(accelerated)
        .expect("observe accelerated Succinct cover")
}

fn seed_view(
    fixture: &Fixture,
) -> (
    MemoryRepo,
    CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob>,
) {
    let mut store = fixture.store.clone();
    let seed = maintain_succinct(
        &mut store,
        &fixture.signing_key,
        fixture.raw,
        fixture.accelerated,
    );
    assert_eq!(
        seed.support().expect("resolve seed support").len(),
        1,
        "the seed stands on the author commit alone"
    );
    let seed_view: UnionArchive<OrderedUniverse> = seed.view().expect("materialize seed view");
    assert_eq!(
        seed_view.iter().count(),
        2,
        "seed contains the author facts"
    );
    (store, seed)
}

struct FullState {
    store: MemoryRepo,
    signing_key: SigningKey,
    collection: Collection<SimpleArchive>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    results: BTreeSet<Row>,
}

impl FullState {
    fn seeded(fixture: &Fixture) -> Self {
        let (store, _) = seed_view(fixture);
        Self {
            store,
            signing_key: fixture.signing_key.clone(),
            collection: fixture.collection,
            raw: fixture.raw,
            accelerated: fixture.accelerated,
            results: BTreeSet::new(),
        }
    }

    fn observe(&mut self, commit: &Fragment) -> Step {
        self.store
            .commit(self.collection, &self.signing_key, commit.clone())
            .expect("publish book commit");
        let start = Instant::now();
        let full = maintain_succinct(
            &mut self.store,
            &self.signing_key,
            self.raw,
            self.accelerated,
        );
        let full_view: UnionArchive<OrderedUniverse> =
            full.view().expect("materialize full-query view");
        let mut raw_rows = 0usize;
        let mut next = BTreeSet::new();
        for row in find!(
            (author: Entity, book: Entity, title: Title),
            pattern!(&full_view, [
                { ?author @ literature::firstname: "Frank" },
                { ?book @ literature::author: ?author, literature::title: ?title }
            ])
        ) {
            raw_rows += 1;
            next.insert(row);
        }
        let distinct_rows = next.len();
        self.results = next;
        black_box(self.results.len());
        Step {
            elapsed: start.elapsed(),
            raw_rows,
            distinct_rows,
        }
    }
}

struct IncrementalState {
    store: MemoryRepo,
    signing_key: SigningKey,
    collection: Collection<SimpleArchive>,
    raw: Collection<SuccinctArchiveBlob>,
    accelerated: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    snapshot: CollectionSnapshot<MemoryRepoSnapshot, Rank9AcceleratedSuccinctArchiveBlob>,
    results: BTreeSet<Row>,
}

impl IncrementalState {
    fn seeded(fixture: &Fixture) -> Self {
        let (store, seed) = seed_view(fixture);
        Self {
            store,
            signing_key: fixture.signing_key.clone(),
            collection: fixture.collection,
            raw: fixture.raw,
            accelerated: fixture.accelerated,
            snapshot: seed,
            results: BTreeSet::new(),
        }
    }

    fn observe(&mut self, commit: &Fragment) -> Step {
        self.store
            .commit(self.collection, &self.signing_key, commit.clone())
            .expect("publish book commit");
        let start = Instant::now();
        let next = maintain_succinct(
            &mut self.store,
            &self.signing_key,
            self.raw,
            self.accelerated,
        );
        // The delta is the source payloads added since the previous step,
        // read from the root through the same two snapshots: supports are
        // collection-local, and the Succinct target answers the full side of
        // the query.
        let root_now = next
            .snapshot()
            .collection(self.collection)
            .expect("observe the source now");
        let root_before = self
            .snapshot
            .snapshot()
            .collection(self.collection)
            .expect("observe the source before");
        let changed_support = root_now
            .support()
            .expect("resolve incremental support")
            .additions_since(root_before.support().expect("resolve previous support"))
            .expect("benchmark support grows monotonically");
        assert_eq!(changed_support.len(), 1, "one payload is observed per step");
        let mut changed_view = TribleSet::new();
        for member in changed_support.members() {
            let payload: TribleSet = next
                .snapshot()
                .get(member)
                .expect("read changed source payload");
            changed_view.union(payload);
        }
        let next_view: UnionArchive<OrderedUniverse> =
            next.view().expect("materialize complete incremental view");

        let mut raw_rows = 0usize;
        let mut batch = BTreeSet::new();
        for row in find!(
            (author: Entity, book: Entity, title: Title),
            pattern_changes!(&next_view, &changed_view, [
                { ?author @ literature::firstname: "Frank" },
                { ?book @ literature::author: ?author, literature::title: ?title }
            ])
        ) {
            raw_rows += 1;
            batch.insert(row);
        }
        let distinct_rows = batch.len();
        self.results.extend(batch);
        self.snapshot = next;
        black_box(self.results.len());
        Step {
            elapsed: start.elapsed(),
            raw_rows,
            distinct_rows,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Arm {
    Full,
    Incremental,
}

#[derive(Clone, Copy, Debug)]
struct Step {
    elapsed: Duration,
    raw_rows: usize,
    distinct_rows: usize,
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    arm: Arm,
    commits: usize,
    total_results: usize,
    step: Step,
}

struct Run {
    samples: Vec<Sample>,
    results: BTreeSet<Row>,
}

fn geometric_checkpoints(commits: usize) -> BTreeSet<usize> {
    let mut checkpoints = BTreeSet::new();
    let mut next = 1usize;
    while next < commits {
        checkpoints.insert(next);
        next = next.saturating_mul(2);
    }
    checkpoints.insert(commits);
    checkpoints
}

fn run_full(fixture: &Fixture, checkpoints: &BTreeSet<usize>) -> Run {
    let mut state = FullState::seeded(fixture);
    let mut expected = BTreeSet::new();
    let mut samples = Vec::with_capacity(checkpoints.len());
    for (index, (commit, batch)) in fixture
        .commits
        .iter()
        .zip(&fixture.expected_batches)
        .enumerate()
    {
        expected.extend(batch.iter().cloned());
        let step = state.observe(commit);
        assert_eq!(step.raw_rows, expected.len());
        assert_eq!(step.distinct_rows, expected.len());
        assert_eq!(state.results, expected);
        let commits = index + 1;
        if checkpoints.contains(&commits) {
            samples.push(Sample {
                arm: Arm::Full,
                commits,
                total_results: expected.len(),
                step,
            });
        }
    }
    Run {
        samples,
        results: state.results,
    }
}

fn run_incremental(fixture: &Fixture, checkpoints: &BTreeSet<usize>) -> Run {
    let mut state = IncrementalState::seeded(fixture);
    let mut expected = BTreeSet::new();
    let mut samples = Vec::with_capacity(checkpoints.len());
    for (index, (commit, batch)) in fixture
        .commits
        .iter()
        .zip(&fixture.expected_batches)
        .enumerate()
    {
        expected.extend(batch.iter().cloned());
        let step = state.observe(commit);
        assert_eq!(step.raw_rows, batch.len());
        assert_eq!(step.distinct_rows, batch.len());
        assert_eq!(state.results, expected);
        let commits = index + 1;
        // The seed author plus every commit so far: the retained snapshot
        // stands on the whole source frontier.
        assert_eq!(
            state.snapshot.support().expect("resolve support").len(),
            commits + 1
        );
        if checkpoints.contains(&commits) {
            samples.push(Sample {
                arm: Arm::Incremental,
                commits,
                total_results: expected.len(),
                step,
            });
        }
    }
    Run {
        samples,
        results: state.results,
    }
}

#[derive(Default)]
struct Aggregate {
    elapsed_ns: Vec<u128>,
    raw_rows: Option<usize>,
    distinct_rows: Option<usize>,
    total_results: Option<usize>,
}

impl Aggregate {
    fn push(&mut self, sample: Sample) {
        self.elapsed_ns.push(sample.step.elapsed.as_nanos());
        assert_eq_or_init(&mut self.raw_rows, sample.step.raw_rows);
        assert_eq_or_init(&mut self.distinct_rows, sample.step.distinct_rows);
        assert_eq_or_init(&mut self.total_results, sample.total_results);
    }
}

fn assert_eq_or_init(slot: &mut Option<usize>, value: usize) {
    match slot {
        Some(expected) => assert_eq!(*expected, value),
        None => *slot = Some(value),
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

fn parse_usize(args: &[String], index: &mut usize, option: &str) -> usize {
    *index += 1;
    args.get(*index)
        .unwrap_or_else(|| panic!("{option} needs an integer"))
        .parse()
        .unwrap_or_else(|_| panic!("{option} needs an integer"))
}

fn main() {
    let mut commits = 64usize;
    let mut books_per_commit = 256usize;
    let mut warmup = 1usize;
    let mut iterations = 4usize;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--commits" => commits = parse_usize(&args, &mut index, "--commits"),
            "--books-per-commit" => {
                books_per_commit = parse_usize(&args, &mut index, "--books-per-commit")
            }
            "--warmup" => warmup = parse_usize(&args, &mut index, "--warmup"),
            "--iters" => iterations = parse_usize(&args, &mut index, "--iters"),
            "--bench" => {}
            other => panic!("unknown option {other:?}"),
        }
        index += 1;
    }
    assert!(commits > 0, "--commits must be nonzero");
    assert!(books_per_commit > 0, "--books-per-commit must be nonzero");
    assert!(iterations > 0, "--iters must be nonzero");

    let fixture = build_fixture(commits, books_per_commit);
    let checkpoints = geometric_checkpoints(commits);
    let mut aggregates = BTreeMap::<(usize, Arm), Aggregate>::new();
    for iteration in 0..warmup + iterations {
        let (full, incremental) = if iteration.is_multiple_of(2) {
            (
                run_full(&fixture, &checkpoints),
                run_incremental(&fixture, &checkpoints),
            )
        } else {
            let incremental = run_incremental(&fixture, &checkpoints);
            let full = run_full(&fixture, &checkpoints);
            (full, incremental)
        };
        assert_eq!(full.results, incremental.results);
        if iteration >= warmup {
            for sample in full.samples.into_iter().chain(incremental.samples) {
                aggregates
                    .entry((sample.commits, sample.arm))
                    .or_default()
                    .push(sample);
            }
        }
    }

    println!("incremental collection-query maintenance");
    println!("  commits              : {commits}");
    println!("  books per commit     : {books_per_commit}");
    println!("  discarded warm runs : {warmup}");
    println!("  measured whole runs  : {iterations}");
    println!(
        "\n{:>7} {:>9} {:>12} {:>12} {:>9} {:>12} {:>12}",
        "commits", "results", "full-ms", "incr-ms", "speedup", "full-rows", "delta-rows"
    );
    for checkpoint in checkpoints {
        let full = &aggregates[&(checkpoint, Arm::Full)];
        let incremental = &aggregates[&(checkpoint, Arm::Incremental)];
        let full_ns = median(&full.elapsed_ns);
        let incremental_ns = median(&incremental.elapsed_ns);
        println!(
            "{:>7} {:>9} {:>12.3} {:>12.3} {:>8.2}x {:>12} {:>12}",
            checkpoint,
            full.total_results.expect("full result count"),
            full_ns as f64 / 1_000_000.0,
            incremental_ns as f64 / 1_000_000.0,
            full_ns as f64 / incremental_ns.max(1) as f64,
            full.raw_rows.expect("full raw rows"),
            incremental.raw_rows.expect("incremental raw rows"),
        );
    }
    println!(
        "\nEach row is median latency for one commit observation; both arms include Succinct maintenance, target attachment, and application BTreeSet maintenance."
    );
}
