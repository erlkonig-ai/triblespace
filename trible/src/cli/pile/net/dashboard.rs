//! Read-only colony dashboard. One sampler owns the pile; renderers only see
//! its latest observation. No network host, producer, or inventory scan starts
//! here. Retained collection observations avoid rebuilding unchanged covers.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::collection::{
    AdmissionPolicy, Collection, CollectionHandle, CollectionPolicy, CollectionSnapshot,
    CollectionSnapshotExt, CollectionStoreExt, TryFromCoverError,
};
use triblespace_core::repo::memoryrepo::MemoryRepo;
use triblespace_core::repo::pile::{Pile, PileSnapshot};
use triblespace_core::repo::SnapshotSource;
use triblespace_core::trible::TribleSet;
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::descriptor;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::inline::Inline;
use triblespace_net::dashboard::{self, CountMetric, Freshness, ObserverReport};
use triblespace_net::health_record;
use triblespace_net::telemetry::{self, Metric, WorkerReport};

#[cfg(feature = "dashboard-gui")]
mod gui;

#[derive(Clone)]
pub(super) struct Options {
    pub pile: PathBuf,
    pub key: Option<PathBuf>,
    pub telemetry: Vec<CollectionHandle>,
    pub max_age: Duration,
    pub interval: Duration,
    pub once: bool,
    pub gui: bool,
    pub lattice: bool,
}

pub(super) fn run(mut options: Options) -> Result<()> {
    if options.interval.is_zero() {
        bail!("dashboard observation interval must be positive");
    }
    if options.gui {
        #[cfg(feature = "dashboard-gui")]
        return gui::run(options);
        #[cfg(not(feature = "dashboard-gui"))]
        bail!("this trible was built without the dashboard-gui feature");
    }
    let live = io::stdout().is_terminal() && !options.once;
    options.once = !live;
    run_terminal(options, live)
}

// Storage error text (and its source chain) can contain a full bearer H. Drop
// it at the reader boundary, before a frame, sampler result, or renderer can
// retain it. Control stripping and truncation are not capability redaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadFailure {
    PileMissing,
    PileNotARegularFile,
    PileUnreadable,
    OpenPile,
    RefreshPile,
    ClosePile,
    OpenCollection,
    ObserveCollection,
    MemberUnavailable,
    InvalidFacts,
    HealthDescriptor,
    SamplerPanicked,
}

impl ReadFailure {
    fn message(self) -> &'static str {
        match self {
            Self::PileMissing => {
                "no pile at the given path -- pass the ABSOLUTE path to the pile file, since a \
                 relative one resolves against the current directory"
            }
            Self::PileNotARegularFile => "the given path exists but is not a regular file",
            Self::PileUnreadable => "the pile path cannot be read (permissions?)",
            Self::OpenPile => "cannot open existing regular dashboard pile",
            Self::RefreshPile => "cannot refresh dashboard pile",
            Self::ClosePile => "cannot close dashboard pile",
            Self::OpenCollection => "collection descriptor unavailable or invalid",
            Self::ObserveCollection => "collection observation unavailable",
            Self::MemberUnavailable => "selected member unavailable",
            Self::InvalidFacts => "selected member cannot form a fact view",
            Self::HealthDescriptor => "cannot prepare health descriptor",
            Self::SamplerPanicked => "dashboard sampler panicked",
        }
    }
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ReadFailure {}

impl<GetError, ViewError> From<TryFromCoverError<GetError, ViewError>> for ReadFailure {
    fn from(error: TryFromCoverError<GetError, ViewError>) -> Self {
        match error {
            TryFromCoverError::MemberGet { .. } => Self::MemberUnavailable,
            TryFromCoverError::View(_) => Self::InvalidFacts,
            TryFromCoverError::DescriptorGet { .. }
            | TryFromCoverError::InvalidDescriptor { .. } => Self::OpenCollection,
        }
    }
}

type ReadResult<T> = std::result::Result<T, ReadFailure>;

struct SelectedSource {
    handle: CollectionHandle,
    observed: Option<(CollectionSnapshot<PileSnapshot, SimpleArchive>, TribleSet)>,
}

impl SelectedSource {
    fn new(handle: CollectionHandle) -> Self {
        Self {
            handle,
            observed: None,
        }
    }

    fn is_current(&self, snapshot: &PileSnapshot) -> bool {
        self.observed
            .as_ref()
            .is_some_and(|(observed, _)| observed.is_current(snapshot))
    }

    fn facts(&mut self, snapshot: &PileSnapshot) -> ReadResult<&TribleSet> {
        if !self.is_current(snapshot) {
            let collection = Collection::<SimpleArchive>::open(snapshot, self.handle)
                .map_err(|_| ReadFailure::OpenCollection)?;
            let observed = snapshot
                .collection(collection)
                .map_err(|_| ReadFailure::ObserveCollection)?;
            let facts = observed.view::<TribleSet>().map_err(ReadFailure::from)?;
            self.observed = Some((observed, facts));
        }
        Ok(&self.observed.as_ref().expect("observation installed").1)
    }
}

struct Reader {
    pile: Pile,
    sources: Vec<SelectedSource>,
    health: Option<SelectedSource>,
    setup_warnings: Vec<String>,
    max_age: Duration,
    lattice: bool,
    /// Collection whose members the next sample should project, if any.
    focus: Option<[u8; 32]>,
    // Only the final display projection, not a mutable report catalogue. Its
    // application time is independent of the store's scoped dependencies.
    retained: Option<(i128, Frame)>,
    #[cfg(test)]
    projection_runs: usize,
}

impl Reader {
    fn open(options: &Options) -> ReadResult<Self> {
        // Say WHICH of the three this is. The path is deliberately not named:
        // a pile filename can itself be a hex capability handle, which is what
        // `reader_open_failure_does_not_retain_a_sensitive_path` guards. An
        // `io::ErrorKind` is a closed enum and carries no storage error text.
        match std::fs::metadata(&options.pile) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ReadFailure::PileMissing);
            }
            Err(_) => return Err(ReadFailure::PileUnreadable),
            Ok(metadata) if !metadata.is_file() => {
                return Err(ReadFailure::PileNotARegularFile);
            }
            Ok(_) => {}
        }
        let mut setup_warnings = Vec::new();
        let health = match super::load_existing_key(options.key.clone(), &options.pile) {
            Ok(signer) => {
                let authority = signer.verifying_key();
                let mut descriptors = MemoryRepo::default();
                let collection: Collection<SimpleArchive> = descriptors
                    .collection(
                        health_record::COLLECTION_NAME,
                        CollectionPolicy::new(
                            AdmissionPolicy::direct(authority),
                            AdmissionPolicy::direct(authority),
                        ),
                    )
                    .map_err(|_| ReadFailure::HealthDescriptor)?;
                Some(SelectedSource::new(collection.handle()))
            }
            Err(_) => {
                setup_warnings.push("Health fallback unavailable: cannot read signing key".into());
                None
            }
        };
        let mut handles = options.telemetry.clone();
        handles.sort_unstable_by_key(|handle| handle.raw);
        handles.dedup();
        let sources = handles.into_iter().map(SelectedSource::new).collect();
        let pile =
            crate::cli::pile::open_refreshed(&options.pile).map_err(|_| ReadFailure::OpenPile)?;
        Ok(Self {
            pile,
            sources,
            health,
            setup_warnings,
            max_age: options.max_age,
            lattice: options.lattice,
            focus: None,
            retained: None,
            #[cfg(test)]
            projection_runs: 0,
        })
    }

    fn sample(&mut self) -> ReadResult<Frame> {
        self.sample_with_clock(|| {
            triblespace_core::clock::epoch_now()
                .to_tai_duration()
                .total_nanoseconds()
        })
    }

    #[cfg(test)]
    fn sample_at(&mut self, now_ns: i128) -> ReadResult<Frame> {
        self.sample_with_clock(|| now_ns)
    }

    fn sample_with_clock(&mut self, clock: impl FnOnce() -> i128) -> ReadResult<Frame> {
        let started = Instant::now();
        let snapshot = self.pile.snapshot().map_err(|_| {
            self.retained = None;
            ReadFailure::RefreshPile
        })?;
        // Retain the original application boundary: a blocking snapshot must
        // finish before we decide whether the producer samples are fresh.
        let now_ns = clock();
        if let Some((origin_ns, retained)) = &self.retained {
            if self.focus.is_none()
                && retained.can_age_from(*origin_ns, now_ns)
                && self
                    .sources
                    .iter()
                    .all(|source| source.is_current(&snapshot))
                && self
                    .health
                    .as_ref()
                    .is_none_or(|source| source.is_current(&snapshot))
            {
                let mut frame = retained.at(now_ns);
                frame.sampled = Instant::now();
                frame.observation_time = started.elapsed();
                return Ok(frame);
            }
        }
        // Partial/error observations must retry. Never let an older successful
        // frame conceal unavailable evidence or recovery of a selected source.
        self.retained = None;
        #[cfg(test)]
        {
            self.projection_runs += 1;
        }
        let mut facts = TribleSet::new();
        let mut warnings = self.setup_warnings.clone();
        let mut readable_sources = 0;
        for source in &mut self.sources {
            match source.facts(&snapshot) {
                Ok(selected) => {
                    facts += selected.clone();
                    readable_sources += 1;
                }
                Err(error) => warnings.push(format!(
                    "Telemetry {} unreadable: {}",
                    short(&source.handle.raw),
                    error
                )),
            }
        }
        let workers = telemetry::observe(&facts, now_ns, self.max_age);
        let mut health_readable = true;
        let health = match self.health.as_mut() {
            Some(source) => match source.facts(&snapshot) {
                Ok(facts) => dashboard::observe_health(facts, now_ns, self.max_age),
                Err(error) => {
                    health_readable = false;
                    warnings.push(format!("Health reports unreadable: {error}"));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        // Sampled from the same frozen snapshot as the telemetry above, so
        // the lattice and the worker backlog describe the same instant.
        let lattice = match self.lattice {
            true => match observe_lattice(
                &snapshot,
                // Handles the dashboard knows without a record scan: what the
                // operator selected, and what the observers are complaining
                // about. On a live pile these are usually the only evidence
                // that an unstarted derivation exists at all.
                self.sources
                    .iter()
                    .map(|source| source.handle.raw)
                    .chain(health.iter().flat_map(|observer| {
                        observer
                            .conditions
                            .iter()
                            .flat_map(|condition| condition.collections.iter().copied())
                    }))
                    .collect::<Vec<_>>(),
            ) {
                Ok(lattice) => Some(lattice),
                Err(error) => {
                    warnings.push(format!("Collection lattice unreadable: {error}"));
                    None
                }
            },
            false => None,
        };
        // An indexed per-collection lookup, so this costs the selected
        // collection's own records rather than the store's.
        let members = match (self.lattice, self.focus) {
            (true, Some(collection)) => match observe_members(&snapshot, collection, MEMBER_LIMIT) {
                Ok(members) => Some(members),
                Err(error) => {
                    warnings.push(format!("Collection members unreadable: {error}"));
                    None
                }
            },
            _ => None,
        };
        let frame = Frame {
            workers,
            health,
            lattice,
            members,
            warnings,
            sampled: Instant::now(),
            observation_time: started.elapsed(),
            readable_sources,
            selected_sources: self.sources.len(),
            max_age: self.max_age,
        };
        // The retention test only proves the *selected* telemetry sources are
        // unchanged. The lattice depends on every stored record and every
        // resident blob, so a retained frame could show a stale lattice beside
        // fresh backlog. Rather than widen the test, do not retain at all when
        // the lattice was asked for: the caller already accepted the cost.
        if readable_sources == self.sources.len()
            && health_readable
            && !self.lattice
            && self.focus.is_none()
        {
            self.retained = Some((now_ns, frame.clone()));
        }
        Ok(frame)
    }

    fn close(self) -> ReadResult<()> {
        // Release retained snapshots before the owning pile's true close boundary.
        let Self {
            pile,
            sources,
            health,
            ..
        } = self;
        drop(sources);
        drop(health);
        pile.close().map_err(|_| ReadFailure::ClosePile)
    }
}

/// One collection as a single frozen observation sees it.
///
/// A flat display row, computed once per observation and dropped with the
/// frame. It is deliberately not a catalogue anything later queries: the
/// answers below are read back out of the store's own projections every time.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LatticeCollection {
    /// Descriptor handle. This, not the entity inside the archive, is the
    /// collection's identity.
    handle: [u8; 32],
    /// The name a root descriptor carries, when its bytes are here.
    name: Option<String>,
    /// The collection this one derives from. `None` is what being a root
    /// means; it is not a failure to read one.
    source: Option<[u8; 32]>,
    /// Whether this collection's descriptor archive is resident and decodable
    /// in this observation.
    descriptor_resident: bool,
    /// Signed records naming this collection, by kind.
    commits: u64,
    merges: u64,
    derives: u64,
    /// Records naming it whose member, join result or mapping output blob is
    /// actually here. The shortfall against the three counts above is the
    /// concrete "what is missing": endorsed work whose bytes this store does
    /// not hold.
    result_resident: u64,
    /// Attestations of this collection that no capability proof admits yet.
    ///
    /// A different absence from `result_resident`, and the reason it is worth
    /// its own field: missing bytes arrive on their own once replication
    /// catches up, while an unadmitted signer waits on a grant somebody has to
    /// issue. One is weather, the other is work, and a view that showed only
    /// the first would report a collection as merely behind when it is
    /// actually blocked on a person.
    unadmitted: u64,
}

impl LatticeCollection {
    fn stored(&self) -> u64 {
        self.commits
            .saturating_add(self.merges)
            .saturating_add(self.derives)
    }
}

/// Project the collection lattice from one frozen observation.
///
/// Two independent facts are needed, and they live in two different places,
/// which is why this is not one query. `inspect_local` already counts the
/// signed records naming each collection and how many of their result blobs
/// are resident — that is *what is here and what is missing*. It never reads a
/// descriptor, so it cannot say which collection derives from which; that
/// ordering lives in the descriptor archive and is read with the library's own
/// `descriptor::*` queries, the same ones resolution and retention use.
/// Reusing both rather than re-deriving either is what keeps this a view and
/// not a second inventory of the store.
///
/// The walk closes over handles that no record names. A derivation's source
/// can have no records here at all, and a chain that stopped at the first
/// non-resident link would answer "where did this come from" with silence
/// instead of with the hole that is actually there.
///
/// `seeds` exist because records are not the only evidence a collection is
/// real, and relying on them alone hides exactly the case worth seeing: a
/// derived collection that was registered and never once maintained has no
/// records at all, so a record-seeded walk would omit the empty derivation
/// rather than draw it. The dashboard already holds handles that did not come
/// from a record scan — the operator's selected telemetry collections, and the
/// collections named inside health conditions — and seeding with those is what
/// makes an unstarted derivation appear as the hole it is.
///
/// Every descriptor read that fails is a skip, never an error: the store is an
/// open world, and a collection whose bytes are elsewhere is ordinary, not
/// corrupt.
///
/// Cost, measured end to end on self.pile — 6.1 GB, 423562 stored records over
/// 275 collections — with a debug build on this aarch64 box: **37 s for one
/// whole observation**, snapshot and all. That is the figure that matters,
/// because it is what the sampler actually spends per sample. A first cold
/// open of the same pile took ~925 s in `snapshot()` alone, so the 37 s is a
/// warm-cache steady state and a first sample after boot will be far worse.
/// Either way it is seconds to minutes where the rest of a sample is
/// milliseconds, which is why it is behind a flag rather than always on.
fn observe_lattice<R: triblespace_core::repo::StoreRead>(
    snapshot: &R,
    seeds: impl IntoIterator<Item = [u8; 32]>,
) -> ReadResult<Vec<LatticeCollection>> {
    // No blob samples are retained: this view never shows individual blobs,
    // and asking for none keeps the report to the counts actually rendered.
    let local = dashboard::inspect_local(snapshot, 0).map_err(|_| ReadFailure::RefreshPile)?;
    let evidence: std::collections::BTreeMap<[u8; 32], _> = local
        .collections
        .iter()
        .map(|collection| (collection.collection, collection))
        .collect();

    let mut pending: Vec<[u8; 32]> = evidence.keys().copied().chain(seeds).collect();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    while let Some(raw) = pending.pop() {
        if !seen.insert(raw) {
            continue;
        }
        let handle = CollectionHandle::new(raw);
        let facts: Option<TribleSet> = snapshot.get(handle).ok();
        let source = facts
            .as_ref()
            .and_then(|facts| descriptor::source(facts).ok().flatten())
            .map(|source| source.raw);
        let name = facts.as_ref().and_then(|facts| {
            let named = descriptor::name(facts).ok().flatten()?;
            let blob: Blob<UTF8String> = snapshot.get(named).ok()?;
            std::str::from_utf8(&blob.bytes).ok().map(str::to_owned)
        });
        if let Some(source) = source {
            pending.push(source);
        }
        let (commits, merges, derives, result_resident) = match evidence.get(&raw) {
            Some(found) => (
                found.commits.stored,
                found.merges.stored,
                found.derives.stored,
                found
                    .commits
                    .result_resident
                    .saturating_add(found.merges.result_resident)
                    .saturating_add(found.derives.result_resident),
            ),
            None => (0, 0, 0, 0),
        };
        out.push(LatticeCollection {
            handle: raw,
            name,
            source,
            descriptor_resident: facts.is_some(),
            commits,
            merges,
            derives,
            result_resident,
            // Filled below: admission is a question about the whole lattice at
            // once, not about one collection as it is discovered.
            unadmitted: 0,
        });
    }

    // Admission, asked ONCE for the whole lattice.
    //
    // The index decides only the lineages it is asked about, and a collection
    // it has never been asked about holds no parked rows at all -- so asking
    // per-collection as they were discovered would report zero unadmitted for
    // exactly the collections nobody has looked at, which reads as "clean" and
    // is the opposite of the truth. Settling every collection in the lattice as
    // one lineage first is what makes a zero here mean zero.
    let lineage: BTreeSet<CollectionHandle> = out
        .iter()
        .map(|collection| CollectionHandle::new(collection.handle))
        .collect();
    let coverage = snapshot
        .index(&lineage)
        .map_err(|_| ReadFailure::RefreshPile)?;
    for collection in &mut out {
        collection.unadmitted =
            coverage.unadmitted_in(CollectionHandle::new(collection.handle)) as u64;
    }

    // A stable order: named collections alphabetically, then the rest by
    // handle. The drawing places nodes by rank and then by this order, so a
    // fixed order is what stops the picture jumping between observations.
    out.sort_by(|left, right| {
        (left.name.is_none(), &left.name, left.handle)
            .cmp(&(right.name.is_none(), &right.name, right.handle))
    });
    Ok(out)
}

/// A node's label: the host its own daemons declare, beside the short handle.
///
/// The handle alone is unreadable, and a name alone is ambiguous: mid-cutover
/// one host appears TWICE, once under its signing key and once under its old
/// transport endpoint, and both sets of daemons call themselves `sky`. Showing
/// both is what lets a reader see that those two marks are one machine without
/// having to be told.
///
/// The name is not looked up anywhere. A worker report carries the name its own
/// daemon chose -- `sky-sync`, `mac-maintenance` -- so the host is the part
/// before the first `-`. Nothing is invented when that evidence is absent or
/// disagrees: a peer named only inside somebody else's condition has no daemon
/// here to name it, and it keeps the bare handle rather than borrowing a name
/// from a neighbour.
fn node_label(frame: &Frame, node: &[u8; 32]) -> String {
    let mut host: Option<&str> = None;
    for worker in frame.workers.iter().filter(|worker| worker.node == *node) {
        // Only read the convention where it is visibly followed. `sky-sync`
        // names a host and a role; a bare `maintainer` names only a role, and
        // taking its whole name as a host would invent one.
        let Some((declared, _)) = worker.worker.split_once('-') else {
            continue;
        };
        if declared.is_empty() {
            continue;
        }
        match host {
            None => host = Some(declared),
            // Two daemons on one node disagreeing about which host they are on
            // is not something to average. Fall back to the handle.
            Some(seen) if seen != declared => return short(node),
            Some(_) => {}
        }
    }
    match host {
        Some(host) => format!("{host} · {}", short(node)),
        None => short(node),
    }
}

/// Members above which the join lattice is reported but not drawn.
///
/// A truncated graph is a false picture rather than a partial one: dropping
/// nodes silently deletes the joins that ran through them, so what is left
/// reads as a collection with fewer merges than it has. Past this size the
/// view states the count and draws nothing.
const MEMBER_LIMIT: usize = 240;

/// One member of a collection, as this observation sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Member {
    /// The payload handle. Members are named by content, not by an entity.
    handle: [u8; 32],
    /// A `COMMIT` here names this handle as data. That is a positive fact; its
    /// absence is not the opposite fact, only the lack of one.
    committed: bool,
    /// The member's bytes are here.
    resident: bool,
    /// A record *in this collection* produced it: a `MERGE` result or a
    /// `DERIVE` output.
    ///
    /// `false` with `committed` also false is a member reached only as
    /// somebody else's join input — real, resident, and made by a record this
    /// observation cannot see. It was already counted here and printed as a
    /// number beside the picture, which is the one absence in the whole view a
    /// reader could not point at. It is now carried per member so the mark can
    /// carry it too.
    produced: bool,
    /// Whether an admitted record put it here.
    ///
    /// The three flags above come from the record scan, which does not consult
    /// the admission oracle at all: a `COMMIT` nobody is allowed to write sets
    /// `committed` exactly as an admitted one does. So a member waiting on a
    /// grant was indistinguishable from a folded-in one, which is the absence
    /// this field exists to name.
    admission: Admission,
}

/// Whether the record that put a member here is one the store admits.
///
/// Admitted wins over waiting, and the core already says so: an unadmitted
/// route contributes nothing to a node an admitted route reached. A member
/// somebody is allowed to write and somebody else is not is not half-waiting;
/// it is here, by the route that was allowed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Admission {
    /// An admitted record attested it.
    Admitted,
    /// A record attests it and no capability proof admits that record's signer
    /// yet. Waiting on a grant somebody must issue.
    Unadmitted,
    /// Neither. Either nothing here produced it — it was reached as somebody
    /// else's join input — or its lineage has not replicated, which is waiting
    /// on bytes rather than on a grant and belongs to nobody in particular.
    #[default]
    Unknown,
}

/// The join lattice *inside* one collection.
///
/// The panel above draws the order *between* collections. This is the order
/// *within* one, and it is the merge chain: `MERGE(C, low, high, result)`
/// states `low ⊔ high = result` under C's join law, so its two inputs are
/// literally the two edges below a join. Nothing is summarised — the edges are
/// the equations.
#[derive(Clone, Debug, Eq, PartialEq)]
struct MemberLattice {
    /// The collection these members belong to.
    collection: [u8; 32],
    members: Vec<Member>,
    /// `(from, to)` indices into `members`: an input of a join, and its result.
    joins: Vec<(usize, usize)>,
    /// Members this collection's records reach that no record here produces —
    /// a join input whose own commit or merge lives somewhere else.
    unproduced: usize,
    /// The lattice was too large to draw honestly, so it was not built.
    /// A truncated graph is a false picture, not a partial one.
    too_large: Option<usize>,
}

/// Project one collection's member lattice from a frozen observation.
///
/// This is an indexed lookup, not another walk: a pile keys its records by
/// collection, so asking for one collection's records costs its own records
/// rather than the store's. That is why this is safe to do per selection while
/// the collection-level pass is not safe to do per frame.
///
/// A `DERIVE` naming this collection contributes only its output. Its input is
/// a member of the *source* collection and has no place in this order; drawing
/// it here would put two different collections' members in one lattice.
fn observe_members<R: triblespace_core::repo::StoreRead>(
    snapshot: &R,
    collection: [u8; 32],
    limit: usize,
) -> ReadResult<MemberLattice> {
    use triblespace_core::collection::records::{CollectionData, CollectionRecord};
    use triblespace_core::collection::CollectionRecordSelector;

    let selectors = BTreeSet::from([CollectionRecordSelector::Collection(
        CollectionHandle::new(collection),
    )]);
    let records = snapshot
        .select_records(&selectors)
        .map_err(|_| ReadFailure::RefreshPile)?;

    let mut committed = BTreeSet::new();
    let mut produced = BTreeSet::new();
    let mut raw_joins = Vec::new();
    let mut handles = BTreeSet::new();
    for record in records {
        match record {
            CollectionRecord::Commit(commit) => {
                let data = commit.data().raw;
                committed.insert(data);
                handles.insert(data);
            }
            CollectionRecord::Merge(merge) => {
                let (low, high) = merge.inputs();
                let result = merge.result().raw;
                produced.insert(result);
                handles.insert(result);
                for input in [low.raw, high.raw] {
                    handles.insert(input);
                    raw_joins.push((input, result));
                }
            }
            CollectionRecord::Derive(derive) => {
                let output = derive.output().raw;
                produced.insert(output);
                handles.insert(output);
            }
        }
    }

    let unproduced = handles
        .iter()
        .filter(|handle| !committed.contains(*handle) && !produced.contains(*handle))
        .count();
    if handles.len() > limit {
        return Ok(MemberLattice {
            collection,
            members: Vec::new(),
            joins: Vec::new(),
            unproduced,
            too_large: Some(handles.len()),
        });
    }

    // Admission is the one fact above the scan cannot see, so it comes from the
    // fold rather than from the records. Settling this one collection is what
    // makes its answers mean anything: an index never asked about a lineage
    // holds no parked rows for it, so a per-collection question asked without
    // settling first reports a clean zero for exactly the collections nobody
    // has looked at. The snapshot memoises the fold, so asking again for a
    // collection the lattice pass already settled costs the clone and nothing
    // else.
    let target = CollectionHandle::new(collection);
    let coverage = snapshot
        .index(&BTreeSet::from([target]))
        .map_err(|_| ReadFailure::RefreshPile)?;
    let waiting = coverage.unadmitted_nodes_in(target);

    let order: Vec<[u8; 32]> = handles.into_iter().collect();
    let members = order
        .iter()
        .map(|handle| Member {
            handle: *handle,
            committed: committed.contains(handle),
            // A storage error and a missing blob are both "not here" for
            // drawing purposes; neither is a reason to refuse the whole view.
            resident: snapshot
                .contains_blob(Inline::<Handle<UnknownBlob>>::new(*handle))
                .unwrap_or(false),
            produced: produced.contains(handle),
            admission: {
                let node = CollectionData::new(*handle);
                if coverage.coverage(target, node).is_some() {
                    Admission::Admitted
                } else if waiting.contains(&node) {
                    Admission::Unadmitted
                } else {
                    Admission::Unknown
                }
            },
        })
        .collect();
    let index = |handle: &[u8; 32]| order.binary_search(handle).ok();
    let mut joins: Vec<(usize, usize)> = raw_joins
        .iter()
        .filter_map(|(from, to)| Some((index(from)?, index(to)?)))
        .filter(|(from, to)| from != to)
        .collect();
    joins.sort_unstable();
    joins.dedup();

    Ok(MemberLattice {
        collection,
        members,
        joins,
        unproduced,
        too_large: None,
    })
}

#[derive(Clone)]
struct Frame {
    workers: Vec<WorkerReport>,
    health: Vec<ObserverReport>,
    /// The member lattice of the collection the viewer selected, when one is
    /// selected. Requested by the renderer and answered on the next sample,
    /// because the sampler owns the store and the renderer owns the pointer.
    members: Option<MemberLattice>,
    /// The collection lattice, when this dashboard was asked for it.
    ///
    /// `None` is not "no collections": it is "not looked at". The renderers
    /// say so, because an empty lattice and an unsampled one look identical
    /// on screen and mean opposite things.
    lattice: Option<Vec<LatticeCollection>>,
    warnings: Vec<String>,
    sampled: Instant,
    observation_time: Duration,
    readable_sources: usize,
    selected_sources: usize,
    max_age: Duration,
}

impl Frame {
    fn can_age_from(&self, origin_ns: i128, now_ns: i128) -> bool {
        // observe() omits rates when evidence is stale/future. Aging can only
        // suppress rates, so a clock before the original observation or a
        // formerly future sample becoming current requires the real query.
        now_ns >= origin_ns
            && !self
                .workers
                .iter()
                .any(|worker| worker.created_ns > origin_ns && worker.created_ns <= now_ns)
    }

    // Sampling may be blocked in local storage. Repainting must keep aging the
    // producer evidence independently, without reopening the pile or inventing
    // a new rate. A fresh reader frame does not make an old producer fresh.
    fn at(&self, now_ns: i128) -> Self {
        let mut frame = self.clone();
        let max_age = i128::try_from(self.max_age.as_nanos()).unwrap_or(i128::MAX);
        let age = |created_ns| {
            now_ns
                .checked_sub(created_ns)
                .filter(|age| *age >= 0)
                .and_then(|age| u64::try_from(age / 1_000_000_000).ok())
        };
        let freshness = |created_ns| {
            if created_ns > now_ns {
                Freshness::Future
            } else if now_ns.saturating_sub(created_ns) < max_age {
                Freshness::Fresh
            } else {
                Freshness::Stale
            }
        };
        for worker in &mut frame.workers {
            worker.freshness = freshness(worker.created_ns);
            worker.age_seconds = age(worker.created_ns);
            let prior_fresh = worker
                .previous_created_ns
                .is_some_and(|at| freshness(at) == Freshness::Fresh);
            if worker.freshness != Freshness::Fresh || !prior_fresh {
                worker.previous_created_ns = None;
                for metric in &mut worker.metrics {
                    metric.per_second = None;
                }
            }
        }
        for observer in &mut frame.health {
            observer.freshness = freshness(observer.created_ns);
            observer.age_seconds = age(observer.created_ns);
        }
        frame
    }

    fn nodes(&self) -> BTreeSet<[u8; 32]> {
        self.workers
            .iter()
            .map(|worker| worker.node)
            .chain(
                self.health
                    .iter()
                    .flat_map(|observer| observer.endpoints.iter().copied()),
            )
            .collect()
    }

    fn coverage(&self) -> String {
        format!(
            "{} observed nodes · {} worker scopes · {}/{} telemetry sources readable",
            self.nodes().len(),
            self.workers
                .iter()
                .map(|worker| worker.subject)
                .collect::<BTreeSet<_>>()
                .len(),
            self.readable_sources,
            self.selected_sources
        )
    }
}

#[derive(Default)]
struct Shared {
    stop: bool,
    finished: bool,
    revision: u64,
    latest: Option<ReadResult<Arc<Frame>>>,
    /// The collection whose member lattice the renderer wants next, and a
    /// counter that changes whenever that choice does. The renderer holds the
    /// pointer and the sampler holds the store, so the selection has to cross
    /// between them; the counter is what lets the sampler tell "asked again"
    /// from "asked for something else" without comparing frames.
    focus: Option<[u8; 32]>,
    focus_revision: u64,
    /// When the pass now running began, or `None` between passes.
    ///
    /// A viewer opening a large pile waits tens of seconds for the first
    /// observation, and without this the only honest thing it could say was
    /// that it had started. The sampler is the only holder that knows a pass
    /// is in flight, so it is the only one that can say so.
    sampling_since: Option<Instant>,
}

type SharedState = Arc<(Mutex<Shared>, Condvar)>;

struct Sampler {
    shared: SharedState,
    worker: Option<JoinHandle<ReadResult<()>>>,
}

impl Sampler {
    fn start(options: Options) -> Result<Self> {
        let shared = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let state = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("colony-dashboard".into())
            .spawn(move || finish_sampling(&state, || sample_until_stopped(&options, &state)))
            .context("start dashboard sampler")?;
        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }

    fn finish(&mut self) -> Result<()> {
        {
            let mut shared = self
                .shared
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            shared.stop = true;
            self.shared.1.notify_all();
        }
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| ReadFailure::SamplerPanicked)?
                .map_err(anyhow::Error::from),
            None => Ok(()),
        }
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("dashboard shutdown: {error}");
        }
    }
}

fn finish_sampling(shared: &SharedState, work: impl FnOnce() -> ReadResult<()>) -> ReadResult<()> {
    // GUI renderers cannot inspect the owning JoinHandle. Publish panics as
    // failures too, including before the first frame, rather than leaving an
    // apparently live "opening" view until the user closes the window.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .unwrap_or(Err(ReadFailure::SamplerPanicked));
    let mut state = shared.0.lock().unwrap_or_else(|error| error.into_inner());
    if let Err(error) = &result {
        state.latest = Some(Err(*error));
        state.revision += 1;
    }
    state.finished = true;
    shared.1.notify_all();
    result
}

fn sample_until_stopped(options: &Options, shared: &SharedState) -> ReadResult<()> {
    let mut reader = Reader::open(options)?;
    let mut once_error = None;
    loop {
        if shared
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stop
        {
            break;
        }
        let (focus, focus_revision) = {
            let state = shared.0.lock().unwrap_or_else(|error| error.into_inner());
            (state.focus, state.focus_revision)
        };
        reader.focus = focus;
        {
            let mut state = shared.0.lock().unwrap_or_else(|error| error.into_inner());
            state.sampling_since = Some(Instant::now());
        }
        let observation = reader.sample().map(Arc::new);
        if options.once {
            once_error = observation.as_ref().err().cloned();
        }
        let mut state = shared.0.lock().unwrap_or_else(|error| error.into_inner());
        state.latest = Some(observation);
        state.sampling_since = None;
        state.revision += 1;
        shared.1.notify_all();
        if options.once || state.stop {
            break;
        }
        // Also stop waiting when the viewer selects a different collection:
        // a member lattice that arrives a whole interval after the click reads
        // as the view being broken rather than merely periodic.
        let waited = shared
            .1
            .wait_timeout_while(state, options.interval, |state| {
                !state.stop && state.focus_revision == focus_revision
            })
            .unwrap_or_else(|error| error.into_inner());
        if waited.0.stop {
            break;
        }
    }
    reader.close()?;
    match once_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn run_terminal(options: Options, live: bool) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let shutdown = crate::cli::util::shutdown_signal()?;
        tokio::pin!(shutdown);
        let mut sampler = Sampler::start(options)?;
        let mut revision = 0;
        let mut last_paint = Instant::now();
        loop {
            let (next, finished, latest) = {
                let shared = sampler
                    .shared
                    .0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                (shared.revision, shared.finished, shared.latest.clone())
            };
            if next != revision || (live && last_paint.elapsed() >= Duration::from_secs(1)) {
                revision = next;
                last_paint = Instant::now();
                let text = match latest {
                    Some(Ok(frame)) => render_terminal(
                        &frame.at(triblespace_core::clock::epoch_now()
                            .to_tai_duration()
                            .total_nanoseconds()),
                    ),
                    Some(Err(error)) => format!("Colony state unknown: {error}\n"),
                    None => String::new(),
                };
                let mut output = io::stdout().lock();
                if live {
                    output.write_all(b"\x1b[2J\x1b[H")?;
                }
                output.write_all(text.as_bytes())?;
                output.flush()?;
            }
            if finished {
                break;
            }
            if sampler.worker.as_ref().is_some_and(JoinHandle::is_finished) {
                // A worker panic must reach join(), not leave a terminal waiting
                // forever for the final publication that never happened.
                break;
            }
            tokio::select! {
                result = &mut shutdown => { result?; break; },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
        sampler.finish()
    })
}

/// Convergence for one node: completed over completed plus pending merges and
/// derives. Backlog is what "behind" means here.
///
/// Reported as a plain percentage with the two counts beside it, deliberately
/// without a drawn bar. This view is read by agents as often as by people, and
/// an ASCII bar costs a reader tokens to decode into the number it already
/// encodes. `None` means the node reported no comparable work at all, which is
/// absence of evidence and must never print as full convergence.
fn node_convergence(frame: &Frame, node: &[u8; 32]) -> Option<(u128, u128)> {
    let mut done = 0u128;
    let mut pending = 0u128;
    for worker in frame.workers.iter().filter(|worker| worker.node == *node) {
        for measured in &worker.metrics {
            let Some(value) = measured.value.value() else {
                continue;
            };
            match measured.metric {
                Metric::CompletedMerges | Metric::CompletedDerives => done += value,
                Metric::PendingMerges | Metric::PendingDerives => pending += value,
                _ => {}
            }
        }
    }
    (done + pending > 0).then_some((done, pending))
}

fn render_terminal(frame: &Frame) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "COLONY · live work observations\n{}", frame.coverage());
    let _ = writeln!(
        out,
        "Reader observation {:.2}s · completed {:.1}s ago",
        frame.observation_time.as_secs_f64(),
        frame.sampled.elapsed().as_secs_f64()
    );
    let _ = writeln!(
        out,
        "Partial coverage: absent/stale reports are not idle. CPU is reported once per process; scopes are not summed.\n"
    );
    for node in frame.nodes() {
        let workers: Vec<_> = frame
            .workers
            .iter()
            .filter(|worker| worker.node == node && worker.role != "link")
            .collect();
        let converged = match node_convergence(frame, &node) {
            Some((done, pending)) => format!(
                " · converged {:.0}% ({done} done / {pending} pending)",
                (done as f64 / (done + pending) as f64) * 100.0
            ),
            None => String::new(),
        };
        let _ = writeln!(
            out,
            "NODE {} · {} observed worker scopes{converged}",
            node_label(frame, &node),
            workers
                .iter()
                .map(|worker| worker.subject)
                .collect::<BTreeSet<_>>()
                .len()
        );
        if workers.is_empty() {
            if frame
                .health
                .iter()
                .any(|observer| observer.endpoints.contains(&node))
            {
                out.push_str("  Health endpoint observed; worker telemetry not observed.\n");
            } else {
                out.push_str("  Link endpoint observed; worker effort not observed.\n");
            }
        }
        for worker in workers {
            let _ = writeln!(
                out,
                "  {} / {} · {} · stage {}",
                clean(&worker.worker, 36),
                clean(&worker.role, 24),
                observation_age(worker),
                labels(&worker.stages)
            );
            let mut effort = Vec::new();
            for (metric, label) in [
                (Metric::Queued, "queued"),
                (Metric::Active, "active"),
                (Metric::Parallelism, "configured concurrency"),
                (Metric::Failed, "failures"),
            ] {
                if has_metric(worker, metric) {
                    effort.push(format!("{label} {}", count(worker, metric)));
                }
            }
            if worker.role == "process" {
                effort.push(format!("CPU {}", cpu(worker)));
            }
            if effort.is_empty() {
                effort.push("activity and effort not observed".into());
            }
            let _ = writeln!(out, "    {}", effort.join(" · "));

            let mut progress = Vec::new();
            for (metric, label, bytes) in [
                (Metric::ReceivedBytes, "receive", true),
                (Metric::SentBytes, "send", true),
                (Metric::Completed, "completed", false),
                (Metric::CompletedMerges, "merge publications", false),
                (Metric::CompletedDerives, "derive publications", false),
            ] {
                if has_metric(worker, metric) {
                    progress.push(format!("{label} {}", rate(worker, metric, bytes)));
                }
            }
            if has_metric(worker, Metric::WorkNs) {
                progress.push(format!("wall work {} (not CPU)", wall_work(worker)));
            }
            if !progress.is_empty() {
                let _ = writeln!(out, "    {}", progress.join(" · "));
            }
            if worker.role == "maintenance"
                || has_metric(worker, Metric::PendingMerges)
                || has_metric(worker, Metric::PendingDerives)
            {
                let _ = writeln!(
                    out,
                    "    pending merges {} · pending derives {}",
                    count(worker, Metric::PendingMerges),
                    count(worker, Metric::PendingDerives)
                );
            }
            if !worker.parallel_compiled.is_empty()
                || !worker.compiled_backends.is_empty()
                || !worker.backends.is_empty()
            {
                let _ = writeln!(
                    out,
                    "    backend {} · compiled {} · parallel path {}",
                    labels(&worker.backends),
                    labels(&worker.compiled_backends),
                    compiled_parallel(worker)
                );
            }
            if !worker.targets.is_empty() {
                let _ = writeln!(out, "    selected targets {}", handles(&worker.targets));
            }
        }
        for observer in frame
            .health
            .iter()
            .filter(|observer| observer.endpoints.contains(&node))
        {
            let _ = writeln!(
                out,
                "  Health: {} · {}s old · {} scoped alerts",
                freshness(observer.freshness),
                observer
                    .age_seconds
                    .map_or_else(|| "?".into(), |age| age.to_string()),
                observer
                    .conditions
                    .iter()
                    .filter(|condition| condition.alert)
                    .count()
            );
            for condition in observer
                .conditions
                .iter()
                .filter(|condition| condition.alert)
                .take(8)
            {
                let _ = writeln!(
                    out,
                    "    {:?}: {:?} · peer {} · collection {}",
                    condition.components,
                    condition.states,
                    handles(&condition.peers),
                    handles(&condition.collections)
                );
            }
        }
        out.push('\n');
    }
    match &frame.lattice {
        None => out.push_str(
            "COLLECTION LATTICE · not sampled. Rerun with --lattice; an unsampled lattice is not an empty one.\n\n",
        ),
        Some(collections) if collections.is_empty() => out.push_str(
            "COLLECTION LATTICE · sampled; this pile references no collections.\n\n",
        ),
        Some(collections) => {
            let derived = collections.iter().filter(|c| c.source.is_some()).count();
            let absent = collections.iter().filter(|c| !c.descriptor_resident).count();
            let _ = writeln!(
                out,
                "COLLECTION LATTICE · {} collections, {derived} derived, {absent} with no resident descriptor",
                collections.len()
            );
            out.push_str(
                "  Resident is result blobs actually here over records naming the collection, per collection.\n",
            );
            // Derived descriptors carry no name of their own, so they sort
            // last; a flat cut then hides every derivation behind the roots,
            // which are the least interesting rows here. Sample both.
            let (derived_rows, root_rows): (Vec<_>, Vec<_>) =
                collections.iter().partition(|c| c.source.is_some());
            for (rows, kind) in [(&root_rows, "root"), (&derived_rows, "derived")] {
                for collection in rows.iter().take(12) {
                    let _ = writeln!(
                        out,
                        "  {} {} · {} commit / {} merge / {} derive · {} of {} results resident{}",
                        if collection.descriptor_resident { "+" } else { "?" },
                        collection
                            .name
                            .clone()
                            .unwrap_or_else(|| short(&collection.handle)),
                        collection.commits,
                        collection.merges,
                        collection.derives,
                        collection.result_resident,
                        collection.stored(),
                        match collection.source {
                            Some(source) => format!(" · derives from {}", short(&source)),
                            None => String::new(),
                        }
                    );
                }
                if rows.len() > 12 {
                    let _ = writeln!(out, "  ... {} more {kind} not listed", rows.len() - 12);
                }
            }
            out.push('\n');
        }
    }
    let links: Vec<_> = frame
        .workers
        .iter()
        .filter(|worker| worker.role == "link" || !worker.peers.is_empty())
        .collect();
    if !links.is_empty() {
        out.push_str("OBSERVED LINKS · payload throughput, not bandwidth capacity\n");
        for link in links {
            let _ = writeln!(
                out,
                "  {} -> {} · {} · {} · RTT {}",
                short(&link.node),
                handles(&link.peers),
                labels(&link.paths),
                observation_age(link),
                rtt(link)
            );
            let _ = writeln!(
                out,
                "    from reporting node: receive {} · send {}",
                rate(link, Metric::ReceivedBytes, true),
                rate(link, Metric::SentBytes, true)
            );
        }
        out.push('\n');
    } else {
        out.push_str("LINKS · path, RTT and per-link throughput not observed.\n");
    }
    if frame.workers.is_empty() {
        out.push_str("Worker effort/backlog/throughput are not observed. Select producer telemetry collections; health alone cannot establish them.\n");
    }
    for warning in &frame.warnings {
        let _ = writeln!(out, "! {warning}");
    }
    out.push_str("Known queues cover their reporting selection only; unknown descendants and unobserved nodes are not counted.\n");
    out
}

fn freshness(value: Freshness) -> &'static str {
    match value {
        Freshness::Fresh => "fresh",
        Freshness::Stale => "STALE (historical)",
        Freshness::Future => "UNKNOWN (future timestamp)",
    }
}

fn observation_age(worker: &WorkerReport) -> String {
    format!(
        "{} / {}s old",
        freshness(worker.freshness),
        worker
            .age_seconds
            .map_or_else(|| "?".into(), |age| age.to_string())
    )
}

fn short(value: &[u8; 32]) -> String {
    hex::encode(&value[..6])
}

fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .take(limit)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn labels(values: &[String]) -> String {
    if values.is_empty() {
        "unknown".into()
    } else {
        values
            .iter()
            .map(|value| clean(value, 40))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn handles(values: &[[u8; 32]]) -> String {
    if values.is_empty() {
        "not observed".into()
    } else {
        values.iter().map(short).collect::<Vec<_>>().join(", ")
    }
}

fn has_metric(worker: &WorkerReport, metric: Metric) -> bool {
    worker
        .metrics
        .iter()
        .any(|value| value.metric == metric && value.value != CountMetric::Absent)
}

fn count(worker: &WorkerReport, metric: Metric) -> String {
    match worker
        .metrics
        .iter()
        .find(|value| value.metric == metric)
        .map(|value| &value.value)
    {
        Some(CountMetric::Value(value)) => value.to_string(),
        Some(CountMetric::Ambiguous(_)) => "multiple values".into(),
        _ => "unknown".into(),
    }
}

fn measured_rate(worker: &WorkerReport, metric: Metric) -> Option<f64> {
    (worker.freshness == Freshness::Fresh).then_some(())?;
    worker
        .metrics
        .iter()
        .find(|value| value.metric == metric)?
        .per_second
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn rate(worker: &WorkerReport, metric: Metric, bytes: bool) -> String {
    measured_rate(worker, metric).map_or_else(
        || "unmeasured".into(),
        |value| {
            if bytes {
                format!("{:.2} MiB/s", value / (1024.0 * 1024.0))
            } else {
                format!("{value:.2}/s")
            }
        },
    )
}

fn cpu(worker: &WorkerReport) -> String {
    measured_rate(worker, Metric::CpuNs).map_or_else(
        || "unmeasured".into(),
        |value| format!("{:.2} effective cores", value / 1e9),
    )
}

fn compiled_parallel(worker: &WorkerReport) -> &'static str {
    match worker.parallel_compiled.as_slice() {
        [true] => "yes",
        [false] => "no",
        [] => "unknown",
        _ => "multiple reports",
    }
}

fn wall_work(worker: &WorkerReport) -> String {
    measured_rate(worker, Metric::WorkNs).map_or_else(
        || "unmeasured".into(),
        |value| format!("{:.2} seconds/second", value / 1e9),
    )
}

fn rtt(worker: &WorkerReport) -> String {
    worker
        .metrics
        .iter()
        .find(|value| value.metric == Metric::RttNs)
        .and_then(|value| value.value.value())
        .map_or_else(
            || "unknown".into(),
            |value| format!("{:.2} ms", value as f64 / 1e6),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use triblespace_core::collection::records::{CollectionDerive, CollectionMerge};
    use triblespace_core::collection::{empty_metadata_handle, CollectionCommit, CollectionRecord};
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::metadata;
    use triblespace_core::prelude::*;
    use triblespace_net::telemetry::MetricValue;

    /// A root collection with one commit, plus a derivation registered over it
    /// that has never been maintained.
    fn lattice_fixture() -> (MemoryRepo, CollectionHandle, CollectionHandle) {
        use triblespace_core::blob::encodings::succinctarchive::SuccinctArchiveBlob;
        let mut store = MemoryRepo::default();
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let source: Collection<SimpleArchive> =
            store.collection("facts", policy.clone()).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        store
            .commit(source, &signer, entity! { metadata::name: "first" })
            .unwrap();
        let target = store
            .derive::<SuccinctArchiveBlob>(source, (), policy)
            .unwrap();
        (store, source.handle(), target.handle())
    }

    #[test]
    fn a_derivation_reports_the_collection_it_reads() {
        // The order itself: without the source link there is no lattice, only
        // a list, and no chain to walk back.
        let (mut store, source, target) = lattice_fixture();
        let snapshot = store.snapshot().unwrap();
        let lattice = observe_lattice(&snapshot, [target.raw]).unwrap();
        let derived = lattice
            .iter()
            .find(|collection| collection.handle == target.raw)
            .expect("the derived collection is projected");
        assert_eq!(derived.source, Some(source.raw));
        let root = lattice
            .iter()
            .find(|collection| collection.handle == source.raw)
            .expect("the source collection is projected");
        assert_eq!(root.source, None, "a root has no source; that is not a failure");
        assert_eq!(root.name.as_deref(), Some("facts"));
        assert_eq!(root.commits, 1);
    }

    #[test]
    fn a_registered_but_unmaintained_derivation_is_still_projected() {
        // This is the case the view exists for. The target has no records at
        // all, so a walk seeded only from stored records would omit it and
        // draw a lattice that looks finished. Seeded, it appears with nothing
        // endorsed, which is what "missing" looks like here.
        let (mut store, _source, target) = lattice_fixture();
        let snapshot = store.snapshot().unwrap();
        let unseeded = observe_lattice(&snapshot, []).unwrap();
        assert!(
            !unseeded.iter().any(|c| c.handle == target.raw),
            "records alone cannot evidence an unstarted derivation"
        );
        let seeded = observe_lattice(&snapshot, [target.raw]).unwrap();
        let derived = seeded
            .iter()
            .find(|collection| collection.handle == target.raw)
            .expect("a seeded handle is projected");
        assert_eq!(derived.stored(), 0, "nothing has been derived yet");
        assert_eq!(derived.derives, 0);
        assert!(derived.descriptor_resident, "its descriptor is right here");
    }

    #[test]
    fn a_source_reached_only_through_a_descriptor_closes_the_chain() {
        // Seeding with the derived target alone must still reach the root, or
        // "where did this come from" has no answer.
        let (mut store, source, target) = lattice_fixture();
        let snapshot = store.snapshot().unwrap();
        let lattice = observe_lattice(&snapshot, [target.raw]).unwrap();
        assert!(lattice.iter().any(|c| c.handle == source.raw));
    }

    #[test]
    fn an_unknown_seed_becomes_a_hole_rather_than_being_dropped() {
        // A collection named by an observer but absent here is exactly what
        // must be drawn, not omitted: omitting it redraws an incomplete
        // lattice as a complete one.
        let (mut store, _source, _target) = lattice_fixture();
        let snapshot = store.snapshot().unwrap();
        let absent = [0x5A_u8; 32];
        let lattice = observe_lattice(&snapshot, [absent]).unwrap();
        let hole = lattice
            .iter()
            .find(|collection| collection.handle == absent)
            .expect("an unreadable collection is still a row");
        assert!(!hole.descriptor_resident);
        assert_eq!(hole.source, None);
        assert_eq!(hole.name, None);
        assert_eq!(hole.stored(), 0);
    }

    #[test]
    fn the_projection_is_ordered_and_free_of_duplicates() {
        // The drawing places nodes by rank and then by this order, so a
        // repeated observation of one snapshot must not move the picture.
        let (mut store, source, target) = lattice_fixture();
        let snapshot = store.snapshot().unwrap();
        let once = observe_lattice(&snapshot, [target.raw, source.raw, target.raw]).unwrap();
        let twice = observe_lattice(&snapshot, [target.raw, source.raw]).unwrap();
        assert_eq!(once, twice, "one snapshot projects one lattice");
        let mut handles: Vec<_> = once.iter().map(|c| c.handle).collect();
        let count = handles.len();
        handles.sort_unstable();
        handles.dedup();
        assert_eq!(handles.len(), count, "each collection appears once");
    }

    /// Two commits joined by one merge whose result bytes are not here.
    fn member_fixture() -> (MemoryRepo, [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        use triblespace_core::collection::CollectionStore;
        let mut store = MemoryRepo::default();
        let policy = CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open);
        let collection: Collection<SimpleArchive> =
            store.collection("members", policy).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
        let first = store
            .commit(collection, &signer, entity! { metadata::name: "a" })
            .unwrap();
        let second = store
            .commit(collection, &signer, entity! { metadata::name: "b" })
            .unwrap();
        // A real join equation. Its result blob is deliberately not stored:
        // an endorsed merge whose bytes were collected is ordinary, and it is
        // exactly the case the drawing must not show as complete.
        let result = Inline::new([0x77; 32]);
        let merge = CollectionMerge::sign(
    &signer,
    collection.handle(),
    first.data(),
    second.data(),
    result,
);
        store.insert(CollectionRecord::Merge(merge)).unwrap();
        (
            store,
            collection.handle().raw,
            first.data().raw,
            second.data().raw,
            result.raw,
        )
    }

    #[test]
    fn a_merge_puts_both_of_its_inputs_under_its_result() {
        // The join equation is the lattice. If the two inputs do not both land
        // below the result, the picture is not of `low join high = result`.
        let (mut store, collection, first, second, result) = member_fixture();
        let snapshot = store.snapshot().unwrap();
        let members = observe_members(&snapshot, collection, MEMBER_LIMIT).unwrap();
        let at = |handle: [u8; 32]| {
            members
                .members
                .iter()
                .position(|member| member.handle == handle)
                .expect("member projected")
        };
        assert_eq!(members.members.len(), 3);
        assert_eq!(
            members.joins,
            {
                let mut expected = vec![(at(first), at(result)), (at(second), at(result))];
                expected.sort_unstable();
                expected
            },
            "both inputs feed the one result"
        );
        assert!(members.members[at(first)].committed);
        assert!(members.members[at(first)].resident);
        assert!(
            !members.members[at(result)].committed,
            "a join result is computed, never authored"
        );
        assert!(
            !members.members[at(result)].resident,
            "its bytes were never stored, and must draw as the hole they are"
        );
        assert_eq!(members.unproduced, 0, "both inputs are commits here");
    }

    #[test]
    fn a_derive_contributes_its_output_and_not_its_input() {
        // A derive's input is a member of the *source* collection. Drawing it
        // in the target's lattice would mix two collections' members into one
        // order, which is not a lattice at all.
        use triblespace_core::collection::CollectionStore;
        let (mut store, _source, target) = lattice_fixture();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let input = Inline::new([0x31; 32]);
        let output = Inline::new([0x32; 32]);
        let commit = CollectionCommit::sign(
            &signer,
            CollectionHandle::new([0x99; 32]),
            input,
            empty_metadata_handle(),
        );
        let derive = CollectionDerive::sign(
    &signer,
    CollectionHandle::new(target.raw),
    input,
    output,
);
        store
            .insert(CollectionRecord::Derive(derive))
            .unwrap();
        let snapshot = store.snapshot().unwrap();
        let members = observe_members(&snapshot, target.raw, MEMBER_LIMIT).unwrap();
        let handles: Vec<[u8; 32]> = members.members.iter().map(|m| m.handle).collect();
        assert!(handles.contains(&output.raw), "the output is a member here");
        assert!(
            !handles.contains(&input.raw),
            "the input belongs to the source collection"
        );
        assert!(members.joins.is_empty(), "a derive is not a join");
    }

    #[test]
    fn an_oversized_member_lattice_is_declined_rather_than_truncated() {
        // Dropping nodes would silently delete the joins that ran through
        // them, so the remainder would read as fewer merges than exist.
        let (mut store, collection, ..) = member_fixture();
        let snapshot = store.snapshot().unwrap();
        let members = observe_members(&snapshot, collection, 2).unwrap();
        assert_eq!(members.too_large, Some(3));
        assert!(members.members.is_empty());
        assert!(members.joins.is_empty());
    }

    #[test]
    fn a_member_waiting_on_a_grant_is_told_apart_from_a_folded_in_one() {
        // The record scan does not consult the admission oracle, so a COMMIT
        // nobody is allowed to write sets `committed` exactly as an admitted
        // one does. Before this the two were one picture, and the reader had
        // no way to ask which members the store had actually folded in.
        use triblespace_core::collection::CollectionStore;
        let mut store = MemoryRepo::default();
        let root = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[22; 32]);
        let collection: Collection<SimpleArchive> = store
            .collection(
                "guarded",
                CollectionPolicy::new(
                    AdmissionPolicy::Open,
                    AdmissionPolicy::direct(root.verifying_key()),
                ),
            )
            .unwrap();

        // Two commits into one collection, identical in every way the scan can
        // see and differing only in who signed them.
        let vouched = Inline::new([0x41; 32]);
        let parked = Inline::new([0x42; 32]);
        for (signer, payload) in [(&root, vouched), (&stranger, parked)] {
            store
                .insert(CollectionRecord::Commit(CollectionCommit::sign(
                    signer,
                    collection.handle(),
                    payload,
                    empty_metadata_handle(),
                )))
                .unwrap();
        }

        let snapshot = store.snapshot().unwrap();
        let members = observe_members(&snapshot, collection.handle().raw, MEMBER_LIMIT).unwrap();
        let at = |handle: [u8; 32]| {
            members
                .members
                .iter()
                .find(|member| member.handle == handle)
                .expect("member projected")
        };

        // Both are members and both are committed -- that is the point.
        assert!(at(vouched.raw).committed && at(parked.raw).committed);
        assert_eq!(at(vouched.raw).admission, Admission::Admitted);
        assert_eq!(
            at(parked.raw).admission,
            Admission::Unadmitted,
            "the one whose signer no proof admits is the one waiting"
        );
    }

    #[test]
    fn a_member_reached_only_as_a_join_input_is_neither_admitted_nor_waiting() {
        // Three answers, not two. A member nothing here produced is not
        // waiting on a grant -- nobody can issue one, because there is no
        // record here to admit -- and drawing it as such would send a reader
        // to ask the wrong person for the wrong thing.
        let (mut store, collection, first, _second, result) = member_fixture();
        let snapshot = store.snapshot().unwrap();
        let members = observe_members(&snapshot, collection, MEMBER_LIMIT).unwrap();
        let at = |handle: [u8; 32]| {
            members
                .members
                .iter()
                .find(|member| member.handle == handle)
                .expect("member projected")
        };
        // The fixture is an open collection, so everything it records is
        // admitted; nothing here is ever Unadmitted.
        assert_eq!(at(first).admission, Admission::Admitted);
        assert_eq!(at(result).admission, Admission::Admitted);
        assert!(members
            .members
            .iter()
            .all(|member| member.admission != Admission::Unadmitted));
    }

    #[test]
    fn a_member_known_only_as_a_join_input_is_counted_not_hidden() {
        use triblespace_core::collection::CollectionStore;
        let (mut store, collection, first, _second, result) = member_fixture();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        // Join the earlier result with a member nothing here produces.
        let orphan = Inline::new([0x44; 32]);
        let commit = CollectionCommit::sign(
            &signer,
            CollectionHandle::new(collection),
            orphan,
            empty_metadata_handle(),
        );
        let merge = CollectionMerge::sign(
    &signer,
    CollectionHandle::new(collection),
    Inline::new(result),
    orphan,
    Inline::new([0x55; 32]),
);
        store.insert(CollectionRecord::Merge(merge)).unwrap();
        let snapshot = store.snapshot().unwrap();
        let members = observe_members(&snapshot, collection, MEMBER_LIMIT).unwrap();
        assert_eq!(
            members.unproduced, 1,
            "the orphan input is reported, not silently dropped"
        );
        assert!(
            members.members.iter().any(|m| m.handle == orphan.raw),
            "and it is still drawn"
        );
        assert!(members.members.iter().any(|m| m.handle == first));
    }

    #[test]
    fn an_unsampled_lattice_is_reported_as_unsampled_not_as_empty() {
        let mut frame = Frame {
            workers: vec![],
            health: vec![],
            lattice: None,
            members: None,
            warnings: vec![],
            sampled: Instant::now(),
            observation_time: Duration::ZERO,
            readable_sources: 0,
            selected_sources: 0,
            max_age: Duration::from_secs(30),
        };
        assert!(render_terminal(&frame).contains("not sampled"));
        frame.lattice = Some(vec![]);
        let rendered = render_terminal(&frame);
        assert!(rendered.contains("references no collections"));
        assert!(!rendered.contains("not sampled"));
    }


    fn worker() -> WorkerReport {
        let id = Id::new([1; 16]).unwrap();
        WorkerReport {
            subject: id,
            node: [1; 32],
            worker: "maintainer".into(),
            role: "maintenance".into(),
            report: id,
            session: id,
            created_ns: 0,
            previous_created_ns: None,
            age_seconds: Some(2),
            freshness: Freshness::Fresh,
            backends: vec!["cpu".into()],
            parallel_compiled: vec![],
            compiled_backends: vec![],
            stages: vec![],
            paths: vec![],
            peers: vec![],
            targets: vec![],
            metrics: vec![],
        }
    }

    /// A node is labelled by the host its own daemons declare, and never by a
    /// name invented from evidence that does not carry one.
    #[test]
    fn a_node_is_named_by_its_daemons_or_not_at_all() {
        let mut frame = Frame {
            workers: vec![],
            health: vec![],
            lattice: None,
            members: None,
            warnings: vec![],
            sampled: Instant::now(),
            observation_time: Duration::ZERO,
            readable_sources: 1,
            selected_sources: 1,
            max_age: Duration::from_secs(30),
        };

        // A role-only worker name carries no host. Inventing one from it would
        // put "maintainer" where a machine belongs.
        let mut role_only = worker();
        role_only.node = [7; 32];
        role_only.worker = "maintainer".into();
        frame.workers = vec![role_only];
        assert_eq!(node_label(&frame, &[7; 32]), short(&[7; 32]));

        // The live convention is host-role, and the handle STAYS: mid-cutover
        // one machine reports under two identities and both sets of daemons
        // call themselves the same host.
        let mut host_role = worker();
        host_role.node = [8; 32];
        host_role.worker = "sky-maintenance".into();
        frame.workers = vec![host_role];
        let labelled = node_label(&frame, &[8; 32]);
        assert!(labelled.starts_with("sky · "), "{labelled}");
        assert!(labelled.ends_with(&short(&[8; 32])), "{labelled}");

        // Two daemons on one node disagreeing is not something to average.
        let mut one = worker();
        one.node = [9; 32];
        one.worker = "sky-sync".into();
        let mut two = worker();
        two.node = [9; 32];
        two.worker = "mac-sync".into();
        frame.workers = vec![one, two];
        assert_eq!(node_label(&frame, &[9; 32]), short(&[9; 32]));

        // A peer named only inside somebody else's condition has no daemon
        // here to name it.
        frame.workers = vec![];
        assert_eq!(node_label(&frame, &[1; 32]), short(&[1; 32]));
    }

    #[test]
    fn missing_stale_and_measured_zero_are_distinct() {
        let mut worker = worker();
        assert_eq!(count(&worker, Metric::Active), "unknown");
        assert_eq!(cpu(&worker), "unmeasured");
        worker.metrics.push(MetricValue {
            metric: Metric::CpuNs,
            value: CountMetric::Value(0),
            per_second: Some(0.0),
        });
        assert_eq!(cpu(&worker), "0.00 effective cores");
        worker.freshness = Freshness::Stale;
        assert_eq!(cpu(&worker), "unmeasured");
        assert!(observation_age(&worker).contains("historical"));
    }

    #[test]
    fn retained_frame_ages_even_when_the_sampler_is_stalled() {
        let mut worker = worker();
        worker.created_ns = 20_000_000_000;
        worker.previous_created_ns = Some(10_000_000_000);
        worker.metrics.push(MetricValue {
            metric: Metric::CpuNs,
            value: CountMetric::Value(30_000_000_000),
            per_second: Some(2e9),
        });
        let frame = Frame {
            workers: vec![worker],
            health: vec![],
            lattice: None,
            members: None,
            warnings: vec![],
            sampled: Instant::now(),
            observation_time: Duration::ZERO,
            readable_sources: 1,
            selected_sources: 1,
            max_age: Duration::from_secs(30),
        };
        assert_eq!(
            cpu(&frame.at(30_000_000_000).workers[0]),
            "2.00 effective cores"
        );
        let old_interval = frame.at(40_000_000_000);
        assert_eq!(old_interval.workers[0].freshness, Freshness::Fresh);
        assert_eq!(old_interval.workers[0].previous_created_ns, None);
        assert_eq!(cpu(&old_interval.workers[0]), "unmeasured");
        let stale = frame.at(50_000_000_000);
        assert_eq!(stale.workers[0].freshness, Freshness::Stale);
        assert_eq!(stale.workers[0].age_seconds, Some(30));
        assert_eq!(cpu(&stale.workers[0]), "unmeasured");
        assert_eq!(
            frame.at(19_000_000_000).workers[0].freshness,
            Freshness::Future
        );
        assert_eq!(cpu(&frame.workers[0]), "2.00 effective cores");
    }

    #[test]
    fn sampler_stop_wakes_an_idle_wait_and_joins() {
        let shared = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let waiting = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            let state = waiting.0.lock().unwrap();
            let state = waiting.1.wait_while(state, |state| !state.stop).unwrap();
            assert!(state.stop);
            Ok(())
        });
        let mut sampler = Sampler {
            shared,
            worker: Some(worker),
        };
        sampler.finish().unwrap();
        assert!(sampler.worker.is_none());
    }

    #[test]
    fn sampler_panic_is_published_before_window_close() {
        let shared = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let state = Arc::clone(&shared);
        let worker =
            thread::spawn(move || finish_sampling(&state, || panic!("injected sampler failure")));
        let result = worker.join().expect("panic is converted to a read failure");
        assert_eq!(
            result.unwrap_err().to_string(),
            "dashboard sampler panicked"
        );
        let state = shared.0.lock().unwrap();
        assert!(state.finished);
        assert_eq!(state.revision, 1);
        assert!(matches!(
            state.latest,
            Some(Err(ReadFailure::SamplerPanicked))
        ));
    }

    #[test]
    fn terminal_text_does_not_accept_control_sequences_from_labels() {
        assert_eq!(clean("bad\x1b[2J\nname", 80), "bad [2J name");
        assert_eq!(clean("long name", 4), "long");
    }

    #[test]
    fn a_health_only_endpoint_is_visible_without_claiming_idle_workers() {
        let id = Id::new([1; 16]).unwrap();
        let frame = Frame {
            workers: vec![],
            health: vec![ObserverReport {
                node: id,
                report: id,
                sessions: vec![id],
                endpoints: vec![[2; 32]],
                created_ns: 0,
                age_seconds: Some(2),
                freshness: Freshness::Fresh,
                conditions: vec![],
            }],
            lattice: None,
            members: None,
            warnings: vec![],
            sampled: Instant::now(),
            observation_time: Duration::ZERO,
            readable_sources: 0,
            selected_sources: 0,
            max_age: Duration::from_secs(30),
        };
        let output = render_terminal(&frame);
        assert!(output.contains("NODE 020202020202"));
        assert!(output.contains("worker telemetry not observed"));
        assert!(!output.contains("active 0"));
    }

    #[test]
    fn completed_wall_work_is_not_labeled_as_cpu() {
        let mut worker = worker();
        worker.metrics.push(MetricValue {
            metric: Metric::WorkNs,
            value: CountMetric::Value(4_000_000_000),
            per_second: Some(2_000_000_000.0),
        });
        assert_eq!(wall_work(&worker), "2.00 seconds/second");
        assert_eq!(cpu(&worker), "unmeasured");
    }

    #[test]
    fn terminal_does_not_promote_stage_cpu_or_absent_link_data() {
        let mut stage = worker();
        stage.metrics.push(MetricValue {
            metric: Metric::CpuNs,
            value: CountMetric::Value(10_000_000_000),
            per_second: Some(2_000_000_000.0),
        });
        let mut process = stage.clone();
        process.role = "process".into();
        let mut frame = Frame {
            workers: vec![stage],
            health: vec![],
            lattice: None,
            members: None,
            warnings: vec![],
            sampled: Instant::now(),
            observation_time: Duration::ZERO,
            readable_sources: 1,
            selected_sources: 1,
            max_age: Duration::from_secs(30),
        };
        let stage_only = render_terminal(&frame);
        assert!(!stage_only.contains("CPU 2.00"));
        assert!(stage_only.contains("activity and effort not observed"));
        assert!(stage_only.contains("LINKS · path, RTT and per-link throughput not observed"));
        frame.workers.push(process);
        assert_eq!(
            render_terminal(&frame)
                .matches("CPU 2.00 effective cores")
                .count(),
            1
        );
    }

    #[test]
    fn admitted_malformed_member_warnings_never_expose_the_bearer_handle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("malformed-member.pile");
        std::fs::File::create(&path).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let authority = signer.verifying_key();
        let mut writer = Pile::open(&path).unwrap();
        let collection: Collection<SimpleArchive> = writer
            .collection(
                "dashboard-malformed-member-test",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(authority),
                    AdmissionPolicy::direct(authority),
                ),
            )
            .unwrap();
        // A properly hashed blob and admitted COMMIT do not establish that its
        // bytes form a SimpleArchive. No decoder or admission rule is bypassed.
        let malformed = writer
            .put::<SimpleArchive, _>(Blob::new(anybytes::Bytes::from(vec![1_u8; 63])))
            .unwrap();
        CollectionStore::insert(
            &mut writer,
            CollectionRecord::Commit(CollectionCommit::sign(
                &signer,
                collection.handle(),
                Handle::<SimpleArchive>::to_hash(malformed),
                empty_metadata_handle(),
            )),
        )
        .unwrap();
        let upper = hex::encode_upper(malformed.raw);
        let lower = hex::encode(malformed.raw);
        {
            let snapshot = writer.snapshot().unwrap();
            let observed = snapshot.collection(collection).unwrap();
            let error = observed.view::<TribleSet>().unwrap_err();
            assert!(matches!(
                &error,
                TryFromCoverError::View(error)
                    if error.member == Handle::<SimpleArchive>::to_hash(malformed)
            ));
            // Positive control for the original leak: cleaning/truncation does
            // not remove this generated capability from the backend's error.
            assert!(clean(&error.to_string(), 140).contains(&upper));
        }
        writer.close().unwrap();
        let before = std::fs::read(&path).unwrap();
        let options = Options {
            pile: path.clone(),
            key: Some(directory.path().join("absent.key")),
            telemetry: vec![collection.handle()],
            max_age: Duration::from_secs(180),
            interval: Duration::from_secs(1),
            once: true,
            gui: false,
            lattice: false,
        };
        let mut reader = Reader::open(&options).unwrap();
        // Exercise the health warning arm over the same disposable bad member.
        reader.health = Some(SelectedSource::new(collection.handle()));
        let frame = reader.sample().unwrap();
        assert_eq!((frame.selected_sources, frame.readable_sources), (1, 0));
        assert!(frame.workers.is_empty() && frame.health.is_empty());
        assert!(frame.warnings.iter().any(|warning| warning
            == &format!(
                "Telemetry {} unreadable: selected member cannot form a fact view",
                short(&collection.handle().raw)
            )));
        assert!(frame.warnings.iter().any(|warning| warning
            == "Health reports unreadable: selected member cannot form a fact view"));
        // Both frontends consume these same warnings; check the common frame
        // and the terminal rendering, not merely the conversion in isolation.
        let rendered = render_terminal(&frame);
        for text in frame.warnings.iter().chain(std::iter::once(&rendered)) {
            assert!(!text.contains(&upper));
            assert!(!text.contains(&lower));
        }
        reader.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn missing_member_failure_is_safe_through_shared_state_and_join() {
        let mut store = MemoryRepo::default();
        let snapshot = store.snapshot().unwrap();
        let missing: Blob<SimpleArchive> = Blob::new(anybytes::Bytes::from(vec![7_u8; 63]));
        let handle = missing.get_handle();
        let mut descriptors = MemoryRepo::default();
        let collection: Collection<SimpleArchive> = descriptors
            .collection(
                "dashboard-missing-member-test",
                CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open),
            )
            .unwrap();
        // Force a cover read at the same generic view boundary. A resident-only
        // collection attachment may otherwise omit a member still in flight.
        let error =
            TribleSet::try_from_cover(&collection.cover([handle]), &Fragment::empty(), &snapshot)
                .unwrap_err();
        assert!(matches!(&error, TryFromCoverError::MemberGet { member, .. }
            if *member == Handle::<SimpleArchive>::to_hash(handle)));
        assert!(clean(&error.to_string(), 140).contains(&hex::encode_upper(handle.raw)));
        let safe = ReadFailure::from(error);
        assert_eq!(safe, ReadFailure::MemberUnavailable);
        assert!(std::error::Error::source(&safe).is_none());
        let shared = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let state = Arc::clone(&shared);
        let mut sampler = Sampler {
            shared,
            worker: Some(thread::spawn(move || finish_sampling(&state, || Err(safe)))),
        };
        let failure = sampler.finish().unwrap_err();
        assert_eq!(failure.to_string(), "selected member unavailable");
        assert_eq!(failure.chain().count(), 1);
        for rendered in [format!("{failure:#}"), format!("{failure:?}")] {
            assert!(!rendered.contains(&hex::encode_upper(handle.raw)));
            assert!(!rendered.contains(&hex::encode(handle.raw)));
        }
        let state = sampler.shared.0.lock().unwrap();
        assert!(state.finished);
        assert!(matches!(
            state.latest,
            Some(Err(ReadFailure::MemberUnavailable))
        ));
    }

    #[test]
    fn reader_open_failure_does_not_retain_a_sensitive_path() {
        let directory = tempfile::tempdir().unwrap();
        let generated: Blob<SimpleArchive> = Blob::new(anybytes::Bytes::from(vec![9_u8; 63]));
        let private_name = hex::encode_upper(generated.get_handle().raw);
        let options = Options {
            pile: directory.path().join(private_name),
            key: None,
            telemetry: vec![],
            max_age: Duration::from_secs(180),
            interval: Duration::from_secs(1),
            once: true,
            gui: false,
            lattice: false,
        };
        let failure = match Reader::open(&options) {
            Err(error) => error,
            Ok(_) => panic!("missing pile must not be opened or created"),
        };
        assert_eq!(failure, ReadFailure::PileMissing);
        assert!(
            failure.to_string().contains("ABSOLUTE path"),
            "the message must say what to do: {failure}"
        );
        let shown = failure.to_string();
        assert!(
            !shown.contains(&options.pile.display().to_string()),
            "a pile filename can be a capability handle and must never be echoed: {shown}"
        );
        assert!(std::error::Error::source(&failure).is_none());
        assert!(!options.pile.exists());
    }

    #[test]
    fn selected_reader_refreshes_appends_without_publishing_or_losing_coverage() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("telemetry.pile");
        std::fs::File::create(&path).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let authority = signer.verifying_key();
        let mut writer = Pile::open(&path).unwrap();
        let collection = writer
            .collection(
                "dashboard-test",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(authority),
                    AdmissionPolicy::direct(authority),
                ),
            )
            .unwrap();
        let subject = genid();
        let session = genid();
        let mut facts = entity! { &subject @
            health_record::attrs::endpoint: authority,
            telemetry::attrs::worker: "maintainer",
            telemetry::attrs::role: "maintenance",
        };
        let first = genid();
        let at = hifitime::Epoch::from_tai_seconds(100.0);
        facts += entity! { &first @
            metadata::tag: &telemetry::KIND_SAMPLE,
            telemetry::attrs::subject: &subject,
            health_record::attrs::session: &session,
            metadata::created_at: (at, at).try_to_inline().unwrap(),
            telemetry::attrs::elapsed_ns: 1_u128,
            telemetry::attrs::queued: 8_u128,
        };
        writer.commit(collection, &signer, facts).unwrap();
        writer.close().unwrap();
        let before = std::fs::read(&path).unwrap();
        let options = Options {
            pile: path.clone(),
            key: Some(directory.path().join("absent.key")),
            telemetry: vec![collection.handle(), collection.handle()],
            max_age: Duration::from_secs(180),
            interval: Duration::from_secs(1),
            once: true,
            gui: false,
            lattice: false,
        };
        let mut reader = Reader::open(&options).unwrap();
        for _ in 0..2 {
            let frame = reader.sample().unwrap();
            assert_eq!((frame.selected_sources, frame.readable_sources), (1, 1));
            assert_eq!(frame.workers.len(), 1);
            assert_eq!(count(&frame.workers[0], Metric::Queued), "8");
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        assert_eq!(reader.projection_runs, 1);
        // A disjoint arrival must not make the dashboard walk telemetry
        // history again. It still takes a new snapshot and checks dependencies.
        let mut writer = Pile::open(&path).unwrap();
        writer
            .put::<SimpleArchive, _>(Blob::new(anybytes::Bytes::from(vec![42_u8; 63])))
            .unwrap();
        writer.close().unwrap();
        reader.sample().unwrap();
        assert_eq!(reader.projection_runs, 1);
        let second = genid();
        let at = hifitime::Epoch::from_tai_seconds(101.0);
        let mut writer = Pile::open(&path).unwrap();
        writer
            .commit(
                collection,
                &signer,
                entity! { &second @
                    metadata::tag: &telemetry::KIND_SAMPLE,
                    telemetry::attrs::subject: &subject,
                    health_record::attrs::session: &session,
                    metadata::created_at: (at, at).try_to_inline().unwrap(),
                    telemetry::attrs::elapsed_ns: 2_u128,
                    telemetry::attrs::queued: 3_u128,
                },
            )
            .unwrap();
        writer.close().unwrap();
        let after_writer = std::fs::read(&path).unwrap();
        let frame = reader.sample().unwrap();
        assert_eq!(frame.readable_sources, 1);
        assert_eq!(frame.workers[0].report, second.id);
        assert_eq!(count(&frame.workers[0], Metric::Queued), "3");
        assert_eq!(reader.projection_runs, 2);
        reader.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), after_writer);
    }

    #[test]
    fn retained_projection_matches_real_queries_across_clock_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("clocks.pile");
        std::fs::File::create(&path).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let authority = signer.verifying_key();
        let mut writer = Pile::open(&path).unwrap();
        let collection = writer
            .collection(
                "clocked-reports",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(authority),
                    AdmissionPolicy::direct(authority),
                ),
            )
            .unwrap();
        let subject = genid();
        let session = genid();
        let mut facts = entity! { &subject @
            health_record::attrs::endpoint: authority,
            telemetry::attrs::worker: "clocked",
            telemetry::attrs::role: "maintenance",
        };
        for seconds in [90, 100] {
            let report = genid();
            let at = hifitime::Epoch::from_tai_seconds(f64::from(seconds));
            facts += entity! { &report @
                metadata::tag: &telemetry::KIND_SAMPLE,
                telemetry::attrs::subject: &subject,
                health_record::attrs::session: &session,
                metadata::created_at: (at, at).try_to_inline().unwrap(),
                telemetry::attrs::elapsed_ns: seconds as u128 * 1_000_000_000,
                telemetry::attrs::completed: seconds as u128 * 2,
            };
        }
        // Health has a different future boundary but no rate derivation. Its
        // freshness can be recomputed from the retained result without a query.
        let health_report = genid();
        let at = hifitime::Epoch::from_tai_seconds(105.0);
        facts += entity! { &health_report @
            metadata::tag: &health_record::KIND_REPORT,
            health_record::attrs::node: &subject,
            health_record::attrs::session: &session,
            metadata::created_at: (at, at).try_to_inline().unwrap(),
        };
        writer.commit(collection, &signer, facts.clone()).unwrap();
        writer.close().unwrap();
        let before = std::fs::read(&path).unwrap();
        let options = Options {
            pile: path.clone(),
            key: Some(directory.path().join("absent.key")),
            telemetry: vec![collection.handle()],
            max_age: Duration::from_secs(30),
            interval: Duration::from_secs(1),
            once: true,
            gui: false,
            lattice: false,
        };
        let mut reader = Reader::open(&options).unwrap();
        reader.health = Some(SelectedSource::new(collection.handle()));
        // Cross Future -> Fresh, prior expiry, current expiry, then return
        // within the original valid interval and finally before its origin.
        // A retained already-aged copy would lose rates on the return to 115.
        for (seconds, expected_queries) in [
            (99, 1),
            (99, 1),
            (100, 2),
            (101, 2),
            (105, 2),
            (110, 2),
            (120, 2),
            (130, 2),
            (115, 2),
            (99, 3),
            (100, 4),
        ] {
            let now_ns = i128::from(seconds) * 1_000_000_000;
            let frame = reader.sample_at(now_ns).unwrap();
            assert_eq!(reader.projection_runs, expected_queries, "at {seconds}");
            assert_eq!(
                frame.workers,
                telemetry::observe(facts.facts(), now_ns, options.max_age)
            );
            assert_eq!(
                frame.health,
                dashboard::observe_health(facts.facts(), now_ns, options.max_age)
            );
        }
        assert_eq!(
            measured_rate(
                &reader.sample_at(115_000_000_000).unwrap().workers[0],
                Metric::Completed
            ),
            Some(2.0)
        );
        reader.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn unreadable_health_retries_until_payload_arrival_then_reuses() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("late-health.pile");
        std::fs::File::create(&path).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let authority = signer.verifying_key();
        let policy = CollectionPolicy::new(
            AdmissionPolicy::direct(authority),
            AdmissionPolicy::direct(authority),
        );
        let mut writer = Pile::open(&path).unwrap();
        let reports: Collection<SimpleArchive> =
            writer.collection("reports", policy.clone()).unwrap();
        let mut descriptors = MemoryRepo::default();
        let health: Collection<SimpleArchive> = descriptors
            .collection("pending-health", policy.clone())
            .unwrap();
        let node = genid();
        let report = genid();
        let at = hifitime::Epoch::from_tai_seconds(100.0);
        let facts = entity! { &report @
            metadata::tag: &health_record::KIND_REPORT,
            health_record::attrs::node: &node,
            metadata::created_at: (at, at).try_to_inline().unwrap(),
        };
        let payload: Blob<SimpleArchive> = facts.facts().clone().to_blob();
        let handle = payload.get_handle();
        writer.close().unwrap();
        let options = Options {
            pile: path.clone(),
            key: Some(directory.path().join("absent.key")),
            telemetry: vec![reports.handle()],
            max_age: Duration::from_secs(30),
            interval: Duration::from_secs(1),
            once: true,
            gui: false,
            lattice: false,
        };
        let mut reader = Reader::open(&options).unwrap();
        // A missing key means health=None and does not block the fast path.
        reader.sample_at(100_000_000_000).unwrap();
        reader.sample_at(101_000_000_000).unwrap();
        assert_eq!(reader.projection_runs, 1);
        reader.health = Some(SelectedSource::new(health.handle()));
        for expected in 2..=3 {
            let frame = reader.sample_at(102_000_000_000).unwrap();
            assert!(frame.warnings.iter().any(|warning| warning
                == "Health reports unreadable: collection descriptor unavailable or invalid"));
            assert_eq!(reader.projection_runs, expected);
            assert!(reader.retained.is_none());
        }
        let mut writer = Pile::open(&path).unwrap();
        let installed: Collection<SimpleArchive> =
            writer.collection("pending-health", policy).unwrap();
        assert_eq!(installed.handle(), health.handle());
        CollectionStore::insert(
            &mut writer,
            CollectionRecord::Commit(CollectionCommit::sign(
                &signer,
                health.handle(),
                Handle::<SimpleArchive>::to_hash(handle),
                empty_metadata_handle(),
            )),
        )
        .unwrap();
        writer.close().unwrap();
        // A known COMMIT with an absent payload is a successful empty resident
        // cover, not a view error. Its missing-blob dependency must still wake
        // the reader when those bytes arrive; do not invent an error here.
        for _ in 0..2 {
            let frame = reader.sample_at(103_000_000_000).unwrap();
            assert!(frame.health.is_empty());
            assert!(!frame
                .warnings
                .iter()
                .any(|warning| warning.starts_with("Health reports unreadable")));
            assert_eq!(reader.projection_runs, 4);
        }
        let mut writer = Pile::open(&path).unwrap();
        assert_eq!(writer.put(payload).unwrap(), handle);
        writer.close().unwrap();
        let before = std::fs::read(&path).unwrap();
        for _ in 0..2 {
            let frame = reader.sample_at(103_000_000_000).unwrap();
            assert_eq!(frame.health.len(), 1);
            assert!(!frame
                .warnings
                .iter()
                .any(|warning| warning.starts_with("Health reports unreadable")));
            assert_eq!(reader.projection_runs, 5);
        }
        reader.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn disposable_reader_does_not_append_or_create_a_pile() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dashboard.pile");
        std::fs::File::create(&path).unwrap();
        let mut options = Options {
            pile: path.clone(),
            key: Some(directory.path().join("absent.key")),
            telemetry: vec![],
            max_age: Duration::from_secs(180),
            interval: Duration::from_secs(1),
            once: true,
            gui: false,
            lattice: false,
        };
        let before = std::fs::read(&path).unwrap();
        let mut reader = Reader::open(&options).unwrap();
        let first = reader.sample().unwrap();
        let second = reader.sample().unwrap();
        assert!(first.workers.is_empty() && second.workers.is_empty());
        assert!(!first.warnings.is_empty());
        reader.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!options.key.as_ref().unwrap().exists());
        options.pile = directory.path().join("typo.pile");
        assert!(Reader::open(&options).is_err());
        assert!(!options.pile.exists());
    }
}
