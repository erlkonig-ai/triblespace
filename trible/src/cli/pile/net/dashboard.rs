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

    fn facts(&mut self, snapshot: &PileSnapshot) -> ReadResult<&TribleSet> {
        if !self
            .observed
            .as_ref()
            .is_some_and(|(observed, _)| observed.is_current(snapshot))
        {
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
}

impl Reader {
    fn open(options: &Options) -> ReadResult<Self> {
        if !std::fs::metadata(&options.pile)
            .map_err(|_| ReadFailure::OpenPile)?
            .is_file()
        {
            return Err(ReadFailure::OpenPile);
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
        })
    }

    fn sample(&mut self) -> ReadResult<Frame> {
        let started = Instant::now();
        let snapshot = self.pile.snapshot().map_err(|_| ReadFailure::RefreshPile)?;
        let now_ns = triblespace_core::clock::epoch_now()
            .to_tai_duration()
            .total_nanoseconds();
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
        let health = match self.health.as_mut() {
            Some(source) => match source.facts(&snapshot) {
                Ok(facts) => dashboard::observe_health(facts, now_ns, self.max_age),
                Err(error) => {
                    warnings.push(format!("Health reports unreadable: {error}"));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        Ok(Frame {
            workers,
            health,
            warnings,
            sampled: Instant::now(),
            observation_time: started.elapsed(),
            readable_sources,
            selected_sources: self.sources.len(),
            max_age: self.max_age,
        })
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

#[derive(Clone)]
struct Frame {
    workers: Vec<WorkerReport>,
    health: Vec<ObserverReport>,
    warnings: Vec<String>,
    sampled: Instant,
    observation_time: Duration,
    readable_sources: usize,
    selected_sources: usize,
    max_age: Duration,
}

impl Frame {
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
        let observation = reader.sample().map(Arc::new);
        if options.once {
            once_error = observation.as_ref().err().cloned();
        }
        let mut state = shared.0.lock().unwrap_or_else(|error| error.into_inner());
        state.latest = Some(observation);
        state.revision += 1;
        shared.1.notify_all();
        if options.once || state.stop {
            break;
        }
        let waited = shared
            .1
            .wait_timeout_while(state, options.interval, |state| !state.stop)
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
        let _ = writeln!(
            out,
            "NODE {} · {} observed worker scopes",
            short(&node),
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
    use triblespace_core::collection::{empty_metadata_handle, CollectionCommit, CollectionRecord};
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::metadata;
    use triblespace_core::prelude::*;
    use triblespace_net::telemetry::MetricValue;

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
        };
        let failure = match Reader::open(&options) {
            Err(error) => error,
            Ok(_) => panic!("missing pile must not be opened or created"),
        };
        assert_eq!(failure, ReadFailure::OpenPile);
        assert_eq!(
            failure.to_string(),
            "cannot open existing regular dashboard pile"
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
        };
        let mut reader = Reader::open(&options).unwrap();
        for _ in 0..2 {
            let frame = reader.sample().unwrap();
            assert_eq!((frame.selected_sources, frame.readable_sources), (1, 1));
            assert_eq!(frame.workers.len(), 1);
            assert_eq!(count(&frame.workers[0], Metric::Queued), "8");
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
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
        reader.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), after_writer);
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
