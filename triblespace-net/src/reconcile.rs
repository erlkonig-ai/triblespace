//! Service durable WANTs and explicitly selected collection hydration.
//!
//! Collection repair is a separate raw-record exchange. This reconciler
//! services durable exact-content and collection-operation demand without
//! deciding WRITE admission or claiming global absence:
//! an operation WANT is satisfied iff at least one matching local receipt is
//! visible; otherwise it remains pending while the local store evolves.
//! `Blob(H)` uses H-derived global provider discovery. No collection,
//! provenance guess, or ambient authorization participates in that exact read.
//! Optional shallow/full hydration is local acquisition policy over selected
//! structural records, not semantic admission or another Peer protocol.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use anybytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::blob::locator::blob_locator;
use triblespace_core::collection::reference_summary::{ReferenceSummaryBlob, ReferenceSummaryView};
use triblespace_core::collection::{
    Collection, CollectionHandle, CollectionRead, CollectionRecord, CollectionRecordSelector,
    CollectionSnapshotExt, CollectionStore,
};
use triblespace_core::inline::Inline;
use triblespace_core::patch::{Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::repo::{
    BlobChildren, BlobStore, BlobStoreGet, CapabilityProofStore, SnapshotSource, StorageFlush,
    StoreRead, WantRead, WantRequest, WantStore,
};

use crate::peer::Peer;
use crate::protocol::{RawHash, VerifiedBlob};

/// How much content an explicit collection selection asks this process to obtain.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationMode {
    /// Repair records and service explicit WANTs, without implicit blob demand.
    #[default]
    Demand,
    /// Obtain every direct reference of selected structural collection records.
    Shallow,
    /// Also scan those roots and their readable descendants at 32-byte boundaries.
    Full,
}

/// Hydration observations, separate from durable WANT fulfillment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplicationStats {
    /// Distinct direct handles named by the selected records in this observation.
    pub roots: usize,
    /// Direct roots not yet durably resident. Speculative misses are not roots.
    pub pending: usize,
    /// Blobs fetched and durably landed for hydration during this tick.
    pub acquired: usize,
    /// Complete aligned words examined, including resident and filtered candidates.
    pub candidates: usize,
    /// Candidates rejected locally by a resident, support-covering summary.
    pub filtered: usize,
    /// Exact-H network attempts made for speculative aligned words.
    pub speculative_attempted: usize,
    /// Speculative attempts which did not produce a durable exact blob.
    /// This is an observation, not an assertion that an attachment is missing.
    pub speculative_misses: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileStats {
    pub wants: usize,
    pub missing: usize,
    pub attempted: usize,
    pub fulfilled: usize,
    pub pending: usize,
    pub replication: ReplicationStats,
}

struct WantState {
    last_attempt: Option<crate::clock::Mono>,
    backoff: Duration,
    wanted_since: Option<u64>,
    root_since: Option<u64>,
    first_root_attempt: bool,
}

impl WantState {
    fn new() -> Self {
        Self {
            last_attempt: None,
            backoff: Duration::ZERO,
            wanted_since: None,
            root_since: None,
            first_root_attempt: false,
        }
    }

    fn due(&self, now: crate::clock::Mono) -> bool {
        self.last_attempt
            .is_none_or(|last| now.duration_since(last) >= self.backoff)
    }
}

/// An ordinary round has finite eligibility even while new demand arrives.
/// Only scheduling cutoffs/cursors are retained, not a second root inventory.
#[derive(Default)]
struct ExactRound {
    generation: u64,
    after: Option<RawHash>,
}

impl ExactRound {
    fn candidates(
        &mut self,
        handles: &BTreeSet<RawHash>,
        states: &HashMap<RawHash, WantState>,
        generation: u64,
        now: crate::clock::Mono,
        wanted: bool,
    ) -> Vec<RawHash> {
        let eligible = |round: &Self| {
            handles
                .iter()
                .copied()
                .filter(|handle| round.after.is_none_or(|after| *handle > after))
                .filter(|handle| {
                    states.get(handle).is_some_and(|state| {
                        let seen = if wanted {
                            state.wanted_since
                        } else {
                            state.root_since
                        };
                        seen.is_some_and(|seen| seen <= round.generation) && state.due(now)
                    })
                })
                .collect::<Vec<_>>()
        };
        let candidates = eligible(self);
        if !candidates.is_empty() {
            return candidates;
        }
        self.generation = generation;
        self.after = None;
        eligible(self)
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
enum ServiceTurn {
    #[default]
    Wants,
    FreshRoots,
    Roots,
    Scan,
}

impl ServiceTurn {
    fn next(self) -> Self {
        match self {
            Self::Wants => Self::FreshRoots,
            Self::FreshRoots => Self::Roots,
            Self::Roots => Self::Scan,
            Self::Scan => Self::Wants,
        }
    }
}

/// Retry/traversal state only. Durable demand and all answers remain in the store.
pub struct Reconciler {
    states: HashMap<RawHash, WantState>,
    durable_blob_answers: HashSet<[u8; 32]>,
    initial_backoff: Duration,
    max_backoff: Duration,
    fetch_budget: Duration,
    mode: ReplicationMode,
    collections: BTreeSet<CollectionRecordSelector>,
    observation_generation: u64,
    want_round: ExactRound,
    root_round: ExactRound,
    next_service: ServiceTurn,
    scan: SelectionScans,
}

pub const RECONCILE_FETCH_DEADLINE: Duration = Duration::from_secs(30);

/// Bound CPU work even when every candidate is resident or filtered out.
pub const RECONCILE_SCAN_CANDIDATES_PER_TICK: usize = 16 * 1024;
/// Speculation cannot turn one large binary into an unbounded burst of DHT work.
pub const RECONCILE_SPECULATIVE_FETCHES_PER_TICK: usize = 16;

/// Experimental exact-demand window, not a throughput guarantee. Speculative
/// scanning keeps its separate, serial request path and existing allowance.
const EXACT_FETCHES_IN_FLIGHT: usize = 4;

/// Yield even when a source contains only local or summary-filtered words.
const SCAN_WORDS_PER_QUANTUM: usize = 64;
/// New positive sources get a small head start, not an unlimited priority scan.
const SCAN_STARTUP_WORDS: usize = 128;

impl Default for Reconciler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reconciler {
    pub fn new() -> Self {
        Self::with_backoff(crate::RETRY_BACKOFF_BASE, crate::RETRY_BACKOFF_CAP)
    }

    pub fn with_backoff(initial: Duration, max: Duration) -> Self {
        Self {
            states: HashMap::new(),
            durable_blob_answers: HashSet::new(),
            initial_backoff: initial,
            max_backoff: max,
            fetch_budget: RECONCILE_FETCH_DEADLINE,
            mode: ReplicationMode::Demand,
            collections: BTreeSet::new(),
            observation_generation: 0,
            want_round: ExactRound::default(),
            root_round: ExactRound::default(),
            next_service: ServiceTurn::default(),
            scan: SelectionScans::default(),
        }
    }

    pub fn with_fetch_budget(mut self, budget: Duration) -> Self {
        self.fetch_budget = budget;
        self
    }

    /// Select collection hydration explicitly, independently of READ grants or
    /// Peer activation. This does not activate a collection or publish a WANT.
    ///
    /// Signature-valid but WRITE-inert COMMITs and structural MERGE/DERIVE
    /// equations all contribute direct references. Obtaining their bytes does
    /// not admit their semantic claims. Changing this selection forgets only
    /// process-local traversal state, never stored data or demand.
    pub fn with_replication(
        mut self,
        mode: ReplicationMode,
        collections: impl IntoIterator<Item = CollectionHandle>,
    ) -> Self {
        self.mode = mode;
        self.collections = collections
            .into_iter()
            .map(CollectionRecordSelector::Collection)
            .collect();
        self.scan = SelectionScans::new(self.collections.iter().copied());
        self.root_round = ExactRound::default();
        self.next_service = ServiceTurn::default();
        for state in self.states.values_mut() {
            state.root_since = None;
            state.first_root_attempt = false;
        }
        self
    }

    fn observe_missing(&mut self, wanted: &BTreeSet<RawHash>, roots: &BTreeSet<RawHash>) {
        self.observation_generation = self
            .observation_generation
            .checked_add(1)
            .expect("reconciler observation generation exhausted");
        for handle in wanted.union(roots) {
            if self.durable_blob_answers.contains(handle) {
                continue;
            }
            let state = self.states.entry(*handle).or_insert_with(WantState::new);
            if wanted.contains(handle) {
                state
                    .wanted_since
                    .get_or_insert(self.observation_generation);
            }
            if roots.contains(handle) && state.root_since.is_none() {
                state.root_since = Some(self.observation_generation);
                state.first_root_attempt = true;
            }
        }
    }

    /// Grant one eligible class a fetch-budget quantum. The next class is
    /// retained before any await, so even a request using the whole deadline
    /// cannot repeatedly take scanning's or an older exact request's turn.
    /// Empty or wholly backed-off classes borrow no time. A request keeps the
    /// remaining existing budget; fairness does not divide its DHT/provider
    /// deadline into smaller sub-budgets. Several whole quanta may therefore
    /// pass before a fresh root or its descendant gets a turn.
    fn next_work(
        &mut self,
        wanted: &BTreeSet<RawHash>,
        roots: &BTreeSet<RawHash>,
        now: crate::clock::Mono,
    ) -> Option<(ServiceTurn, Vec<RawHash>)> {
        for _ in 0..4 {
            let turn = self.next_service;
            self.next_service = turn.next();
            let candidates = match turn {
                ServiceTurn::Wants => self.want_round.candidates(
                    wanted,
                    &self.states,
                    self.observation_generation,
                    now,
                    true,
                ),
                ServiceTurn::FreshRoots => {
                    let mut candidates: Vec<_> = roots
                        .iter()
                        .copied()
                        .filter(|handle| {
                            self.states
                                .get(handle)
                                .is_some_and(|state| state.first_root_attempt && state.due(now))
                        })
                        .collect();
                    // A newly observed cohort gets its bounded first attempt
                    // ahead of an old startup burst. Regular frozen rounds
                    // still serve the burst during sustained arrivals.
                    candidates.sort_by_key(|handle| {
                        (std::cmp::Reverse(self.states[handle].root_since), *handle)
                    });
                    candidates
                }
                ServiceTurn::Roots => self.root_round.candidates(
                    roots,
                    &self.states,
                    self.observation_generation,
                    now,
                    false,
                ),
                ServiceTurn::Scan => {
                    if self.mode == ReplicationMode::Full && self.scan.has_eligible_work(now) {
                        return Some((turn, Vec::new()));
                    }
                    continue;
                }
            };
            if !candidates.is_empty() {
                return Some((turn, candidates));
            }
        }
        None
    }

    fn begin_attempt(&mut self, turn: ServiceTurn, handle: RawHash) {
        match turn {
            ServiceTurn::Wants => self.want_round.after = Some(handle),
            ServiceTurn::Roots => self.root_round.after = Some(handle),
            ServiceTurn::FreshRoots => {}
            ServiceTurn::Scan => unreachable!("scan has no exact candidate list"),
        }
        self.states
            .get_mut(&handle)
            .expect("observed missing exact handle")
            .first_root_attempt = false;
    }

    pub async fn tick<S>(&mut self, peer: &mut Peer<S>) -> ReconcileStats
    where
        S: BlobStore
            + CollectionStore
            + CapabilityProofStore
            + WantStore
            + StorageFlush
            + Send
            + 'static,
        S::Snapshot: StoreRead + BlobChildren,
    {
        self.tick_with_reference_filter(peer, |_, _| None).await
    }

    // Internal seam for a concrete summary selected by ordinary tick. None
    // means no covering evidence, never an authoritative empty summary. Only
    // descendants of this exact direct root may use its predicate; WANTs and
    // direct roots bypass it. This does not affect Peer or exact-H acquisition.
    async fn tick_with_reference_filter<S, F>(
        &mut self,
        peer: &mut Peer<S>,
        mut reference_filter: F,
    ) -> ReconcileStats
    where
        S: BlobStore
            + CollectionStore
            + CapabilityProofStore
            + WantStore
            + StorageFlush
            + Send
            + 'static,
        S::Snapshot: StoreRead + BlobChildren,
        F: FnMut(RawHash, RawHash) -> Option<bool>,
    {
        let mut stats = ReconcileStats::default();

        // This is also the explicit external-Pile reobservation and inventory
        // admission boundary.
        peer.refresh();
        let mut snapshot = match peer.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "store snapshot unavailable; skipping reconcile pass"
                );
                return stats;
            }
        };
        let requests: Vec<WantRequest> = match snapshot
            .wants()
            .and_then(|wants| wants.collect::<Result<Vec<_>, _>>())
        {
            Ok(wants) => wants,
            Err(error) => {
                tracing::warn!(?error, "WANT observation failed; skipping reconcile pass");
                return stats;
            }
        };
        stats.wants = requests.len();

        let blob_wants: BTreeSet<_> = requests
            .iter()
            .copied()
            .filter(|request| request.blob_handle().is_some())
            .collect();
        let operation_wants: BTreeSet<_> = requests
            .iter()
            .copied()
            .filter(|request| {
                matches!(
                    request,
                    WantRequest::Merge { .. } | WantRequest::Derive { .. }
                )
            })
            .collect();

        // One native indexed union retains every conflicting answer. Empty is
        // only "not obtained yet", never proof that no answer exists.
        let selectors: BTreeSet<_> = operation_wants
            .iter()
            .copied()
            .map(CollectionRecordSelector::Operation)
            .collect();
        let answered_operations = match answered_operations(&snapshot, &selectors) {
            Ok(answered) => answered,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "operation receipt observation failed; skipping reconcile pass"
                );
                return ReconcileStats::default();
            }
        };
        let missing_operations = operation_wants
            .iter()
            .filter(|request| !answered_operations.contains(request))
            .count();

        let wanted_blob_handles: BTreeSet<_> = blob_wants
            .iter()
            .filter_map(|request| request.blob_handle().map(|handle| handle.raw))
            .collect();
        let selected_roots = if self.mode == ReplicationMode::Demand {
            Vec::new()
        } else {
            // One indexed read per selection retains membership only for this
            // tick. COMMIT signatures are checked once, before physical union.
            let observed = self
                .collections
                .iter()
                .map(|selector| direct_roots(&snapshot, &BTreeSet::from([*selector])))
                .collect::<Result<Vec<_>, _>>();
            match observed {
                Ok(roots) => roots,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "hydration record observation failed; skipping roots"
                    );
                    Vec::new()
                }
            }
        };
        let roots: BTreeSet<_> = selected_roots.iter().flatten().copied().collect();
        stats.replication.roots = roots.len();
        let exact_handles: BTreeSet<_> = wanted_blob_handles.union(&roots).copied().collect();
        let visible_blobs: HashSet<_> = exact_handles
            .iter()
            .copied()
            .filter(|handle| {
                BlobStoreGet::get::<Bytes, UnknownBlob>(&snapshot, Inline::new(*handle)).is_ok()
            })
            .collect();

        self.durable_blob_answers
            .retain(|handle| exact_handles.contains(handle) && visible_blobs.contains(handle));
        let newly_visible: HashSet<_> = visible_blobs
            .difference(&self.durable_blob_answers)
            .copied()
            .collect();
        if !newly_visible.is_empty() {
            let durable = peer.store().flush();
            match durable {
                Ok(()) => {
                    self.durable_blob_answers
                        .extend(newly_visible.iter().copied());
                }
                Err(error) => tracing::warn!(
                    ?error,
                    "visible requested blobs are not durable; keeping them pending"
                ),
            }
        }
        stats.missing = missing_operations
            + wanted_blob_handles
                .iter()
                .filter(|handle| !self.durable_blob_answers.contains(*handle))
                .count();
        self.states.retain(|handle, _| {
            exact_handles.contains(handle) && !self.durable_blob_answers.contains(handle)
        });
        self.observe_missing(&wanted_blob_handles, &roots);
        if self.mode == ReplicationMode::Full {
            self.scan
                .observe_roots(&selected_roots, &self.durable_blob_answers);
        }

        let started = crate::clock::mono_now();
        let deadline = tokio::time::Instant::now() + self.fetch_budget;
        let work = self.next_work(&wanted_blob_handles, &roots, started);
        let scan_turn = matches!(work, Some((ServiceTurn::Scan, _)));
        if let Some((turn, handles)) = work {
            // One class owns this finite observation and its original budget.
            // Network futures own no Peer/store borrow; only this task lands
            // results, one at a time. No task survives this tick's cancellation.
            let mut handles = handles.into_iter();
            let mut pending = FuturesUnordered::new();
            let mut in_flight = BTreeSet::new();
            loop {
                while pending.len() < EXACT_FETCHES_IN_FLIGHT
                    && !self.remaining(started).is_zero()
                    && tokio::time::Instant::now() < deadline
                {
                    let Some(handle) = handles.next() else {
                        break;
                    };
                    self.begin_attempt(turn, handle);
                    if wanted_blob_handles.contains(&handle) {
                        stats.attempted += 1;
                    }
                    // A failed durability barrier is retried locally, not
                    // turned into a network fetch of already-visible bytes.
                    let fetch = (!visible_blobs.contains(&handle)).then(|| {
                        peer.fetch_verified_with_deadline(
                            handle,
                            deadline.saturating_duration_since(tokio::time::Instant::now()),
                        )
                    });
                    in_flight.insert(handle);
                    pending.push(async move {
                        let verified = match fetch {
                            Some(fetch) if tokio::time::Instant::now() < deadline => {
                                tokio::time::timeout_at(deadline, fetch)
                                    .await
                                    .ok()
                                    .flatten()
                            }
                            _ => None,
                        };
                        (handle, verified)
                    });
                }
                if pending.is_empty()
                    || self.remaining(started).is_zero()
                    || tokio::time::Instant::now() >= deadline
                {
                    break;
                }
                let Ok(Some((handle, verified))) =
                    tokio::time::timeout_at(deadline, pending.next()).await
                else {
                    break;
                };
                in_flight.remove(&handle);
                let is_want = wanted_blob_handles.contains(&handle);
                let landed = if visible_blobs.contains(&handle) {
                    peer.store().flush().is_ok()
                } else {
                    verified
                        .and_then(|verified| land_exact(peer, verified))
                        .is_some()
                };
                if !landed {
                    self.record_unavailable(handle);
                    continue;
                }
                self.durable_blob_answers.insert(handle);
                self.states.remove(&handle);
                if is_want {
                    stats.fulfilled += 1;
                }
                if roots.contains(&handle) && !visible_blobs.contains(&handle) {
                    stats.replication.acquired += 1;
                }
                peer.refresh();
            }
            // Expiry cancels admitted unfinished requests, not untouched tail
            // candidates. Charge each once; no answer is durable until its
            // serial landing barrier succeeds. Dropping the entire tick also
            // drops these futures, without inventing a completion or miss.
            drop(pending);
            for handle in in_flight {
                self.record_unavailable(handle);
            }
        }
        stats.pending = missing_operations
            + wanted_blob_handles
                .iter()
                .filter(|handle| !self.durable_blob_answers.contains(*handle))
                .count();
        stats.replication.pending = roots
            .iter()
            .filter(|handle| !self.durable_blob_answers.contains(*handle))
            .count();

        if !scan_turn {
            return stats;
        }
        snapshot = match peer.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(?error, "cannot observe hydrated blobs; deferring full scan");
                return stats;
            }
        };
        // Summaries are ordinary, explicitly selected derived collections.
        // Observe only their resident realization; never ensure/map here:
        // this consumer need not possess the producer's complete blob closure.
        // Structural endpoints landed during an earlier exact-service turn
        // can now make a previously absent summary usable.
        let mut summaries = Vec::new();
        for selector in &self.collections {
            let CollectionRecordSelector::Collection(handle) = selector else {
                continue;
            };
            let Ok(collection) = Collection::<ReferenceSummaryBlob>::open(&snapshot, *handle)
            else {
                continue;
            };
            let Ok(observed) = snapshot.collection(collection) else {
                continue;
            };
            let Ok(descriptor) =
                BlobStoreGet::get::<triblespace_core::trible::TribleSet, _>(&snapshot, *handle)
            else {
                continue;
            };
            // A resident summary can be readable without complete historical
            // provenance. Unavailable support cannot justify a negative hint.
            let Ok(support) = observed.support() else {
                continue;
            };
            // Foundational support is not necessarily the mapping's immediate
            // input: a SimpleArchive projection may have dropped references.
            // This walker starts at COMMIT payloads, so only a summary mapped
            // directly from their foundational collection describes those bytes.
            if triblespace_core::collection::descriptor::source(&descriptor)
                .ok()
                .flatten()
                != Some(support.collection().handle())
            {
                continue;
            }
            if let Ok(view) = observed.view::<ReferenceSummaryView>() {
                // Preparing one batch decodes sparse gaps once; attachment
                // itself keeps the summary's original bytes. An unreadable
                // optional hint supplies no negative answer.
                if let Ok(query) = view.query() {
                    summaries.push((support.clone(), query));
                }
            }
        }
        let mut snapshot_flushed = false;
        let mut negative = HashSet::new();
        let mut scan_steps = 0;
        while scan_steps < RECONCILE_SCAN_CANDIDATES_PER_TICK && !self.remaining(started).is_zero()
        {
            scan_steps += 1;
            let cursor = match self.scan.next() {
                ScanStep::Ready(cursor) => cursor,
                ScanStep::Skip => continue,
                ScanStep::Idle => break,
            };
            let (root, source) = cursor.handles();
            let bytes =
                match BlobStoreGet::get::<Bytes, UnknownBlob>(&snapshot, Inline::new(source)) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        // Forgetting or temporary local unavailability is not a
                        // closed edge. Roots and later parent sweeps rediscover it.
                        self.scan.forget_source(&cursor.key);
                        continue;
                    }
                };
            let Some(chunk) = bytes
                .as_ref()
                .get(cursor.offset..)
                .and_then(|tail| tail.get(..32))
            else {
                self.scan
                    .finish_source(self.initial_backoff, self.max_backoff);
                continue;
            };
            let candidate: RawHash = chunk.try_into().expect("one complete aligned word");
            if exact_handles.contains(&candidate) && !self.durable_blob_answers.contains(&candidate)
            {
                self.scan.advance();
                stats.replication.candidates += 1;
                continue;
            }
            let summarized = reference_filter(root, candidate).or_else(|| {
                summaries.iter().find_map(|(support, view)| {
                    // The summary describes this exact source data payload,
                    // not arbitrary metadata, descriptors, or physical images
                    // of its logical value. Empty/partial support grants no
                    // negative answer about a root it does not contain.
                    support
                        .contains(Inline::new(root))
                        .then(|| view.contains_locator(blob_locator(candidate)))
                })
            });
            if summarized == Some(false) {
                self.scan.advance();
                stats.replication.candidates += 1;
                stats.replication.filtered += 1;
                continue;
            }
            let local =
                BlobStoreGet::get::<Bytes, UnknownBlob>(&snapshot, Inline::new(candidate)).ok();
            let speculative_budget = self.remaining(started);
            if local.is_none()
                && !negative.contains(&candidate)
                && (stats.replication.speculative_attempted
                    >= RECONCILE_SPECULATIVE_FETCHES_PER_TICK
                    || speculative_budget.is_zero())
            {
                // Leave this exact offset for the next tick. No candidate
                // array or absent-handle frontier is ever materialized.
                break;
            }
            self.scan.advance();
            stats.replication.candidates += 1;
            if local.is_some() {
                if !snapshot_flushed {
                    if let Err(error) = peer.store().flush() {
                        tracing::warn!(
                            ?error,
                            "resident scan child is not durable; retry on next sweep"
                        );
                        continue;
                    }
                    snapshot_flushed = true;
                }
                self.scan.observe(root, candidate);
                continue;
            }
            if !negative.insert(candidate) {
                continue;
            }
            stats.replication.speculative_attempted += 1;
            // A request may consume the entire deadline. Persist the next lane
            // and this source's exact progress before awaiting it.
            self.scan.yield_source();
            if fetch_and_land(peer, candidate, speculative_budget)
                .await
                .is_none()
            {
                stats.replication.speculative_misses += 1;
                continue;
            }
            stats.replication.acquired += 1;
            self.scan.observe(root, candidate);
            peer.refresh();
            snapshot = match peer.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::warn!(?error, "cannot observe scan progress; deferring full scan");
                    break;
                }
            };
            // This newer prefix may include an external append which happened
            // after the landing's flush. Freeze first, then flush any newly
            // discovered resident child before calling it positive work.
            snapshot_flushed = false;
        }
        // CPU/time exits are quantum boundaries too. A selected but wholly
        // unexamined word stays active, so quota exhaustion cannot skip its turn.
        self.scan.yield_source();
        stats
    }

    fn remaining(&self, started: crate::clock::Mono) -> Duration {
        self.fetch_budget
            .saturating_sub(crate::clock::mono_now().duration_since(started))
    }

    fn record_unavailable(&mut self, handle: RawHash) {
        let now = crate::clock::mono_now();
        let state = self.states.entry(handle).or_insert_with(WantState::new);
        state.backoff = if state.last_attempt.is_some() {
            (state.backoff * 2).min(self.max_backoff)
        } else {
            self.initial_backoff
        };
        state.last_attempt = Some(now);
    }
}

/// One sustained quantum per explicit selection, including regular revisits.
/// Only process-local traversal is partitioned: exact demand, physical roots,
/// deadlines, counters and per-tick negative observations remain shared.
#[derive(Default)]
struct SelectionScans {
    lanes: Vec<(CollectionRecordSelector, FullScan)>,
    next_lane: usize,
    active: Option<usize>,
    last_lane: usize,
}

impl SelectionScans {
    fn new(selectors: impl IntoIterator<Item = CollectionRecordSelector>) -> Self {
        Self {
            lanes: selectors
                .into_iter()
                .map(|selector| (selector, FullScan::default()))
                .collect(),
            ..Self::default()
        }
    }

    fn observe_roots(&mut self, selected_roots: &[BTreeSet<RawHash>], resident: &HashSet<RawHash>) {
        for ((selector, scan), roots) in self.lanes.iter_mut().zip(selected_roots) {
            // Reuse this tick's native discovery without rechecking signatures.
            // Shared roots get service in each selecting lane, while physical
            // acquisition and negative-request deduplication remain global.
            let selected = BTreeSet::from([*selector]);
            scan.observe_roots(roots, &selected, resident);
        }
    }

    fn has_eligible_work(&self, now: crate::clock::Mono) -> bool {
        self.lanes.iter().any(|(_, scan)| {
            scan.sources.iter().any(|key| {
                let progress = scan.sources.get(key).expect("existing scan source");
                progress
                    .last_scan
                    .is_none_or(|last| now.duration_since(last) >= progress.backoff)
            })
        })
    }

    fn next(&mut self) -> ScanStep {
        if let Some(lane) = self.active {
            return self.lanes[lane].1.next();
        }
        if self.lanes.iter().all(|(_, scan)| scan.sources.is_empty()) {
            return ScanStep::Idle;
        }
        let lane = self.next_lane;
        self.next_lane = (lane + 1) % self.lanes.len();
        self.last_lane = lane;
        match self.lanes[lane].1.next() {
            ScanStep::Ready(cursor) => {
                self.active = Some(lane);
                ScanStep::Ready(cursor)
            }
            ScanStep::Skip | ScanStep::Idle => ScanStep::Skip,
        }
    }

    fn advance(&mut self) {
        self.lanes[self.last_lane].1.advance();
        self.release_finished_quantum();
    }

    fn yield_source(&mut self) {
        if self.active.is_some() {
            self.lanes[self.last_lane].1.yield_source();
            self.release_finished_quantum();
        }
    }

    fn release_finished_quantum(&mut self) {
        if self.lanes[self.last_lane].1.cursor.is_none() {
            self.active = None;
        }
    }

    fn observe(&mut self, root: RawHash, source: RawHash) {
        self.lanes[self.last_lane].1.observe(root, source);
    }

    fn finish_source(&mut self, initial: Duration, max: Duration) {
        self.lanes[self.last_lane].1.finish_source(initial, max);
        self.active = None;
    }

    fn forget_source(&mut self, key: &[u8; 64]) {
        let scan = &mut self.lanes[self.last_lane].1;
        scan.sources.remove(key);
        scan.cursor = None;
        if scan.recent_active == Some(*key) {
            scan.recent_active = None;
        }
        self.active = None;
    }
}

/// Positive traversal state only: one key per (direct root, readable source).
///
/// The root half preserves the scope of a covering reference summary.
/// Shared descendants may therefore be scanned separately for several roots;
/// these are traversal observations, not distinct acquired blobs. Arbitrary
/// absent words never enter this PATCH or the exact-demand retry map.
#[derive(Default)]
struct FullScan {
    sources: PATCH<64, IdentitySchema, SourceProgress>,
    /// A frozen round grants one quantum per positive source, not a whole blob.
    /// New insertions cannot lengthen the round ahead of older work.
    pass: Option<PATCH<64, IdentitySchema, SourceProgress>>,
    cursor: Option<ScanCursor>,
    after: Option<[u8; 64]>,
    /// Choose bounded startup windows newest-first. Once started, a window
    /// keeps its remaining allowance across yields and subsequent arrivals.
    /// Every entry also gets ordinary rounds, independently of this priority.
    recent: Vec<[u8; 64]>,
    recent_active: Option<[u8; 64]>,
    /// Deliberately retained across ticks, including a fetch timeout.
    prefer_recent: bool,
}

#[derive(Clone, Copy)]
struct SourceProgress {
    offset: usize,
    startup_left: usize,
    last_scan: Option<crate::clock::Mono>,
    backoff: Duration,
}

enum ScanStep {
    Ready(ScanCursor),
    /// One bounded scheduling step (round boundary, stale entry, or cooldown).
    Skip,
    Idle,
}

#[derive(Clone, Copy)]
struct ScanCursor {
    key: [u8; 64],
    offset: usize,
    words: usize,
    recent: bool,
}

impl ScanCursor {
    fn handles(self) -> (RawHash, RawHash) {
        (
            self.key[..32].try_into().expect("root half"),
            self.key[32..].try_into().expect("source half"),
        )
    }
}

impl FullScan {
    fn observe_roots(
        &mut self,
        roots: &BTreeSet<RawHash>,
        selected: &BTreeSet<CollectionRecordSelector>,
        resident: &HashSet<RawHash>,
    ) {
        // Seed ordinary roots first: the existing recent LIFO then gives the
        // few selected descriptors their finite startup window. This changes
        // only first-observation order, never closure membership or old offsets.
        for &root in roots {
            if !selected.contains(&CollectionRecordSelector::Collection(
                CollectionHandle::new(root),
            )) && resident.contains(&root)
            {
                self.observe(root, root);
            }
        }
        for selector in selected {
            if let CollectionRecordSelector::Collection(collection) = selector {
                let root = collection.raw;
                if roots.contains(&root) && resident.contains(&root) {
                    self.observe(root, root);
                }
            }
        }
    }

    fn observe(&mut self, root: RawHash, source: RawHash) {
        let mut key = [0; 64];
        key[..32].copy_from_slice(&root);
        key[32..].copy_from_slice(&source);
        if self.sources.get(&key).is_none() {
            self.sources.insert(&PatchEntry::with_value(
                &key,
                SourceProgress {
                    offset: 0,
                    startup_left: SCAN_STARTUP_WORDS,
                    last_scan: None,
                    backoff: Duration::ZERO,
                },
            ));
            self.recent.push(key);
        }
    }

    fn next(&mut self) -> ScanStep {
        if let Some(cursor) = self.cursor {
            return ScanStep::Ready(cursor);
        }
        if self.sources.is_empty() {
            return ScanStep::Idle;
        }
        let recent =
            self.prefer_recent && (self.recent_active.is_some() || !self.recent.is_empty());
        self.prefer_recent = !self.prefer_recent;
        let key = if recent {
            match self.recent_active {
                Some(key) => key,
                None => {
                    let key = self.recent.pop().expect("nonempty recent lane");
                    self.recent_active = Some(key);
                    key
                }
            }
        } else {
            let pass = self.pass.get_or_insert_with(|| self.sources.clone());
            let next = match self.after {
                Some(after) => pass.next_infix_after(&[], &after, &[u8::MAX; 64]),
                None => pass.first_infix_range(&[], &[0; 64], &[u8::MAX; 64]),
            };
            let Some(key) = next else {
                self.after = None;
                self.pass = None;
                return ScanStep::Skip;
            };
            self.after = Some(key);
            key
        };
        let Some(progress) = self.sources.get(&key) else {
            if recent {
                self.recent_active = None;
            }
            return ScanStep::Skip;
        };
        if recent && progress.startup_left == 0 {
            self.recent_active = None;
            return ScanStep::Skip;
        }
        if progress
            .last_scan
            .is_some_and(|last| crate::clock::mono_now().duration_since(last) < progress.backoff)
        {
            return ScanStep::Skip;
        }
        let cursor = ScanCursor {
            key,
            offset: progress.offset,
            words: 0,
            recent,
        };
        self.cursor = Some(cursor);
        ScanStep::Ready(cursor)
    }

    fn advance(&mut self) {
        let cursor = self.cursor.as_mut().expect("active scan");
        cursor.offset += 32;
        cursor.words += 1;
        // The per-source startup allowance also bounds a partial local-word
        // quantum; this does not change collection or global request limits.
        if cursor.words >= SCAN_WORDS_PER_QUANTUM
            || (cursor.recent
                && cursor.words
                    >= self
                        .sources
                        .get(&cursor.key)
                        .expect("positive source")
                        .startup_left)
        {
            self.yield_source();
        }
    }

    fn yield_source(&mut self) {
        let Some(cursor) = self.cursor.filter(|cursor| cursor.words != 0) else {
            return;
        };
        debug_assert!(!cursor.recent || self.recent_active == Some(cursor.key));
        self.cursor = None;
        let mut progress = *self.sources.get(&cursor.key).expect("positive source");
        progress.offset = cursor.offset;
        progress.startup_left = progress.startup_left.saturating_sub(cursor.words);
        self.sources
            .replace(&PatchEntry::with_value(&cursor.key, progress));
        if progress.startup_left == 0 && self.recent_active == Some(cursor.key) {
            self.recent_active = None;
        }
    }

    fn finish_source(&mut self, initial: Duration, max: Duration) {
        let cursor = self.cursor.take().expect("active scan");
        if self.recent_active == Some(cursor.key) {
            self.recent_active = None;
        }
        let mut progress = *self.sources.get(&cursor.key).expect("positive source");
        progress.offset = 0;
        progress.startup_left = 0;
        progress.last_scan = Some(crate::clock::mono_now());
        progress.backoff = if progress.backoff.is_zero() {
            initial
        } else {
            progress.backoff.saturating_mul(2).min(max)
        };
        self.sources
            .replace(&PatchEntry::with_value(&cursor.key, progress));
    }
}

fn direct_roots<R>(
    snapshot: &R,
    selectors: &BTreeSet<CollectionRecordSelector>,
) -> Result<BTreeSet<RawHash>, R::RecordsError>
where
    R: CollectionRead,
{
    let mut roots = BTreeSet::new();
    for record in snapshot.select_records(selectors)? {
        // Records are trusted local evidence; foreign signatures were checked
        // at ingress. WRITE admission does not govern structural ownership.
        roots.extend(record.blob_references().map(|handle| handle.raw));
    }
    Ok(roots)
}

async fn fetch_and_land<S>(peer: &mut Peer<S>, handle: RawHash, budget: Duration) -> Option<()>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    let verified = peer.fetch_verified_with_deadline(handle, budget).await?;
    land_exact(peer, verified)
}

fn land_exact<S>(peer: &Peer<S>, verified: VerifiedBlob) -> Option<()>
where
    S: BlobStore
        + CollectionStore
        + CapabilityProofStore
        + WantStore
        + StorageFlush
        + Send
        + 'static,
    S::Snapshot: StoreRead + BlobChildren,
{
    let landing = {
        let mut store = peer.store();
        // Verified on the wire and matched against the requested handle at
        // the capability boundary; it lands under that handle without a
        // second hash.
        match store.put::<UnknownBlob, _>(verified.into_blob()) {
            Ok(_) => store
                .flush()
                .map_err(|error| format!("flush failed: {error:?}")),
            Err(error) => Err(format!("put failed: {error:?}")),
        }
    };
    if let Err(error) = landing {
        tracing::warn!(%error, "exact blob landing failed; acquisition remains unfinished");
        return None;
    }
    Some(())
}

fn answered_operations<R>(
    snapshot: &R,
    selectors: &BTreeSet<CollectionRecordSelector>,
) -> Result<HashSet<WantRequest>, R::RecordsError>
where
    R: CollectionRead,
{
    Ok(snapshot
        .select_records(selectors)?
        .into_iter()
        .filter_map(want_request_for_record)
        .collect())
}

fn want_request_for_record(record: CollectionRecord) -> Option<WantRequest> {
    match record {
        CollectionRecord::Commit(_) => None,
        CollectionRecord::Merge(merge) => {
            let (low, high) = merge.inputs();
            Some(WantRequest::merge(merge.collection(), low, high))
        }
        CollectionRecord::Derive(derive) => {
            Some(WantRequest::derive(derive.collection(), derive.input()))
        }
    }
}

#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.
    fn witnessed(
        signer: &ed25519_dalek::SigningKey,
        collection: triblespace_core::collection::CollectionHandle,
        data: triblespace_core::collection::CollectionData,
    ) -> (
        triblespace_core::collection::CollectionData,
        triblespace_core::collection::CollectionRecordFingerprint,
    ) {
        let record = triblespace_core::collection::CollectionCommit::sign(
            signer,
            collection,
            data,
            triblespace_core::collection::empty_metadata_handle(),
        );
        (data, record.fingerprint())
    }

    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use triblespace_core::blob::{BlobEncoding, IntoBlob};
    use triblespace_core::capability::CapabilityProof;
    use triblespace_core::collection::{CollectionCommit, CollectionDerive, CollectionMerge};
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::inline::{Inline, InlineEncoding};
    use triblespace_core::repo::BlobStorePut;
    use triblespace_core::repo::memoryrepo::MemoryRepo;

    // Scheduling tokens only; no record or blob is published by these tests.
    fn scheduled_handle(class: u8, ordinal: u32) -> RawHash {
        let mut handle = [0; 32];
        handle[0] = class;
        handle[1..5].copy_from_slice(&ordinal.to_be_bytes());
        handle
    }

    #[test]
    fn fresh_missing_root_bypasses_31k_startup_roots_without_renewing_priority() {
        let mut reconciler = Reconciler::with_backoff(Duration::ZERO, Duration::ZERO);
        let mut roots: BTreeSet<_> = (0..31_000)
            .map(|ordinal| scheduled_handle(10, ordinal))
            .collect();
        let wanted = BTreeSet::new();
        reconciler.observe_missing(&wanted, &roots);
        let startup_generation = reconciler.observation_generation;
        reconciler.root_round.generation = startup_generation;
        reconciler.root_round.after = Some(scheduled_handle(9, 0));

        // This root arrives after the startup observation, behind the cursor.
        let fresh = scheduled_handle(8, 0);
        roots.insert(fresh);
        reconciler.observe_missing(&wanted, &roots);
        let (turn, candidates) = reconciler
            .next_work(&wanted, &roots, crate::clock::mono_now())
            .unwrap();
        assert_eq!(turn, ServiceTurn::FreshRoots);
        assert_eq!(candidates[0], fresh);
        assert!(reconciler.states[&fresh].first_root_attempt);
        // Selection alone does not spend the attempt: a deadline can expire
        // before the request starts.
        let first_seen = reconciler.states[&fresh].root_since;
        reconciler.begin_attempt(turn, fresh);
        reconciler.record_unavailable(fresh);
        reconciler.observe_missing(&wanted, &roots);
        assert_eq!(reconciler.states[&fresh].root_since, first_seen);
        assert!(!reconciler.states[&fresh].first_root_attempt);

        reconciler.next_service = ServiceTurn::FreshRoots;
        let (turn, candidates) = reconciler
            .next_work(&wanted, &roots, crate::clock::mono_now())
            .unwrap();
        assert_eq!(turn, ServiceTurn::FreshRoots);
        assert!(!candidates.contains(&fresh));
        assert_eq!(candidates.len(), 31_000);
    }

    #[test]
    fn service_turns_preserve_old_rounds_wants_and_scans_during_continuous_arrival() {
        let mut reconciler = Reconciler::with_backoff(Duration::ZERO, Duration::ZERO)
            .with_replication(
                ReplicationMode::Full,
                [Inline::new(scheduled_handle(30, 0))],
            );
        let old_roots: BTreeSet<_> = (0..64)
            .map(|ordinal| scheduled_handle(10, ordinal))
            .collect();
        let old_wants: BTreeSet<_> = (0..7)
            .map(|ordinal| scheduled_handle(20, ordinal))
            .collect();
        let mut roots = old_roots.clone();
        let mut wanted = old_wants.clone();
        reconciler.observe_missing(&wanted, &roots);
        reconciler.root_round.generation = reconciler.observation_generation;
        reconciler.want_round.generation = reconciler.observation_generation;
        // A resident source remains eligible for scanner service throughout.
        reconciler.scan.lanes[0]
            .1
            .observe(scheduled_handle(30, 0), scheduled_handle(30, 1));

        let mut regular = Vec::new();
        let mut want_attempts = Vec::new();
        let mut scans = 0;
        let mut fresh = 0;
        for quantum in 0..64 * 4 {
            roots.insert(scheduled_handle(9, quantum));
            wanted.insert(scheduled_handle(19, quantum));
            reconciler.observe_missing(&wanted, &roots);
            let (turn, candidates) = reconciler
                .next_work(&wanted, &roots, crate::clock::mono_now())
                .unwrap();
            assert_eq!(
                turn,
                [
                    ServiceTurn::Wants,
                    ServiceTurn::FreshRoots,
                    ServiceTurn::Roots,
                    ServiceTurn::Scan,
                ][quantum as usize % 4],
                "one request may exhaust a quantum, but cannot erase the next class's turn",
            );
            if turn == ServiceTurn::Scan {
                assert!(candidates.is_empty());
                scans += 1;
                continue;
            }
            let handle = candidates[0];
            reconciler.begin_attempt(turn, handle);
            reconciler.record_unavailable(handle);
            match turn {
                ServiceTurn::Wants => want_attempts.push(handle),
                ServiceTurn::FreshRoots => fresh += 1,
                ServiceTurn::Roots => regular.push(handle),
                ServiceTurn::Scan => unreachable!(),
            }
        }
        assert_eq!(regular, old_roots.into_iter().collect::<Vec<_>>());
        assert_eq!(
            &want_attempts[..old_wants.len()],
            old_wants.into_iter().collect::<Vec<_>>(),
        );
        assert_eq!(scans, 64);
        assert_eq!(fresh, 64);
    }

    #[test]
    fn roots_in_backoff_yield_to_scanning_and_keep_their_retry_deadline() {
        let mut reconciler =
            Reconciler::with_backoff(Duration::from_secs(60), Duration::from_secs(60))
                .with_replication(
                    ReplicationMode::Full,
                    [Inline::new(scheduled_handle(30, 0))],
                );
        let root = scheduled_handle(10, 0);
        let roots = BTreeSet::from([root]);
        let wanted = BTreeSet::from([root]);
        reconciler.observe_missing(&wanted, &BTreeSet::new());
        reconciler.begin_attempt(ServiceTurn::Wants, root);
        reconciler.record_unavailable(root);
        // The same H becomes a selected root while its WANT attempt is still
        // in cooldown. Fresh-root priority must not bypass that shared delay.
        reconciler.observe_missing(&wanted, &roots);
        let last_attempt = reconciler.states[&root].last_attempt;
        reconciler.scan.lanes[0].1.observe(root, root);
        reconciler.next_service = ServiceTurn::Wants;
        let (turn, _) = reconciler
            .next_work(&wanted, &roots, crate::clock::mono_now())
            .unwrap();
        assert_eq!(turn, ServiceTurn::Scan);
        assert_eq!(reconciler.states[&root].last_attempt, last_attempt);
        assert_eq!(reconciler.states[&root].backoff, Duration::from_secs(60));
        assert!(reconciler.states[&root].first_root_attempt);
    }

    struct FailingCollectionRead;

    impl CollectionRead for FailingCollectionRead {
        type RecordsError = std::io::Error;
        type RecordIter<'a> = std::vec::IntoIter<Result<CollectionRecord, Self::RecordsError>>;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            Err(std::io::Error::other("collection observation failed"))
        }
    }

    #[test]
    fn operation_observation_failure_aborts_projection() {
        let collection = Inline::new([1; 32]);
        let a = Inline::new([2; 32]);
        let b = Inline::new([3; 32]);
        let selectors = BTreeSet::from([CollectionRecordSelector::Operation(WantRequest::merge(
            collection, a, b,
        ))]);

        let error = answered_operations(&FailingCollectionRead, &selectors).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn receipts_project_to_exact_input_only_wants() {
        let collection = Inline::new([1; 32]);
        let target = Inline::new([2; 32]);
        let a = Inline::new([3; 32]);
        let b = Inline::new([4; 32]);
        let result = Inline::new([5; 32]);
        assert_eq!(
            want_request_for_record(CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection,
                witnessed(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    collection,
                    b
                ),
                witnessed(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    collection,
                    a
                ),
                result,
            ))),
            Some(WantRequest::merge(collection, a, b))
        );
        assert_eq!(
            want_request_for_record(CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                target,
                witnessed(&ed25519_dalek::SigningKey::from_bytes(&[7; 32]), target, a),
                result,
            ))),
            Some(WantRequest::derive(target, a))
        );
    }

    #[test]
    fn hydration_roots_use_selected_structural_records_without_loading_descriptors() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let collection = Inline::new([1; 32]);
        let other = Inline::new([9; 32]);
        let mut store = MemoryRepo::default();
        for record in [
            CollectionRecord::Commit(CollectionCommit::sign(
                &key,
                collection,
                Inline::new([2; 32]),
                Inline::new([3; 32]),
            )),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection,
                witnessed(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    collection,
                    Inline::new([4; 32]),
                ),
                witnessed(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    collection,
                    Inline::new([5; 32]),
                ),
                Inline::new([6; 32]),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection,
                witnessed(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    collection,
                    Inline::new([6; 32]),
                ),
                Inline::new([7; 32]),
            )),
            CollectionRecord::Commit(CollectionCommit::sign(
                &key,
                other,
                Inline::new([10; 32]),
                Inline::new([11; 32]),
            )),
        ] {
            store.insert(record).unwrap();
        }
        let snapshot = store.snapshot().unwrap();
        let selectors = BTreeSet::from([CollectionRecordSelector::Collection(collection)]);
        assert_eq!(
            direct_roots(&snapshot, &selectors).unwrap(),
            (1..=7).map(|byte| [byte; 32]).collect(),
        );
        assert!(
            direct_roots(&snapshot, &BTreeSet::new())
                .unwrap()
                .is_empty()
        );
        assert!(direct_roots(&FailingCollectionRead, &selectors).is_err());
    }

    fn next_ready(scan: &mut FullScan) -> ScanCursor {
        for _ in 0..20_000 {
            match scan.next() {
                ScanStep::Ready(cursor) => return cursor,
                ScanStep::Skip => {}
                ScanStep::Idle => panic!("expected positive work"),
            }
        }
        panic!("positive work did not receive service");
    }

    fn scan_key(root: RawHash, source: RawHash) -> [u8; 64] {
        let mut key = [0; 64];
        key[..32].copy_from_slice(&root);
        key[32..].copy_from_slice(&source);
        key
    }

    fn next_selection(scan: &mut SelectionScans) -> ScanCursor {
        for _ in 0..20_000 {
            match scan.next() {
                ScanStep::Ready(cursor) => return cursor,
                ScanStep::Skip => {}
                ScanStep::Idle => panic!("expected positive selection work"),
            }
        }
        panic!("selection did not receive service");
    }

    #[test]
    fn selection_scans_sustain_all_28_lanes_beyond_the_startup_window() {
        let mut scans = SelectionScans::new(
            (1_u8..=28).map(|byte| CollectionRecordSelector::Collection(Inline::new([byte; 32]))),
        );
        for ordinal in 0_u32..4_096 {
            let mut source = [0; 32];
            source[..4].copy_from_slice(&ordinal.to_be_bytes());
            scans.lanes[0].1.observe([1; 32], source);
        }
        for byte in 2_u8..=28 {
            scans.lanes[usize::from(byte - 1)]
                .1
                .observe([byte; 32], [byte; 32]);
        }
        let mut words = [0; 28];
        for _ in 0..28 * 300 {
            let cursor = next_selection(&mut scans);
            words[scans.last_lane] += 1;
            if cursor.handles().0 == [2; 32] {
                assert_eq!(cursor.offset, (words[1] - 1) * 32);
            }
            scans.advance();
            // One network attempt/deadline exit is one completed quantum.
            scans.yield_source();
        }
        assert!(words.iter().all(|words| *words > SCAN_STARTUP_WORDS));
        let old_sources = &scans.lanes[0].1.sources;
        assert!(
            old_sources
                .iter()
                .filter(|key| old_sources.get(*key).unwrap().offset > 0)
                .count()
                > 64
        );
    }

    #[test]
    fn selection_scans_keep_deadline_turns_and_attach_children_to_the_parent_lane() {
        let selectors =
            [1_u8, 2].map(|byte| CollectionRecordSelector::Collection(Inline::new([byte; 32])));
        let mut scans = SelectionScans::new(selectors);
        for byte in [1_u8, 2] {
            scans.lanes[usize::from(byte - 1)]
                .1
                .observe([byte; 32], [byte; 32]);
        }
        assert_eq!(next_selection(&mut scans).handles().0, [1; 32]);
        scans.advance();
        scans.yield_source();
        let owed = next_selection(&mut scans);
        assert_eq!(owed.handles().0, [2; 32]);
        // Global quota/deadline expired before attempting this word.
        scans.yield_source();
        assert_eq!(next_selection(&mut scans).key, owed.key);
        assert_eq!(next_selection(&mut scans).offset, owed.offset);
        for _ in 0..SCAN_WORDS_PER_QUANTUM {
            scans.advance();
        }
        assert!(scans.active.is_none());
        // A resident child on the last word of a quantum still belongs to B.
        scans.observe([2; 32], [3; 32]);
        assert!(
            scans.lanes[1]
                .1
                .sources
                .get(&scan_key([2; 32], [3; 32]))
                .is_some()
        );
        assert!(
            scans.lanes[0]
                .1
                .sources
                .get(&scan_key([2; 32], [3; 32]))
                .is_none()
        );
        assert_eq!(next_selection(&mut scans).handles().0, [1; 32]);
    }

    #[test]
    fn full_scan_regular_rounds_preserve_offsets_and_yield_before_eof() {
        let mut scan = FullScan::default();
        let root = [5; 32];
        scan.observe(root, [20; 32]);
        scan.observe(root, [30; 32]);
        scan.recent.clear();
        let first = next_ready(&mut scan);
        assert_eq!(first.handles(), (root, [20; 32]));
        for _ in 0..SCAN_WORDS_PER_QUANTUM {
            scan.advance();
        }
        assert!(
            scan.cursor.is_none(),
            "a large source must yield before EOF"
        );
        assert_eq!(next_ready(&mut scan).handles(), (root, [30; 32]));
        scan.advance();
        scan.yield_source();
        let resumed = next_ready(&mut scan);
        assert_eq!(resumed.handles(), (root, [20; 32]));
        assert_eq!(resumed.offset, SCAN_WORDS_PER_QUANTUM * 32);
    }

    #[test]
    fn full_scan_recent_descriptor_gets_a_window_beyond_its_first_word() {
        let mut scan = FullScan::default();
        let old = [1; 32];
        for ordinal in 0_u32..4_096 {
            let mut source = [0; 32];
            source[..4].copy_from_slice(&ordinal.to_be_bytes());
            scan.observe(old, source);
        }
        next_ready(&mut scan);
        scan.advance();
        scan.yield_source();
        // This newly observed descriptor sorts after the entire frozen round.
        let descriptor = [250; 32];
        scan.observe(descriptor, descriptor);
        let mut descriptor_offsets = Vec::new();
        let mut regular_turns = 0;
        for _ in 0..16 {
            let cursor = next_ready(&mut scan);
            if cursor.handles() == (descriptor, descriptor) {
                descriptor_offsets.push(cursor.offset);
            } else {
                regular_turns += 1;
            }
            // One speculative request per turn, including deadline exits.
            scan.advance();
            scan.yield_source();
        }
        assert_eq!(
            descriptor_offsets,
            (0..8).map(|word| word * 32).collect::<Vec<_>>(),
            "a name in word eight must not wait behind the old root backlog",
        );
        assert_eq!(regular_turns, 8);
    }

    #[test]
    fn full_scan_started_window_survives_arrivals_and_expires_without_taking_regular_turns() {
        let mut scan = FullScan::default();
        let old = scheduled_handle(1, 0);
        for ordinal in 0..4_096 {
            scan.observe(old, scheduled_handle(2, ordinal));
        }
        scan.recent.clear();
        // Freeze an old round which does not contain the incoming message.
        let first = next_ready(&mut scan);
        assert_eq!(first.handles(), (old, scheduled_handle(2, 0)));
        scan.advance();
        scan.yield_source();

        let message = scheduled_handle(250, 0);
        scan.observe(message, message);
        let first_word = next_ready(&mut scan);
        assert!(first_word.recent);
        assert_eq!(first_word.handles(), (message, message));
        assert_eq!(first_word.offset, 0);
        scan.advance();
        scan.yield_source();

        let mut regular_turns = 0;
        for word in 1..SCAN_STARTUP_WORDS {
            // A fresh positive source arrives between every startup grant.
            // It must not push the already-started message's next word behind
            // thousands of ordinary sources or a growing newest-first stack.
            let arrival = scheduled_handle(251, word as u32);
            scan.observe(arrival, arrival);
            let regular = next_ready(&mut scan);
            assert!(!regular.recent);
            assert_eq!(regular.handles(), (old, scheduled_handle(2, word as u32)));
            scan.advance();
            scan.yield_source();
            regular_turns += 1;

            let resumed = next_ready(&mut scan);
            assert!(resumed.recent);
            assert_eq!(resumed.handles(), (message, message));
            assert_eq!(resumed.offset, word * 32);
            scan.advance();
            scan.yield_source();
        }
        assert_eq!(regular_turns, SCAN_STARTUP_WORDS - 1);
        assert_eq!(
            scan.sources
                .get(&scan_key(message, message))
                .unwrap()
                .startup_left,
            0
        );

        // Exhausting the existing allowance releases the startup position;
        // the next grant goes to the newest still-unstarted arrival.
        let regular = next_ready(&mut scan);
        assert!(!regular.recent);
        assert_eq!(
            regular.handles(),
            (old, scheduled_handle(2, SCAN_STARTUP_WORDS as u32))
        );
        scan.advance();
        scan.yield_source();
        let next = next_ready(&mut scan);
        let newest = scheduled_handle(251, (SCAN_STARTUP_WORDS - 1) as u32);
        assert!(next.recent);
        assert_eq!(next.handles(), (newest, newest));
        assert_eq!(next.offset, 0);
    }

    #[test]
    fn full_scan_started_window_caps_partial_resident_quanta_at_128_words() {
        let mut scan = FullScan::default();
        let old = scheduled_handle(1, 0);
        for ordinal in 0..4 {
            scan.observe(old, scheduled_handle(2, ordinal));
        }
        scan.recent.clear();
        next_ready(&mut scan);
        scan.advance();
        scan.yield_source();
        let source = scheduled_handle(3, 0);
        scan.observe(source, source);
        let mut offset = 0;
        for words in [
            1,
            SCAN_WORDS_PER_QUANTUM,
            SCAN_STARTUP_WORDS - SCAN_WORDS_PER_QUANTUM - 1,
        ] {
            let recent = next_ready(&mut scan);
            assert!(recent.recent);
            assert_eq!(recent.handles(), (source, source));
            assert_eq!(recent.offset, offset);
            for _ in 0..words {
                scan.advance();
                offset += 32;
            }
            if words == 1 {
                // A speculative request interrupts the first quantum. Later
                // resident/filtered words must use only the remaining budget.
                scan.yield_source();
            }
            assert!(scan.cursor.is_none());
            if offset < SCAN_STARTUP_WORDS * 32 {
                let regular = next_ready(&mut scan);
                assert!(!regular.recent);
                assert_eq!(regular.handles().0, old);
                scan.advance();
                scan.yield_source();
            }
        }
        assert_eq!(offset, SCAN_STARTUP_WORDS * 32);
        assert_eq!(
            scan.sources
                .get(&scan_key(source, source))
                .unwrap()
                .startup_left,
            0
        );
    }

    #[test]
    fn selection_scan_started_window_releases_on_eof_or_unavailable_source() {
        for unavailable in [false, true] {
            let selector = CollectionRecordSelector::Collection(Inline::new([1; 32]));
            let mut scans = SelectionScans::new([selector]);
            let old = scheduled_handle(1, 0);
            let source = scheduled_handle(2, 0);
            let arrival = scheduled_handle(3, 0);
            scans.lanes[0].1.observe(old, old);
            scans.lanes[0].1.observe(source, source);
            // Ordinary work starts the round, then the second source starts
            // a recent window. Both lanes share that source's exact offset.
            assert_eq!(next_selection(&mut scans).handles(), (old, old));
            scans.advance();
            scans.yield_source();
            let recent = next_selection(&mut scans);
            assert!(recent.recent);
            assert_eq!(recent.handles(), (source, source));
            scans.advance();
            scans.yield_source();
            scans.lanes[0].1.observe(arrival, arrival);

            let regular = next_selection(&mut scans);
            assert!(!regular.recent);
            assert_eq!(regular.handles(), (source, source));
            assert_eq!(regular.offset, 32);
            if unavailable {
                scans.forget_source(&regular.key);
                assert!(scans.lanes[0].1.sources.get(&regular.key).is_none());
            } else {
                // A 32-byte source reaches EOF during its ordinary turn.
                // Completion there must also release its recent reservation.
                scans.finish_source(Duration::from_secs(60), Duration::from_secs(60));
                let progress = scans.lanes[0].1.sources.get(&regular.key).unwrap();
                assert_eq!(progress.startup_left, 0);
                assert_eq!(progress.offset, 0);
                assert!(progress.last_scan.is_some());
            }
            let next = next_selection(&mut scans);
            assert!(next.recent);
            assert_eq!(next.handles(), (arrival, arrival));
            assert_eq!(next.offset, 0);
        }
    }

    #[test]
    fn full_scan_recent_cohort_spends_finite_windows_without_taking_regular_turns() {
        let mut scan = FullScan::default();
        for ordinal in 0_u32..1_024 {
            let mut source = [0; 32];
            source[..4].copy_from_slice(&ordinal.to_be_bytes());
            scan.observe([1; 32], source);
        }
        scan.recent.clear();
        next_ready(&mut scan);
        scan.advance();
        scan.yield_source();
        scan.observe([2; 32], [2; 32]);
        scan.observe([3; 32], [3; 32]);
        let mut recent_roots = Vec::new();
        let mut regular_turns = 0;
        for _ in 0..SCAN_STARTUP_WORDS * 4 {
            let cursor = next_ready(&mut scan);
            if cursor.recent {
                recent_roots.push(cursor.handles().0[0]);
            } else {
                regular_turns += 1;
                assert_eq!(cursor.handles().0, [1; 32]);
            }
            scan.advance();
            scan.yield_source();
        }
        assert_eq!(regular_turns, SCAN_STARTUP_WORDS * 2);
        assert_eq!(
            recent_roots,
            [vec![3; SCAN_STARTUP_WORDS], vec![2; SCAN_STARTUP_WORDS]].concat(),
            "newest-first is a finite window per arrival, not cohort round-robin",
        );
        assert!(scan.recent.is_empty());
    }

    #[test]
    fn full_scan_startup_descriptors_reach_word_28_without_requeueing_or_widening_roots() {
        let descriptor = [128; 32];
        let missing_descriptor = [129; 32];
        let unrelated_descriptor = [130; 32];
        let selected = [descriptor, missing_descriptor, unrelated_descriptor]
            .map(|root| CollectionRecordSelector::Collection(CollectionHandle::new(root)))
            .into_iter()
            .collect();
        let mut roots = BTreeSet::from([descriptor, missing_descriptor, [255; 32]]);
        for ordinal in 0_u32..4_096 {
            let mut root = [0; 32];
            root[..4].copy_from_slice(&ordinal.to_be_bytes());
            roots.insert(root);
        }
        let mut resident: HashSet<_> = roots.iter().copied().collect();
        resident.remove(&missing_descriptor);
        resident.insert(unrelated_descriptor);
        let mut scan = FullScan::default();
        scan.observe_roots(&roots, &selected, &resident);
        assert_eq!(scan.sources.len(), roots.len() as u64 - 1);
        assert!(
            scan.sources
                .get(&scan_key(unrelated_descriptor, unrelated_descriptor))
                .is_none()
        );
        let mut descriptor_words = Vec::new();
        let mut regular_turns = 0;
        for _ in 0..64 {
            // Identical snapshots must not reset progress or push descriptors
            // back above an owed regular turn.
            scan.observe_roots(&roots, &selected, &resident);
            let cursor = next_ready(&mut scan);
            if cursor.handles().0 == descriptor {
                descriptor_words.push(cursor.offset / 32);
            } else {
                regular_turns += 1;
            }
            scan.advance();
            scan.yield_source();
        }
        assert_eq!(descriptor_words, (0..32).collect::<Vec<_>>());
        assert!(
            descriptor_words.contains(&27),
            "the model name sits in word 28"
        );
        assert_eq!(regular_turns, 32);
        // A completed descriptor is not promoted again by a steady snapshot.
        let cursor = next_ready(&mut scan);
        scan.advance();
        scan.yield_source();
        assert_ne!(cursor.handles().0, descriptor);
        assert_eq!(next_ready(&mut scan).handles().0, descriptor);
        scan.finish_source(Duration::from_secs(60), Duration::from_secs(60));
        scan.observe_roots(&roots, &selected, &resident);
        assert!(!scan.recent.contains(&scan_key(descriptor, descriptor)));
        assert_eq!(
            scan.sources
                .get(&scan_key(descriptor, descriptor))
                .unwrap()
                .startup_left,
            0
        );
    }

    #[test]
    fn full_scan_request_deadline_and_untouched_quota_word_keep_the_owed_turn() {
        let mut scan = FullScan::default();
        scan.observe([1; 32], [1; 32]);
        scan.observe([2; 32], [2; 32]);
        let first = next_ready(&mut scan);
        // A quota exit before examining this word must not silently skip it.
        scan.yield_source();
        assert_eq!(next_ready(&mut scan).key, first.key);
        assert_eq!(next_ready(&mut scan).offset, 0);
        scan.advance();
        // tick does this BEFORE awaiting a request that can use all its time.
        scan.yield_source();
        assert!(scan.prefer_recent);
        assert_eq!(next_ready(&mut scan).handles(), ([2; 32], [2; 32]));
        scan.advance();
        scan.yield_source();
        // A new arrival cannot steal the regular turn owed after the timeout.
        scan.observe([3; 32], [3; 32]);
        assert!(!scan.prefer_recent);
        let regular = next_ready(&mut scan);
        assert_eq!(regular.handles(), ([2; 32], [2; 32]));
        assert_eq!(regular.offset, 32, "recent and regular share one offset");
    }

    #[test]
    fn full_scan_global_request_cap_preserves_the_next_unattempted_word() {
        let mut scan = FullScan::default();
        scan.observe([1; 32], [1; 32]);
        scan.observe([2; 32], [2; 32]);
        for _ in 0..RECONCILE_SPECULATIVE_FETCHES_PER_TICK {
            next_ready(&mut scan);
            scan.advance();
            scan.yield_source();
        }
        let pending = next_ready(&mut scan);
        assert_eq!(pending.words, 0);
        scan.yield_source();
        let next_tick = next_ready(&mut scan);
        assert_eq!(next_tick.key, pending.key);
        assert_eq!(next_tick.offset, pending.offset);
        scan.advance();
        scan.yield_source();
        assert_eq!(
            scan.sources.get(&pending.key).unwrap().offset,
            pending.offset + 32,
        );
    }

    #[test]
    fn full_scan_arrivals_do_not_postpone_partial_work_or_completed_parent_revisits() {
        let mut scan = FullScan::default();
        scan.observe([1; 32], [1; 32]);
        scan.observe([2; 32], [2; 32]);
        scan.recent.clear();
        let mut partial_turns = 0;
        let mut parent_visits = 0;
        for ordinal in 3_u8..80 {
            scan.observe([ordinal; 32], [ordinal; 32]);
            let cursor = next_ready(&mut scan);
            match cursor.handles().0[0] {
                1 => partial_turns += 1,
                2 => {
                    parent_visits += 1;
                    assert_eq!(cursor.offset, 0);
                    scan.finish_source(Duration::ZERO, Duration::ZERO);
                    continue;
                }
                _ => {}
            }
            scan.advance();
            scan.yield_source();
        }
        assert!(
            partial_turns >= 2,
            "large sources keep advancing under arrivals"
        );
        assert!(parent_visits >= 2, "EOF is not a permanent closed edge");
    }

    fn local_peer(store: MemoryRepo) -> Peer<MemoryRepo> {
        Peer::lazy(
            store,
            SigningKey::from_bytes(&[7; 32]),
            crate::host::PeerConfig {
                peers: Vec::new(),
                qos: crate::inventory::ReconcileQos::default(),
                provider_publication_budget: Some(0),
            },
        )
    }

    fn put(store: &mut MemoryRepo, bytes: impl Into<Vec<u8>>) -> RawHash {
        store
            .put::<UnknownBlob, _>(Bytes::from_source(bytes.into()))
            .unwrap()
            .raw
    }

    fn raw_commit(store: &mut MemoryRepo, descriptor: RawHash, data: RawHash, metadata: RawHash) {
        store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &SigningKey::from_bytes(&[7; 32]),
                Inline::new(descriptor),
                Inline::new(data),
                Inline::new(metadata),
            )))
            .unwrap();
    }

    #[derive(Default)]
    struct LandingTrace {
        put: Vec<RawHash>,
        unflushed: BTreeSet<RawHash>,
        durable: BTreeSet<RawHash>,
        fail_flush: bool,
    }

    struct LandingStore {
        inner: MemoryRepo,
        trace: Arc<Mutex<LandingTrace>>,
    }

    impl SnapshotSource for LandingStore {
        type Snapshot = <MemoryRepo as SnapshotSource>::Snapshot;
        type SnapshotError = <MemoryRepo as SnapshotSource>::SnapshotError;

        fn snapshot_at(
            &mut self,
            instant: hifitime::Epoch,
        ) -> Result<Self::Snapshot, Self::SnapshotError> {
            self.inner.snapshot_at(instant)
        }
    }

    impl BlobStorePut for LandingStore {
        type PutError = <MemoryRepo as BlobStorePut>::PutError;

        fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
        where
            E: BlobEncoding + 'static,
            T: IntoBlob<E>,
            Handle<E>: InlineEncoding,
        {
            let handle = self.inner.put(item)?;
            let mut trace = self.trace.lock().unwrap();
            trace.put.push(handle.raw);
            trace.unflushed.insert(handle.raw);
            Ok(handle)
        }
    }

    impl CollectionStore for LandingStore {
        type InsertError = <MemoryRepo as CollectionStore>::InsertError;

        fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
            self.inner.insert(record)
        }
    }

    impl CapabilityProofStore for LandingStore {
        type InsertError = <MemoryRepo as CapabilityProofStore>::InsertError;

        fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
            self.inner.insert_proof(proof)
        }
    }

    impl WantStore for LandingStore {
        type WantError = <MemoryRepo as WantStore>::WantError;

        fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
            self.inner.want(request)
        }
    }

    impl StorageFlush for LandingStore {
        type Error = std::io::Error;

        fn flush(&mut self) -> Result<(), Self::Error> {
            let mut trace = self.trace.lock().unwrap();
            if trace.fail_flush {
                return Err(std::io::Error::other("test durability barrier failed"));
            }
            let landed = std::mem::take(&mut trace.unflushed);
            trace.durable.extend(landed);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FetchTrace {
        calls: Vec<RawHash>,
        active: usize,
        peak: usize,
        cancelled: usize,
    }

    struct FetchGuard {
        trace: Arc<Mutex<FetchTrace>>,
        completed: bool,
    }

    impl Drop for FetchGuard {
        fn drop(&mut self) {
            let mut trace = self.trace.lock().unwrap();
            trace.active -= 1;
            trace.cancelled += usize::from(!self.completed);
        }
    }

    struct ControlledFetches {
        answers: BTreeMap<RawHash, Bytes>,
        blocked: BTreeSet<RawHash>,
        delay: Mutex<Duration>,
        released: Arc<AtomicBool>,
        wake: Arc<tokio::sync::Notify>,
        trace: Arc<Mutex<FetchTrace>>,
    }

    impl ControlledFetches {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.wake.notify_waiters();
        }
    }

    impl crate::host::NetCapability for ControlledFetches {
        fn fetch_blob(
            &self,
            hash: RawHash,
        ) -> futures::future::BoxFuture<'static, Option<crate::protocol::VerifiedBlob>> {
            let answer = self.answers.get(&hash).cloned();
            let blocked = self.blocked.contains(&hash);
            let delay = *self.delay.lock().unwrap();
            let released = self.released.clone();
            let wake = self.wake.clone();
            let trace = self.trace.clone();
            Box::pin(async move {
                {
                    let mut trace = trace.lock().unwrap();
                    trace.calls.push(hash);
                    trace.active += 1;
                    trace.peak = trace.peak.max(trace.active);
                }
                let mut guard = FetchGuard {
                    trace,
                    completed: false,
                };
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if blocked {
                    let notified = wake.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if !released.load(Ordering::SeqCst) {
                        notified.await;
                    }
                }
                guard.completed = true;
                answer.and_then(|bytes| crate::protocol::VerifiedBlob::verify(bytes, hash))
            })
        }
    }

    fn controlled_peer(
        store: MemoryRepo,
        answers: BTreeMap<RawHash, Bytes>,
        blocked: BTreeSet<RawHash>,
    ) -> (
        Peer<LandingStore>,
        Arc<ControlledFetches>,
        Arc<Mutex<LandingTrace>>,
    ) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let (sender, receiver, wiring) =
            crate::host::wire(crate::identity::iroh_secret(&key).public().into());
        let fetches = Arc::new(ControlledFetches {
            answers,
            blocked,
            delay: Mutex::new(Duration::ZERO),
            released: Arc::new(AtomicBool::new(false)),
            wake: Arc::new(tokio::sync::Notify::new()),
            trace: Arc::new(Mutex::new(FetchTrace::default())),
        });
        wiring.install_test_capability(fetches.clone());
        let landings = Arc::new(Mutex::new(LandingTrace::default()));
        let peer = Peer::with_wiring(
            LandingStore {
                inner: store,
                trace: landings.clone(),
            },
            crate::inventory::ReconcileQos::default(),
            sender,
            receiver,
        );
        (peer, fetches, landings)
    }

    struct ExactFixture {
        peer: Peer<LandingStore>,
        fetches: Arc<ControlledFetches>,
        landings: Arc<Mutex<LandingTrace>>,
        roots: Vec<RawHash>,
        collection: CollectionHandle,
    }

    fn exact_fixture(count: usize, blocked: usize) -> ExactFixture {
        let mut source = MemoryRepo::default();
        let answers: BTreeMap<_, _> = (0..count)
            .map(|ordinal| {
                let bytes = Bytes::from_source(format!("exact root {ordinal}").into_bytes());
                (
                    source.put::<UnknownBlob, _>(bytes.clone()).unwrap().raw,
                    bytes,
                )
            })
            .collect();
        let roots: Vec<_> = answers.keys().copied().collect();
        let mut store = MemoryRepo::default();
        let collection = put(&mut store, b"exact-window descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        for &root in &roots {
            raw_commit(&mut store, collection, root, metadata);
        }
        let (peer, fetches, landings) = controlled_peer(
            store,
            answers,
            roots.iter().take(blocked).copied().collect(),
        );
        ExactFixture {
            peer,
            fetches,
            landings,
            roots,
            collection: Inline::new(collection),
        }
    }

    #[tokio::test]
    async fn exact_window_lands_ready_roots_before_the_first_stalled_root() {
        let mut fixture = exact_fixture(9, 1);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Shallow, [fixture.collection]);
        let mut tick = Box::pin(reconciler.tick(&mut fixture.peer));
        assert!(futures::poll!(tick.as_mut()).is_pending());
        assert_eq!(
            fixture.landings.lock().unwrap().durable,
            fixture.roots[1..].iter().copied().collect(),
            "the first pending network request must not hold later durable answers",
        );
        {
            let trace = fixture.fetches.trace.lock().unwrap();
            assert_eq!(trace.calls.len(), fixture.roots.len());
            assert_eq!(trace.active, 1);
            assert!(trace.peak <= EXACT_FETCHES_IN_FLIGHT);
        }
        fixture.fetches.release();
        let stats = tick.await;
        assert_eq!(stats.replication.acquired, fixture.roots.len());
        assert_eq!(stats.replication.pending, 0);
        assert_eq!(stats.replication.speculative_attempted, 0);
        assert_eq!(fixture.fetches.trace.lock().unwrap().cancelled, 0);
        assert!(reconciler.states.is_empty());
    }

    #[tokio::test]
    async fn dropping_exact_tick_cancels_only_its_bounded_started_window() {
        let mut fixture = exact_fixture(9, 9);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Shallow, [fixture.collection]);
        let mut tick = Box::pin(reconciler.tick(&mut fixture.peer));
        assert!(futures::poll!(tick.as_mut()).is_pending());
        assert_eq!(
            fixture.fetches.trace.lock().unwrap().active,
            EXACT_FETCHES_IN_FLIGHT
        );
        drop(tick);
        {
            let trace = fixture.fetches.trace.lock().unwrap();
            assert_eq!(trace.calls, fixture.roots[..EXACT_FETCHES_IN_FLIGHT]);
            assert_eq!(trace.peak, EXACT_FETCHES_IN_FLIGHT);
            assert_eq!(trace.active, 0);
            assert_eq!(trace.cancelled, EXACT_FETCHES_IN_FLIGHT);
        }
        assert!(fixture.landings.lock().unwrap().put.is_empty());
        for (index, handle) in fixture.roots.iter().enumerate() {
            let state = &reconciler.states[handle];
            assert_eq!(state.first_root_attempt, index >= EXACT_FETCHES_IN_FLIGHT);
            assert!(
                state.last_attempt.is_none(),
                "external drop is not a reported miss"
            );
        }
        assert_eq!(reconciler.next_service, ServiceTurn::Roots);
        fixture.fetches.release();
        tokio::task::yield_now().await;
        assert_eq!(
            fixture.fetches.trace.lock().unwrap().calls.len(),
            EXACT_FETCHES_IN_FLIGHT
        );
        assert!(fixture.landings.lock().unwrap().put.is_empty());
    }

    #[cfg(feature = "sim")]
    #[tokio::test(start_paused = true)]
    async fn exact_window_refills_share_one_deadline_instead_of_renewing_it() {
        let mut fixture = exact_fixture(9, 0);
        *fixture.fetches.delay.lock().unwrap() = Duration::from_secs(10);
        let mut reconciler = Reconciler::new()
            .with_replication(ReplicationMode::Shallow, [fixture.collection])
            .with_fetch_budget(Duration::from_secs(25));
        let started = tokio::time::Instant::now();
        let stats = reconciler.tick(&mut fixture.peer).await;
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            Duration::from_secs(25)
        );
        assert_eq!(stats.replication.acquired, 8);
        assert_eq!(stats.replication.pending, 1);
        let trace = fixture.fetches.trace.lock().unwrap();
        assert_eq!(trace.calls.len(), 9);
        assert_eq!(trace.peak, EXACT_FETCHES_IN_FLIGHT);
        assert_eq!(trace.active, 0);
        assert_eq!(trace.cancelled, 1);
        assert_eq!(fixture.landings.lock().unwrap().durable.len(), 8);
    }

    #[cfg(feature = "sim")]
    #[tokio::test(start_paused = true)]
    async fn exact_window_deadline_preserves_the_unstarted_tail_and_next_service() {
        let mut fixture = exact_fixture(9, 9);
        let mut reconciler =
            Reconciler::with_backoff(Duration::from_secs(5), Duration::from_secs(20))
                .with_replication(ReplicationMode::Full, [fixture.collection])
                .with_fetch_budget(Duration::from_secs(30));
        reconciler.next_service = ServiceTurn::Roots;
        let started = tokio::time::Instant::now();
        let stats = reconciler.tick(&mut fixture.peer).await;
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            Duration::from_secs(30)
        );
        assert_eq!(stats.replication.acquired, 0);
        assert_eq!(stats.replication.pending, fixture.roots.len());
        assert_eq!(stats.replication.speculative_attempted, 0);
        assert_eq!(reconciler.next_service, ServiceTurn::Scan);
        assert_eq!(
            reconciler.root_round.after,
            Some(fixture.roots[EXACT_FETCHES_IN_FLIGHT - 1])
        );
        assert_eq!(
            fixture.fetches.trace.lock().unwrap().cancelled,
            EXACT_FETCHES_IN_FLIGHT
        );
        assert_eq!(fixture.fetches.trace.lock().unwrap().active, 0);
        for (index, handle) in fixture.roots.iter().enumerate() {
            let state = &reconciler.states[handle];
            assert_eq!(state.first_root_attempt, index >= EXACT_FETCHES_IN_FLIGHT);
            assert_eq!(
                state.last_attempt.is_some(),
                index < EXACT_FETCHES_IN_FLIGHT
            );
            assert_eq!(
                state.backoff,
                if index < EXACT_FETCHES_IN_FLIGHT {
                    Duration::from_secs(5)
                } else {
                    Duration::ZERO
                }
            );
        }
        assert_eq!(
            fixture.fetches.trace.lock().unwrap().calls,
            fixture.roots[..EXACT_FETCHES_IN_FLIGHT]
        );
    }

    #[tokio::test]
    async fn exact_window_zero_budget_preserves_every_unstarted_priority() {
        let mut fixture = exact_fixture(9, 0);
        let mut reconciler = Reconciler::new()
            .with_replication(ReplicationMode::Shallow, [fixture.collection])
            .with_fetch_budget(Duration::ZERO);
        let stats = reconciler.tick(&mut fixture.peer).await;
        assert_eq!(stats.replication.pending, fixture.roots.len());
        assert!(fixture.fetches.trace.lock().unwrap().calls.is_empty());
        assert!(fixture.landings.lock().unwrap().put.is_empty());
        for handle in fixture.roots {
            assert!(reconciler.states[&handle].first_root_attempt);
            assert!(reconciler.states[&handle].last_attempt.is_none());
        }
    }

    #[tokio::test]
    async fn exact_window_failed_flush_stays_pending_and_retries_without_fetching() {
        let bytes = Bytes::from_source(b"one failed landing barrier".to_vec());
        let mut source = MemoryRepo::default();
        let handle = source.put::<UnknownBlob, _>(bytes.clone()).unwrap();
        let mut store = MemoryRepo::default();
        store.want(WantRequest::blob(handle)).unwrap();
        let (mut peer, fetches, landings) = controlled_peer(
            store,
            BTreeMap::from([(handle.raw, bytes)]),
            BTreeSet::new(),
        );
        landings.lock().unwrap().fail_flush = true;
        let mut reconciler = Reconciler::new();
        let first = reconciler.tick(&mut peer).await;
        assert_eq!(first.attempted, 1);
        assert_eq!(first.fulfilled, 0);
        assert_eq!(first.pending, 1);
        assert!(landings.lock().unwrap().durable.is_empty());
        assert!(!reconciler.durable_blob_answers.contains(&handle.raw));
        landings.lock().unwrap().fail_flush = false;
        let second = reconciler.tick(&mut peer).await;
        assert_eq!(second.pending, 0);
        assert_eq!(second.attempted, 0);
        assert_eq!(fetches.trace.lock().unwrap().calls, [handle.raw]);
        assert_eq!(landings.lock().unwrap().put, [handle.raw]);
        assert!(landings.lock().unwrap().durable.contains(&handle.raw));
    }

    #[tokio::test]
    async fn exact_window_does_not_parallelize_or_expand_speculative_scans() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"scan descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        let words: Vec<_> = (0..40)
            .flat_map(|word| {
                *blake3::hash(format!("absent scan word {word}").as_bytes()).as_bytes()
            })
            .collect();
        let data = put(&mut store, words);
        raw_commit(&mut store, descriptor, data, metadata);
        let (mut peer, fetches, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [Inline::new(descriptor)]);
        let stats = reconciler.tick(&mut peer).await;
        assert_eq!(
            stats.replication.speculative_attempted,
            RECONCILE_SPECULATIVE_FETCHES_PER_TICK
        );
        assert_eq!(
            stats.replication.speculative_misses,
            RECONCILE_SPECULATIVE_FETCHES_PER_TICK
        );
        let trace = fetches.trace.lock().unwrap();
        assert_eq!(trace.calls.len(), RECONCILE_SPECULATIVE_FETCHES_PER_TICK);
        assert_eq!(trace.peak, 1);
        assert_eq!(trace.active, 0);
        assert_eq!(peer.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[tokio::test]
    async fn full_scan_deadline_expiring_during_filter_does_not_consume_a_word() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        let data = put(&mut store, vec![42; 32]);
        raw_commit(&mut store, descriptor, data, metadata);
        let mut peer = local_peer(store);
        let mut reconciler = Reconciler::new()
            .with_replication(ReplicationMode::Full, [Inline::new(descriptor)])
            .with_fetch_budget(Duration::from_millis(50));
        let stats = reconciler
            .tick_with_reference_filter(&mut peer, |_, _| {
                std::thread::sleep(Duration::from_millis(60));
                None
            })
            .await;
        assert_eq!(stats.replication.speculative_attempted, 0);
        assert_eq!(stats.replication.candidates, 0);
        assert_eq!(
            reconciler.scan.lanes[0]
                .1
                .sources
                .get(&scan_key(data, data))
                .unwrap()
                .offset,
            0
        );
        assert_eq!(peer.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[tokio::test]
    async fn full_filter_keeps_root_scope_on_shared_children_and_never_scans_plain_wants() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"descriptor".to_vec());
        let child = put(&mut store, b"shared child".to_vec());
        let data = put(&mut store, child.to_vec());
        let mut metadata_bytes = child.to_vec();
        metadata_bytes.push(1);
        let metadata = put(&mut store, metadata_bytes);
        let mut wanted_bytes = child.to_vec();
        wanted_bytes.push(2);
        let wanted = put(&mut store, wanted_bytes);
        store
            .want(WantRequest::blob::<UnknownBlob>(Inline::new(wanted)))
            .unwrap();
        raw_commit(&mut store, descriptor, data, metadata);
        let mut peer = local_peer(store);
        let mut reconciler = Reconciler::with_backoff(Duration::ZERO, Duration::ZERO)
            .with_replication(ReplicationMode::Full, [Inline::new(descriptor)]);
        let mut visited_roots = BTreeSet::new();
        let stats = reconciler
            .tick_with_reference_filter(&mut peer, |root, _| {
                visited_roots.insert(root);
                (root == data).then_some(false)
            })
            .await;
        assert_eq!(stats.replication.roots, 3);
        assert_eq!(stats.replication.pending, 0);
        assert_eq!(stats.replication.speculative_attempted, 0);
        assert_eq!(visited_roots, BTreeSet::from([data, metadata]));
        let mut key = [0; 64];
        key[..32].copy_from_slice(&data);
        key[32..].copy_from_slice(&child);
        assert!(reconciler.scan.lanes[0].1.sources.get(&key).is_none());
        key[..32].copy_from_slice(&metadata);
        assert!(reconciler.scan.lanes[0].1.sources.get(&key).is_some());
        assert_eq!(peer.snapshot().unwrap().wants().unwrap().count(), 1);
    }

    #[tokio::test]
    async fn full_scan_bounds_filtered_large_blob_work_without_a_negative_frontier() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        let bytes = vec![42; RECONCILE_SCAN_CANDIDATES_PER_TICK * 32 * 3];
        let data = put(&mut store, bytes);
        raw_commit(&mut store, descriptor, data, metadata);
        let mut peer = local_peer(store);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [Inline::new(descriptor)]);
        let first = reconciler
            .tick_with_reference_filter(&mut peer, |_, _| Some(false))
            .await;
        assert!(first.replication.candidates > RECONCILE_SCAN_CANDIDATES_PER_TICK / 2);
        assert!(first.replication.candidates <= RECONCILE_SCAN_CANDIDATES_PER_TICK);
        let key = scan_key(data, data);
        let before = reconciler.scan.lanes[0].1.sources.get(&key).unwrap().offset;
        let second = reconciler
            .tick_with_reference_filter(&mut peer, |_, _| Some(false))
            .await;
        assert!(second.replication.candidates <= RECONCILE_SCAN_CANDIDATES_PER_TICK);
        assert!(reconciler.scan.lanes[0].1.sources.get(&key).unwrap().offset > before);
        assert_eq!(reconciler.scan.lanes[0].1.sources.len(), 3);
        assert!(reconciler.states.is_empty());
        assert_eq!(peer.snapshot().unwrap().wants().unwrap().count(), 0);
    }
}
