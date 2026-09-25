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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Duration;

use anybytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::{
    CollectionHandle, CollectionRead, CollectionRecordSelector, CollectionStore,
};
use triblespace_core::inline::Inline;
use triblespace_core::patch::{Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::repo::{
    BlobChildren, BlobStore, BlobStoreGet, CapabilityProofStore, SnapshotSource, StorageFlush,
    StoreRead, WantRead, WantRequest, WantStore,
};

use crate::peer::{Peer, PeerSnapshot};
use crate::protocol::RawHash;
use crate::transport::PeerId;

/// How much content an explicit collection selection asks this process to obtain.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationMode {
    /// Repair records and service explicit WANTs, without implicit blob demand.
    #[default]
    Demand,
    /// Obtain every direct reference of selected structural collection records.
    Shallow,
    /// Also obtain positive resident-blob hints received through selected READ repair.
    Full,
}

/// Hydration observations, separate from durable WANT fulfillment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplicationStats {
    /// Distinct direct handles named by the selected records in this observation.
    pub roots: usize,
    /// Direct roots not yet locally readable. Speculative misses are not roots.
    pub pending: usize,
    /// Blobs fetched and locally landed for hydration during this tick.
    pub acquired: usize,
    /// Distinct nonresident positive inventory hints retained for this tick.
    pub inventory: usize,
    /// Offered handles still unreadable after this tick's exact acquisition window.
    pub inventory_pending: usize,
    /// Compatibility counter; speculative scanning was removed and this stays zero.
    pub candidates: usize,
    /// Compatibility counter; reference-summary filtering was removed and this stays zero.
    pub filtered: usize,
    /// Compatibility counter; no speculative network requests are made.
    pub speculative_attempted: usize,
    /// Compatibility counter; no speculative misses are recorded.
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
    /// Verified network payloads successfully put during this completed tick,
    /// including positive inventory acquisitions. A payload shared by a WANT and a root
    /// counts once. Neither local hits nor failed puts contribute.
    pub landed: usize,
    pub received_bytes: u64,
    /// Distinct unreadable exact blob WANTs, selected direct roots and retained hints at the
    /// end of this tick's exact acquisition window. None means that exact-set
    /// observation failed.
    /// This excludes operation WANTs and unknown recursive descendants, not a
    /// global backlog.
    pub pending_blobs: Option<usize>,
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

/// One source's share of a bounded hint cohort. Repeated offers cannot displace work which has
/// never had an actual acquisition attempt. The lexical cursor advances only
/// after service, and an explicit completed inventory pass supplies wrapping.
#[derive(Default)]
struct BlobHintRound {
    after: Option<RawHash>,
    unattempted: PATCH<32, IdentitySchema, ()>,
    serviced_through: Option<RawHash>,
    saw_forward: bool,
    /// A cursor advanced partway through a pass cannot wrap at that pass's end:
    /// earlier suffix offers may have been dropped while the window was full.
    advanced_in_pass: bool,
    completed_passes: u64,
    last_observed: u64,
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
}

impl ServiceTurn {
    fn next(self) -> Self {
        match self {
            Self::Wants => Self::FreshRoots,
            Self::FreshRoots => Self::Roots,
            Self::Roots => Self::Wants,
        }
    }
}

/// Retry/traversal state only. Durable demand and all answers remain in the store.
pub struct Reconciler {
    states: HashMap<RawHash, WantState>,
    initial_backoff: Duration,
    max_backoff: Duration,
    fetch_budget: Duration,
    mode: ReplicationMode,
    collections: BTreeSet<CollectionRecordSelector>,
    observation_generation: u64,
    want_round: ExactRound,
    root_round: ExactRound,
    next_service: ServiceTurn,
    blob_hints: BTreeMap<CollectionHandle, PATCH<32, IdentitySchema, PeerId>>,
    hint_rounds: BTreeMap<CollectionHandle, BTreeMap<PeerId, BlobHintRound>>,
    hint_observation_generation: u64,
    hint_pass_generation: u64,
}

pub const RECONCILE_FETCH_DEADLINE: Duration = Duration::from_secs(30);

/// Best-effort positive window per selected collection, not a complete inventory.
/// Completed, serviced cohorts rotate; an unavailable prefix cannot pin it.
const MAX_BLOB_HINTS_PER_COLLECTION: u64 = 4096;

/// Scheduling provenance only. Least-recently observed, fully serviced sources
/// may be evicted; new sources wait when every retained source protects work.
const MAX_BLOB_HINT_SOURCES_PER_COLLECTION: usize = 128;

#[cfg(test)]
const TEST_BLOB_HINT_SOURCE: PeerId = [249; 32];

/// Shared exact-demand and positive-inventory window, not a throughput guarantee.
const EXACT_FETCHES_IN_FLIGHT: usize = 4;

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
            initial_backoff: initial,
            max_backoff: max,
            fetch_budget: RECONCILE_FETCH_DEADLINE,
            mode: ReplicationMode::Demand,
            collections: BTreeSet::new(),
            observation_generation: 0,
            want_round: ExactRound::default(),
            root_round: ExactRound::default(),
            next_service: ServiceTurn::default(),
            blob_hints: BTreeMap::new(),
            hint_rounds: BTreeMap::new(),
            hint_observation_generation: 0,
            hint_pass_generation: 0,
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
        self.set_replication(mode, collections);
        self
    }

    pub(crate) fn set_replication(
        &mut self,
        mode: ReplicationMode,
        collections: impl IntoIterator<Item = CollectionHandle>,
    ) {
        self.mode = mode;
        self.collections = collections
            .into_iter()
            .map(CollectionRecordSelector::Collection)
            .collect();
        self.blob_hints.retain(|collection, _| {
            mode == ReplicationMode::Full
                && self
                    .collections
                    .contains(&CollectionRecordSelector::Collection(*collection))
        });
        self.hint_rounds.retain(|collection, _| {
            mode == ReplicationMode::Full
                && self
                    .collections
                    .contains(&CollectionRecordSelector::Collection(*collection))
        });
        self.root_round = ExactRound::default();
        self.next_service = ServiceTurn::default();
        for state in self.states.values_mut() {
            state.root_since = None;
            state.first_root_attempt = false;
        }
    }

    #[cfg(test)]
    fn observe_blob_hint(&mut self, collection: CollectionHandle, handle: RawHash) {
        self.observe_blob_hint_from(collection, TEST_BLOB_HINT_SOURCE, handle);
    }

    /// Retain a positive hint already received through READ-authorized repair.
    /// Selection is local acquisition policy, not additional authority. A full
    /// window protects unattempted work. After service it advances to the next
    /// lexical cohort; a completed remote pass eventually wraps the cursor.
    /// Nothing here creates a durable WANT or a negative fact.
    pub(crate) fn observe_blob_hint_from(
        &mut self,
        collection: CollectionHandle,
        source: PeerId,
        handle: RawHash,
    ) {
        if self.mode != ReplicationMode::Full
            || !self
                .collections
                .contains(&CollectionRecordSelector::Collection(collection))
        {
            return;
        }
        if !self.observe_hint_source(collection, source) {
            return;
        }
        if self
            .blob_hints
            .get(&collection)
            .is_some_and(|hints| hints.len() == MAX_BLOB_HINTS_PER_COLLECTION)
        {
            let serviced: Vec<_> = self.hint_rounds[&collection]
                .iter()
                .filter(|(_, round)| {
                    round.unattempted.is_empty() && round.serviced_through.is_some()
                })
                .map(|(source, _)| *source)
                .collect();
            for source in serviced {
                self.retire_hint_cohort(collection, source);
                self.hint_rounds
                    .get_mut(&collection)
                    .unwrap()
                    .get_mut(&source)
                    .unwrap()
                    .advanced_in_pass = true;
            }
        }
        let round = self
            .hint_rounds
            .get_mut(&collection)
            .unwrap()
            .get_mut(&source)
            .unwrap();
        if round.after.is_some_and(|after| handle <= after) {
            return;
        }
        round.saw_forward = true;
        let hints = self.blob_hints.entry(collection).or_default();
        if hints.has_prefix(&handle) {
            // An immutable H needs one attempt, not a duplicate per supplier.
            // Keep the first supplier's ownership and unattempted protection.
            return;
        }
        if hints.len() < MAX_BLOB_HINTS_PER_COLLECTION {
            hints.insert(&PatchEntry::with_value(&handle, source));
            round
                .unattempted
                .insert(&PatchEntry::with_value(&handle, ()));
        }
    }

    fn observe_hint_source(&mut self, collection: CollectionHandle, source: PeerId) -> bool {
        let rounds = self.hint_rounds.entry(collection).or_default();
        if !rounds.contains_key(&source) && rounds.len() == MAX_BLOB_HINT_SOURCES_PER_COLLECTION {
            let replace = rounds
                .iter()
                .filter(|(_, round)| round.unattempted.is_empty())
                .min_by_key(|(_, round)| round.last_observed)
                .map(|(source, _)| *source);
            let Some(replace) = replace else {
                return false;
            };
            // Only actual service can make a source replaceable. Losing an
            // idle cursor under churn may repeat attempts, never erase work
            // which has not yet had one.
            self.retire_hint_cohort(collection, replace);
            self.hint_rounds
                .get_mut(&collection)
                .unwrap()
                .remove(&replace);
        }
        self.hint_observation_generation = self
            .hint_observation_generation
            .checked_add(1)
            .expect("blob hint observation counter exhausted");
        self.hint_rounds
            .get_mut(&collection)
            .unwrap()
            .entry(source)
            .or_default()
            .last_observed = self.hint_observation_generation;
        true
    }

    /// The sender finished walking one pinned inventory, not a global absence
    /// claim. A shrinking inventory can therefore release a stale cursor too.
    pub(crate) fn finish_blob_inventory_pass(
        &mut self,
        collection: CollectionHandle,
        source: PeerId,
    ) {
        if self.mode != ReplicationMode::Full
            || !self
                .collections
                .contains(&CollectionRecordSelector::Collection(collection))
        {
            return;
        }
        let Some(round) = self
            .hint_rounds
            .get_mut(&collection)
            .and_then(|rounds| rounds.get_mut(&source))
        else {
            // Empty inventories and sources beyond the provenance cap cannot
            // spend state or alter another source's cursor.
            return;
        };
        // Global within this reconciler so evicting and readmitting a source
        // cannot make an external worker mistake its new pass for an old one.
        self.hint_pass_generation = self
            .hint_pass_generation
            .checked_add(1)
            .expect("blob inventory pass counter exhausted");
        round.completed_passes = self.hint_pass_generation;
        self.finish_hint_round(collection, source);
    }

    fn retire_hint_cohort(&mut self, collection: CollectionHandle, source: PeerId) {
        let round = self
            .hint_rounds
            .get_mut(&collection)
            .and_then(|rounds| rounds.get_mut(&source))
            .expect("observed hint round");
        debug_assert!(round.unattempted.is_empty());
        round.after = round.serviced_through.take().or(round.after);
        if let Some(hints) = self.blob_hints.get_mut(&collection) {
            let retired: Vec<_> = hints
                .iter_ordered()
                .filter(|handle| hints.get(handle) == Some(&source))
                .copied()
                .collect();
            for handle in retired {
                hints.remove(&handle);
            }
        }
    }

    fn finish_hint_round(&mut self, collection: CollectionHandle, source: PeerId) {
        let round = self
            .hint_rounds
            .get_mut(&collection)
            .unwrap()
            .get_mut(&source)
            .unwrap();
        let retire = round.unattempted.is_empty() && round.serviced_through.is_some();
        if round.unattempted.is_empty() && !retire && !round.saw_forward && !round.advanced_in_pass
        {
            // Only an actual end marker permits wrapping. Partial prefix
            // batches cannot keep refilling a failed early cohort.
            round.after = None;
        }
        round.saw_forward = false;
        round.advanced_in_pass = false;
        if retire {
            self.retire_hint_cohort(collection, source);
        }
    }

    fn mark_hint_attempt(&mut self, collection: CollectionHandle, handle: RawHash) {
        if let Some(source) = self
            .blob_hints
            .get(&collection)
            .and_then(|hints| hints.get(&handle))
            .copied()
        {
            let round = self
                .hint_rounds
                .get_mut(&collection)
                .and_then(|rounds| rounds.get_mut(&source))
                .expect("hint has a round");
            round.unattempted.remove(&handle);
            round.serviced_through =
                Some(round.serviced_through.map_or(handle, |old| old.max(handle)));
        }
    }

    /// Copy only positive evidence relevant to this reconciler's own selection.
    /// External `tick(peer)` uses this after the peer admits its queued events.
    pub(crate) fn merge_blob_hints_from(&mut self, other: &Self) {
        for (collection, hints) in &other.blob_hints {
            for handle in hints.iter_ordered() {
                self.observe_blob_hint_from(*collection, *hints.get(handle).unwrap(), *handle);
            }
        }
        for (collection, sources) in &other.hint_rounds {
            if self.mode != ReplicationMode::Full
                || !self
                    .collections
                    .contains(&CollectionRecordSelector::Collection(*collection))
            {
                continue;
            }
            for (source, progress) in sources {
                let Some(round) = self
                    .hint_rounds
                    .get_mut(collection)
                    .and_then(|rounds| rounds.get_mut(source))
                else {
                    continue;
                };
                if progress.completed_passes > round.completed_passes {
                    round.completed_passes = progress.completed_passes;
                    self.hint_pass_generation =
                        self.hint_pass_generation.max(progress.completed_passes);
                    self.finish_hint_round(*collection, *source);
                }
            }
        }
    }

    /// External acquisition reports actual service back to the Peer-owned
    /// admission window. Merely copying or selecting a hint is not service.
    pub(crate) fn merge_blob_hint_progress_from(&mut self, other: &Self) {
        for (collection, hints) in &other.blob_hints {
            for handle in hints.iter_ordered() {
                let source = hints.get(handle).unwrap();
                if !other.hint_rounds[collection][source]
                    .unattempted
                    .has_prefix(handle)
                    && self
                        .blob_hints
                        .get(collection)
                        .and_then(|hints| hints.get(handle))
                        == Some(source)
                {
                    self.mark_hint_attempt(*collection, *handle);
                }
            }
        }
    }

    /// Forget hints already readable in one passive store observation. This is
    /// also used by peer refresh when an external reconciler owns acquisition.
    pub(crate) fn prune_blob_hints<R: BlobStoreGet>(&mut self, snapshot: &R) {
        let resident = self
            .blob_hints
            .values()
            .flat_map(|hints| hints.iter_ordered().copied())
            .filter(|handle| {
                BlobStoreGet::get::<Bytes, UnknownBlob>(snapshot, Inline::new(*handle)).is_ok()
            })
            .collect();
        self.prune_resident_hints(&resident);
    }

    fn prune_resident_hints(&mut self, resident: &HashSet<RawHash>) {
        self.blob_hints.retain(|collection, hints| {
            let landed: Vec<_> = hints
                .iter_ordered()
                .filter(|handle| resident.contains(*handle))
                .copied()
                .collect();
            for handle in landed {
                let source = *hints.get(&handle).expect("retained hint");
                let round = self
                    .hint_rounds
                    .get_mut(collection)
                    .and_then(|rounds| rounds.get_mut(&source))
                    .expect("hint has a round");
                round.unattempted.remove(&handle);
                round.serviced_through =
                    Some(round.serviced_through.map_or(handle, |old| old.max(handle)));
                hints.remove(&handle);
            }
            !hints.is_empty()
        });
    }

    fn observe_missing(&mut self, wanted: &BTreeSet<RawHash>, roots: &BTreeSet<RawHash>) {
        self.observation_generation = self
            .observation_generation
            .checked_add(1)
            .expect("reconciler observation generation exhausted");
        for handle in wanted.union(roots) {
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
    /// cannot repeatedly take an older exact request's turn.
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
        for _ in 0..3 {
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
            };
            if !candidates.is_empty() {
                return Some((turn, candidates));
            }
        }
        None
    }

    fn begin_attempt(&mut self, turn: ServiceTurn, handle: RawHash) {
        for (collection, hints) in &self.blob_hints {
            if let Some(source) = hints.get(&handle) {
                let round = self
                    .hint_rounds
                    .get_mut(collection)
                    .and_then(|rounds| rounds.get_mut(source))
                    .expect("hint has a round");
                round.unattempted.remove(&handle);
                round.serviced_through =
                    Some(round.serviced_through.map_or(handle, |old| old.max(handle)));
            }
        }
        match turn {
            ServiceTurn::Wants => self.want_round.after = Some(handle),
            ServiceTurn::Roots => self.root_round.after = Some(handle),
            ServiceTurn::FreshRoots => {}
        }
        self.states
            .get_mut(&handle)
            .expect("observed missing exact handle")
            .first_root_attempt = false;
    }

    /// Apply this reconciler's explicit hydration selection before admitting
    /// queued peer hints, then service one quantum. This configures local policy
    /// only: it neither activates collections nor starts a lazy host.
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
        if peer.reconciler().mode != self.mode || peer.reconciler().collections != self.collections
        {
            peer.set_replication(
                self.mode,
                self.collections
                    .iter()
                    .filter_map(|selector| match selector {
                        CollectionRecordSelector::Collection(collection) => Some(*collection),
                        _ => None,
                    }),
            );
        }
        // This is also the explicit external-Pile reobservation and inventory
        // admission boundary.
        let snapshot = match peer.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "store snapshot unavailable; skipping reconcile pass"
                );
                return ReconcileStats::default();
            }
        };
        self.merge_blob_hints_from(peer.reconciler());
        let stats = self.tick_snapshot(snapshot).await;
        peer.reconciler_mut().merge_blob_hint_progress_from(self);
        if stats.landed != 0 {
            peer.refresh();
        }
        stats
    }

    pub(crate) async fn tick_snapshot<S>(&mut self, snapshot: PeerSnapshot<S>) -> ReconcileStats
    where
        S: BlobStore + Send + 'static,
        S::Snapshot: StoreRead + BlobChildren,
    {
        let mut stats = ReconcileStats::default();
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

        let wanted_blob_handles: BTreeSet<_> = requests
            .iter()
            .filter_map(|request| request.blob_handle().map(|handle| handle.raw))
            .collect();
        let mut roots_observed = true;
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
                    roots_observed = false;
                    Vec::new()
                }
            }
        };
        let roots: BTreeSet<_> = selected_roots.iter().flatten().copied().collect();
        stats.replication.roots = roots.len();
        let hints: BTreeSet<_> = self
            .blob_hints
            .values()
            .flat_map(|hints| hints.iter_ordered().copied())
            .collect();
        let hydration: BTreeSet<_> = roots.union(&hints).copied().collect();
        let exact_handles: BTreeSet<_> = wanted_blob_handles.union(&hydration).copied().collect();
        // This is a pure observation of the selected inputs for this tick,
        // not a retained answer catalogue. A physical occurrence alone can be
        // corrupt, so keep the existing readable-blob test rather than treating
        // contains_blob/blob_info as proof that imported bytes are usable.
        let mut visible_blobs: HashSet<_> = exact_handles
            .iter()
            .copied()
            .filter(|handle| {
                BlobStoreGet::get::<Bytes, UnknownBlob>(&snapshot, Inline::new(*handle)).is_ok()
            })
            .collect();

        let missing_wanted: BTreeSet<_> = wanted_blob_handles
            .iter()
            .filter(|handle| !visible_blobs.contains(*handle))
            .copied()
            .collect();
        let missing_roots: BTreeSet<_> = hydration
            .iter()
            .filter(|handle| !visible_blobs.contains(*handle))
            .copied()
            .collect();
        stats.missing = missing_wanted.len();
        stats.replication.inventory = hints
            .iter()
            .filter(|handle| !visible_blobs.contains(*handle))
            .count();
        self.states
            .retain(|handle, _| exact_handles.contains(handle) && !visible_blobs.contains(handle));
        self.observe_missing(&missing_wanted, &missing_roots);
        self.prune_resident_hints(&visible_blobs);

        let started = crate::clock::mono_now();
        let deadline = tokio::time::Instant::now() + self.fetch_budget;
        let work = self.next_work(&missing_wanted, &missing_roots, started);
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
                    if visible_blobs.contains(&handle) || !in_flight.insert(handle) {
                        continue;
                    }
                    self.begin_attempt(turn, handle);
                    if wanted_blob_handles.contains(&handle) {
                        stats.attempted += 1;
                    }
                    let fetch = snapshot.fetch_verified_with_deadline(
                        handle,
                        deadline.saturating_duration_since(tokio::time::Instant::now()),
                    );
                    pending.push(async move {
                        let verified = tokio::time::timeout_at(deadline, fetch)
                            .await
                            .ok()
                            .flatten();
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
                let landed = verified.and_then(|verified| snapshot.land_verified(verified));
                let Some(bytes) = landed else {
                    self.record_unavailable(handle);
                    continue;
                };
                stats.landed += 1;
                stats.received_bytes = stats.received_bytes.saturating_add(bytes);
                // A successful put is visible before an optional durability
                // boundary. Keep only this tick's completion delta; the next
                // tick observes the actual store again, including bad imports.
                visible_blobs.insert(handle);
                self.states.remove(&handle);
                if is_want {
                    stats.fulfilled += 1;
                }
                if hydration.contains(&handle) {
                    stats.replication.acquired += 1;
                }
            }
            // Expiry cancels admitted unfinished requests, not untouched tail
            // candidates. Charge each once; no answer is present until its
            // serial put succeeds. Dropping the entire tick also
            // drops these futures, without inventing a completion or miss.
            drop(pending);
            for handle in in_flight {
                self.record_unavailable(handle);
            }
        }
        stats.pending = wanted_blob_handles
            .iter()
            .filter(|handle| !visible_blobs.contains(*handle))
            .count();
        stats.replication.pending = roots
            .iter()
            .filter(|handle| !visible_blobs.contains(*handle))
            .count();
        stats.replication.inventory_pending = hints
            .iter()
            .filter(|handle| !visible_blobs.contains(*handle))
            .count();
        stats.pending_blobs = roots_observed.then(|| {
            exact_handles
                .iter()
                .filter(|handle| !visible_blobs.contains(*handle))
                .count()
        });

        self.prune_resident_hints(&visible_blobs);
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

#[cfg(test)]
mod tests {
    // Canonical but deliberately uninserted COMMIT witnesses keep these
    // physical-storage fixtures independent of ancestor arrival order.

    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use triblespace_core::blob::{Blob, BlobEncoding, IntoBlob};
    use triblespace_core::capability::CapabilityProof;
    use triblespace_core::collection::{
        CollectionCommit, CollectionDerive, CollectionMerge, CollectionRecord,
    };
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::inline::{Inline, InlineEncoding};
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
    use triblespace_core::repo::{BlobStoreList, BlobStorePut, StorageClose};

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
    fn service_turns_preserve_old_rounds_and_wants_during_continuous_hint_arrival() {
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
        let mut regular = Vec::new();
        let mut want_attempts = Vec::new();
        let mut fresh = 0;
        for quantum in 0..64 * 3 {
            reconciler.observe_blob_hint(
                Inline::new(scheduled_handle(30, 0)),
                scheduled_handle(9, quantum),
            );
            roots.extend(
                reconciler
                    .blob_hints
                    .values()
                    .flat_map(|hints| hints.iter_ordered().copied()),
            );
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
                ][quantum as usize % 3],
                "one request may exhaust a quantum, but cannot erase the next class's turn",
            );
            let handle = candidates[0];
            reconciler.begin_attempt(turn, handle);
            reconciler.record_unavailable(handle);
            match turn {
                ServiceTurn::Wants => want_attempts.push(handle),
                ServiceTurn::FreshRoots => fresh += 1,
                ServiceTurn::Roots => regular.push(handle),
            }
        }
        assert_eq!(regular, old_roots.into_iter().collect::<Vec<_>>());
        assert_eq!(
            &want_attempts[..old_wants.len()],
            old_wants.into_iter().collect::<Vec<_>>(),
        );
        assert_eq!(fresh, 64);
    }

    #[test]
    fn roots_in_backoff_keep_their_retry_deadline_without_speculation() {
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
        reconciler.next_service = ServiceTurn::Wants;
        assert!(reconciler
            .next_work(&wanted, &roots, crate::clock::mono_now())
            .is_none());
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

        fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
            Err(std::io::Error::other("collection observation failed"))
        }
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
            CollectionRecord::Merge(
                CollectionMerge::sign(
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                    collection,
                    [Inline::new([4; 32]), Inline::new([5; 32])],
                    Inline::new([6; 32]),
                )
                .unwrap(),
            ),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection,
                triblespace_core::collection::SourceLocator::of([6; 32]),
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
        assert!(direct_roots(&snapshot, &BTreeSet::new())
            .unwrap()
            .is_empty());
        assert!(direct_roots(&FailingCollectionRead, &selectors).is_err());
    }

    #[test]
    fn positive_hints_are_selected_full_only_bounded_and_reopen_after_landing() {
        let selected = Inline::new([61; 32]);
        let other = Inline::new([62; 32]);
        for mode in [ReplicationMode::Demand, ReplicationMode::Shallow] {
            let mut reconciler = Reconciler::new().with_replication(mode, [selected]);
            reconciler.observe_blob_hint(selected, [1; 32]);
            assert!(reconciler.blob_hints.is_empty());
        }
        let mut reconciler = Reconciler::new().with_replication(ReplicationMode::Full, [selected]);
        reconciler.observe_blob_hint(other, [1; 32]);
        assert!(reconciler.blob_hints.is_empty());
        for index in 0..MAX_BLOB_HINTS_PER_COLLECTION as u32 {
            reconciler.observe_blob_hint(selected, scheduled_handle(1, index));
        }
        let overflow = scheduled_handle(2, 0);
        reconciler.observe_blob_hint(selected, overflow);
        assert_eq!(
            reconciler.blob_hints[&selected].len(),
            MAX_BLOB_HINTS_PER_COLLECTION
        );
        assert!(reconciler.blob_hints[&selected].get(&overflow).is_none());
        reconciler.prune_resident_hints(&HashSet::from([scheduled_handle(1, 0)]));
        reconciler.observe_blob_hint(selected, overflow);
        assert!(reconciler.blob_hints[&selected].get(&overflow).is_some());
        assert_eq!(
            reconciler.blob_hints[&selected].len(),
            MAX_BLOB_HINTS_PER_COLLECTION
        );
        reconciler.set_replication(ReplicationMode::Full, [other]);
        assert!(reconciler.blob_hints.is_empty());
    }

    #[test]
    fn merging_positive_hints_does_not_expand_the_receivers_selection() {
        let selected = Inline::new([63; 32]);
        let other = Inline::new([64; 32]);
        let mut source =
            Reconciler::new().with_replication(ReplicationMode::Full, [selected, other]);
        source.observe_blob_hint(selected, [1; 32]);
        source.observe_blob_hint(other, [2; 32]);
        let mut receiver = Reconciler::new().with_replication(ReplicationMode::Full, [selected]);
        receiver.merge_blob_hints_from(&source);
        assert_eq!(receiver.blob_hints.len(), 1);
        assert_eq!(receiver.blob_hints[&selected].len(), 1);
        assert!(receiver.blob_hints[&selected].get(&[1; 32]).is_some());
        assert!(
            receiver.states.is_empty(),
            "hints do not author demand or an attempt"
        );
    }

    #[test]
    fn completed_hint_passes_rotate_past_failed_cohorts_without_losing_unattempted_work() {
        let collection = Inline::new([65; 32]);
        let mut reconciler = Reconciler::with_backoff(Duration::ZERO, Duration::ZERO)
            .with_replication(ReplicationMode::Full, [collection]);
        let total = MAX_BLOB_HINTS_PER_COLLECTION as u32 * 2 + 17;
        let offered: Vec<_> = (0..total).map(|index| scheduled_handle(1, index)).collect();
        let mut attempted = BTreeSet::new();
        for _ in 0..3 {
            for &handle in &offered {
                reconciler.observe_blob_hint(collection, handle);
            }
            reconciler.finish_blob_inventory_pass(collection, TEST_BLOB_HINT_SOURCE);
            let retained: BTreeSet<_> = reconciler
                .blob_hints
                .values()
                .flat_map(|hints| hints.iter_ordered().copied())
                .collect();
            assert!(retained.len() <= MAX_BLOB_HINTS_PER_COLLECTION as usize);
            reconciler
                .states
                .retain(|handle, _| retained.contains(handle));
            reconciler.observe_missing(&BTreeSet::new(), &retained);
            for handle in retained {
                reconciler.begin_attempt(ServiceTurn::FreshRoots, handle);
                reconciler.record_unavailable(handle);
                attempted.insert(handle);
            }
        }
        assert_eq!(attempted, offered.into_iter().collect());
    }

    #[test]
    fn repeated_hint_passes_cannot_evict_the_unattempted_part_of_a_cohort() {
        let collection = Inline::new([66; 32]);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        let original: BTreeSet<_> = (0..MAX_BLOB_HINTS_PER_COLLECTION as u32)
            .map(|index| scheduled_handle(1, index))
            .collect();
        for &handle in &original {
            reconciler.observe_blob_hint(collection, handle);
        }
        reconciler.observe_missing(&BTreeSet::new(), &original);
        reconciler.begin_attempt(ServiceTurn::FreshRoots, *original.first().unwrap());
        let later = scheduled_handle(2, 0);
        for _ in 0..4 {
            for &handle in &original {
                reconciler.observe_blob_hint(collection, handle);
            }
            reconciler.observe_blob_hint(collection, later);
            reconciler.finish_blob_inventory_pass(collection, TEST_BLOB_HINT_SOURCE);
        }
        assert_eq!(
            reconciler.blob_hints[&collection]
                .iter_ordered()
                .copied()
                .collect::<BTreeSet<_>>(),
            original
        );
        assert!(!reconciler.blob_hints[&collection].has_prefix(&later));
        assert_eq!(
            reconciler.hint_rounds[&collection][&TEST_BLOB_HINT_SOURCE]
                .unattempted
                .len(),
            MAX_BLOB_HINTS_PER_COLLECTION - 1
        );
    }

    #[test]
    fn completed_shrunk_inventory_wraps_a_serviced_watermark() {
        let collection = Inline::new([67; 32]);
        let low = scheduled_handle(1, 0);
        let high = scheduled_handle(2, 0);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        for handle in [low, high] {
            reconciler.observe_blob_hint(collection, handle);
        }
        reconciler.observe_missing(&BTreeSet::new(), &BTreeSet::from([low, high]));
        for handle in [low, high] {
            reconciler.begin_attempt(ServiceTurn::FreshRoots, handle);
        }
        reconciler.finish_blob_inventory_pass(collection, TEST_BLOB_HINT_SOURCE);
        assert_eq!(
            reconciler.hint_rounds[&collection][&TEST_BLOB_HINT_SOURCE].after,
            Some(high)
        );
        // The next pinned inventory no longer contains the former high key.
        reconciler.observe_blob_hint(collection, low);
        reconciler.finish_blob_inventory_pass(collection, TEST_BLOB_HINT_SOURCE);
        assert_eq!(
            reconciler.hint_rounds[&collection][&TEST_BLOB_HINT_SOURCE].after,
            None
        );
        reconciler.observe_blob_hint(collection, low);
        assert!(reconciler.blob_hints[&collection].has_prefix(&low));
        assert!(reconciler.hint_rounds[&collection][&TEST_BLOB_HINT_SOURCE]
            .unattempted
            .has_prefix(&low));
    }

    #[test]
    fn external_hint_service_is_reported_back_to_the_peer_admission_window() {
        let collection = Inline::new([68; 32]);
        let mut owner = Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        let mut worker = Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        let original: BTreeSet<_> = (0..MAX_BLOB_HINTS_PER_COLLECTION as u32)
            .map(|index| scheduled_handle(1, index))
            .collect();
        for &handle in &original {
            owner.observe_blob_hint(collection, handle);
        }
        owner.finish_blob_inventory_pass(collection, TEST_BLOB_HINT_SOURCE);
        worker.merge_blob_hints_from(&owner);
        worker.observe_missing(&BTreeSet::new(), &original);
        for &handle in &original {
            worker.begin_attempt(ServiceTurn::FreshRoots, handle);
        }
        owner.merge_blob_hint_progress_from(&worker);
        let later = scheduled_handle(2, 0);
        for &handle in &original {
            owner.observe_blob_hint(collection, handle);
        }
        owner.observe_blob_hint(collection, later);
        owner.finish_blob_inventory_pass(collection, TEST_BLOB_HINT_SOURCE);
        worker.merge_blob_hints_from(&owner);
        assert!(owner.blob_hints[&collection].has_prefix(&later));
        assert!(worker.blob_hints[&collection].has_prefix(&later));
        assert!(worker.hint_rounds[&collection][&TEST_BLOB_HINT_SOURCE]
            .unattempted
            .has_prefix(&later));
    }

    #[test]
    fn another_sources_small_pass_cannot_reset_a_large_inventory_cursor() {
        let collection = Inline::new([69; 32]);
        let source_a = [1; 32];
        let source_b = [2; 32];
        let total = MAX_BLOB_HINTS_PER_COLLECTION as u32 * 2 + 17;
        let offered: Vec<_> = (0..total).map(|index| scheduled_handle(1, index)).collect();
        // Exercise both Peer-owned acquisition and the external tick handoff.
        for external in [false, true] {
            let mut owner = Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
            let mut worker =
                Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
            let mut attempted = BTreeSet::new();
            for _ in 0..3 {
                for &handle in &offered {
                    owner.observe_blob_hint_from(collection, source_a, handle);
                }
                owner.finish_blob_inventory_pass(collection, source_a);
                let executor = if external {
                    worker.merge_blob_hints_from(&owner);
                    &mut worker
                } else {
                    &mut owner
                };
                let retained: BTreeSet<_> = executor.blob_hints[&collection]
                    .iter_ordered()
                    .copied()
                    .collect();
                assert!(retained.len() <= MAX_BLOB_HINTS_PER_COLLECTION as usize);
                executor.observe_missing(&BTreeSet::new(), &retained);
                for handle in retained {
                    executor.begin_attempt(ServiceTurn::FreshRoots, handle);
                    executor.record_unavailable(handle);
                    attempted.insert(handle);
                }
                if external {
                    owner.merge_blob_hint_progress_from(&worker);
                }
                // B's low-H inventory arrives after A's serviced window. It
                // may trigger retirement but its completion belongs only to B.
                owner.observe_blob_hint_from(collection, source_b, offered[0]);
                let after_a = owner.hint_rounds[&collection][&source_a].after;
                owner.finish_blob_inventory_pass(collection, source_b);
                assert_eq!(owner.hint_rounds[&collection][&source_a].after, after_a);
                assert!(owner.blob_hints[&collection].len() <= MAX_BLOB_HINTS_PER_COLLECTION);
            }
            assert_eq!(
                attempted,
                offered.iter().copied().collect(),
                "external={external}"
            );
        }
    }

    #[test]
    fn duplicate_hint_has_one_owner_and_other_completion_cannot_retire_it() {
        let collection = Inline::new([70; 32]);
        let source_a = [1; 32];
        let source_b = [2; 32];
        let handle = scheduled_handle(1, 0);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        reconciler.observe_blob_hint_from(collection, source_a, handle);
        for _ in 0..4 {
            reconciler.observe_blob_hint_from(collection, source_b, handle);
            reconciler.finish_blob_inventory_pass(collection, source_b);
        }
        assert_eq!(reconciler.blob_hints[&collection].len(), 1);
        assert_eq!(
            reconciler.blob_hints[&collection].get(&handle),
            Some(&source_a)
        );
        assert!(reconciler.hint_rounds[&collection][&source_a]
            .unattempted
            .has_prefix(&handle));
        assert!(reconciler.hint_rounds[&collection][&source_b]
            .unattempted
            .is_empty());
        reconciler.observe_missing(&BTreeSet::new(), &BTreeSet::from([handle]));
        reconciler.begin_attempt(ServiceTurn::FreshRoots, handle);
        reconciler.finish_blob_inventory_pass(collection, source_b);
        assert!(reconciler.blob_hints[&collection].has_prefix(&handle));
        reconciler.finish_blob_inventory_pass(collection, source_a);
        assert!(!reconciler.blob_hints[&collection].has_prefix(&handle));
        reconciler.observe_blob_hint_from(collection, source_b, handle);
        assert_eq!(
            reconciler.blob_hints[&collection].get(&handle),
            Some(&source_b)
        );
    }

    #[test]
    fn source_churn_replaces_serviced_state_but_never_unattempted_work() {
        let collection = Inline::new([71; 32]);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        for index in 0..MAX_BLOB_HINT_SOURCES_PER_COLLECTION as u32 {
            reconciler.observe_blob_hint_from(
                collection,
                scheduled_handle(9, index),
                scheduled_handle(1, index),
            );
        }
        let newcomer = scheduled_handle(9, MAX_BLOB_HINT_SOURCES_PER_COLLECTION as u32);
        let new_handle = scheduled_handle(2, 0);
        reconciler.observe_blob_hint_from(collection, newcomer, new_handle);
        reconciler.finish_blob_inventory_pass(collection, newcomer);
        assert_eq!(
            reconciler.hint_rounds[&collection].len(),
            MAX_BLOB_HINT_SOURCES_PER_COLLECTION
        );
        assert!(!reconciler.hint_rounds[&collection].contains_key(&newcomer));
        let serviced = scheduled_handle(1, 0);
        reconciler.observe_missing(&BTreeSet::new(), &BTreeSet::from([serviced]));
        reconciler.begin_attempt(ServiceTurn::FreshRoots, serviced);
        reconciler.observe_blob_hint_from(collection, newcomer, new_handle);
        assert!(!reconciler.hint_rounds[&collection].contains_key(&scheduled_handle(9, 0)));
        assert!(reconciler.blob_hints[&collection].has_prefix(&new_handle));
        // The sole replaceable slot can keep following actual peer churn.
        for index in 1..256 {
            let old = scheduled_handle(2, index - 1);
            reconciler.observe_missing(&BTreeSet::new(), &BTreeSet::from([old]));
            reconciler.begin_attempt(ServiceTurn::FreshRoots, old);
            reconciler.observe_blob_hint_from(
                collection,
                scheduled_handle(10, index),
                scheduled_handle(2, index),
            );
            assert_eq!(
                reconciler.hint_rounds[&collection].len(),
                MAX_BLOB_HINT_SOURCES_PER_COLLECTION
            );
            assert_eq!(
                reconciler.blob_hints[&collection].len(),
                MAX_BLOB_HINT_SOURCES_PER_COLLECTION as u64
            );
            assert!(reconciler.blob_hints[&collection].has_prefix(&scheduled_handle(1, 1)));
        }
    }

    #[test]
    fn external_completion_receipt_survives_source_eviction_and_readmission() {
        let collection = Inline::new([73; 32]);
        let source = scheduled_handle(9, 0);
        let first = scheduled_handle(10, 0);
        let next = scheduled_handle(10, 1);
        let mut owner = Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        let mut worker = Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        owner.observe_blob_hint_from(collection, source, first);
        owner.finish_blob_inventory_pass(collection, source);
        worker.merge_blob_hints_from(&owner);
        worker.mark_hint_attempt(collection, first);
        owner.merge_blob_hint_progress_from(&worker);
        owner.finish_blob_inventory_pass(collection, source);
        worker.merge_blob_hints_from(&owner);
        let previous = worker.hint_rounds[&collection][&source].completed_passes;
        for index in 1..=MAX_BLOB_HINT_SOURCES_PER_COLLECTION as u32 {
            let peer = scheduled_handle(9, index);
            let handle = scheduled_handle(2, index);
            owner.observe_blob_hint_from(collection, peer, handle);
            owner.mark_hint_attempt(collection, handle);
            owner.finish_blob_inventory_pass(collection, peer);
        }
        assert!(!owner.hint_rounds[&collection].contains_key(&source));
        owner.observe_blob_hint_from(collection, source, next);
        owner.finish_blob_inventory_pass(collection, source);
        worker.merge_blob_hints_from(&owner);
        assert!(owner.hint_rounds[&collection][&source].completed_passes > previous);
        assert_eq!(
            worker.hint_rounds[&collection][&source].completed_passes,
            owner.hint_rounds[&collection][&source].completed_passes
        );
        assert!(worker.hint_rounds[&collection][&source]
            .unattempted
            .has_prefix(&next));
    }

    #[test]
    fn mid_pass_retirement_cannot_wrap_before_a_new_complete_pass() {
        let collection = Inline::new([72; 32]);
        let source_a = [1; 32];
        let source_b = [2; 32];
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        let original: BTreeSet<_> = (0..MAX_BLOB_HINTS_PER_COLLECTION as u32)
            .map(|index| scheduled_handle(1, index))
            .collect();
        for &handle in &original {
            reconciler.observe_blob_hint_from(collection, source_a, handle);
        }
        reconciler.observe_blob_hint_from(collection, source_a, scheduled_handle(2, 0));
        reconciler.observe_missing(&BTreeSet::new(), &original);
        for &handle in &original {
            reconciler.begin_attempt(ServiceTurn::FreshRoots, handle);
        }
        reconciler.observe_blob_hint_from(collection, source_b, scheduled_handle(0, 0));
        reconciler.finish_blob_inventory_pass(collection, source_a);
        assert_eq!(
            reconciler.hint_rounds[&collection][&source_a].after,
            original.last().copied()
        );
        reconciler.observe_blob_hint_from(collection, source_a, scheduled_handle(2, 0));
        assert!(reconciler.blob_hints[&collection].has_prefix(&scheduled_handle(2, 0)));
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
        snapshot_put_counts: Vec<usize>,
        snapshots: usize,
        flushes: usize,
        closes: usize,
        fail_next_snapshot: bool,
        fail_snapshot: bool,
        fail_snapshot_after_puts: Option<usize>,
        fail_flush: bool,
        fail_close: bool,
        fail_put: bool,
    }

    struct LandingStore {
        inner: MemoryRepo,
        trace: Arc<Mutex<LandingTrace>>,
    }

    impl SnapshotSource for LandingStore {
        type Snapshot = <MemoryRepo as SnapshotSource>::Snapshot;
        type SnapshotError = std::io::Error;

        fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
            let mut trace = self.trace.lock().unwrap();
            trace.snapshots += 1;
            let puts = trace.put.len();
            trace.snapshot_put_counts.push(puts);
            if trace.fail_snapshot
                || std::mem::take(&mut trace.fail_next_snapshot)
                || trace
                    .fail_snapshot_after_puts
                    .is_some_and(|limit| puts >= limit)
            {
                return Err(std::io::Error::other("test snapshot failed once"));
            }
            drop(trace);
            Ok(self.inner.snapshot().unwrap())
        }
    }

    impl BlobStorePut for LandingStore {
        type PutError = std::io::Error;

        fn put<E, T>(&mut self, item: T) -> Result<Inline<Handle<E>>, Self::PutError>
        where
            E: BlobEncoding + 'static,
            T: IntoBlob<E>,
            Handle<E>: InlineEncoding,
        {
            if self.trace.lock().unwrap().fail_put {
                return Err(std::io::Error::other("test put failed"));
            }
            let handle = self.inner.put(item).unwrap();
            let mut trace = self.trace.lock().unwrap();
            trace.put.push(handle.raw);
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
            trace.flushes += 1;
            if trace.fail_flush {
                return Err(std::io::Error::other("test durability barrier failed"));
            }
            Ok(())
        }
    }

    impl StorageClose for LandingStore {
        type Error = std::io::Error;

        fn close(self) -> Result<(), Self::Error> {
            let mut trace = self.trace.lock().unwrap();
            trace.closes += 1;
            if trace.fail_close {
                return Err(std::io::Error::other("test close failed"));
            }
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
        ) -> futures::future::BoxFuture<'static, Option<Blob<UnknownBlob>>> {
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
                answer
                    .map(Blob::<UnknownBlob>::new)
                    .filter(|blob| blob.get_handle().raw == hash)
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
    async fn external_tick_applies_selection_before_admitting_peer_hints_without_activation() {
        use crate::channel::{NetEvent, NetEventBatch};

        let key = SigningKey::from_bytes(&[7; 32]);
        let (sender, receiver, wiring) =
            crate::host::wire(crate::identity::iroh_secret(&key).public().into());
        let observer = sender.clone();
        let collection = Inline::new([65; 32]);
        let bytes = Bytes::from_source(b"offered through peer event".to_vec());
        let handle = Blob::<UnknownBlob>::new(bytes.clone()).get_handle().raw;
        let fetches = Arc::new(ControlledFetches {
            answers: BTreeMap::from([(handle, bytes)]),
            blocked: BTreeSet::new(),
            delay: Mutex::new(Duration::ZERO),
            released: Arc::new(AtomicBool::new(false)),
            wake: Arc::new(tokio::sync::Notify::new()),
            trace: Arc::new(Mutex::new(FetchTrace::default())),
        });
        wiring.install_test_capability(fetches.clone());
        let mut peer = Peer::with_wiring(
            MemoryRepo::default(),
            crate::inventory::ReconcileQos::default(),
            sender,
            receiver,
        );
        assert_eq!(peer.reconciler().mode, ReplicationMode::Demand);
        let mut batch = NetEventBatch::default();
        batch
            .try_push(NetEvent::BlobHint {
                collection,
                source: TEST_BLOB_HINT_SOURCE,
                handle,
            })
            .unwrap();
        batch
            .try_push(NetEvent::BlobHint {
                collection: Inline::new([66; 32]),
                source: TEST_BLOB_HINT_SOURCE,
                handle: [67; 32],
            })
            .unwrap();
        wiring.send_admission(batch).await;
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [collection]);
        let stats = reconciler.tick(&mut peer).await;
        assert_eq!(stats.landed, 1);
        assert_eq!(stats.replication.inventory, 1);
        assert_eq!(stats.replication.roots, 0);
        assert_eq!(fetches.trace.lock().unwrap().calls, [handle]);
        assert!(peer.snapshot().unwrap().wants().unwrap().next().is_none());
        assert_eq!(
            observer.current_snapshot().unwrap().collections().count(),
            0
        );
        let again = reconciler.tick(&mut peer).await;
        assert_eq!(again.landed, 0);
        assert_eq!(fetches.trace.lock().unwrap().calls, [handle]);
    }

    #[tokio::test]
    async fn full_false_payload_words_cause_no_network_requests() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"positive-inventory descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        let words: Vec<_> = (0..1024)
            .flat_map(|word| *blake3::hash(format!("false word {word}").as_bytes()).as_bytes())
            .collect();
        let data = put(&mut store, words);
        raw_commit(&mut store, descriptor, data, metadata);
        let (mut peer, fetches, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [Inline::new(descriptor)]);
        for _ in 0..4 {
            let stats = reconciler.tick(&mut peer).await;
            assert_eq!(stats.replication.roots, 3);
            assert_eq!(stats.replication.pending, 0);
            assert_eq!(stats.replication.inventory, 0);
            assert_eq!(stats.replication.candidates, 0);
            assert_eq!(stats.replication.filtered, 0);
            assert_eq!(stats.replication.speculative_attempted, 0);
            assert_eq!(stats.replication.speculative_misses, 0);
        }
        assert!(fetches.trace.lock().unwrap().calls.is_empty());
        assert_eq!(peer.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    fn nested_hint_fixture(blocked: usize) -> ExactFixture {
        let grandchild_bytes = Bytes::from_source(b"offered nested body".to_vec());
        let grandchild = Blob::<UnknownBlob>::new(grandchild_bytes.clone())
            .get_handle()
            .raw;
        let child_bytes = Bytes::from_source(grandchild.to_vec());
        let child = Blob::<UnknownBlob>::new(child_bytes.clone())
            .get_handle()
            .raw;
        let mut answers = BTreeMap::from([(grandchild, grandchild_bytes), (child, child_bytes)]);
        for ordinal in 0..7 {
            let bytes = Bytes::from_source(format!("offered sibling {ordinal}").into_bytes());
            answers.insert(
                Blob::<UnknownBlob>::new(bytes.clone()).get_handle().raw,
                bytes,
            );
        }
        let hints: Vec<_> = answers.keys().copied().collect();
        let mut store = MemoryRepo::default();
        let collection = put(&mut store, b"nested-hint descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        let data = put(
            &mut store,
            hints
                .iter()
                .filter(|&&handle| handle != grandchild)
                .flat_map(|handle| *handle)
                .collect::<Vec<_>>(),
        );
        raw_commit(&mut store, collection, data, metadata);
        let (peer, fetches, landings) = controlled_peer(
            store,
            answers,
            hints.iter().take(blocked).copied().collect(),
        );
        ExactFixture {
            peer,
            fetches,
            landings,
            roots: hints,
            collection: Inline::new(collection),
        }
    }

    #[tokio::test]
    async fn full_offered_nested_handles_share_the_bounded_parallel_window() {
        let mut fixture = nested_hint_fixture(1);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [fixture.collection]);
        for &handle in &fixture.roots {
            reconciler.observe_blob_hint(fixture.collection, handle);
        }
        let mut tick = Box::pin(reconciler.tick(&mut fixture.peer));
        assert!(futures::poll!(tick.as_mut()).is_pending());
        assert_eq!(fixture.landings.lock().unwrap().put.len(), 8);
        assert!(fixture.fetches.trace.lock().unwrap().peak <= EXACT_FETCHES_IN_FLIGHT);
        fixture.fetches.release();
        let stats = tick.await;
        assert_eq!(stats.replication.roots, 3);
        assert_eq!(stats.replication.inventory, 9);
        assert_eq!(stats.replication.inventory_pending, 0);
        assert_eq!(stats.replication.acquired, 9);
        assert_eq!(stats.landed, 9);
        assert_eq!(stats.pending_blobs, Some(0));
        assert_eq!(stats.replication.speculative_attempted, 0);
        assert!(reconciler.blob_hints.is_empty());
        assert_eq!(fixture.peer.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[tokio::test]
    async fn failed_inventory_prefix_cannot_permanently_hide_a_later_reachable_blob() {
        let (good, bytes) = (0..256)
            .find_map(|ordinal| {
                let bytes = Bytes::from_source(
                    format!("late reachable inventory blob {ordinal}").into_bytes(),
                );
                let handle = Blob::<UnknownBlob>::new(bytes.clone()).get_handle().raw;
                (handle[0] != 0).then_some((handle, bytes))
            })
            .unwrap();
        let collection = Inline::new([69; 32]);
        let (mut peer, fetches, _) = controlled_peer(
            MemoryRepo::default(),
            BTreeMap::from([(good, bytes)]),
            BTreeSet::new(),
        );
        let mut reconciler = Reconciler::with_backoff(Duration::ZERO, Duration::ZERO)
            .with_replication(ReplicationMode::Full, [collection]);
        let mut offered: Vec<_> = (0..MAX_BLOB_HINTS_PER_COLLECTION as u32)
            .map(|index| scheduled_handle(0, index))
            .collect();
        assert!(offered.iter().all(|handle| *handle < good));
        offered.push(good);
        for pass in 0..2 {
            for &handle in &offered {
                reconciler.observe_blob_hint(collection, handle);
            }
            reconciler.finish_blob_inventory_pass(collection, TEST_BLOB_HINT_SOURCE);
            let stats = reconciler.tick(&mut peer).await;
            assert_eq!(stats.replication.speculative_attempted, 0);
            if pass == 0 {
                assert_eq!(stats.landed, 0);
            }
        }
        assert!(fetches.trace.lock().unwrap().calls.contains(&good));
        let snapshot = peer.snapshot().unwrap();
        assert!(BlobStoreGet::get::<Bytes, UnknownBlob>(&snapshot, Inline::new(good)).is_ok());
        assert_eq!(snapshot.wants().unwrap().count(), 0);
    }

    #[tokio::test]
    async fn cancelling_full_hint_acquisition_keeps_unstarted_hints_and_drops_owned_fetches() {
        let mut fixture = nested_hint_fixture(9);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Full, [fixture.collection]);
        for &handle in &fixture.roots {
            reconciler.observe_blob_hint(fixture.collection, handle);
        }
        let mut tick = Box::pin(reconciler.tick(&mut fixture.peer));
        assert!(futures::poll!(tick.as_mut()).is_pending());
        assert_eq!(
            fixture.fetches.trace.lock().unwrap().active,
            EXACT_FETCHES_IN_FLIGHT
        );
        drop(tick);
        assert_eq!(fixture.fetches.trace.lock().unwrap().active, 0);
        assert_eq!(
            fixture.fetches.trace.lock().unwrap().cancelled,
            EXACT_FETCHES_IN_FLIGHT
        );
        assert_eq!(
            fixture.fetches.trace.lock().unwrap().calls.len(),
            EXACT_FETCHES_IN_FLIGHT
        );
        assert_eq!(reconciler.blob_hints[&fixture.collection].len(), 9);
        fixture.fetches.release();
        let stats = reconciler.tick(&mut fixture.peer).await;
        assert_eq!(stats.landed, 9);
        assert_eq!(stats.replication.inventory_pending, 0);
        assert!(reconciler.blob_hints.is_empty());
        assert_eq!(fixture.peer.snapshot().unwrap().wants().unwrap().count(), 0);
    }

    #[tokio::test]
    async fn exact_window_lands_ready_roots_before_the_first_stalled_root() {
        let mut fixture = exact_fixture(9, 1);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Shallow, [fixture.collection]);
        let mut tick = Box::pin(reconciler.tick(&mut fixture.peer));
        assert!(futures::poll!(tick.as_mut()).is_pending());
        assert_eq!(
            fixture
                .landings
                .lock()
                .unwrap()
                .put
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            fixture.roots[1..].iter().copied().collect(),
            "the first pending network request must not hold later local answers",
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
        assert_eq!(stats.landed, fixture.roots.len());
        assert_eq!(
            stats.received_bytes,
            (0..9)
                .map(|ordinal| format!("exact root {ordinal}").len() as u64)
                .sum::<u64>()
        );
        assert_eq!(stats.pending_blobs, Some(0));
        assert_eq!(stats.replication.pending, 0);
        assert_eq!(stats.replication.speculative_attempted, 0);
        assert_eq!(fixture.fetches.trace.lock().unwrap().cancelled, 0);
        assert!(reconciler.states.is_empty());
    }

    #[tokio::test]
    async fn peer_hydration_lands_ready_batch_before_publishing_its_snapshot() {
        let mut fixture = exact_fixture(9, 0);
        // READ/activation do not imply downloading the collection's payloads.
        let demand = fixture.peer.reconcile().await;
        assert_eq!(demand.landed, 0);
        assert!(fixture.fetches.trace.lock().unwrap().calls.is_empty());

        fixture
            .peer
            .set_replication(ReplicationMode::Shallow, [fixture.collection]);
        fixture.landings.lock().unwrap().snapshot_put_counts.clear();
        let stats = fixture.peer.reconcile().await;
        assert_eq!(stats.landed, 9);
        assert_eq!(stats.replication.pending, 0);
        let trace = fixture.landings.lock().unwrap();
        assert_eq!(trace.put.len(), 9);
        assert!(trace.snapshot_put_counts.contains(&0));
        assert!(trace.snapshot_put_counts.contains(&9));
        assert!(
            trace
                .snapshot_put_counts
                .iter()
                .all(|&puts| puts == 0 || puts == 9),
            "no intermediate serving rebuild may consume the ready fetch window: {:?}",
            trace.snapshot_put_counts,
        );
    }

    #[tokio::test]
    async fn cancelled_peer_hydration_keeps_selection_and_resumes_from_resident_state() {
        let mut fixture = exact_fixture(9, 1);
        fixture
            .peer
            .set_replication(ReplicationMode::Shallow, [fixture.collection]);
        let mut turn = Box::pin(fixture.peer.reconcile());
        assert!(futures::poll!(turn.as_mut()).is_pending());
        assert_eq!(fixture.landings.lock().unwrap().put.len(), 8);
        drop(turn);
        assert_eq!(fixture.fetches.trace.lock().unwrap().active, 0);
        assert_eq!(fixture.fetches.trace.lock().unwrap().cancelled, 1);
        fixture.fetches.release();
        let stats = fixture.peer.reconcile().await;
        assert_eq!(stats.landed, 1);
        assert_eq!(stats.replication.pending, 0);
        assert_eq!(fixture.landings.lock().unwrap().put.len(), 9);
        let calls = &fixture.fetches.trace.lock().unwrap().calls;
        for &handle in &fixture.roots[1..] {
            assert_eq!(calls.iter().filter(|&&called| called == handle).count(), 1);
        }
    }

    #[tokio::test]
    async fn failed_batch_publication_withdraws_serving_without_losing_landed_bytes() {
        let mut fixture = exact_fixture(9, 0);
        fixture
            .peer
            .set_replication(ReplicationMode::Shallow, [fixture.collection]);
        assert!(fixture.peer.health().store.serving_snapshot);
        fixture.landings.lock().unwrap().fail_snapshot_after_puts = Some(9);
        let stats = fixture.peer.reconcile().await;
        assert_eq!(stats.landed, 9);
        assert!(!fixture.peer.health().store.serving_snapshot);
        assert_eq!(fixture.landings.lock().unwrap().put.len(), 9);
        fixture.landings.lock().unwrap().fail_snapshot_after_puts = None;
        let retry = fixture.peer.reconcile().await;
        assert!(fixture.peer.health().store.serving_snapshot);
        assert_eq!(retry.landed, 0);
        assert_eq!(retry.replication.pending, 0);
        assert_eq!(fixture.fetches.trace.lock().unwrap().calls.len(), 9);
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
        assert_eq!(fixture.landings.lock().unwrap().put.len(), 8);
        assert_eq!(fixture.landings.lock().unwrap().flushes, 0);
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
        assert_eq!(reconciler.next_service, ServiceTurn::Wants);
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
    async fn exact_window_fulfills_without_flush_and_close_errors_still_propagate() {
        let bytes = Bytes::from_source(b"put visibility precedes persistence".to_vec());
        let expected_bytes = bytes.len() as u64;
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
        assert_eq!(first.fulfilled, 1);
        assert_eq!(first.pending, 0);
        assert_eq!(first.landed, 1);
        assert_eq!(first.received_bytes, expected_bytes);
        assert_eq!(first.pending_blobs, Some(0));
        assert!(BlobStoreGet::get::<Bytes, UnknownBlob>(&peer.snapshot().unwrap(), handle).is_ok());
        assert!(reconciler.states.is_empty());
        let second = reconciler.tick(&mut peer).await;
        assert_eq!(second.pending, 0);
        assert_eq!(second.attempted, 0);
        assert_eq!(second.landed, 0);
        assert_eq!(second.received_bytes, 0);
        assert_eq!(second.pending_blobs, Some(0));
        assert_eq!(fetches.trace.lock().unwrap().calls, [handle.raw]);
        assert_eq!(landings.lock().unwrap().put, [handle.raw]);
        assert_eq!(landings.lock().unwrap().flushes, 0);
        assert!(
            peer.flush().is_err(),
            "manual flush still delegates its real error"
        );
        assert_eq!(landings.lock().unwrap().flushes, 1);
        landings.lock().unwrap().fail_close = true;
        assert_eq!(peer.close().unwrap_err().to_string(), "test close failed");
        assert_eq!(landings.lock().unwrap().closes, 1);
    }

    #[tokio::test]
    async fn exact_window_put_failure_remains_missing_and_retries() {
        let mut fixture = exact_fixture(1, 0);
        fixture.landings.lock().unwrap().fail_put = true;
        let mut reconciler = Reconciler::with_backoff(Duration::ZERO, Duration::ZERO)
            .with_replication(ReplicationMode::Shallow, [fixture.collection]);
        let first = reconciler.tick(&mut fixture.peer).await;
        assert_eq!(first.replication.acquired, 0);
        assert_eq!(first.replication.pending, 1);
        assert_eq!(first.landed, 0);
        assert_eq!(first.received_bytes, 0);
        assert_eq!(first.pending_blobs, Some(1));
        assert!(fixture.landings.lock().unwrap().put.is_empty());
        fixture.landings.lock().unwrap().fail_put = false;
        let second = reconciler.tick(&mut fixture.peer).await;
        assert_eq!(second.replication.acquired, 1);
        assert_eq!(second.replication.pending, 0);
        assert_eq!(second.landed, 1);
        assert_eq!(second.received_bytes, b"exact root 0".len() as u64);
        assert_eq!(second.pending_blobs, Some(0));
        assert_eq!(fixture.landings.lock().unwrap().flushes, 0);
    }

    #[tokio::test]
    async fn telemetry_backlog_distinguishes_failed_observation_from_empty_selection() {
        let (mut peer, _, landings) =
            controlled_peer(MemoryRepo::default(), BTreeMap::new(), BTreeSet::new());
        let mut reconciler = Reconciler::new();
        landings.lock().unwrap().fail_snapshot = true;
        let failed = reconciler.tick(&mut peer).await;
        assert_eq!(failed.pending_blobs, None);
        assert_eq!(failed.landed, 0);
        assert_eq!(failed.received_bytes, 0);
        landings.lock().unwrap().fail_snapshot = false;
        let empty = reconciler.tick(&mut peer).await;
        assert_eq!(empty.pending_blobs, Some(0));
        assert_eq!(empty.landed, 0);
        assert_eq!(empty.received_bytes, 0);
    }

    #[tokio::test]
    async fn telemetry_counts_one_landing_for_a_shared_want_and_selected_root() {
        let mut fixture = exact_fixture(1, 0);
        fixture
            .peer
            .store()
            .want(WantRequest::blob::<UnknownBlob>(Inline::new(
                fixture.roots[0],
            )))
            .unwrap();
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Shallow, [fixture.collection]);
        let stats = reconciler.tick(&mut fixture.peer).await;
        assert_eq!(stats.fulfilled, 1);
        assert_eq!(stats.replication.acquired, 1);
        assert_eq!(stats.landed, 1);
        assert_eq!(stats.received_bytes, b"exact root 0".len() as u64);
        assert_eq!(stats.pending_blobs, Some(0));
        assert_eq!(fixture.fetches.trace.lock().unwrap().calls.len(), 1);
    }

    #[tokio::test]
    async fn incoming_blob_record_and_auth_are_published_without_flush_and_put_errors_withdraw() {
        check_incoming_admission_without_flush(false).await;
    }

    #[tokio::test]
    async fn incoming_admission_snapshot_failure_recovers_without_redelivery_or_flush() {
        check_incoming_admission_without_flush(true).await;
    }

    async fn check_incoming_admission_without_flush(fail_first_snapshot: bool) {
        use crate::channel::{NetEvent, NetEventBatch};
        use crate::collection_activation::collection_repair_overlay;
        use crate::collection_session::manifest;
        use crate::peer::PeerSnapshotError;
        use triblespace_core::capability::CapabilityResource;
        use triblespace_core::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
        use triblespace_core::repo::CapabilityProofRead;

        let key = SigningKey::from_bytes(&[7; 32]);
        let reader = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let collection = store
            .collection(
                "unflushed-repair",
                CollectionPolicy::new(
                    AdmissionPolicy::direct(key.verifying_key()),
                    AdmissionPolicy::Open,
                ),
            )
            .unwrap()
            .handle();
        let (sender, receiver, wiring) =
            crate::host::wire(crate::identity::iroh_secret(&key).public().into());
        let observer = sender.clone();
        let trace = Arc::new(Mutex::new(LandingTrace {
            fail_flush: true,
            ..Default::default()
        }));
        let mut peer = Peer::with_wiring(
            LandingStore {
                inner: store,
                trace: trace.clone(),
            },
            crate::inventory::ReconcileQos::default(),
            sender,
            receiver,
        );
        peer.activate_collection(collection);
        let before = peer.snapshot().unwrap();
        let previous_serving = observer.current_snapshot().unwrap();
        assert!(previous_serving
            .collections()
            .any(|c| c.collection() == collection));
        let frontier = || {
            observer
                .health()
                .collections
                .iter()
                .find(|c| c.collection == collection)
                .unwrap()
                .local_frontier
        };
        let initial_overlay = collection_repair_overlay(&before, collection).unwrap();
        assert!(initial_overlay.records().is_empty());
        assert!(initial_overlay.authorization_evidence().is_empty());
        assert!(!initial_overlay
            .authorization_evidence()
            .reader_is_admitted_by(reader, &[]));
        let initial_frontier = frontier().unwrap();
        assert_eq!(initial_frontier.records, manifest(&initial_overlay).records);
        assert_eq!(
            initial_frontier.authorization_evidence,
            manifest(&initial_overlay).authorization_evidence
        );
        let blob = Blob::<UnknownBlob>::new(Bytes::from_source(b"network batch".to_vec()));
        let handle = blob.get_handle();
        let record = CollectionRecord::Commit(CollectionCommit::sign(
            &key,
            collection,
            handle.transmute(),
            triblespace_core::collection::empty_metadata_handle(),
        ));
        let proof = CapabilityProof::new(
            CapabilityResource::new(collection.raw),
            &key,
            triblespace_core::collection::read_capability(),
            reader,
        );
        let mut batch = NetEventBatch::default();
        batch.try_push(NetEvent::CollectionRecord(record)).unwrap();
        batch
            .try_push(NetEvent::CapabilityProof(proof.clone()))
            .unwrap();
        batch.try_push(NetEvent::Blob(blob)).unwrap();
        wiring.send_admission(batch).await;
        let snapshots_before = trace.lock().unwrap().snapshots;
        if fail_first_snapshot {
            trace.lock().unwrap().fail_next_snapshot = true;
            assert!(matches!(
                peer.try_refresh(),
                Err(PeerSnapshotError::Store(_))
            ));
            assert_eq!(trace.lock().unwrap().snapshots, snapshots_before + 1);
            assert_eq!(trace.lock().unwrap().put, [handle.raw]);
            assert_eq!(trace.lock().unwrap().flushes, 0);
            assert!(observer.current_snapshot().is_none());
            assert_eq!(frontier(), None);
            assert_eq!(
                observer.health().store.last_failure,
                Some(crate::health::StoreFailure::Snapshot)
            );
            assert!(!before.contains_blob(handle).unwrap());
            assert_eq!(before.records().unwrap().count(), 0);
            assert_eq!(before.proofs().unwrap().count(), 0);
            // The batch was already consumed and applied. Retry only the
            // observation: no event is sent again and no blob is re-landed.
        }
        peer.try_refresh().unwrap();
        assert_eq!(
            trace.lock().unwrap().snapshots,
            snapshots_before + 1 + usize::from(fail_first_snapshot)
        );
        assert_eq!(trace.lock().unwrap().put, [handle.raw]);
        let published_after_refresh = observer.current_snapshot().unwrap();
        let frontier_after_refresh = frontier();
        let after = peer.snapshot().unwrap();
        assert!(Arc::ptr_eq(
            &published_after_refresh,
            &observer.current_snapshot().unwrap()
        ));
        assert_eq!(trace.lock().unwrap().flushes, 0);
        assert!(!before.contains_blob(handle).unwrap());
        assert!(BlobStoreGet::get::<Bytes, UnknownBlob>(&after, handle).is_ok());
        assert_eq!(after.records().unwrap().count(), 1);
        assert_eq!(after.proofs().unwrap().count(), 1);
        let expected = collection_repair_overlay(&after, collection).unwrap();
        assert_eq!(expected.records().get(record.fingerprint()), Some(record));
        assert_eq!(
            expected.authorization_evidence().get(proof.id()),
            Some(&proof)
        );
        assert!(expected
            .authorization_evidence()
            .reader_is_admitted_by(reader, std::slice::from_ref(&proof)));
        // Health commits to the actual serving inventory as well as the
        // complete semantic record and AUTH PATCHes.
        let published = frontier_after_refresh.unwrap();
        assert_eq!(published.records, manifest(&expected).records);
        assert_eq!(
            published.authorization_evidence,
            manifest(&expected).authorization_evidence
        );
        // A bare semantic overlay has no resident inventory. The serving
        // product root also commits to the readable descriptor and payload.
        assert_ne!(published.wake_root, manifest(&expected).wake_root);
        assert_ne!(initial_frontier.wake_root, published.wake_root);
        assert_ne!(
            manifest(&initial_overlay).wake_root,
            manifest(&expected).wake_root
        );
        assert!(observer
            .current_snapshot()
            .unwrap()
            .collections()
            .any(|c| c.collection() == collection));
        assert!(!Arc::ptr_eq(
            &previous_serving,
            &observer.current_snapshot().unwrap()
        ));

        trace.lock().unwrap().fail_put = true;
        let mut batch = NetEventBatch::default();
        batch
            .try_push(NetEvent::Blob(Blob::<UnknownBlob>::new(
                Bytes::from_source(b"failed batch".to_vec()),
            )))
            .unwrap();
        wiring.send_admission(batch).await;
        assert!(matches!(
            peer.try_refresh(),
            Err(PeerSnapshotError::Overlay(_))
        ));
        assert!(observer.current_snapshot().is_none());
        assert!(
            BlobStoreGet::get::<Bytes, UnknownBlob>(&after, handle).is_ok(),
            "failure does not mutate an already frozen observation"
        );
        assert_eq!(trace.lock().unwrap().flushes, 0);
        peer.close().unwrap();
        assert_eq!(trace.lock().unwrap().closes, 1);
    }

    #[tokio::test]
    async fn exact_window_reads_unflushed_external_pile_append_without_a_fetch() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let mut writer = Pile::open(path.path()).unwrap();
        let blob =
            Blob::<UnknownBlob>::new(Bytes::from_source(b"external unflushed answer".to_vec()));
        let handle = blob.get_handle();
        writer.want(WantRequest::blob(handle)).unwrap();
        let mut peer = Peer::lazy(
            Pile::open(path.path()).unwrap(),
            SigningKey::from_bytes(&[7; 32]),
            crate::host::PeerConfig {
                peers: Vec::new(),
                qos: crate::inventory::ReconcileQos::default(),
                provider_publication_budget: Some(0),
            },
        );
        let frozen = peer.snapshot().unwrap();
        writer.put::<UnknownBlob, _>(blob).unwrap();
        assert!(!frozen.contains_blob(handle).unwrap());
        let stats = Reconciler::new().tick(&mut peer).await;
        assert_eq!(stats.wants, 1);
        assert_eq!(stats.missing, 0);
        assert_eq!(stats.attempted, 0);
        assert_eq!(stats.pending, 0);
        assert!(BlobStoreGet::get::<Bytes, UnknownBlob>(&peer.snapshot().unwrap(), handle).is_ok());
        peer.close().unwrap();
        writer.close().unwrap();
    }

    #[tokio::test]
    async fn exact_window_corrupt_primary_is_missing_but_valid_duplicate_satisfies_it() {
        use std::io::{Seek, SeekFrom, Write};

        for valid_duplicate in [false, true] {
            let path = tempfile::NamedTempFile::new().unwrap();
            let bytes = Bytes::from_source(b"actual requested content".to_vec());
            let mut pile = Pile::open(path.path()).unwrap();
            let handle = pile.put::<UnknownBlob, _>(bytes.clone()).unwrap();
            pile.want(WantRequest::blob(handle)).unwrap();
            pile.close().unwrap();
            let original_frames = std::fs::read(path.path()).unwrap();
            let body_offset = PileRecords::open(path.path())
                .unwrap()
                .find_map(|record| match record.unwrap().content {
                    PileRecordContent::Blob {
                        hash, data_offset, ..
                    } if hash.raw == handle.raw => Some(data_offset),
                    _ => None,
                })
                .unwrap();
            // Prepare a corrupt imported occurrence before any tested reader
            // maps the file. Native framing supplies the offset; no magic IDs.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(path.path())
                .unwrap();
            file.seek(SeekFrom::Start(body_offset as u64)).unwrap();
            file.write_all(&[0xff]).unwrap();
            drop(file);
            if valid_duplicate {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(path.path())
                    .unwrap()
                    .write_all(&original_frames)
                    .unwrap();
            }
            let key = SigningKey::from_bytes(&[7; 32]);
            let (sender, receiver, wiring) =
                crate::host::wire(crate::identity::iroh_secret(&key).public().into());
            let fetches = Arc::new(ControlledFetches {
                answers: BTreeMap::from([(handle.raw, bytes.clone())]),
                blocked: BTreeSet::new(),
                delay: Mutex::new(Duration::ZERO),
                released: Arc::new(AtomicBool::new(true)),
                wake: Arc::new(tokio::sync::Notify::new()),
                trace: Arc::new(Mutex::new(FetchTrace::default())),
            });
            wiring.install_test_capability(fetches.clone());
            let mut peer = Peer::with_wiring(
                Pile::open(path.path()).unwrap(),
                crate::inventory::ReconcileQos::default(),
                sender,
                receiver,
            );
            let frozen = peer.snapshot().unwrap();
            assert!(
                frozen.contains_blob(handle).unwrap(),
                "physical presence alone does not imply readable bytes"
            );
            assert_eq!(
                BlobStoreGet::get::<Bytes, UnknownBlob>(&frozen, handle).is_ok(),
                valid_duplicate
            );
            let mut reconciler = Reconciler::new();
            let first = reconciler.tick(&mut peer).await;
            assert_eq!(first.attempted, usize::from(!valid_duplicate));
            assert_eq!(first.pending, 0);
            assert_eq!(
                BlobStoreGet::get::<Bytes, UnknownBlob>(&peer.snapshot().unwrap(), handle).unwrap(),
                bytes
            );
            let second = reconciler.tick(&mut peer).await;
            assert_eq!(second.attempted, 0);
            assert_eq!(second.pending, 0);
            assert_eq!(
                fetches.trace.lock().unwrap().calls.len(),
                usize::from(!valid_duplicate)
            );
            // The old prefix remains frozen and must not inherit validation
            // from a later successful put under the same H.
            assert_eq!(
                BlobStoreGet::get::<Bytes, UnknownBlob>(&frozen, handle).is_ok(),
                valid_duplicate
            );
            peer.close().unwrap();
        }
    }
}
