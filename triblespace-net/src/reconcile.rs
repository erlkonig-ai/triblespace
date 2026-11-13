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

use std::any::Any;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use anybytes::Bytes;
use futures::stream::{FuturesUnordered, StreamExt};
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::covered::{Covered, CoveredSnapshot};
use triblespace_core::collection::held::HeldSource;
use triblespace_core::collection::{
    CollectionHandle, CollectionRecordSelector, CollectionStore, HeldRead, HeldStore,
    RecordViewChanges,
};
use triblespace_core::inline::Inline;
use triblespace_core::patch::{Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::repo::{
    BlobChildren, BlobStore, BlobStoreGet, BlobStoreList, CapabilityProofStore, SnapshotSource,
    SnapshotStep, StorageFlush, StoreChanges, StoreDependencies, StoreRead, WantRead, WantRequest,
    WantStore,
};

use crate::peer::{Peer, PeerSnapshot};
use crate::protocol::RawHash;

/// How much content an explicit collection selection asks this process to obtain.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationMode {
    /// Repair records and service explicit WANTs, without implicit blob demand.
    #[default]
    Demand,
    /// Obtain every direct reference of the selected collections' foundations:
    /// descriptor, COMMIT data and metadata, and DERIVE outputs.
    Shallow,
    /// Also hold what a Full neighbour holds in each selected collection:
    /// its pushed references tree ([`crate::walk`]) names it, and what is
    /// not resident is fetched from that neighbour.
    Full,
}

/// Hydration observations, separate from durable WANT fulfillment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplicationStats {
    /// Distinct direct handles named by the selected records in this observation.
    pub roots: usize,
    /// Direct roots not yet resident. Speculative misses are not roots.
    pub pending: usize,
    /// Blobs fetched and locally landed for hydration during this tick.
    pub acquired: usize,
    /// Compatibility counter; speculative scanning was removed and this stays zero.
    pub candidates: usize,
    /// Compatibility counter; candidate filtering was removed and this stays zero.
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
    /// Verified network payloads successfully put during this completed tick.
    /// A payload shared by a WANT and a root counts once. Neither local hits nor failed puts contribute.
    pub landed: usize,
    pub received_bytes: u64,
    /// Distinct unreadable exact blob WANTs and absent selected direct roots at the
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

/// Retry/traversal state, plus the last hydration observation memoised on the
/// store snapshot it answers. Durable demand and all answers remain in the store.
pub struct Reconciler {
    states: HashMap<RawHash, WantState>,
    initial_backoff: Duration,
    max_backoff: Duration,
    fetch_budget: Duration,
    mode: ReplicationMode,
    /// The selected collections, keyed by the handle's bytes.
    collections: PATCH<32, IdentitySchema>,
    observation_generation: u64,
    want_round: ExactRound,
    root_round: ExactRound,
    next_service: ServiceTurn,
    /// A [`Hydration`] over the snapshot type of the store last ticked. It is
    /// type-erased only so the reconciler stays independent of its store. A
    /// selection change keeps it: the next advance reads a newly selected
    /// collection whole, and a collection leaving the selection resets it. A
    /// different store type, Demand mode, or a failed observation discards
    /// it, and the next tick advances a new one from empty.
    hydration: Option<Box<dyn Any + Send + Sync>>,
}

/// The selected direct roots as of one store snapshot, and the subset of them
/// that snapshot does not hold.
///
/// This is a memo of one query answer, keyed on the snapshot it answers. It
/// starts empty -- the answer for a store that holds nothing -- and is only
/// ever advanced, to a later snapshot, through that snapshot's own change
/// evidence: `changes_for` says whether the selected records or the blob view
/// moved at all, `select_record_view_changes` supplies the selected records
/// that were added, and `blobs_diff` in reverse names blobs that went away. A
/// collection the memo has not answered for yet is read whole, as an advance
/// from its empty view. Anything the evidence cannot express as pure addition
/// -- a semantic record removal, a replaced or truncated source, a failed
/// enumeration, a collection leaving the selection -- resets the memo to empty
/// and advances it again, through the same steps, to the current snapshot.
///
/// So there is one way to reach an answer, and a caller decides only how big
/// the steps are. A daemon's ticks are small steps. A cold start is one big
/// step, unless the store is climbed: snapshots of growing prefixes of one
/// pile ([`Covered::snapshot_step`](triblespace_core::collection::covered::Covered::snapshot_step)),
/// each an append to the last, fed here in order. A prefix is only a partial
/// pile, so a root it names but does not yet hold is missing exactly as it
/// would be at the tail.
///
/// A root is held when the snapshot's blob index has it ([`resident`]). No
/// payload is read or hashed here: the handle a store indexes was computed
/// from the bytes when they were written, or checked against them when they
/// were received, and hydration trusts it as written. The bytes are checked
/// where they are used: every read that hands them out (serving, the held
/// scan, a reader) validates them, and a fetch hashes what it receives
/// against the handle it asked for. So a resident root whose bytes no longer
/// match counts as held, and hydration does not fetch it again. A held root
/// stays held in a later snapshot unless it left the blob view.
pub struct Hydration<T> {
    /// The snapshot answered; `None` for the empty answer.
    snapshot: Option<T>,
    /// The collections answered for, keyed by the handle's bytes.
    collections: PATCH<32, IdentitySchema>,
    roots: BTreeSet<RawHash>,
    missing: BTreeSet<RawHash>,
    counts: HydrationCounts,
}

/// What a [`Hydration`] has done since it was created, across resets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HydrationCounts {
    /// Advances, including the first from the empty answer.
    pub advances: usize,
    /// Resets to the empty answer forced by evidence that was not an append.
    pub resets: usize,
    /// Roots that were missing at one advance and resident at a later one.
    /// During a climb each would have been a fetch decision had a tick
    /// observed that prefix; in a daemon they are blobs that landed.
    pub arrived: usize,
}

impl<T> Default for Hydration<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Hydration<T> {
    /// The empty answer: no collection, no root, no snapshot.
    pub fn new() -> Self {
        Self {
            snapshot: None,
            collections: PATCH::new(),
            roots: BTreeSet::new(),
            missing: BTreeSet::new(),
            counts: HydrationCounts::default(),
        }
    }

    /// The selected direct roots of the snapshot answered.
    pub fn roots(&self) -> &BTreeSet<RawHash> {
        &self.roots
    }

    /// The roots that snapshot does not hold.
    pub fn missing(&self) -> &BTreeSet<RawHash> {
        &self.missing
    }

    /// The collections answered for, keyed by the handle's bytes.
    pub fn collections(&self) -> &PATCH<32, IdentitySchema> {
        &self.collections
    }

    pub fn counts(&self) -> HydrationCounts {
        self.counts
    }

    fn reset(&mut self) {
        #[cfg(test)]
        tests::RESETS.with(|count| count.set(count.get() + 1));
        let counts = HydrationCounts {
            resets: self.counts.resets + 1,
            ..self.counts
        };
        *self = Self::new();
        self.counts = counts;
    }
}

/// Evidence an advance cannot apply as an append.
enum NotAnAppend<E> {
    Reset,
    Failed(E),
}

impl<T: StoreRead> Hydration<T> {
    /// The same answer for `snapshot` and `collections`, reading only what
    /// changed since the snapshot answered: added selected records, the
    /// still-missing roots, roots whose blobs left the view, and the whole of
    /// any collection not answered for before. Evidence that is not an append
    /// resets the answer to empty and advances it from there.
    ///
    /// The first advance reads every selected record and looks up every root
    /// in the blob index, which for a large pile is still a lot of work. So
    /// it yields once a chunk of that has taken [`ADVANCE_TURN`]. That is a
    /// threshold between steps, not a latency bound: a single lookup, and an
    /// index selection, stay synchronous. A caller's other branches (a
    /// daemon's stop signal) are polled at those yields. Dropped at a yield,
    /// it has read only immutable snapshots and published nothing: the memo
    /// it consumed is gone, and the next advance starts from empty.
    pub async fn advance(
        mut self,
        snapshot: &T,
        collections: &[CollectionHandle],
    ) -> Result<Self, T::RecordsError> {
        let collections: BTreeSet<_> = collections.iter().copied().collect();
        self.counts.advances += 1;
        match self.advance_from(snapshot, &collections).await {
            Ok(()) => return Ok(self),
            Err(NotAnAppend::Failed(error)) => return Err(error),
            Err(NotAnAppend::Reset) => self.reset(),
        }
        // From the empty answer every collection is read whole, and nothing
        // can be anything but an append.
        match self.advance_from(snapshot, &collections).await {
            Ok(()) => Ok(self),
            Err(NotAnAppend::Failed(error)) => Err(error),
            Err(NotAnAppend::Reset) => unreachable!("an advance from empty is an append"),
        }
    }

    async fn advance_from(
        &mut self,
        snapshot: &T,
        collections: &BTreeSet<CollectionHandle>,
    ) -> Result<(), NotAnAppend<T::RecordsError>> {
        let collections = {
            let mut set = PATCH::<32, IdentitySchema>::new();
            for collection in collections {
                set.insert(&PatchEntry::new(&collection.raw));
            }
            set
        };
        // A root may be named only by a collection that left the selection.
        if !self.collections.difference(&collections).is_empty() {
            return Err(NotAnAppend::Reset);
        }
        #[cfg(test)]
        if self.snapshot.is_none() {
            tests::FROM_EMPTY.with(|count| count.set(count.get() + 1));
        }
        let mut turn = crate::clock::mono_now();
        let mut added = Vec::new();
        if let Some(previous) = &self.snapshot {
            let selectors: BTreeSet<_> = self
                .collections
                .iter_ordered()
                .map(|raw| CollectionRecordSelector::Foundations(Inline::new(*raw)))
                .collect();
            let read_set = StoreDependencies {
                records: selectors.iter().copied().collect(),
                all_blobs: true,
                ..StoreDependencies::default()
            };
            let changes = snapshot.changes_for(previous, &read_set);
            if changes.contains(StoreChanges::COLLECTION_RECORDS) && !selectors.is_empty() {
                let views = match snapshot
                    .select_record_view_changes(previous, &selectors)
                    .map_err(NotAnAppend::Failed)?
                {
                    RecordViewChanges::Append(views) => views,
                    RecordViewChanges::Delta { added, removed } if removed.is_empty() => added,
                    // A removed record may have been the only one naming a root.
                    RecordViewChanges::Delta { .. } | RecordViewChanges::Rebuild => {
                        return Err(NotAnAppend::Reset);
                    }
                };
                for view in views {
                    for handle in view.to_record().blob_references() {
                        if self.roots.insert(handle.raw) {
                            added.push(handle.raw);
                        }
                    }
                    yield_after_turn(&mut turn).await;
                }
            }
            if changes.contains(StoreChanges::BLOBS) {
                // An arrival.
                for handle in self.missing.clone() {
                    if resident(snapshot, handle) {
                        self.missing.remove(&handle);
                        self.counts.arrived += 1;
                    }
                    yield_after_turn(&mut turn).await;
                }
                // What was here before and is not now; empty for an append-only pile.
                for gone in previous.blobs_diff(snapshot) {
                    let Ok(gone) = gone else {
                        return Err(NotAnAppend::Reset);
                    };
                    let handle = gone.handle.raw;
                    if self.roots.contains(&handle)
                        && !self.missing.contains(&handle)
                        && !resident(snapshot, handle)
                    {
                        self.missing.insert(handle);
                    }
                    yield_after_turn(&mut turn).await;
                }
            }
        }
        // Collections not answered for before are read whole: their view in
        // the previous answer was empty. One indexed read per collection;
        // COMMIT signatures are checked once, before physical union.
        let fresh = collections.difference(&self.collections);
        for raw in fresh.iter_ordered() {
            let selectors =
                BTreeSet::from([CollectionRecordSelector::Foundations(Inline::new(*raw))]);
            let views = snapshot
                .select_record_views(&selectors)
                .map_err(NotAnAppend::Failed)?;
            yield_after_turn(&mut turn).await;
            for view in views {
                // Records are trusted local evidence; foreign signatures were
                // checked at ingress. WRITE admission does not govern
                // structural ownership.
                for handle in view.to_record().blob_references() {
                    if self.roots.insert(handle.raw) {
                        added.push(handle.raw);
                    }
                }
                yield_after_turn(&mut turn).await;
            }
        }
        for handle in added {
            if !resident(snapshot, handle) {
                self.missing.insert(handle);
            }
            yield_after_turn(&mut turn).await;
        }
        self.collections = collections;
        self.snapshot = Some(snapshot.clone());
        Ok(())
    }
}

/// Bytes of pile replayed per [`climb`] step at a daemon's startup. Replay
/// does not read blob payloads, so a step's replay is short; what the step
/// then reads for hydration is about the payload of the roots its own records
/// name, which in file order sit in the same step or an earlier one.
pub const CLIMB_STEP_BYTES: u64 = 1 << 30;

/// Replay `pile` to the end of its file in steps of about `step_bytes`, and
/// advance one [`Hydration`] from empty through a snapshot of every prefix,
/// each with the collections `selection` names in it.
///
/// This is a cold start fed in pieces. Every prefix is a partial pile and
/// every step an append to the previous one, so the answer equals one advance
/// over the last snapshot, while no single advance reads more than one step's
/// roots and the caller's other branches (a stop) are polled between and
/// within steps. A collection the selection names only from some prefix on is
/// read whole from there; one it stops naming resets the climb's answer.
/// `on_step` sees the answer after each step, and whether that step reached
/// the end of the file as it observed it.
///
/// Hand the result to [`Peer::adopt_hydration`](crate::peer::Peer::adopt_hydration)
/// once the peer is assembled over the same `pile`.
///
/// `pile` is any covered store that steps ([`SnapshotStep`]): a
/// [`Pile`](triblespace_core::repo::pile::Pile), or custody's
/// `Covered<Repairing<PileFile>>` ([`Repairing`](crate::peer::Repairing)).
pub async fn climb<S, E>(
    pile: &mut Covered<S>,
    step_bytes: u64,
    mut selection: impl FnMut(&CoveredSnapshot<S::Snapshot>) -> Result<Vec<CollectionHandle>, E>,
    mut on_step: impl FnMut(&Hydration<CoveredSnapshot<S::Snapshot>>, bool),
) -> anyhow::Result<Hydration<CoveredSnapshot<S::Snapshot>>>
where
    S: SnapshotStep,
    S::Snapshot: HeldSource,
    CoveredSnapshot<S::Snapshot>: StoreRead,
    E: Into<anyhow::Error>,
{
    let mut hydration = Hydration::new();
    loop {
        let (snapshot, reached_end) = pile.snapshot_step(step_bytes)?;
        let collections = selection(&snapshot).map_err(Into::into)?;
        hydration = hydration.advance(&snapshot, &collections).await?;
        on_step(&hydration, reached_end);
        if reached_end {
            return Ok(hydration);
        }
        tokio::task::yield_now().await;
    }
}

/// How long a hydration advance runs before it yields to its runtime.
const ADVANCE_TURN: Duration = Duration::from_millis(10);

/// Yield once `turn` is [`ADVANCE_TURN`] old, and start a new turn.
async fn yield_after_turn(turn: &mut crate::clock::Mono) {
    if crate::clock::mono_now().duration_since(*turn) >= ADVANCE_TURN {
        tokio::task::yield_now().await;
        *turn = crate::clock::mono_now();
    }
}

/// Whether `snapshot` holds `handle`: one lookup in its blob index, without
/// reading the payload. Hydration's root check; see [`Hydration`] for why the
/// indexed handle is trusted. A failed lookup counts as absent.
fn resident<R: BlobStoreList>(snapshot: &R, handle: RawHash) -> bool {
    #[cfg(test)]
    {
        tests::READS.with(|count| count.set(count.get() + 1));
        std::thread::sleep(tests::READ_DELAY.get());
    }
    snapshot
        .contains_blob::<UnknownBlob>(Inline::new(handle))
        .unwrap_or(false)
}

/// Whether `snapshot` hands out bytes for `handle`: the validated read, for
/// an exact WANT. A physical occurrence alone can be corrupt.
fn readable<R: BlobStoreGet>(snapshot: &R, handle: RawHash) -> bool {
    #[cfg(test)]
    {
        tests::READS.with(|count| count.set(count.get() + 1));
        std::thread::sleep(tests::READ_DELAY.get());
    }
    BlobStoreGet::get::<Bytes, UnknownBlob>(snapshot, Inline::new(handle)).is_ok()
}

pub const RECONCILE_FETCH_DEADLINE: Duration = Duration::from_secs(30);

/// Base backoff for a failed WANT fulfillment; it doubles per attempt up to
/// [`WANT_BACKOFF_CAP`]. A transient fault (peer restarting, partition
/// healing) is retried promptly while a persistently dead source costs at
/// most one attempt per cap period.
const WANT_BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Upper bound the exponential WANT backoff saturates at.
const WANT_BACKOFF_CAP: Duration = Duration::from_secs(60);

/// Shared exact-demand and direct-root request window. Eight leaves
/// nominal headroom below the sixteen process-wide exact body receivers; this
/// is neither a reserved slot allocation nor a throughput or memory guarantee.
const EXACT_FETCHES_IN_FLIGHT: usize = 8;

impl Default for Reconciler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reconciler {
    pub fn new() -> Self {
        Self::with_backoff(WANT_BACKOFF_BASE, WANT_BACKOFF_CAP)
    }

    pub fn with_backoff(initial: Duration, max: Duration) -> Self {
        Self {
            states: HashMap::new(),
            initial_backoff: initial,
            max_backoff: max,
            fetch_budget: RECONCILE_FETCH_DEADLINE,
            mode: ReplicationMode::Demand,
            collections: PATCH::new(),
            observation_generation: 0,
            want_round: ExactRound::default(),
            root_round: ExactRound::default(),
            next_service: ServiceTurn::default(),
            hydration: None,
        }
    }

    pub fn with_fetch_budget(mut self, budget: Duration) -> Self {
        self.fetch_budget = budget;
        self
    }

    /// Select collection hydration explicitly, independently of READ grants or
    /// Peer activation. This does not activate a collection or publish a WANT.
    ///
    /// Signature-valid but WRITE-inert COMMITs and DERIVEs contribute direct
    /// references; a MERGE never replicates and contributes none. Obtaining
    /// their bytes does not admit their semantic claims. Changing this
    /// selection forgets only process-local traversal state, never stored
    /// data or demand.
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
        self.collections = PATCH::new();
        for collection in collections {
            self.collections.insert(&PatchEntry::new(&collection.raw));
        }
        self.root_round = ExactRound::default();
        self.next_service = ServiceTurn::default();
        // The hydration memo stays: its next advance reads a collection that
        // joined the selection whole, and one that left resets it.
        for state in self.states.values_mut() {
            state.root_since = None;
            state.first_root_attempt = false;
        }
    }

    /// The selected collections, in ascending handle order.
    fn selected(&self) -> impl Iterator<Item = CollectionHandle> + '_ {
        self.collections
            .iter_ordered()
            .map(|raw| CollectionHandle::new(*raw))
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

    /// Apply this reconciler's explicit hydration selection, then service one
    /// quantum. This configures local policy
    /// only: it neither activates collections nor starts a lazy host.
    pub async fn tick<S>(&mut self, peer: &mut Peer<S>) -> ReconcileStats
    where
        S: BlobStore
            + CollectionStore
            + CapabilityProofStore
            + WantStore
            + StorageFlush
            + HeldStore
            + Send
            + 'static,
        S::Snapshot: StoreRead + BlobChildren + HeldRead,
    {
        if peer.reconciler().mode != self.mode || peer.reconciler().collections != self.collections
        {
            peer.set_replication(self.mode, self.selected());
        }
        // This is also the explicit external-Pile reobservation boundary.
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
        let stats = self.tick_snapshot(snapshot).await;
        if stats.landed != 0 {
            peer.refresh();
        }
        stats
    }

    pub(crate) async fn tick_snapshot<S>(&mut self, snapshot: PeerSnapshot<S>) -> ReconcileStats
    where
        S: BlobStore + HeldStore + Send + 'static,
        S::Snapshot: StoreRead + BlobChildren + HeldRead,
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
        let (roots_observed, root_count, missing_roots) = if self.mode == ReplicationMode::Demand {
            self.hydration = None;
            (true, 0, BTreeSet::new())
        } else {
            match self.observe_roots(&*snapshot).await {
                Ok((count, missing)) => (true, count, missing),
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "hydration record observation failed; skipping roots"
                    );
                    (false, 0, BTreeSet::new())
                }
            }
        };
        stats.replication.roots = root_count;
        let missing_wanted: BTreeSet<_> = wanted_blob_handles
            .iter()
            .copied()
            .filter(|&handle| !readable(&snapshot, handle))
            .collect();
        stats.missing = missing_wanted.len();
        // A handle keeps retry state exactly while it is wanted or a root and
        // this snapshot cannot read it.
        self.states
            .retain(|handle, _| missing_wanted.contains(handle) || missing_roots.contains(handle));
        self.observe_missing(&missing_wanted, &missing_roots);
        // Only this tick's completion delta; the next tick observes the actual
        // store again, including bad imports.
        let mut arrived = HashSet::new();

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
                    if arrived.contains(&handle) || !in_flight.insert(handle) {
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
                // boundary.
                arrived.insert(handle);
                self.states.remove(&handle);
                if is_want {
                    stats.fulfilled += 1;
                }
                if missing_roots.contains(&handle) {
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
        let unlanded = |handles: &BTreeSet<RawHash>| {
            handles
                .iter()
                .filter(|handle| !arrived.contains(*handle))
                .count()
        };
        stats.pending = unlanded(&missing_wanted);
        stats.replication.pending = unlanded(&missing_roots);
        stats.pending_blobs = roots_observed.then(|| {
            missing_wanted
                .union(&missing_roots)
                .filter(|handle| !arrived.contains(*handle))
                .count()
        });
        stats
    }

    /// Continue from `hydration`, an answer advanced over earlier snapshots of
    /// the store this reconciler will tick (a climb at startup), instead of
    /// from empty. The next tick advances it to its own snapshot, which
    /// resets it if the store or the selection moved in a way that is not an
    /// append, so a stale or foreign answer costs a reread, never a wrong
    /// one.
    pub(crate) fn adopt_hydration<T: StoreRead>(&mut self, hydration: Hydration<T>) {
        if self.mode != ReplicationMode::Demand {
            self.hydration = Some(Box::new(hydration));
        }
    }

    /// The selected root count and the roots `snapshot` cannot read: the
    /// previous tick's [`Hydration`] when there is one for this store type
    /// and selection, or the empty one, advanced to `snapshot`.
    async fn observe_roots<T: StoreRead>(
        &mut self,
        snapshot: &T,
    ) -> Result<(usize, BTreeSet<RawHash>), T::RecordsError> {
        let collections: Vec<_> = self.selected().collect();
        // Taken before the read: a failure leaves no memo behind.
        let previous = self
            .hydration
            .take()
            .and_then(|memo| memo.downcast::<Hydration<T>>().ok())
            .map_or_else(Hydration::new, |memo| *memo);
        let hydration = previous.advance(snapshot, &collections).await?;
        let observed = (hydration.roots.len(), hydration.missing.clone());
        self.hydration = Some(Box::new(hydration));
        Ok(observed)
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
        CollectionCommit, CollectionDerive, CollectionMerge, CollectionRead, CollectionRecord,
    };
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::inline::{Inline, InlineEncoding};
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::pile::{Pile, PileRecordContent, PileRecords};
    use triblespace_core::repo::{BlobStoreList, BlobStorePut, StorageClose};

    std::thread_local! {
        /// Root lookups and WANT reads made by the reconciler on this thread.
        pub(super) static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        /// Hydration resets to empty forced on this thread.
        pub(super) static RESETS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        /// Hydration advances from the empty answer on this thread.
        pub(super) static FROM_EMPTY: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        /// Time each root lookup or WANT read takes on this thread, standing
        /// in for a large pile's first pass.
        pub(super) static READ_DELAY: std::cell::Cell<Duration> =
            const { std::cell::Cell::new(Duration::ZERO) };
    }

    /// Reset the counters, returning their previous `(reads, advances from
    /// empty)`; a reset is followed by an advance from empty, so it counts.
    fn take_counts() -> (usize, usize) {
        RESETS.replace(0);
        (READS.replace(0), FROM_EMPTY.replace(0))
    }

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
    fn service_turns_preserve_old_rounds_and_wants_during_continuous_root_arrival() {
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
        assert!(
            reconciler
                .next_work(&wanted, &roots, crate::clock::mono_now())
                .is_none()
        );
        assert_eq!(reconciler.states[&root].last_attempt, last_attempt);
        assert_eq!(reconciler.states[&root].backoff, Duration::from_secs(60));
        assert!(reconciler.states[&root].first_root_attempt);
    }

    /// Hydration roots are the foundations' direct references: descriptor,
    /// commit data and metadata, and derive outputs -- never a MERGE's inputs
    /// or result.
    #[tokio::test]
    async fn hydration_roots_are_foundation_references_without_loading_descriptors() {
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
                    (4..12).map(|byte| Inline::new([byte; 32])),
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
        let selected = Hydration::new().advance(&snapshot, &[collection]).await;
        assert_eq!(
            selected.unwrap().roots,
            [1, 2, 3, 7].map(|byte| [byte; 32]).into_iter().collect(),
        );
        let unknown = Hydration::new()
            .advance(&snapshot, &[Inline::new([12; 32])])
            .await;
        assert!(unknown.unwrap().roots.is_empty());
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

    impl HeldStore for LandingStore {
        fn track_held(&mut self, collections: impl IntoIterator<Item = CollectionHandle>) {
            self.inner.track_held(collections)
        }

        fn note_held(&mut self, collection: CollectionHandle, handle: Inline<Handle<UnknownBlob>>) {
            self.inner.note_held(collection, handle)
        }

        fn drive_held(&mut self) -> Option<triblespace_core::collection::HeldWork> {
            self.inner.drive_held()
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
    async fn full_false_payload_words_cause_no_network_requests() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"false-word descriptor".to_vec());
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
            assert_eq!(stats.replication.candidates, 0);
            assert_eq!(stats.replication.filtered, 0);
            assert_eq!(stats.replication.speculative_attempted, 0);
            assert_eq!(stats.replication.speculative_misses, 0);
        }
        assert!(fetches.trace.lock().unwrap().calls.is_empty());
        assert_eq!(peer.snapshot().unwrap().wants().unwrap().count(), 0);
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

    /// The daemon's shape: one current-thread runtime, a stop raised from
    /// another thread (as a signal is), and a first pass whose derivation
    /// reads many roots. The stop must win long before the derivation would
    /// end, and the next pass derives from scratch with the full answer.
    #[test]
    fn a_stop_during_the_first_derivation_is_answered_without_waiting_for_it() {
        const ROOTS: u32 = 2_000;
        const READ: Duration = Duration::from_millis(2);
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"long first pass".to_vec());
        let metadata = put(&mut store, Vec::new());
        for ordinal in 0..ROOTS {
            let data = put(
                &mut store,
                format!("first-pass root {ordinal}").into_bytes(),
            );
            raw_commit(&mut store, descriptor, data, metadata);
        }
        let (mut peer, fetches, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        peer.set_replication(ReplicationMode::Shallow, [Inline::new(descriptor)]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (raise, stop) = tokio::sync::oneshot::channel::<()>();
        let raiser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            raise.send(()).unwrap();
        });
        READ_DELAY.set(READ);
        take_counts();
        let started = std::time::Instant::now();
        let stopped = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = stop => true,
                _ = peer.reconcile() => false,
            }
        });
        let elapsed = started.elapsed();
        READ_DELAY.set(Duration::ZERO);
        raiser.join().unwrap();
        let (reads, derivations) = take_counts();
        // The whole derivation is ROOTS + 2 reads of READ each, about 4 s.
        assert!(
            stopped,
            "the pass ended before the stop was seen, after {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the stop took {elapsed:?}, after {reads} of {} reads",
            ROOTS + 2,
        );
        assert_eq!(derivations, 1);
        assert!(reads < ROOTS as usize / 2, "{reads} reads before the stop");
        // A stopped derivation leaves no memo: the next pass derives again
        // and reaches the same answer as a reconciler that never stopped.
        let stats = runtime.block_on(peer.reconcile());
        assert_eq!(take_counts(), (ROOTS as usize + 2, 1));
        assert_eq!(stats.replication.roots, ROOTS as usize + 2);
        assert_eq!(stats.replication.pending, 0);
        assert!(fetches.trace.lock().unwrap().calls.is_empty());
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
        // Eight pending requests must leave more than one window untouched.
        let count = 2 * EXACT_FETCHES_IN_FLIGHT + 1;
        let mut fixture = exact_fixture(count, count);
        let mut reconciler =
            Reconciler::new().with_replication(ReplicationMode::Shallow, [fixture.collection]);
        let mut tick = Box::pin(reconciler.tick(&mut fixture.peer));
        assert!(futures::poll!(tick.as_mut()).is_pending());
        assert_eq!(fixture.fetches.trace.lock().unwrap().active, 8);
        assert!(fixture.roots.len() - 8 > 8);
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
        // Two complete waves fit; the third still owes its original deadline.
        let completed = 2 * EXACT_FETCHES_IN_FLIGHT;
        let mut fixture = exact_fixture(completed + 1, 0);
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
        assert_eq!(stats.replication.acquired, completed);
        assert_eq!(stats.replication.pending, 1);
        let trace = fixture.fetches.trace.lock().unwrap();
        assert_eq!(trace.calls.len(), fixture.roots.len());
        assert_eq!(trace.peak, EXACT_FETCHES_IN_FLIGHT);
        assert_eq!(trace.active, 0);
        assert_eq!(trace.cancelled, 1);
        assert_eq!(fixture.landings.lock().unwrap().put.len(), completed);
        assert_eq!(fixture.landings.lock().unwrap().flushes, 0);
    }

    #[cfg(feature = "sim")]
    #[tokio::test(start_paused = true)]
    async fn exact_window_deadline_preserves_the_unstarted_tail_and_next_service() {
        let count = 2 * EXACT_FETCHES_IN_FLIGHT + 1;
        let mut fixture = exact_fixture(count, count);
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
        use crate::collection_wire::manifest;
        use crate::peer::PeerSnapshotError;
        use triblespace_core::capability::{CapabilityResource, QuorumOutcome};
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
            sender,
            receiver,
        );
        peer.activate_collection(collection);
        let before = peer.snapshot().unwrap();
        let previous_serving = observer.current_snapshot().unwrap();
        assert!(
            previous_serving
                .collections()
                .any(|c| c.collection() == collection)
        );
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
        assert_eq!(
            initial_overlay
                .authorization_evidence()
                .reader_is_admitted_by(&before, reader, &[]),
            QuorumOutcome::Unmet
        );
        let initial_frontier = frontier().unwrap();
        assert_eq!(initial_frontier.commits, manifest(&initial_overlay).commits);
        assert_eq!(initial_frontier.derives, manifest(&initial_overlay).derives);
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
        assert!(published_after_refresh.same_observation(&observer.current_snapshot().unwrap()));
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
        assert_eq!(
            expected.authorization_evidence().reader_is_admitted_by(
                &after,
                reader,
                std::slice::from_ref(&proof)
            ),
            QuorumOutcome::Met
        );
        // Health commits to the complete record PATCHes.
        let published = frontier_after_refresh.unwrap();
        assert_eq!(published.commits, manifest(&expected).commits);
        assert_eq!(published.derives, manifest(&expected).derives);
        // The root leaves held blobs out, so a bare semantic overlay and the
        // serving one share it.
        assert_eq!(published.wake_root, manifest(&expected).wake_root);
        assert_ne!(initial_frontier.wake_root, published.wake_root);
        assert_ne!(
            manifest(&initial_overlay).wake_root,
            manifest(&expected).wake_root
        );
        assert!(
            observer
                .current_snapshot()
                .unwrap()
                .collections()
                .any(|c| c.collection() == collection)
        );
        assert!(!previous_serving.same_observation(&observer.current_snapshot().unwrap()));

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
                daemon: None,
                provider_publication_budget: Some(0),
                bind: None,
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
            let mut peer = Peer::with_wiring(Pile::open(path.path()).unwrap(), sender, receiver);
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

    fn commit_record(descriptor: RawHash, data: RawHash, metadata: RawHash) -> CollectionRecord {
        CollectionRecord::Commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[7; 32]),
            Inline::new(descriptor),
            Inline::new(data),
            Inline::new(metadata),
        ))
    }

    /// Roots and pending roots as a reconciler without any memo sees them.
    async fn derived_from_scratch<S>(
        peer: &mut Peer<S>,
        collections: impl IntoIterator<Item = CollectionHandle>,
    ) -> (usize, usize)
    where
        S: BlobStore
            + CollectionStore
            + CapabilityProofStore
            + WantStore
            + StorageFlush
            + HeldStore
            + Send
            + 'static,
        S::Snapshot: StoreRead + BlobChildren + HeldRead,
    {
        let mut fresh = Reconciler::new()
            .with_replication(ReplicationMode::Shallow, collections)
            .with_fetch_budget(Duration::ZERO);
        let stats = fresh.tick_snapshot(peer.snapshot().unwrap()).await;
        (stats.replication.roots, stats.replication.pending)
    }

    #[tokio::test]
    async fn unchanged_store_tick_reads_no_roots() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"steady descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        for ordinal in 0..32 {
            let data = put(&mut store, format!("steady data {ordinal}").into_bytes());
            raw_commit(&mut store, descriptor, data, metadata);
        }
        // One root that no provider answers stays missing across ticks.
        raw_commit(&mut store, descriptor, [0xee; 32], metadata);
        let (mut peer, fetches, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        let mut reconciler = Reconciler::new()
            .with_replication(ReplicationMode::Shallow, [Inline::new(descriptor)])
            .with_fetch_budget(Duration::ZERO);
        take_counts();
        let first = reconciler.tick(&mut peer).await;
        assert_eq!(first.replication.roots, 35);
        assert_eq!(first.replication.pending, 1);
        assert_eq!(first.pending_blobs, Some(1));
        assert_eq!(take_counts(), (35, 1));
        for _ in 0..3 {
            let steady = reconciler.tick(&mut peer).await;
            assert_eq!(steady, first);
            assert_eq!(take_counts(), (0, 0), "an unchanged store reads no root");
        }
        assert!(fetches.trace.lock().unwrap().calls.is_empty());
        assert_eq!(
            derived_from_scratch(&mut peer, [Inline::new(descriptor)]).await,
            (35, 1)
        );
    }

    #[tokio::test]
    async fn new_records_and_arriving_blobs_are_read_incrementally() {
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"incremental descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        let first_data = put(&mut store, b"first data".to_vec());
        raw_commit(&mut store, descriptor, first_data, metadata);
        let (mut peer, _, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        let selection = [Inline::new(descriptor)];
        let mut reconciler = Reconciler::new()
            .with_replication(ReplicationMode::Shallow, selection)
            .with_fetch_budget(Duration::ZERO);
        let first = reconciler.tick(&mut peer).await;
        assert_eq!((first.replication.roots, first.replication.pending), (3, 0));

        // A new record naming one new, absent root and two known ones.
        let late = Blob::<UnknownBlob>::new(Bytes::from_source(b"late data".to_vec()));
        let late_handle = late.get_handle().raw;
        peer.store()
            .insert(commit_record(descriptor, late_handle, metadata))
            .unwrap();
        take_counts();
        let named = reconciler.tick(&mut peer).await;
        assert_eq!((named.replication.roots, named.replication.pending), (4, 1));
        assert_eq!(take_counts(), (1, 0), "only the newly named root is read");
        assert_eq!(derived_from_scratch(&mut peer, selection).await, (4, 1));
        assert!(reconciler.states[&late_handle].first_root_attempt);

        // Its blob arrives by another path. This store's blob view has no
        // indexed difference, so the forgotten-blob check lists every blob;
        // the pile test below pins the per-change read count.
        peer.store().put::<UnknownBlob, _>(late).unwrap();
        take_counts();
        let arrived = reconciler.tick(&mut peer).await;
        assert_eq!(
            (arrived.replication.roots, arrived.replication.pending),
            (4, 0)
        );
        assert_eq!(arrived.pending_blobs, Some(0));
        assert_eq!(take_counts().1, 0, "an arrival advances, never rederives");
        assert!(reconciler.states.is_empty());
        assert_eq!(derived_from_scratch(&mut peer, selection).await, (4, 0));
    }

    #[tokio::test]
    async fn selection_changes_rederive_roots() {
        let mut store = MemoryRepo::default();
        let first = put(&mut store, b"first selected descriptor".to_vec());
        let second = put(&mut store, b"second selected descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        for ordinal in 0..3 {
            let data = put(
                &mut store,
                format!("first collection {ordinal}").into_bytes(),
            );
            raw_commit(&mut store, first, data, metadata);
        }
        raw_commit(&mut store, second, [0xdd; 32], metadata);
        let (mut peer, _, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        let mut reconciler = Reconciler::new()
            .with_replication(ReplicationMode::Shallow, [Inline::new(first)])
            .with_fetch_budget(Duration::ZERO);
        let stats = reconciler.tick(&mut peer).await;
        assert_eq!((stats.replication.roots, stats.replication.pending), (5, 0));

        reconciler.set_replication(ReplicationMode::Shallow, [Inline::new(second)]);
        take_counts();
        let stats = reconciler.tick(&mut peer).await;
        assert_eq!((stats.replication.roots, stats.replication.pending), (3, 1));
        assert_eq!(take_counts(), (3, 1), "a new selection derives afresh");

        reconciler.set_replication(
            ReplicationMode::Full,
            [Inline::new(first), Inline::new(second)],
        );
        let stats = reconciler.tick(&mut peer).await;
        assert_eq!((stats.replication.roots, stats.replication.pending), (7, 1));
        assert_eq!(take_counts(), (4, 0), "a grown selection advances");

        reconciler.set_replication(ReplicationMode::Demand, [Inline::new(first)]);
        let stats = reconciler.tick(&mut peer).await;
        assert_eq!((stats.replication.roots, stats.replication.pending), (0, 0));
        assert_eq!(stats.pending_blobs, Some(0));
        assert!(reconciler.hydration.is_none());
        assert!(reconciler.states.is_empty());
    }

    /// A selection change keeps the reconciler's hydration memo: a
    /// collection that joins is read whole by the next tick, and only one
    /// that leaves resets it. Every answer equals a fresh advance over the
    /// same snapshot.
    #[tokio::test]
    async fn a_selection_change_keeps_the_hydration_memo() {
        fn memo_of<T: StoreRead + Send + Sync + 'static>(
            reconciler: &Reconciler,
            _: &T,
        ) -> (BTreeSet<RawHash>, BTreeSet<RawHash>) {
            let memo = reconciler
                .hydration
                .as_ref()
                .expect("a memo after a Shallow tick")
                .downcast_ref::<Hydration<T>>()
                .expect("a memo over this store's snapshots");
            (memo.roots.clone(), memo.missing.clone())
        }
        let mut store = MemoryRepo::default();
        let a = put(&mut store, b"collection a descriptor".to_vec());
        let b = put(&mut store, b"collection b descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        for ordinal in 0..2 {
            let data = put(&mut store, format!("a data {ordinal}").into_bytes());
            raw_commit(&mut store, a, data, metadata);
        }
        raw_commit(&mut store, b, [0xdd; 32], metadata);
        let (mut peer, _, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        let mut reconciler = Reconciler::new().with_fetch_budget(Duration::ZERO);
        take_counts();
        let mut from_empty = 0;
        let mut resets = 0;
        // (step, selection, (roots, pending), root lookups, cumulative
        // advances from empty, cumulative resets)
        for (step, selection, observed, reads, expected_from_empty, expected_resets) in [
            ("[a]", vec![a], (4, 0), 4, 1, 0),
            ("grown to [a, b]", vec![a, b], (6, 1), 2, 1, 0),
            ("shrunk to [a]", vec![a], (4, 0), 4, 2, 1),
        ] {
            let collections: Vec<_> = selection.iter().map(|raw| Inline::new(*raw)).collect();
            reconciler.set_replication(ReplicationMode::Shallow, collections.iter().copied());
            let stats = reconciler.tick(&mut peer).await;
            resets += RESETS.get();
            let (lookups, advanced_from_empty) = take_counts();
            from_empty += advanced_from_empty;
            assert_eq!(
                (from_empty, resets),
                (expected_from_empty, expected_resets),
                "advances from empty and resets after {step}"
            );
            assert_eq!(lookups, reads, "root lookups for {step}");
            assert_eq!(
                (stats.replication.roots, stats.replication.pending),
                observed,
                "{step}"
            );
            let snapshot = peer.snapshot().unwrap();
            let fresh = Hydration::new()
                .advance(&*snapshot, &collections)
                .await
                .unwrap();
            assert_eq!(
                memo_of(&reconciler, &*snapshot),
                (fresh.roots.clone(), fresh.missing.clone()),
                "the memo equals a fresh advance after {step}"
            );
            take_counts();
        }
    }

    /// A blob that leaves the view returns its root to the missing set, even
    /// when no selected record changed.
    #[tokio::test]
    async fn forgotten_root_blob_returns_to_missing() {
        let descriptor = Blob::<UnknownBlob>::new(Bytes::from_source(b"kept".to_vec()));
        let forgotten = Blob::<UnknownBlob>::new(Bytes::from_source(b"forgotten".to_vec()));
        let collection = descriptor.get_handle().raw;
        let record = commit_record(collection, forgotten.get_handle().raw, collection);
        let mut held = MemoryRepo::default();
        let mut lost = MemoryRepo::default();
        for store in [&mut held, &mut lost] {
            store.put::<UnknownBlob, _>(descriptor.clone()).unwrap();
            store.insert(record).unwrap();
        }
        held.put::<UnknownBlob, _>(forgotten.clone()).unwrap();
        let held = held.snapshot().unwrap();
        let lost = lost.snapshot().unwrap();
        let selection = [Inline::new(collection)];
        let hydration = Hydration::new().advance(&held, &selection).await.unwrap();
        assert_eq!(hydration.roots.len(), 2);
        assert!(hydration.missing.is_empty());
        take_counts();
        let hydration = hydration.advance(&lost, &selection).await.unwrap();
        assert_eq!(take_counts().1, 0);
        assert_eq!(
            hydration.missing,
            BTreeSet::from([forgotten.get_handle().raw])
        );
        let hydration = hydration.advance(&held, &selection).await.unwrap();
        assert!(hydration.missing.is_empty());
        assert_eq!(take_counts().1, 0);
    }

    /// Concatenating a pile that repeats our records and adds new ones is an
    /// append: the repeated records fold idempotently and only new roots are
    /// read.
    #[tokio::test]
    async fn concatenated_pile_is_advanced_without_rederiving() {
        use std::io::Write;

        let path = tempfile::NamedTempFile::new().unwrap();
        let mut pile = Pile::open(path.path()).unwrap();
        let descriptor = put_pile(&mut pile, b"merged descriptor".to_vec());
        let metadata = put_pile(&mut pile, b"merged metadata".to_vec());
        for ordinal in 0..4 {
            let data = put_pile(&mut pile, format!("ours {ordinal}"));
            pile.insert(commit_record(descriptor, data, metadata))
                .unwrap();
        }
        pile.close().unwrap();
        // Theirs: a copy of ours plus three records, one naming an absent root.
        let theirs = tempfile::NamedTempFile::new().unwrap();
        std::fs::copy(path.path(), theirs.path()).unwrap();
        let mut other = Pile::open(theirs.path()).unwrap();
        for ordinal in 0..2 {
            let data = put_pile(&mut other, format!("theirs {ordinal}"));
            other
                .insert(commit_record(descriptor, data, metadata))
                .unwrap();
        }
        let late = Blob::<UnknownBlob>::new(Bytes::from_source(b"late merged data".to_vec()));
        let late_handle = late.get_handle().raw;
        other
            .insert(commit_record(descriptor, late_handle, metadata))
            .unwrap();
        other.close().unwrap();

        let key = SigningKey::from_bytes(&[7; 32]);
        let (sender, receiver, _wiring) =
            crate::host::wire(crate::identity::iroh_secret(&key).public().into());
        let mut peer = Peer::with_wiring(Pile::open(path.path()).unwrap(), sender, receiver);
        let selection = [Inline::new(descriptor)];
        let mut reconciler = Reconciler::new()
            .with_replication(ReplicationMode::Shallow, selection)
            .with_fetch_budget(Duration::ZERO);
        let before = reconciler.tick(&mut peer).await;
        assert_eq!(
            (before.replication.roots, before.replication.pending),
            (6, 0)
        );

        let appended = std::fs::read(theirs.path()).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(path.path())
            .unwrap()
            .write_all(&appended)
            .unwrap();
        take_counts();
        let after = reconciler.tick(&mut peer).await;
        assert_eq!((after.replication.roots, after.replication.pending), (9, 1));
        assert_eq!(
            take_counts(),
            (3, 0),
            "a concatenation is an append: only its three new roots are read"
        );
        assert_eq!(derived_from_scratch(&mut peer, selection).await, (9, 1));

        // The missing blob arrives: one reread, nothing else.
        peer.store().put::<UnknownBlob, _>(late).unwrap();
        take_counts();
        let arrived = reconciler.tick(&mut peer).await;
        assert_eq!(
            (arrived.replication.roots, arrived.replication.pending),
            (9, 0)
        );
        assert_eq!(take_counts(), (1, 0), "only the missing root is reread");
        assert!(reconciler.states.is_empty());

        // An unrelated blob moves the blob view without naming a root.
        put_pile(&mut *peer.store(), b"unrelated".to_vec());
        take_counts();
        assert_eq!(reconciler.tick(&mut peer).await, arrived);
        assert_eq!(take_counts(), (0, 0));
        assert_eq!(derived_from_scratch(&mut peer, selection).await, (9, 0));
        peer.close().unwrap();
    }

    /// The selection a hydration answered for is kept as a key-only PATCH
    /// set. A selection that grows is an append: only the new collections'
    /// roots are read, in any order the caller names them. One that shrinks
    /// resets. Every answer equals a fresh advance over the same selection.
    #[tokio::test]
    async fn a_selection_that_grows_advances_and_one_that_shrinks_resets() {
        let mut store = MemoryRepo::default();
        let metadata = put(&mut store, Vec::new());
        let descriptors: Vec<RawHash> = (0..3)
            .map(|ordinal| {
                put(
                    &mut store,
                    format!("selection descriptor {ordinal}").into_bytes(),
                )
            })
            .collect();
        for (ordinal, &descriptor) in descriptors.iter().enumerate() {
            for leaf in 0..=ordinal {
                let data = put(
                    &mut store,
                    format!("selection data {ordinal} {leaf}").into_bytes(),
                );
                raw_commit(&mut store, descriptor, data, metadata);
            }
        }
        // A root no blob backs, named only by the third collection.
        raw_commit(&mut store, descriptors[2], [0xcd; 32], metadata);
        let snapshot = store.snapshot().unwrap();
        let [a, b, c] = [0, 1, 2].map(|ordinal| Inline::new(descriptors[ordinal]));
        let fresh = |selection: Vec<CollectionHandle>| {
            let snapshot = snapshot.clone();
            async move {
                let fresh = Hydration::new()
                    .advance(&snapshot, &selection)
                    .await
                    .unwrap();
                (fresh.roots, fresh.missing)
            }
        };
        let answer =
            |hydration: &Hydration<_>| (hydration.roots.clone(), hydration.missing.clone());

        take_counts();
        let hydration = Hydration::new().advance(&snapshot, &[a]).await.unwrap();
        assert_eq!(take_counts(), (3, 1));
        assert_eq!(hydration.roots().len(), 3);

        // Growing: only b's three new roots are looked up, nothing resets.
        let hydration = hydration.advance(&snapshot, &[b, a]).await.unwrap();
        assert_eq!(
            take_counts(),
            (3, 0),
            "a grown selection reads only the new collection"
        );
        assert_eq!(answer(&hydration), fresh(vec![a, b]).await);
        take_counts();
        let hydration = hydration.advance(&snapshot, &[a, b]).await.unwrap();
        assert_eq!(
            take_counts(),
            (0, 0),
            "the same set in another order is unchanged"
        );
        let hydration = hydration.advance(&snapshot, &[c, a, b]).await.unwrap();
        assert_eq!(take_counts(), (5, 0));
        assert_eq!(hydration.missing(), &BTreeSet::from([[0xcd; 32]]));
        assert_eq!(answer(&hydration), fresh(vec![a, b, c]).await);
        assert_eq!(hydration.counts().resets, 0);
        assert_eq!(hydration.collections().len(), 3);

        // Shrinking: a reset, and the answer for what is left.
        take_counts();
        let hydration = hydration.advance(&snapshot, &[c, a]).await.unwrap();
        assert_eq!(
            take_counts(),
            (8, 1),
            "a shrunk selection is read again from empty"
        );
        assert_eq!(hydration.counts().resets, 1);
        assert_eq!(answer(&hydration), fresh(vec![a, c]).await);
        assert!(hydration.roots().contains(&descriptors[2]));
        assert!(!hydration.roots().contains(&descriptors[1]));
        let hydration = hydration.advance(&snapshot, &[]).await.unwrap();
        assert_eq!(hydration.counts().resets, 2);
        assert!(hydration.roots().is_empty() && hydration.missing().is_empty());
        assert!(hydration.collections().is_empty());
    }

    /// A snapshot that counts every payload it hands out (`get`, and a
    /// pile's `metadata`, which validates) and delegates everything else,
    /// the blob index included, to `inner`.
    #[derive(Clone)]
    struct PayloadCounting<T> {
        inner: T,
        payloads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<T: triblespace_core::repo::StoreSnapshot> triblespace_core::repo::StoreSnapshot
        for PayloadCounting<T>
    {
        fn changes_since(&self, previous: &Self) -> StoreChanges {
            self.inner.changes_since(&previous.inner)
        }

        fn changes_for(&self, previous: &Self, dependencies: &StoreDependencies) -> StoreChanges {
            self.inner.changes_for(&previous.inner, dependencies)
        }
    }

    impl<T: BlobStoreGet> BlobStoreGet for PayloadCounting<T> {
        type GetError<E: std::error::Error + Send + Sync + 'static> = T::GetError<E>;

        fn get<V, S>(
            &self,
            handle: Inline<Handle<S>>,
        ) -> Result<V, Self::GetError<<V as triblespace_core::blob::TryFromBlob<S>>::Error>>
        where
            S: BlobEncoding + 'static,
            V: triblespace_core::blob::TryFromBlob<S>,
            Handle<S>: InlineEncoding,
        {
            self.payloads.fetch_add(1, Ordering::SeqCst);
            self.inner.get(handle)
        }
    }

    impl<T: BlobStoreList> BlobStoreList for PayloadCounting<T> {
        type Iter<'a>
            = T::Iter<'a>
        where
            Self: 'a;
        type Err = T::Err;

        fn blobs<'a>(&'a self) -> Self::Iter<'a> {
            self.inner.blobs()
        }

        fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
        where
            S: BlobEncoding + 'static,
            Handle<S>: InlineEncoding,
        {
            self.inner.contains_blob(handle)
        }

        fn blob_info<S>(
            &self,
            handle: Inline<Handle<S>>,
        ) -> Result<Option<triblespace_core::repo::BlobInfo>, Self::Err>
        where
            S: BlobEncoding + 'static,
            Handle<S>: InlineEncoding,
        {
            self.inner.blob_info(handle)
        }

        fn blobs_diff<'a>(&'a self, old: &Self) -> Self::Iter<'a> {
            self.inner.blobs_diff(&old.inner)
        }
    }

    impl<T: triblespace_core::repo::BlobStoreMeta> triblespace_core::repo::BlobStoreMeta
        for PayloadCounting<T>
    {
        type MetaError = T::MetaError;

        fn metadata<S>(
            &self,
            handle: Inline<Handle<S>>,
        ) -> Result<Option<triblespace_core::repo::BlobMetadata>, Self::MetaError>
        where
            S: BlobEncoding + 'static,
            Handle<S>: InlineEncoding,
        {
            self.payloads.fetch_add(1, Ordering::SeqCst);
            self.inner.metadata(handle)
        }

        fn resident(
            &self,
            handles: &PATCH<32, IdentitySchema, ()>,
        ) -> Result<PATCH<32, IdentitySchema, ()>, Self::MetaError> {
            self.inner.resident(handles)
        }
    }

    impl<T: CollectionRead> CollectionRead for PayloadCounting<T> {
        type RecordsError = T::RecordsError;
        type RecordIter<'a>
            = T::RecordIter<'a>
        where
            Self: 'a;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            self.inner.records()
        }

        fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
            self.inner.collections()
        }

        fn select_records(
            &self,
            selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
            self.inner.select_records(selectors)
        }

        fn select_record_views(
            &self,
            selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<triblespace_core::collection::CollectionRecordView>, Self::RecordsError>
        {
            self.inner.select_record_views(selectors)
        }

        fn select_record_view_changes(
            &self,
            previous: &Self,
            selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<RecordViewChanges, Self::RecordsError> {
            self.inner
                .select_record_view_changes(&previous.inner, selectors)
        }

        fn select_record_changes(
            &self,
            previous: &Self,
            selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<(Vec<CollectionRecord>, Vec<CollectionRecord>), Self::RecordsError> {
            self.inner.select_record_changes(&previous.inner, selectors)
        }
    }

    impl<T: triblespace_core::collection::CoverageRead> triblespace_core::collection::CoverageRead
        for PayloadCounting<T>
    {
        fn index(
            &self,
            lineage: &BTreeSet<CollectionHandle>,
        ) -> Result<triblespace_core::collection::coverage::CoverageIndex, Self::RecordsError>
        {
            self.inner.index(lineage)
        }
    }

    impl<T: triblespace_core::repo::CapabilityProofRead> triblespace_core::repo::CapabilityProofRead
        for PayloadCounting<T>
    {
        type ProofsError = T::ProofsError;
        type ProofIter<'a>
            = T::ProofIter<'a>
        where
            Self: 'a;

        fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
            self.inner.proofs()
        }
    }

    impl<T: WantRead> WantRead for PayloadCounting<T> {
        type WantsError = T::WantsError;
        type WantIter<'a>
            = T::WantIter<'a>
        where
            Self: 'a;

        fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
            self.inner.wants()
        }
    }

    /// Hydration looks a root up in the blob index and never reads its
    /// payload: through a first advance, an arrival and an unchanged
    /// snapshot, the store hands out no payload at all. So a resident root
    /// whose bytes were damaged after they were written counts as held, while
    /// a read of it still fails validation; a root no blob backs is missing
    /// until it arrives.
    #[tokio::test]
    async fn hydration_checks_presence_without_reading_payloads() {
        use std::io::{Seek, SeekFrom, Write};

        let path = tempfile::NamedTempFile::new().unwrap();
        let mut pile = Pile::open(path.path()).unwrap();
        let descriptor = put_pile(&mut pile, b"presence descriptor".to_vec());
        let metadata = put_pile(&mut pile, b"presence metadata".to_vec());
        let data: Vec<_> = (0..4)
            .map(|ordinal| put_pile(&mut pile, format!("presence data {ordinal}")))
            .collect();
        for &handle in &data {
            pile.insert(commit_record(descriptor, handle, metadata))
                .unwrap();
        }
        let late = Blob::<UnknownBlob>::new(Bytes::from_source(b"presence late".to_vec()));
        let late_handle = late.get_handle().raw;
        pile.insert(commit_record(descriptor, late_handle, metadata))
            .unwrap();
        pile.close().unwrap();
        // Damage one root's payload in place, after its handle was indexed.
        let damaged = data[0];
        let body_offset = PileRecords::open(path.path())
            .unwrap()
            .find_map(|record| match record.unwrap().content {
                PileRecordContent::Blob {
                    hash, data_offset, ..
                } if hash.raw == damaged => Some(data_offset),
                _ => None,
            })
            .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(path.path())
            .unwrap();
        file.seek(SeekFrom::Start(body_offset as u64)).unwrap();
        file.write_all(&[0xff]).unwrap();
        drop(file);

        let payloads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut pile = Pile::open(path.path()).unwrap();
        let counted = |snapshot| PayloadCounting {
            inner: snapshot,
            payloads: payloads.clone(),
        };
        let selection = [Inline::new(descriptor)];
        let before = counted(pile.snapshot().unwrap());
        let hydration = Hydration::new().advance(&before, &selection).await.unwrap();
        assert_eq!(
            payloads.load(Ordering::SeqCst),
            0,
            "a first advance reads no payload"
        );
        assert_eq!(hydration.roots().len(), 7);
        // The damaged root is held; only the root no blob backs is missing.
        assert_eq!(hydration.missing(), &BTreeSet::from([late_handle]));

        pile.put::<UnknownBlob, _>(late).unwrap();
        let after = counted(pile.snapshot().unwrap());
        let hydration = hydration.advance(&after, &selection).await.unwrap();
        assert!(hydration.missing().is_empty());
        assert_eq!(hydration.counts().arrived, 1);
        let hydration = hydration.advance(&after, &selection).await.unwrap();
        assert!(hydration.missing().is_empty());
        assert_eq!(
            payloads.load(Ordering::SeqCst),
            0,
            "an arrival reads no payload"
        );

        // The damage is still there for any reader of the bytes.
        assert!(matches!(
            BlobStoreGet::get::<Bytes, UnknownBlob>(&after.inner, Inline::new(damaged)),
            Err(triblespace_core::repo::pile::GetBlobError::ValidationError(
                _
            ))
        ));
        drop((before, after));
        pile.close().unwrap();
    }

    fn put_pile(pile: &mut Pile, bytes: impl Into<Vec<u8>>) -> RawHash {
        pile.put::<UnknownBlob, _>(Bytes::from_source(bytes.into()))
            .unwrap()
            .raw
    }

    async fn timed_tick(
        label: &str,
        reconciler: &mut Reconciler,
        peer: &mut Peer<Pile>,
    ) -> ReconcileStats {
        let observed = std::time::Instant::now();
        let snapshot = peer.snapshot().unwrap();
        let observed = observed.elapsed();
        take_counts();
        let ticked = std::time::Instant::now();
        let stats = reconciler.tick_snapshot(snapshot).await;
        let ticked = ticked.elapsed();
        let (reads, derivations) = take_counts();
        eprintln!(
            "probe: {label:<24} tick_snapshot {ticked:>12?}  peer.snapshot {observed:>10?}  \
             roots {} pending {}  reads {reads} derivations {derivations}",
            stats.replication.roots, stats.replication.pending,
        );
        stats
    }

    /// Per-tick cost with ~500k resident roots over 36 selected collections,
    /// in a pile. Run with
    /// `cargo test --release -p triblespace-net hydration_tick_timing_probe -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "timing probe"]
    async fn hydration_tick_timing_probe() {
        const COLLECTIONS: usize = 36;
        const ROOTS: usize = 500_000;
        const COMMITS: usize = ROOTS - 2 * COLLECTIONS;
        let path = tempfile::NamedTempFile::new().unwrap();
        let built = std::time::Instant::now();
        let mut pile = Pile::open(path.path()).unwrap();
        let collections: Vec<_> = (0..COLLECTIONS)
            .map(|ordinal| {
                (
                    put_pile(&mut pile, format!("probe descriptor {ordinal}")),
                    put_pile(&mut pile, format!("probe metadata {ordinal}")),
                )
            })
            .collect();
        for ordinal in 0..COMMITS {
            let (descriptor, metadata) = collections[ordinal % COLLECTIONS];
            let data = put_pile(&mut pile, format!("probe data {ordinal}"));
            pile.insert(commit_record(descriptor, data, metadata))
                .unwrap();
        }
        pile.close().unwrap();
        eprintln!("probe: built {COMMITS} commits in {:?}", built.elapsed());

        let key = SigningKey::from_bytes(&[7; 32]);
        let (sender, receiver, _wiring) =
            crate::host::wire(crate::identity::iroh_secret(&key).public().into());
        let mut peer = Peer::with_wiring(Pile::open(path.path()).unwrap(), sender, receiver);
        let mut reconciler = Reconciler::new().with_replication(
            ReplicationMode::Shallow,
            collections
                .iter()
                .map(|&(descriptor, _)| Inline::new(descriptor)),
        );
        let first = timed_tick("first (cold)", &mut reconciler, &mut peer).await;
        assert_eq!(
            (first.replication.roots, first.replication.pending),
            (ROOTS, 0)
        );
        for _ in 0..3 {
            let stats = timed_tick("unchanged", &mut reconciler, &mut peer).await;
            assert_eq!(stats, first);
        }
        for _ in 0..3 {
            reconciler.hydration = None;
            let stats = timed_tick("forced full derivation", &mut reconciler, &mut peer).await;
            assert_eq!(stats, first);
        }
        for ordinal in 0..3 {
            let (descriptor, metadata) = collections[ordinal];
            let data = put_pile(&mut *peer.store(), format!("probe late {ordinal}"));
            peer.store()
                .insert(commit_record(descriptor, data, metadata))
                .unwrap();
            let stats = timed_tick("one new record + blob", &mut reconciler, &mut peer).await;
            assert_eq!(
                (stats.replication.roots, stats.replication.pending),
                (ROOTS + ordinal + 1, 0)
            );
        }
        peer.close().unwrap();
    }

    /// A pile in file order, as local writes leave it: every blob before the
    /// COMMIT naming it, children before the parents naming them. Three
    /// collections, the third first written to well into the file; one root
    /// never resident; and one root whose bytes land only later in the file,
    /// as a repaired record can arrive before its blob. Returns the path and
    /// the collections.
    fn file_order_pile() -> (tempfile::NamedTempFile, Vec<CollectionHandle>) {
        let path = tempfile::NamedTempFile::new().unwrap();
        let mut pile = Pile::open(path.path()).unwrap();
        let collections: Vec<_> = (0..3)
            .map(|ordinal| put_pile(&mut pile, format!("climb descriptor {ordinal}")))
            .collect();
        let metadata = put_pile(&mut pile, b"climb metadata".to_vec());
        let late = b"a root whose bytes land later".to_vec();
        let late_handle = Blob::<UnknownBlob>::new(Bytes::from_source(late.clone()))
            .get_handle()
            .raw;
        for ordinal in 0..24u32 {
            // The third collection is first written to after the twelfth.
            let collection = collections[if ordinal < 12 {
                ordinal as usize % 2
            } else {
                ordinal as usize % 3
            }];
            let leaf = put_pile(&mut pile, format!("climb leaf {ordinal}"));
            // An aligned word naming the leaf makes it the payload's child.
            let payload = put_pile(&mut pile, [&leaf[..], &[ordinal as u8; 32][..]].concat());
            pile.insert(commit_record(collection, payload, metadata))
                .unwrap();
            if ordinal == 5 {
                pile.insert(commit_record(collections[0], late_handle, metadata))
                    .unwrap();
                pile.insert(commit_record(collections[1], [0xab; 32], metadata))
                    .unwrap();
            }
            if ordinal == 17 {
                put_pile(&mut pile, late.clone());
            }
        }
        pile.close().unwrap();
        (path, collections.into_iter().map(Inline::new).collect())
    }

    /// The collections of `selection` that have a record in `snapshot`: a
    /// selection that grows as a climb reaches the records.
    fn written(
        snapshot: &triblespace_core::repo::pile::PileSnapshot,
        selection: &[CollectionHandle],
    ) -> Vec<CollectionHandle> {
        let present = snapshot.collections().unwrap();
        selection
            .iter()
            .copied()
            .filter(|collection| present.contains(collection))
            .collect()
    }

    fn held_sets(
        snapshot: &impl HeldRead,
        collections: &[CollectionHandle],
    ) -> Vec<Option<BTreeSet<RawHash>>> {
        collections
            .iter()
            .map(|&collection| {
                snapshot
                    .held(collection)
                    .map(|held| held.iter_ordered().copied().collect())
            })
            .collect()
    }

    /// Hydration and held sets a fresh store reads from `length` bytes of
    /// `path` at once: no climb, no cached state.
    async fn read_at_once(
        path: &std::path::Path,
        length: u64,
        collections: &[CollectionHandle],
    ) -> (
        BTreeSet<RawHash>,
        BTreeSet<RawHash>,
        Vec<Option<BTreeSet<RawHash>>>,
    ) {
        let mut fresh = Pile::open_prefix(path, length).unwrap();
        fresh.track_held(collections.iter().copied());
        let snapshot = fresh.snapshot().unwrap();
        let hydration = Hydration::new()
            .advance(&snapshot, &written(&snapshot, collections))
            .await
            .unwrap();
        let held = held_sets(&snapshot, collections);
        drop(snapshot);
        fresh.close().unwrap();
        (hydration.roots, hydration.missing, held)
    }

    /// Climbing a file-order pile in small steps, with the selection growing
    /// as collections appear, gives at every prefix the hydration that a
    /// fresh store reading that prefix at once gives, and at the end the
    /// answer for the whole file, held sets included; before the end no held
    /// set is known. A peer assembled over the climbed pile then continues
    /// from the climb without rereading a root.
    #[tokio::test]
    async fn a_climb_over_a_file_order_pile_equals_reading_its_end() {
        let (path, collections) = file_order_pile();
        let length = std::fs::metadata(path.path()).unwrap().len();
        let mut pile = Pile::open(path.path()).unwrap();
        pile.track_held(collections.iter().copied());
        let mut hydration = Hydration::new();
        let mut steps = 0;
        loop {
            let (snapshot, reached_end) = pile.snapshot_step(700).unwrap();
            steps += 1;
            hydration = hydration
                .advance(&snapshot, &written(&snapshot, &collections))
                .await
                .unwrap();
            let prefix = pile.replayed_length();
            let (roots, missing, held) = read_at_once(path.path(), prefix, &collections).await;
            assert_eq!(hydration.roots, roots, "roots at prefix {prefix}");
            assert_eq!(hydration.missing, missing, "missing at prefix {prefix}");
            if reached_end {
                assert_eq!(
                    held_sets(&snapshot, &collections),
                    held,
                    "held sets at the end"
                );
                break;
            }
            assert!(
                held_sets(&snapshot, &collections)
                    .iter()
                    .all(Option::is_none),
                "held sets unknown at prefix {prefix}"
            );
        }
        assert_eq!(pile.replayed_length(), length);
        assert!(steps > 20, "{steps} steps is not a climb");
        let counts = hydration.counts();
        assert_eq!((counts.advances, counts.resets), (steps, 0));
        assert_eq!(counts.arrived, 1, "the late root was missing, then arrived");
        assert_eq!(hydration.missing, BTreeSet::from([[0xab; 32]]));
        let (roots, missing, held) = read_at_once(path.path(), length, &collections).await;
        assert_eq!((&hydration.roots, &hydration.missing), (&roots, &missing));
        assert!(held.iter().all(Option::is_some), "every held set is known");
        pile.close().unwrap();

        // The library climb, from a fresh open, reaches the same answer, and
        // a peer over that pile adopts it: its first pass reads no root.
        let mut pile = Pile::open(path.path()).unwrap();
        let climbed = climb(
            &mut pile,
            700,
            |snapshot| Ok::<_, std::convert::Infallible>(written(snapshot, &collections)),
            |_, _| {},
        )
        .await
        .unwrap();
        assert_eq!((&climbed.roots, &climbed.missing), (&roots, &missing));
        let key = SigningKey::from_bytes(&[7; 32]);
        let (sender, receiver, wiring) =
            crate::host::wire(crate::identity::iroh_secret(&key).public().into());
        // No host serves the wiring, so the absent root's fetch fails at once.
        drop(wiring);
        let mut peer = Peer::with_wiring(pile, sender, receiver);
        peer.set_replication(ReplicationMode::Shallow, collections.iter().copied());
        peer.adopt_hydration(climbed);
        take_counts();
        let stats = peer.reconcile().await;
        assert_eq!(
            take_counts(),
            (0, 0),
            "the adopted climb is advanced, not reread"
        );
        assert_eq!(
            (stats.replication.roots, stats.replication.pending),
            (roots.len(), 1)
        );
        peer.into_store().close().unwrap();
    }

    /// A climb over a pile that holds a child after its parent ends with the
    /// held set of the whole file. The parent is a COMMIT's payload naming
    /// the child, and the file holds the child only after the parent and its
    /// COMMIT. A prefix with the parent and without the child would scan the
    /// parent without that edge, and the child, which no record names, would
    /// never join (a late child). So no held set is known before the climb
    /// first reaches the end of the file.
    #[tokio::test]
    async fn a_climb_holds_a_child_written_after_its_parent() {
        let path = tempfile::NamedTempFile::new().unwrap();
        let mut pile = Pile::open(path.path()).unwrap();
        let descriptor = put_pile(&mut pile, b"late child descriptor".to_vec());
        let metadata = put_pile(&mut pile, b"late child metadata".to_vec());
        let child = b"a child written after its parent".to_vec();
        let child_handle = Blob::<UnknownBlob>::new(Bytes::from_source(child.clone()))
            .get_handle()
            .raw;
        // An aligned word naming the child makes it the parent's child.
        let parent = put_pile(&mut pile, [&child_handle[..], &[0x5a; 32][..]].concat());
        pile.insert(commit_record(descriptor, parent, metadata))
            .unwrap();
        put_pile(&mut pile, child);
        pile.close().unwrap();
        let length = std::fs::metadata(path.path()).unwrap().len();
        let collections = [Inline::new(descriptor)];

        let mut pile = Pile::open(path.path()).unwrap();
        pile.track_held(collections);
        let mut steps = 0;
        let mut known_before_end = Vec::new();
        let held = loop {
            // One record per step.
            let (snapshot, reached_end) = pile.snapshot_step(1).unwrap();
            steps += 1;
            let held = held_sets(&snapshot, &collections);
            if reached_end {
                break held;
            }
            if held.iter().any(Option::is_some) {
                known_before_end.push(pile.replayed_length());
            }
        };
        assert_eq!(pile.replayed_length(), length);
        assert!(steps >= 5, "{steps} steps is not a climb");
        let set = held[0].as_ref().expect("the held set is known at the end");
        assert!(set.contains(&parent), "the parent is held");
        assert!(set.contains(&child_handle), "the child is held");
        let (_, _, whole) = read_at_once(path.path(), length, &collections).await;
        assert_eq!(held, whole, "the climb ends with the whole file's held set");
        assert_eq!(
            known_before_end,
            Vec::<u64>::new(),
            "no held set is known before the end"
        );
        pile.close().unwrap();
    }

    /// Evidence that is not an append resets the answer to empty, and the
    /// same advance climbs again to the answer a fresh read gives: a record
    /// removed between two stores, and a pile reopened under a held answer
    /// (another origin, so its records cannot be compared by offset).
    #[tokio::test]
    async fn evidence_that_is_not_an_append_resets_and_climbs_again() {
        // A removed record: the only one naming its root.
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"reset descriptor".to_vec());
        let metadata = put(&mut store, Vec::new());
        let kept = put(&mut store, b"kept data".to_vec());
        raw_commit(&mut store, descriptor, kept, metadata);
        let mut without = store.clone();
        let removed = put(&mut store, b"removed data".to_vec());
        raw_commit(&mut store, descriptor, removed, metadata);
        let selection = [Inline::new(descriptor)];
        let with = store.snapshot().unwrap();
        let without = without.snapshot().unwrap();
        let hydration = Hydration::new().advance(&with, &selection).await.unwrap();
        assert!(hydration.roots.contains(&removed));
        take_counts();
        let hydration = hydration.advance(&without, &selection).await.unwrap();
        assert_eq!(RESETS.get(), 1);
        assert_eq!(take_counts(), (3, 1), "reset, then every root read again");
        assert_eq!(
            hydration.roots,
            BTreeSet::from([descriptor, metadata, kept]),
            "a root only the removed record named is gone"
        );
        assert_eq!(hydration.counts().resets, 1);

        // A pile reopened under a held answer, with a record appended.
        let (path, collections) = file_order_pile();
        let mut pile = Pile::open(path.path()).unwrap();
        let hydration = climb(
            &mut pile,
            1 << 20,
            |_| Ok::<_, std::convert::Infallible>(collections.clone()),
            |_, _| {},
        )
        .await
        .unwrap();
        pile.close().unwrap();
        let mut reopened = Pile::open(path.path()).unwrap();
        let extra = put_pile(&mut reopened, b"appended after the reopen".to_vec());
        reopened
            .insert(commit_record(collections[2].raw, extra, extra))
            .unwrap();
        let snapshot = reopened.snapshot().unwrap();
        take_counts();
        let hydration = hydration.advance(&snapshot, &collections).await.unwrap();
        assert_eq!(RESETS.get(), 1, "another origin is not an append");
        let fresh = Hydration::new()
            .advance(&snapshot, &collections)
            .await
            .unwrap();
        let (reads, _) = take_counts();
        assert_eq!(reads, 2 * fresh.roots.len(), "the reset reread every root");
        assert!(hydration.roots.contains(&extra));
        assert_eq!(
            (&hydration.roots, &hydration.missing),
            (&fresh.roots, &fresh.missing)
        );
        drop(snapshot);
        reopened.close().unwrap();
    }

    /// The daemon's shape again, for an advance that is not the first: after
    /// a first pass over a small store, two thousand records arrive at once,
    /// and a stop raised while the next pass reads them is answered long
    /// before the pass would end. The pass after that, from empty, reaches
    /// the full answer.
    #[test]
    fn a_stop_during_a_large_incremental_advance_is_answered_promptly() {
        const ROOTS: u32 = 2_000;
        const READ: Duration = Duration::from_millis(2);
        let mut store = MemoryRepo::default();
        let descriptor = put(&mut store, b"long incremental pass".to_vec());
        let metadata = put(&mut store, Vec::new());
        let (mut peer, fetches, _) = controlled_peer(store, BTreeMap::new(), BTreeSet::new());
        peer.set_replication(ReplicationMode::Shallow, [Inline::new(descriptor)]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // The first pass has no record: nothing to read.
        let stats = runtime.block_on(peer.reconcile());
        assert_eq!(stats.replication.roots, 0);
        for ordinal in 0..ROOTS {
            let mut store = peer.store();
            let data = put(
                &mut store.inner,
                format!("arriving root {ordinal}").into_bytes(),
            );
            raw_commit(&mut store.inner, descriptor, data, metadata);
        }
        let (raise, stop) = tokio::sync::oneshot::channel::<()>();
        let raiser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            raise.send(()).unwrap();
        });
        READ_DELAY.set(READ);
        take_counts();
        let started = std::time::Instant::now();
        let stopped = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = stop => true,
                _ = peer.reconcile() => false,
            }
        });
        let elapsed = started.elapsed();
        READ_DELAY.set(Duration::ZERO);
        raiser.join().unwrap();
        let (reads, from_empty) = take_counts();
        assert!(
            stopped,
            "the pass ended before the stop was seen, after {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the stop took {elapsed:?}, after {reads} of {} reads",
            ROOTS + 2,
        );
        assert_eq!(from_empty, 0, "the stopped pass was an incremental advance");
        assert!(reads < ROOTS as usize / 2, "{reads} reads before the stop");
        let stats = runtime.block_on(peer.reconcile());
        assert_eq!(take_counts(), (ROOTS as usize + 2, 1));
        assert_eq!(stats.replication.roots, ROOTS as usize + 2);
        assert_eq!(stats.replication.pending, 0);
        assert!(fetches.trace.lock().unwrap().calls.is_empty());
    }
}
