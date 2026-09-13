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

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use anybytes::Bytes;
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
use crate::protocol::RawHash;

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
    last_attempt: crate::clock::Mono,
    backoff: Duration,
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
    last_want_attempt: Option<RawHash>,
    last_root_attempt: Option<RawHash>,
    scan: FullScan,
}

pub const RECONCILE_FETCH_DEADLINE: Duration = Duration::from_secs(30);

/// Bound CPU work even when every candidate is resident or filtered out.
pub const RECONCILE_SCAN_CANDIDATES_PER_TICK: usize = 16 * 1024;
/// Speculation cannot turn one large binary into an unbounded burst of DHT work.
pub const RECONCILE_SPECULATIVE_FETCHES_PER_TICK: usize = 16;

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
            last_want_attempt: None,
            last_root_attempt: None,
            scan: FullScan::default(),
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
        self.scan = FullScan::default();
        self.last_root_attempt = None;
        self
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
        let roots = if self.mode == ReplicationMode::Demand {
            BTreeSet::new()
        } else {
            match direct_roots(&snapshot, &self.collections) {
                Ok(roots) => roots,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "hydration record observation failed; skipping roots"
                    );
                    BTreeSet::new()
                }
            }
        };
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

        let started = crate::clock::mono_now();
        // Durable explicit demand precedes direct hydration, which precedes
        // speculation. Each priority class rotates so a deadline cannot let
        // one slow lowest-H request monopolize every pass.
        let mut attempted = HashSet::new();
        for (is_want, handles, after) in [
            (true, &wanted_blob_handles, self.last_want_attempt),
            (false, &roots, self.last_root_attempt),
        ] {
            let mut missing: Vec<_> = handles
                .iter()
                .copied()
                .filter(|handle| !self.durable_blob_answers.contains(handle))
                .collect();
            if let Some(after) = after {
                let split = missing.partition_point(|handle| *handle <= after);
                missing.rotate_left(split);
            }
            for handle in missing {
                if attempted.contains(&handle)
                    || self.states.get(&handle).is_some_and(|state| {
                        crate::clock::mono_now().duration_since(state.last_attempt) < state.backoff
                    })
                {
                    continue;
                }
                let remaining = self.remaining(started);
                if remaining.is_zero() {
                    break;
                }
                attempted.insert(handle);
                if is_want {
                    self.last_want_attempt = Some(handle);
                    stats.attempted += 1;
                } else {
                    self.last_root_attempt = Some(handle);
                }
                // A failed durability barrier is retried locally, not turned
                // into a needless network fetch of already-visible bytes.
                let landed = if visible_blobs.contains(&handle) {
                    peer.store().flush().is_ok()
                } else {
                    fetch_and_land(peer, handle, remaining).await.is_some()
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

        if self.mode != ReplicationMode::Full {
            return stats;
        }
        for root in roots {
            if self.durable_blob_answers.contains(&root) {
                self.scan.observe(root, root);
            }
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
        // Fetching their structural endpoints above can make a previously
        // absent summary usable in this very pass.
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
            // Foundational support is not necessarily the mapping's immediate
            // input: a SimpleArchive projection may have dropped references.
            // This walker starts at COMMIT payloads, so only a summary mapped
            // directly from their foundational collection describes those bytes.
            if triblespace_core::collection::descriptor::source(&descriptor)
                .ok()
                .flatten()
                != Some(observed.support().collection().handle())
            {
                continue;
            }
            if let Ok(view) = observed.view::<ReferenceSummaryView>() {
                summaries.push((observed.support().clone(), view));
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
                        self.scan.sources.remove(&cursor.key);
                        self.scan.cursor = None;
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
        match self.states.entry(handle) {
            Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                state.last_attempt = now;
                state.backoff = (state.backoff * 2).min(self.max_backoff);
            }
            Entry::Vacant(entry) => {
                entry.insert(WantState {
                    last_attempt: now,
                    backoff: self.initial_backoff,
                });
            }
        }
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
    /// A bounded startup window, newest arrivals first. Every entry also gets
    /// ordinary rounds, so sustained arrivals cannot starve older sources.
    recent: Vec<[u8; 64]>,
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
        let recent = self.prefer_recent && !self.recent.is_empty();
        self.prefer_recent = !self.prefer_recent;
        let key = if recent {
            self.recent.pop().expect("nonempty recent lane")
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
            return ScanStep::Skip;
        };
        if recent && progress.startup_left == 0 {
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
        if cursor.words >= SCAN_WORDS_PER_QUANTUM {
            self.yield_source();
        }
    }

    fn yield_source(&mut self) {
        let Some(cursor) = self.cursor.filter(|cursor| cursor.words != 0) else {
            return;
        };
        self.cursor = None;
        let mut progress = *self.sources.get(&cursor.key).expect("positive source");
        progress.offset = cursor.offset;
        progress.startup_left = progress.startup_left.saturating_sub(cursor.words);
        self.sources
            .replace(&PatchEntry::with_value(&cursor.key, progress));
        if cursor.recent && progress.startup_left != 0 {
            self.recent.push(cursor.key);
        }
    }

    fn finish_source(&mut self, initial: Duration, max: Duration) {
        let cursor = self.cursor.take().expect("active scan");
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
        // The same structural boundary as collection repair. WRITE-inert
        // signed records remain eligible; malformed signatures do not.
        if let CollectionRecord::Commit(commit) = record {
            if commit.verify_strict().is_err() {
                continue;
            }
        }
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
    let bytes = peer.fetch_blob_with_deadline(handle, budget).await?;
    let landing = {
        let mut store = peer.store();
        match store.put::<UnknownBlob, Bytes>(bytes) {
            Ok(actual) if actual.raw == handle => store
                .flush()
                .map_err(|error| format!("flush failed: {error:?}")),
            Ok(_) => Err("blob store returned a different handle".to_owned()),
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
    use super::*;
    use ed25519_dalek::SigningKey;
    use triblespace_core::collection::{CollectionCommit, CollectionDerive, CollectionMerge};
    use triblespace_core::inline::Inline;
    use triblespace_core::repo::BlobStorePut;
    use triblespace_core::repo::memoryrepo::MemoryRepo;

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
            want_request_for_record(CollectionRecord::Merge(CollectionMerge::new(
                collection, b, a, result,
            ))),
            Some(WantRequest::merge(collection, a, b))
        );
        assert_eq!(
            want_request_for_record(CollectionRecord::Derive(CollectionDerive::new(
                target, a, result,
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
            CollectionRecord::Merge(CollectionMerge::new(
                collection,
                Inline::new([4; 32]),
                Inline::new([5; 32]),
                Inline::new([6; 32]),
            )),
            CollectionRecord::Derive(CollectionDerive::new(
                collection,
                Inline::new([6; 32]),
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
        let mut invalid = CollectionCommit::sign(
            &key,
            collection,
            Inline::new([12; 32]),
            Inline::new([13; 32]),
        )
        .to_bytes();
        invalid[191] ^= 1;
        store
            .insert(CollectionRecord::Commit(CollectionCommit::from_bytes(
                invalid,
            )))
            .unwrap();
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
            reconciler
                .scan
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
        assert!(reconciler.scan.sources.get(&key).is_none());
        key[..32].copy_from_slice(&metadata);
        assert!(reconciler.scan.sources.get(&key).is_some());
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
        let before = reconciler.scan.sources.get(&key).unwrap().offset;
        let second = reconciler
            .tick_with_reference_filter(&mut peer, |_, _| Some(false))
            .await;
        assert!(second.replication.candidates <= RECONCILE_SCAN_CANDIDATES_PER_TICK);
        assert!(reconciler.scan.sources.get(&key).unwrap().offset > before);
        assert_eq!(reconciler.scan.sources.len(), 3);
        assert!(reconciler.states.is_empty());
        assert_eq!(peer.snapshot().unwrap().wants().unwrap().count(), 0);
    }
}
