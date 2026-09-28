//! Which resident blobs each synced collection holds.
//!
//! Sync advertises, per collection, the positive set of blobs it holds, so a
//! peer can fetch what a payload references but no record names. This module
//! keeps those sets for the collections a store *tracks* (the ones a sync
//! host activated). A store that tracks nothing -- every short-lived reader --
//! pays one lock and nothing else.
//!
//! # Membership
//!
//! `held(C)` is every resident blob reachable from C's *seeds*, plus the
//! memberships peers reported (below). The seeds are the blobs C's replicated
//! records name: the descriptor, each COMMIT's data and metadata archive, each
//! DERIVE's output, and the capability definitions named by the proofs C's
//! authorization evidence keeps ([`validate_proof_evidence`], the predicate
//! the sync host applies: over C from one of C's policy roots, or over a
//! resource whose descriptor entity routes to C and declares the root; a
//! proof whose descriptors arrive later is judged on their arrival). A
//! valid proof irrelevant to C seeds nothing. A MERGE never replicates, so
//! its result is never a seed, and a blob no record names (an attachment, a
//! scratch archive) is never one either.
//!
//! Reachability is the conservative closure: an aligned 32-byte word of a
//! blob is a child when it names a resident blob. Nothing here knows schemas.
//!
//! # Scanning each blob once
//!
//! A blob is read when it is first reached, and its edges to the children
//! resident at that moment are recorded in one edge cache shared by every
//! collection. A new seed, a new edge or a new membership then extends a held
//! set by following cached edges; no bytes are read twice. A shared blob
//! already scanned for one collection joins another without being read again.
//!
//! The price of scanning once is the late child: a child that becomes
//! resident after its parent was scanned is not an edge. Three things catch
//! it:
//!
//! - it is itself a seed (a record names it): seeds are scanned on arrival;
//! - a peer holding it advertises it in C ([`HeldStore::note_held`]): a
//!   resident blob a peer reports in C joins `held(C)` however it arrived.
//!   This is routing evidence, kept in memory only; a reopened store forgets
//!   it unless one of C's own records reaches the blob by then;
//! - the periodic full walk ([`HeldWalker`]) rescans every blob reachable
//!   from the seeds and refreshes the edge cache. A late child nobody
//!   advertised therefore joins `held(C)` only once a walk that *started*
//!   after it arrived has *finished*: the delay is bounded by the walk
//!   interval plus one walk's duration plus scheduling delay, and is only
//!   eventual under CPU saturation.
//!
//! # Snapshots
//!
//! Every snapshot carries the held sets as they stood when it was taken, and
//! they never change afterwards. Taking a snapshot first extends the sets by
//! the closures of what arrived since the previous one -- new records' seeds,
//! seeds whose bytes arrived, memberships peers reported -- computed against
//! that snapshot. That is the publication barrier: an observation is never
//! handed out ahead of its new records' closures. Background walks only
//! enter later snapshots; a changed [`HeldRead::held_generation`] says one did.
//!
//! A held set is *closed*: a blob joins only once every resident child it
//! had when scanned has joined, so every closure computed later stops at a
//! held blob without missing anything below it.
//!
//! When a collection is first tracked, its existing closure is computed
//! synchronously if no walker is attached, and otherwise by a start-up walk
//! of that collection in the background. The walk publishes batch by batch
//! (a positive set is safe to publish incomplete), each blob only after its
//! closure. The start-up walk and the periodic walk never gate a snapshot.
//! While a collection's start-up walk is owed, peer reports for it wait for
//! that walk, which reads those its records do not reach, rather than being
//! read while a snapshot is taken: after a restart peers report their whole
//! held sets, and resolving those reports at once would be the full walk
//! again, on the publication path. Only a caller that owns a long-running
//! host starts a walker; nothing here starts a thread by itself.
//!
//! A snapshot that lost a blob its predecessor had (a store that forgets
//! blobs) resets the index: the edges are forgotten and every collection is
//! recomputed as if newly tracked. A walk that started before the reset stops.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anybytes::Bytes;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::UnknownBlob;
use crate::capability::policy::resource_collection;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
use crate::prelude::{find, pattern};
use crate::repo::{BlobStoreGet, BlobStoreList, CapabilityProofRead, StoreChanges, StoreSnapshot};
use crate::trible::TribleSet;

use super::covered::RecordDelta;
use super::descriptor::validate_proof_evidence;
use super::{CollectionHandle, CollectionRead, CollectionRecord, CollectionRecordSelector};

type Raw = [u8; 32];

/// One collection's held set: positive, and served as a Merkle PATCH.
pub type HeldBlobs = PATCH<32, IdentitySchema, (), Blake3Merkle>;

/// Two 32-byte segments, so a prefix of the first enumerates the second.
mod pair_key {
    crate::key_segmentation!(Segments, 64, [32, 32]);
    crate::key_schema!(Schema, Segments, 64, [0, 1]);
}

/// A relation between two 32-byte handles, keyed `first || second`: a
/// prefix scan on `first` enumerates its seconds. Every state the index
/// keeps across observations is one of these, a set of handles, or the held
/// sets themselves.
type Pairs = PATCH<64, pair_key::Schema, ()>;

/// A set of 32-byte handles.
type Handles = PATCH<32, IdentitySchema, ()>;

/// `collection -> held set`, for every settled collection.
type HeldSets = PATCH<32, IdentitySchema, HeldBlobs>;

fn pair(first: &Raw, second: &Raw) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(first);
    key[32..].copy_from_slice(second);
    key
}

fn split(key: &[u8; 64]) -> (Raw, Raw) {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&key[..32]);
    second.copy_from_slice(&key[32..]);
    (first, second)
}

/// Every `second` related to `first`.
fn related(pairs: &Pairs, first: &Raw) -> Vec<Raw> {
    let mut seconds = Vec::new();
    pairs.infixes(first, |second: &Raw| seconds.push(*second));
    seconds
}

/// Remove and return every `second` related to `first`.
fn take_related(pairs: &mut Pairs, first: &Raw) -> Vec<Raw> {
    let seconds = related(pairs, first);
    for second in &seconds {
        pairs.remove(&pair(first, second));
    }
    seconds
}

/// The held sets of one immutable observation.
pub trait HeldRead {
    /// Every blob `collection` holds in this observation, or `None` when the
    /// store does not track it (or has not yet been able to select its
    /// seeds). Absence from the set is not evidence that a blob is missing.
    fn held(&self, collection: CollectionHandle) -> Option<HeldBlobs>;

    /// Differs between two observations of one store whenever their held sets
    /// may differ, including when only a background walk added to them.
    fn held_generation(&self) -> u64;
}

/// Tracking and routing evidence for a store's held sets.
pub trait HeldStore {
    /// Keep held sets for `collections` from the next snapshot on.
    fn track_held(&mut self, collections: impl IntoIterator<Item = CollectionHandle>);

    /// A peer reported `handle` in its held set of `collection`. If the blob
    /// is resident when the next snapshot is taken, it and everything it
    /// reaches join `held(collection)`; while the collection's start-up walk
    /// is owed, the report waits for that walk, which reads it. Kept in
    /// memory only.
    fn note_held(&mut self, collection: CollectionHandle, handle: Inline<Handle<UnknownBlob>>);
}

/// What the index reads from a snapshot.
pub trait HeldSource:
    StoreSnapshot + RecordDelta + CollectionRead + BlobStoreGet + BlobStoreList + CapabilityProofRead
{
}

impl<T> HeldSource for T where
    T: StoreSnapshot
        + RecordDelta
        + CollectionRead
        + BlobStoreGet
        + BlobStoreList
        + CapabilityProofRead
{
}

/// How often and how widely the background walk runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldWalkConfig {
    /// Time from one periodic walk's start to the next one's. A walk that
    /// takes longer is followed immediately by the next. Start-up walks of
    /// newly tracked collections run when they are owed and do not move this
    /// schedule.
    pub interval: Duration,
    /// Blocking threads that read blobs during one walk.
    pub threads: usize,
}

impl Default for HeldWalkConfig {
    /// Thirty minutes on four threads. A periodic walk covers every tracked
    /// collection. Measured on a 41 GB pile copy with a warm page cache, per
    /// collection on 4 threads: about 60 s for the largest (about 108,000
    /// blobs, 16 GB, 500 M aligned words), about 27 s for the next (which
    /// then still seeded MERGE results, so less now), under 1 s for the
    /// rest. The late-child bound is therefore about 30 minutes plus about
    /// 1.5 minutes of walk plus scheduling delay.
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30 * 60),
            threads: 4,
        }
    }
}

/// Live walker threads in this process.
static WALKER_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Every thread the held-blob index ever spawned in this process: walker
/// threads and the scan threads of multi-threaded walks.
static SPAWNED_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Number of walker threads currently running in this process.
pub fn held_walker_threads() -> usize {
    WALKER_THREADS.load(Ordering::SeqCst)
}

/// Number of threads the held-blob index has spawned in this process so far,
/// walker and scan threads alike, for tests that a reader starts none.
pub fn held_threads_spawned() -> usize {
    SPAWNED_THREADS.load(Ordering::SeqCst)
}

/// The held sets as one snapshot sees them.
#[derive(Clone, Default)]
pub(crate) struct HeldView {
    generation: u64,
    sets: HeldSets,
}

/// Equal when the generations are and every collection holds the same set.
/// A PATCH compares its keys only, so each held set is compared itself.
impl PartialEq for HeldView {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.sets == other.sets
            && self
                .sets
                .iter()
                .all(|collection| self.sets.get(collection) == other.sets.get(collection))
    }
}

impl std::fmt::Debug for HeldView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldView")
            .field("generation", &self.generation)
            .field(
                "sets",
                &self
                    .sets
                    .iter()
                    .map(|collection| {
                        (
                            *collection,
                            self.sets.get(collection).map(|held| held.len()),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl HeldView {
    pub(crate) fn held(&self, collection: CollectionHandle) -> Option<HeldBlobs> {
        self.sets.get(&collection.raw).cloned()
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Default)]
struct Walker {
    /// Collections whose start-up walk is owed.
    requested: Handles,
    stop: bool,
}

/// Everything the index keeps across observations. A tracked collection is
/// *settled* once its seeds are selected: then it has a held set, until a
/// reset or a stopped walker makes it unsettled again.
#[derive(Clone)]
struct State<T> {
    /// The collections held sets are kept for.
    tracked: Handles,
    /// The held set of every settled collection.
    held: HeldSets,
    /// Settled collections whose existing closure is left to a start-up
    /// walk that has not finished.
    warming: Handles,
    /// `collection || blob`: every blob C's records and proofs name,
    /// resident or not.
    seeds: Pairs,
    /// `collection || blob`: resident blobs peers reported in C that were not
    /// already held.
    routes: Pairs,
    /// `collection || blob`: peer reports of resident blobs that arrived
    /// while C was unsettled or warming. With a walker, the walk that ends
    /// the warming reads those it did not reach and makes them routes;
    /// without one, the next observation resolves them.
    deferred: Pairs,
    /// Every blob scanned since the last reset, whether it has children or
    /// not.
    scanned: Handles,
    /// `parent || child`: each scanned blob and every child resident when it
    /// was scanned.
    edges: Pairs,
    /// `blob || collection`: seeds whose bytes were not readable yet, and the
    /// collections waiting for them.
    pending: Pairs,
    /// `collection || blob`: seeds a walk could not read that were resident
    /// by the time it published, reached at the next observation.
    ready: Pairs,
    /// Collection and resource descriptors that were not resident when
    /// proofs were judged; the arrival of one judges the proofs again.
    unrouted: Handles,
    /// Proof seeds are recomputed at the next observation: reading the proofs
    /// failed, or a descriptor arrived.
    proofs_stale: bool,
    /// `collection || blob`: peer reports since the last observation.
    candidates: Pairs,
    /// The last observation fed in.
    fed: Option<T>,
    generation: u64,
    /// Bumped by a reset, so a walk started before it stops and publishes
    /// nothing.
    epoch: u64,
    view: Arc<HeldView>,
    walker: Option<Walker>,
}

/// The shared held-blob index of one store. Its own lock: holding it never
/// blocks a coverage read.
pub(crate) struct HeldIndex<T> {
    state: Mutex<State<T>>,
    wake: Condvar,
    /// Set while a walker is being stopped, so a walk in progress returns
    /// after the blob it is reading rather than after its level.
    halt: AtomicBool,
    /// The state's epoch, readable by a walk without taking the lock.
    epoch: AtomicU64,
}

impl<T> Default for HeldIndex<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                tracked: Handles::new(),
                held: HeldSets::new(),
                warming: Handles::new(),
                seeds: Pairs::new(),
                routes: Pairs::new(),
                deferred: Pairs::new(),
                scanned: Handles::new(),
                edges: Pairs::new(),
                pending: Pairs::new(),
                ready: Pairs::new(),
                unrouted: Handles::new(),
                proofs_stale: false,
                candidates: Pairs::new(),
                fed: None,
                generation: 0,
                epoch: 0,
                view: Arc::new(HeldView::default()),
                walker: None,
            }),
            wake: Condvar::new(),
            halt: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
        }
    }
}

impl<T: Clone> HeldIndex<T> {
    /// An independent copy of this index, with no walker attached. A start-up
    /// walk the original owed is owed by the copy as a synchronous closure.
    pub(crate) fn detached_clone(&self) -> Self {
        let mut state = self.lock().clone();
        state.walker = None;
        state.release_warming();
        let epoch = state.epoch;
        Self {
            state: Mutex::new(state),
            wake: Condvar::new(),
            halt: AtomicBool::new(false),
            epoch: AtomicU64::new(epoch),
        }
    }
}

impl<T> HeldIndex<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().expect("held-blob index is not poisoned")
    }

    pub(crate) fn track(&self, collections: impl IntoIterator<Item = CollectionHandle>) {
        let mut state = self.lock();
        for collection in collections {
            state.tracked.insert(&Entry::new(&collection.raw));
        }
    }

    pub(crate) fn note(&self, collection: CollectionHandle, handle: Raw) {
        let mut state = self.lock();
        if state.tracked.get(&collection.raw).is_some() {
            state
                .candidates
                .insert(&Entry::new(&pair(&collection.raw, &handle)));
        }
    }

    /// The walk that started in `epoch` should stop: the walker is being
    /// stopped, or a reset made its results stale.
    fn abandoned(&self, epoch: u64) -> bool {
        self.halt.load(Ordering::Relaxed) || self.epoch.load(Ordering::Relaxed) != epoch
    }
}

/// The blobs a replicated record names; `None` for a MERGE, which never
/// replicates.
fn seeds_of(record: &CollectionRecord) -> Option<Vec<Raw>> {
    match record {
        CollectionRecord::Commit(commit) => Some(
            commit
                .blob_references()
                .iter()
                .map(|handle| handle.raw)
                .collect(),
        ),
        CollectionRecord::Derive(derive) => Some(
            derive
                .blob_references()
                .iter()
                .map(|handle| handle.raw)
                .collect(),
        ),
        CollectionRecord::Merge(_) => None,
    }
}

/// Seeds contributed by proofs, and descriptors not resident yet.
struct ProofSeeds {
    seeds: Vec<(CollectionHandle, Raw)>,
    /// Collection and resource descriptors that are not resident: their
    /// arrival may let a proof be judged for one of the collections.
    unrouted: Vec<Raw>,
}

/// Capability definitions named by the proofs each of `collections` keeps as
/// authorization evidence ([`validate_proof_evidence`]). `Err` when the
/// proofs cannot be read.
fn proof_seeds<T: HeldSource>(
    snapshot: &T,
    collections: &BTreeSet<CollectionHandle>,
) -> Result<ProofSeeds, T::ProofsError> {
    let mut found = ProofSeeds {
        seeds: Vec::new(),
        unrouted: Vec::new(),
    };
    if collections.is_empty() {
        return Ok(found);
    }
    // Scratch for this call: the descriptors that judge the proofs, read
    // when a proof first names their collection. One not resident yet judges
    // nothing until it arrives.
    let mut descriptors: BTreeMap<CollectionHandle, Option<TribleSet>> = BTreeMap::new();
    for proof in snapshot.proofs()? {
        let proof = proof?;
        let resource: CollectionHandle = Inline::new(proof.resource().into_bytes());
        // Only the proof's own resource, and the collections its resource
        // descriptor names (whether or not the resource is itself tracked),
        // can keep it; the predicate decides.
        let mut candidates = BTreeSet::new();
        if collections.contains(&resource) {
            candidates.insert(resource);
        }
        if let Ok(facts) = snapshot.get::<TribleSet, SimpleArchive>(resource) {
            for (collection,) in find!(
                (collection: Inline<Handle<SimpleArchive>>),
                pattern!(&facts, [{ _?resource @ resource_collection: ?collection }])
            ) {
                if collections.contains(&collection) {
                    candidates.insert(collection);
                }
            }
        } else if !snapshot.contains_blob(resource).unwrap_or(false) {
            found.unrouted.push(resource.raw);
        }
        for collection in candidates {
            let descriptor = descriptors.entry(collection).or_insert_with(|| {
                let facts = snapshot.get::<TribleSet, SimpleArchive>(collection).ok();
                if facts.is_none() && !snapshot.contains_blob(collection).unwrap_or(false) {
                    found.unrouted.push(collection.raw);
                }
                facts
            });
            let Some(descriptor) = descriptor else {
                continue;
            };
            if validate_proof_evidence(snapshot, collection, descriptor, &proof).is_ok() {
                for handle in proof.blob_references() {
                    found.seeds.push((collection, handle.raw));
                }
            }
        }
    }
    Ok(found)
}

/// Read one blob and list its resident children, or `None` if it is not
/// readable. Children are probed in the store's index without reading them.
fn scan<T: HeldSource>(snapshot: &T, handle: &Raw) -> Option<Vec<Raw>> {
    let body: Bytes = snapshot
        .get::<Bytes, UnknownBlob>(Inline::<Handle<UnknownBlob>>::new(*handle))
        .ok()?;
    let mut children: Vec<Raw> = body
        .as_ref()
        .chunks_exact(32)
        .map(|chunk| <Raw>::try_from(chunk).expect("32-byte chunk"))
        .filter(|word| {
            snapshot
                .contains_blob(Inline::<Handle<UnknownBlob>>::new(*word))
                .unwrap_or(false)
        })
        .collect();
    children.sort_unstable();
    children.dedup();
    Some(children)
}

impl<T> State<T> {
    /// Forget every edge and held set; every collection is recomputed as if
    /// newly tracked. Seeds and peer reports are kept as roots.
    fn reset(&mut self) {
        self.scanned = Handles::new();
        self.edges = Pairs::new();
        self.pending = Pairs::new();
        self.ready = Pairs::new();
        self.epoch += 1;
        self.held = HeldSets::new();
        self.warming = Handles::new();
    }

    /// No walker will finish the start-up walks still owed: those
    /// collections are unsettled again and recomputed synchronously at the
    /// next observation.
    fn release_warming(&mut self) {
        for collection in self.warming.iter() {
            self.held.remove(collection);
        }
        self.warming = Handles::new();
    }

    fn publish_view(&mut self) {
        self.generation += 1;
        self.view = Arc::new(HeldView {
            generation: self.generation,
            sets: self.held.clone(),
        });
    }

    /// Roots of one walk over `only` (every settled collection when `None`):
    /// the seeds and peer reports of each.
    fn walk_roots(&self, only: Option<&Handles>) -> Vec<(CollectionHandle, Vec<Raw>)> {
        self.held
            .iter()
            .filter(|collection| only.is_none_or(|only| only.get(collection).is_some()))
            .map(|collection| {
                let mut roots = related(&self.seeds, collection);
                roots.extend(related(&self.routes, collection));
                roots.sort_unstable();
                roots.dedup();
                (Inline::new(*collection), roots)
            })
            .collect()
    }

    /// Record one scan: the blob, and an edge to each resident child.
    /// Returns the children the cache did not name yet.
    fn record_scan(&mut self, handle: Raw, children: &[Raw]) -> Vec<Raw> {
        self.scanned.insert(&Entry::new(&handle));
        let mut learned = Vec::new();
        for child in children {
            let key = pair(&handle, child);
            if self.edges.get(&key).is_none() {
                self.edges.insert(&Entry::new(&key));
                learned.push(*child);
            }
        }
        learned
    }
}

impl<T: HeldSource> State<T> {
    /// Add everything reachable from `roots` to `collection`'s held set.
    ///
    /// A blob joins only after every resident child it has joined, so a held
    /// blob's whole closure is held and a later closure stops at it. With a
    /// snapshot, a blob never scanned is read now. Without one it is unknown:
    /// it and everything above it wait for the walk that will scan it.
    fn reach(
        &mut self,
        snapshot: Option<&T>,
        collection: CollectionHandle,
        roots: impl IntoIterator<Item = Raw>,
    ) -> bool {
        let Some(mut held) = self.held.get(&collection.raw).cloned() else {
            return false;
        };
        let mut changed = false;
        // Scratch for this call: depth first, a blob's children before it.
        let mut entered: HashSet<Raw> = HashSet::new();
        let mut unknown: HashSet<Raw> = HashSet::new();
        let mut stack: Vec<(Raw, Option<Vec<Raw>>)> =
            roots.into_iter().map(|root| (root, None)).collect();
        while let Some((handle, visited)) = stack.pop() {
            if let Some(children) = visited {
                if children.iter().any(|child| unknown.contains(child)) {
                    unknown.insert(handle);
                } else {
                    held.insert(&Entry::new(&handle));
                    changed = true;
                }
                continue;
            }
            if held.has_prefix(&handle) || !entered.insert(handle) {
                continue;
            }
            let children = if self.scanned.get(&handle).is_some() {
                related(&self.edges, &handle)
            } else if let Some(snapshot) = snapshot {
                match scan(snapshot, &handle) {
                    Some(children) => {
                        self.record_scan(handle, &children);
                        children
                    }
                    None => {
                        if self.seeds.get(&pair(&collection.raw, &handle)).is_some() {
                            self.pending
                                .insert(&Entry::new(&pair(&handle, &collection.raw)));
                        }
                        continue;
                    }
                }
            } else {
                unknown.insert(handle);
                continue;
            };
            let unheld: Vec<(Raw, Option<Vec<Raw>>)> = children
                .iter()
                .filter(|child| !held.has_prefix(*child))
                .map(|child| (*child, None))
                .collect();
            // Popped after every child below it has been decided.
            stack.push((handle, Some(children)));
            stack.extend(unheld);
        }
        if changed {
            self.held.replace(&Entry::with_value(&collection.raw, held));
        }
        changed
    }

    /// Add proof seeds to their collections and queue the new ones as roots.
    fn add_proof_seeds(
        &mut self,
        found: ProofSeeds,
        roots: &mut BTreeMap<CollectionHandle, Vec<Raw>>,
    ) {
        for descriptor in found.unrouted {
            self.unrouted.insert(&Entry::new(&descriptor));
        }
        for (collection, seed) in found.seeds {
            let key = pair(&collection.raw, &seed);
            if self.tracked.get(&collection.raw).is_none() || self.seeds.get(&key).is_some() {
                continue;
            }
            self.seeds.insert(&Entry::new(&key));
            roots.entry(collection).or_default().push(seed);
        }
    }
}

impl<T: HeldSource> HeldIndex<T> {
    /// Extend the held sets by everything `now` holds that the last observed
    /// snapshot did not, and hand out the result, fixed from here on.
    pub(crate) fn observe(&self, now: &T) -> Arc<HeldView> {
        let mut state = self.lock();
        if state.tracked.is_empty() {
            state.candidates = Pairs::new();
            return state.view.clone();
        }
        let mut changed = false;
        let changes = state
            .fed
            .as_ref()
            .map_or(StoreChanges::ALL, |fed| now.changes_since(fed));
        // A blob the last observation had and this one lacks. A store without
        // an indexed difference lists every blob here; the residency test
        // keeps that answer exact.
        let lost = changes.contains(StoreChanges::BLOBS)
            && state.fed.as_ref().is_some_and(|fed| {
                fed.blobs_diff(now)
                    .flatten()
                    .any(|info| !now.contains_blob(info.handle).unwrap_or(false))
            });
        if lost {
            state.reset();
            self.epoch.store(state.epoch, Ordering::Relaxed);
            changed = true;
        }

        // Scratch for this observation: what to reach, per collection.
        let mut roots: BTreeMap<CollectionHandle, Vec<Raw>> = BTreeMap::new();
        for key in std::mem::take(&mut state.ready).iter() {
            let (collection, handle) = split(key);
            roots
                .entry(Inline::new(collection))
                .or_default()
                .push(handle);
        }
        if let Some(fed) = state.fed.take() {
            if changes.contains(StoreChanges::COLLECTION_RECORDS) {
                let State { held, seeds, .. } = &mut *state;
                now.for_each_record_since(Some(&fed), &mut |record| {
                    let collection = record.collection();
                    // Untracked, or not settled: its selection reads it.
                    if held.get(&collection.raw).is_none() {
                        return;
                    }
                    let Some(named) = seeds_of(record) else {
                        return;
                    };
                    // Every seed of a new record is a root, known or not: the
                    // record is published with its whole closure even when a
                    // start-up walk still owes a seed another record named.
                    // A held seed costs one lookup.
                    for seed in named {
                        seeds.insert(&Entry::new(&pair(&collection.raw, &seed)));
                        roots.entry(collection).or_default().push(seed);
                    }
                });
            }
            if changes.contains(StoreChanges::BLOBS)
                && !(state.pending.is_empty() && state.unrouted.is_empty())
            {
                // Seeds whose bytes arrived since, and descriptors that may
                // let a proof be judged. A store without an indexed
                // difference lists every blob; entries still match once.
                for info in now.blobs_diff(&fed).flatten() {
                    let raw = info.handle.raw;
                    for collection in take_related(&mut state.pending, &raw) {
                        roots.entry(Inline::new(collection)).or_default().push(raw);
                    }
                    if state.unrouted.get(&raw).is_some() {
                        state.unrouted.remove(&raw);
                        state.proofs_stale = true;
                    }
                }
            }
            if changes.contains(StoreChanges::CAPABILITY_PROOFS) || state.proofs_stale {
                let settled: BTreeSet<CollectionHandle> = state
                    .held
                    .iter()
                    .map(|collection| Inline::new(*collection))
                    .collect();
                match proof_seeds(now, &settled) {
                    Ok(found) => {
                        state.proofs_stale = false;
                        state.add_proof_seeds(found, &mut roots);
                    }
                    // Retried at the next observation.
                    Err(_) => state.proofs_stale = true,
                }
            }
        }

        // Scratch: the tracked collections not settled yet.
        let fresh: BTreeSet<CollectionHandle> = state
            .tracked
            .iter()
            .filter(|collection| state.held.get(collection).is_none())
            .map(|collection| Inline::new(*collection))
            .collect();
        if !fresh.is_empty() {
            let selectors = fresh
                .iter()
                .map(|collection| CollectionRecordSelector::Foundations(*collection))
                .collect();
            // A collection is settled only from a complete selection. When the
            // store cannot answer, it stays unsettled -- absent from the view,
            // not short in it -- and is selected again at the next observation.
            if let (Ok(records), Ok(proofs)) =
                (now.select_records(&selectors), proof_seeds(now, &fresh))
            {
                let mut seeds: BTreeMap<CollectionHandle, Vec<Raw>> = fresh
                    .iter()
                    .map(|collection| (*collection, vec![collection.raw]))
                    .collect();
                for record in records {
                    if let (Some(list), Some(named)) =
                        (seeds.get_mut(&record.collection()), seeds_of(&record))
                    {
                        list.extend(named);
                    }
                }
                for descriptor in proofs.unrouted {
                    state.unrouted.insert(&Entry::new(&descriptor));
                }
                for (collection, seed) in proofs.seeds {
                    seeds.get_mut(&collection).expect("fresh").push(seed);
                }
                let background = state.walker.is_some();
                for (collection, mut list) in seeds {
                    for seed in &list {
                        state
                            .seeds
                            .insert(&Entry::new(&pair(&collection.raw, seed)));
                    }
                    list.extend(related(&state.routes, &collection.raw));
                    state
                        .held
                        .replace(&Entry::with_value(&collection.raw, HeldBlobs::new()));
                    if background {
                        // Its start-up walk reads these; only closures already
                        // scanned join now.
                        state.warming.insert(&Entry::new(&collection.raw));
                        state.reach(None, collection, list);
                    } else {
                        roots.entry(collection).or_default().extend(list);
                    }
                }
                changed = true;
                if let Some(walker) = &mut state.walker {
                    for collection in &fresh {
                        walker.requested.insert(&Entry::new(&collection.raw));
                    }
                    self.wake.notify_all();
                }
            }
        }

        for (collection, list) in roots {
            changed |= state.reach(Some(now), collection, list);
        }

        // Scratch for this observation: the reports to resolve.
        let mut candidates: Vec<(CollectionHandle, Raw)> = std::mem::take(&mut state.candidates)
            .iter()
            .map(|key| {
                let (collection, handle) = split(key);
                (Inline::new(collection), handle)
            })
            .collect();
        // Reports kept for a start-up walk that no walker will run (none is
        // attached, or it stopped): resolved here, as any report is then.
        if !state.deferred.is_empty() {
            let cold: Vec<Raw> = state
                .held
                .iter()
                .filter(|collection| state.warming.get(collection).is_none())
                .copied()
                .collect();
            for collection in cold {
                for handle in take_related(&mut state.deferred, &collection) {
                    candidates.push((Inline::new(collection), handle));
                }
            }
        }
        for (collection, handle) in candidates {
            if state.tracked.get(&collection.raw).is_none() {
                continue;
            }
            let settled = state.held.get(&collection.raw);
            if settled.is_some_and(|held| held.has_prefix(&handle)) {
                continue;
            }
            if settled.is_none() || state.warming.get(&collection.raw).is_some() {
                // Resolving it now could read a whole unscanned subtree while
                // this snapshot is taken; the start-up walk reads it instead.
                // A report of a blob that is not resident is dropped, as
                // below, so only resident blobs wait.
                if now
                    .contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
                    .unwrap_or(false)
                {
                    state
                        .deferred
                        .insert(&Entry::new(&pair(&collection.raw, &handle)));
                }
                continue;
            }
            if state.reach(Some(now), collection, [handle]) {
                state
                    .routes
                    .insert(&Entry::new(&pair(&collection.raw, &handle)));
                changed = true;
            }
        }
        state.fed = Some(now.clone());
        if changed {
            state.publish_view();
        }
        state.view.clone()
    }

    /// Publish the seeds a walk could not read.
    fn publish_unreadable(&self, epoch: u64, unreadable: Vec<(CollectionHandle, Raw)>) {
        let mut state = self.lock();
        if state.epoch != epoch {
            return;
        }
        for (collection, handle) in unreadable {
            let Some(held) = state.held.get(&collection.raw) else {
                continue;
            };
            if held.has_prefix(&handle)
                || state.seeds.get(&pair(&collection.raw, &handle)).is_none()
            {
                continue;
            }
            // The walk read an older observation. A seed that arrived since
            // is in no later difference, so it is reached from the latest
            // observation instead of waiting for one.
            let resident = state.fed.as_ref().is_some_and(|fed| {
                fed.contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
                    .unwrap_or(false)
            });
            if resident {
                state
                    .ready
                    .insert(&Entry::new(&pair(&collection.raw, &handle)));
            } else {
                state
                    .pending
                    .insert(&Entry::new(&pair(&handle, &collection.raw)));
            }
        }
    }

    /// Publish one piece of a walk, children before parents: each blob's
    /// edges, then its membership in the collections that reached it, then
    /// the membership its newly learned children owe the collections that
    /// already hold it. A held blob is thus never left with a cached child
    /// that is not held.
    fn publish_piece(&self, epoch: u64, piece: Vec<(Raw, Arc<[Raw]>, Vec<CollectionHandle>)>) {
        let mut state = self.lock();
        if state.epoch != epoch {
            return;
        }
        let mut changed = false;
        for (handle, children, reached) in piece {
            let learned = state.record_scan(handle, &children);
            for collection in reached {
                changed |= state.reach(None, collection, [handle]);
            }
            if learned.is_empty() {
                continue;
            }
            let holders: Vec<CollectionHandle> = state
                .held
                .iter()
                .filter(|collection| {
                    state
                        .held
                        .get(collection)
                        .is_some_and(|held| held.has_prefix(&handle))
                })
                .map(|collection| Inline::new(*collection))
                .collect();
            for collection in holders {
                changed |= state.reach(None, collection, learned.iter().copied());
            }
        }
        if changed {
            state.publish_view();
        }
    }

    /// One walk against `snapshot` over `only` (every tracked collection when
    /// `None`): rescan every blob reachable from their seeds and peer
    /// reports, and refresh the edge cache. A walk that completes ends the
    /// start-up walks it covered.
    ///
    /// The roots are walked in batches. Each batch is read to the end and
    /// then published children before parents -- each blob's edges with its
    /// membership -- so a blob joins a held set only once its whole resident
    /// closure has, and a held blob never has a cached child that is not
    /// held: a positive set published incomplete, never one that is not
    /// closed. Reports
    /// that waited for the walk and that it did not reach are walked last,
    /// against the latest observation, and become routes; the walk ends only
    /// when none is waiting, so none is left for a snapshot to read.
    pub(crate) fn walk(&self, snapshot: &T, threads: usize, only: Option<&Handles>) {
        let (mut queue, epoch) = {
            let state = self.lock();
            (state.walk_roots(only), state.epoch)
        };
        let covered: Vec<CollectionHandle> =
            queue.iter().map(|(collection, _)| *collection).collect();
        let threads = threads.max(1);
        let abandoned = || self.abandoned(epoch);
        // Scratch for this walk: what it read, and what it reached per
        // collection, so no blob is read twice by one walk.
        let mut known: HashMap<Raw, Option<Arc<[Raw]>>> = HashMap::new();
        let mut seen: BTreeMap<CollectionHandle, HashSet<Raw>> = BTreeMap::new();
        let mut latest: Option<T> = None;
        let mut rounds = 0;
        loop {
            let snapshot = latest.as_ref().unwrap_or(snapshot);
            while let Some(batch) = next_batch(&mut queue) {
                if !self.walk_batch(snapshot, epoch, threads, batch, &mut known, &mut seen) {
                    return;
                }
            }
            let mut state = self.lock();
            if state.epoch != epoch || abandoned() {
                return;
            }
            if rounds == MAX_REPORT_ROUNDS {
                // Reports keep arriving: the collections still owing some
                // stay warming and are walked again by the walker's next turn.
                let owing: Vec<CollectionHandle> = covered
                    .iter()
                    .copied()
                    .filter(|collection| {
                        !related(&state.deferred, &collection.raw).is_empty()
                            || (state.warming.get(&collection.raw).is_some()
                                && !related(&state.candidates, &collection.raw).is_empty())
                    })
                    .collect();
                for collection in &covered {
                    if !owing.contains(collection) {
                        state.warming.remove(&collection.raw);
                    }
                }
                if let Some(walker) = &mut state.walker {
                    for collection in &owing {
                        walker.requested.insert(&Entry::new(&collection.raw));
                    }
                    self.wake.notify_all();
                }
                return;
            }
            let mut reports = Vec::new();
            for collection in &covered {
                if state.warming.get(&collection.raw).is_some() {
                    // Reports noted since the last observation wait for this
                    // walk too, if that observation had their blobs; the
                    // others arrived after it and are ordinary reports.
                    for handle in take_related(&mut state.candidates, &collection.raw) {
                        let resident = state.fed.as_ref().is_some_and(|fed| {
                            fed.contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
                                .unwrap_or(false)
                        });
                        let key = pair(&collection.raw, &handle);
                        if resident {
                            state.deferred.insert(&Entry::new(&key));
                        } else {
                            state.candidates.insert(&Entry::new(&key));
                        }
                    }
                }
                let reached = seen.entry(*collection).or_default();
                let mut unreached = Vec::new();
                for handle in take_related(&mut state.deferred, &collection.raw) {
                    if !reached.contains(&handle) {
                        state
                            .routes
                            .insert(&Entry::new(&pair(&collection.raw, &handle)));
                        unreached.push(handle);
                    }
                }
                if !unreached.is_empty() {
                    reports.push((*collection, unreached));
                }
            }
            if reports.is_empty() {
                for collection in &covered {
                    state.warming.remove(&collection.raw);
                }
                return;
            }
            // Reported blobs were resident when their reports were taken,
            // possibly only after this walk's snapshot.
            latest = state.fed.clone();
            drop(state);
            // A blob the walk could not read holds only for the snapshot it
            // tried: forget it, so the round reads it again.
            rounds += 1;
            known.retain(|handle, children| {
                if children.is_none() {
                    for seen in seen.values_mut() {
                        seen.remove(handle);
                    }
                }
                children.is_some()
            });
            queue = reports;
        }
    }

    /// Walk one batch of roots to the end, level by level, publishing the
    /// unreadable seeds as they come; then publish what it read and reached,
    /// children before parents, in bounded pieces. `false` when the walk was
    /// abandoned.
    fn walk_batch(
        &self,
        snapshot: &T,
        epoch: u64,
        threads: usize,
        mut frontier: Vec<(CollectionHandle, Vec<Raw>)>,
        known: &mut HashMap<Raw, Option<Arc<[Raw]>>>,
        seen: &mut BTreeMap<CollectionHandle, HashSet<Raw>>,
    ) -> bool {
        let abandoned = || self.abandoned(epoch);
        // Scratch for this batch: the collections that reached each readable
        // blob.
        let mut reached: HashMap<Raw, Vec<CollectionHandle>> = HashMap::new();
        while frontier.iter().any(|(_, nodes)| !nodes.is_empty()) {
            if abandoned() {
                return false;
            }
            let mut need: Vec<Raw> = frontier
                .iter()
                .flat_map(|(_, nodes)| nodes.iter().copied())
                .filter(|handle| !known.contains_key(handle))
                .collect();
            need.sort_unstable();
            need.dedup();
            let scanned: Vec<(Raw, Option<Arc<[Raw]>>)> =
                scan_all(snapshot, &need, threads, &abandoned);
            if abandoned() {
                // A partial level is not published.
                return false;
            }
            for (handle, children) in scanned {
                known.insert(handle, children);
            }
            let mut unreadable = Vec::new();
            let mut next = Vec::with_capacity(frontier.len());
            for (collection, nodes) in frontier {
                let seen = seen.entry(collection).or_default();
                let mut after = Vec::new();
                for handle in nodes {
                    if !seen.insert(handle) {
                        continue;
                    }
                    match &known[&handle] {
                        Some(children) => {
                            reached.entry(handle).or_default().push(collection);
                            after.extend(
                                children
                                    .iter()
                                    .copied()
                                    .filter(|child| !seen.contains(child)),
                            );
                        }
                        None => unreadable.push((collection, handle)),
                    }
                }
                next.push((collection, after));
            }
            self.publish_unreadable(epoch, unreadable);
            frontier = next;
        }
        // Published in bounded pieces, so a snapshot taken meanwhile waits
        // for one piece, never for a whole batch.
        let order = children_first(reached.keys().copied(), known);
        for piece in order.chunks(PUBLISH_PIECE) {
            let piece = piece
                .iter()
                .map(|handle| {
                    let children = known[handle].clone().expect("a reached blob was read");
                    (
                        *handle,
                        children,
                        reached.remove(handle).unwrap_or_default(),
                    )
                })
                .collect();
            self.publish_piece(epoch, piece);
        }
        true
    }
}

/// `nodes` ordered so that each comes after those of its children that are
/// among them.
fn children_first(
    nodes: impl IntoIterator<Item = Raw>,
    known: &HashMap<Raw, Option<Arc<[Raw]>>>,
) -> Vec<Raw> {
    let nodes: HashSet<Raw> = nodes.into_iter().collect();
    let mut order = Vec::with_capacity(nodes.len());
    let mut entered: HashSet<Raw> = HashSet::new();
    for start in &nodes {
        let mut stack = vec![(*start, false)];
        while let Some((node, exit)) = stack.pop() {
            if exit {
                order.push(node);
                continue;
            }
            if !entered.insert(node) {
                continue;
            }
            stack.push((node, true));
            if let Some(Some(children)) = known.get(&node) {
                stack.extend(
                    children
                        .iter()
                        .filter(|child| nodes.contains(*child) && !entered.contains(*child))
                        .map(|child| (*child, false)),
                );
            }
        }
    }
    order
}

/// Up to [`WALK_BATCH`] roots from the front of `queue`.
fn next_batch(
    queue: &mut Vec<(CollectionHandle, Vec<Raw>)>,
) -> Option<Vec<(CollectionHandle, Vec<Raw>)>> {
    let mut batch = Vec::new();
    let mut budget = WALK_BATCH;
    while budget > 0 {
        let Some((collection, roots)) = queue.last_mut() else {
            break;
        };
        let take = roots.len().min(budget);
        let taken = roots.split_off(roots.len() - take);
        budget -= take;
        batch.push((*collection, taken));
        if roots.is_empty() {
            queue.pop();
        }
    }
    (!batch.is_empty()).then_some(batch)
}

/// Roots walked to the end before the next ones start: a start-up walk
/// publishes a whole batch's closure at a time, so its held sets fill in
/// progressively rather than only when it ends.
const WALK_BATCH: usize = 4_096;

/// Rounds of waiting reports one walk takes after its roots; reports that
/// keep arriving beyond them are left for the walker's next turn.
const MAX_REPORT_ROUNDS: usize = 16;

/// Blobs published per lock hold by a walk.
const PUBLISH_PIECE: usize = 16_384;

/// Scan `handles` on `threads` blocking threads, stopping early once
/// `abandoned` says so.
fn scan_all<T: HeldSource>(
    snapshot: &T,
    handles: &[Raw],
    threads: usize,
    abandoned: &(dyn Fn() -> bool + Sync),
) -> Vec<(Raw, Option<Arc<[Raw]>>)> {
    let scan_part = |part: &[Raw]| {
        part.iter()
            .take_while(|_| !abandoned())
            .map(|handle| (*handle, scan(snapshot, handle).map(Arc::from)))
            .collect::<Vec<_>>()
    };
    if threads <= 1 || handles.len() < 2 {
        return scan_part(handles);
    }
    let chunk = handles.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let workers: Vec<_> = handles
            .chunks(chunk)
            .map(|part| {
                SPAWNED_THREADS.fetch_add(1, Ordering::SeqCst);
                scope.spawn(move || scan_part(part))
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("held-blob scan thread panicked"))
            .collect()
    })
}

/// The background walker of one store: the start-up walk of newly tracked
/// collections and the periodic full walk. Dropping it stops the thread
/// (after the blob it is reading) and waits for it.
pub struct HeldWalker {
    stop: Option<Box<dyn FnOnce() + Send>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for HeldWalker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldWalker").finish_non_exhaustive()
    }
}

impl Drop for HeldWalker {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl<T: HeldSource> HeldIndex<T> {
    /// Attach the background walker. At most one walker per index: a second
    /// call stops nothing and starts another thread that shares the work.
    pub(crate) fn start_walker(self: &Arc<Self>, config: HeldWalkConfig) -> HeldWalker {
        {
            let mut state = self.lock();
            // Collections already settled were computed in full; the
            // interval decides their next walk.
            state.walker.get_or_insert_with(Walker::default).stop = false;
        }
        WALKER_THREADS.fetch_add(1, Ordering::SeqCst);
        SPAWNED_THREADS.fetch_add(1, Ordering::SeqCst);
        let index = Arc::clone(self);
        let thread = std::thread::Builder::new()
            .name("held-blob-walk".into())
            .spawn(move || {
                index.run_walker(config);
                // An explicit walk after this walker is gone runs in full.
                index.halt.store(false, Ordering::Relaxed);
                WALKER_THREADS.fetch_sub(1, Ordering::SeqCst);
            })
            .expect("spawn the held-blob walker thread");
        let index = Arc::clone(self);
        HeldWalker {
            stop: Some(Box::new(move || {
                index.halt.store(true, Ordering::Relaxed);
                let mut state = index.lock();
                if let Some(walker) = &mut state.walker {
                    walker.stop = true;
                }
                index.wake.notify_all();
            })),
            thread: Some(thread),
        }
    }

    fn run_walker(&self, config: HeldWalkConfig) {
        let mut due = Instant::now() + config.interval;
        loop {
            let (snapshot, only) = {
                let mut state = self.lock();
                loop {
                    let (stop, requested) = match &state.walker {
                        None => return,
                        Some(walker) => (walker.stop, !walker.requested.is_empty()),
                    };
                    if stop {
                        state.walker = None;
                        state.release_warming();
                        return;
                    }
                    let now = Instant::now();
                    if requested || now >= due {
                        break;
                    }
                    state = self
                        .wake
                        .wait_timeout(state, due - now)
                        .expect("held-blob index is not poisoned")
                        .0;
                }
                let requested = std::mem::take(
                    &mut state
                        .walker
                        .as_mut()
                        .expect("the walker is attached")
                        .requested,
                );
                let only = if Instant::now() >= due {
                    // The periodic walk covers every collection, the
                    // requested ones too.
                    due = Instant::now() + config.interval;
                    None
                } else {
                    Some(requested)
                };
                (state.fed.clone(), only)
            };
            if let Some(snapshot) = snapshot {
                self.walk(&snapshot, config.threads, only.as_ref());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::{Blob, BlobEncoding, IntoBlob, TryFromBlob};
    use crate::capability::{CapabilityProof, CapabilityProofId, CapabilityResource};
    use crate::collection::covered::Covered;
    use crate::collection::{
        CollectionCommit, CollectionDerive, CollectionMerge, CollectionStore, SourceLocator,
    };
    use crate::inline::InlineEncoding;
    use crate::prelude::entity;
    use crate::repo::memoryrepo::{MemoryStore, MemoryStoreSnapshot};
    use crate::repo::{BlobInfo, BlobStorePut, CapabilityProofStore, SnapshotSource};

    type Reads = Arc<Mutex<HashMap<Raw, usize>>>;

    /// While closed, holds the walker thread at its next blob read (or only
    /// at its read of one named blob), before the read is counted. Every
    /// other thread passes.
    #[derive(Default)]
    struct Gate {
        closed: Mutex<bool>,
        at: Mutex<Option<Raw>>,
        opened: Condvar,
        waiting: AtomicUsize,
    }

    /// Opens its gate when dropped, so a failing test never leaves the
    /// walker held while its handle waits to join it. Declare it after the
    /// walker, so it drops first.
    struct Opener(Arc<Gate>);

    impl Drop for Opener {
        fn drop(&mut self) {
            self.0.open();
        }
    }

    impl Gate {
        /// Close the gate until the returned opener drops.
        fn hold(self: &Arc<Self>) -> Opener {
            *self.closed.lock().unwrap() = true;
            Opener(Arc::clone(self))
        }

        /// Close the gate for the walker's read of `handle` only.
        fn hold_at(self: &Arc<Self>, handle: Raw) -> Opener {
            *self.at.lock().unwrap() = Some(handle);
            self.hold()
        }

        fn open(&self) {
            *self.closed.lock().unwrap() = false;
            self.opened.notify_all();
        }

        fn pass(&self, handle: &Raw) {
            if std::thread::current().name() != Some("held-blob-walk") {
                return;
            }
            if self.at.lock().unwrap().is_some_and(|at| at != *handle) {
                return;
            }
            let mut closed = self.closed.lock().unwrap();
            if *closed {
                self.waiting.fetch_add(1, Ordering::SeqCst);
                while *closed {
                    closed = self.opened.wait(closed).unwrap();
                }
                self.waiting.fetch_sub(1, Ordering::SeqCst);
            }
        }

        /// Wait until the walker is held at the gate, inside a walk.
        fn await_walker(&self) {
            let start = Instant::now();
            while self.waiting.load(Ordering::SeqCst) == 0 {
                assert!(
                    start.elapsed() < Duration::from_secs(30),
                    "the walker never reached the gate"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// Makes a snapshot's record selection or proof enumeration fail.
    #[derive(Default)]
    struct Faults {
        select: AtomicBool,
        proofs: AtomicBool,
    }

    #[derive(Debug)]
    struct Fault;

    impl std::fmt::Display for Fault {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "injected store fault")
        }
    }

    impl std::error::Error for Fault {}

    fn lift<V>(result: Result<V, Infallible>) -> Result<V, Fault> {
        result.map_err(|never| match never {})
    }

    /// A memory store whose snapshots count every blob body read, per blob.
    #[derive(Default)]
    struct Counting {
        inner: MemoryStore,
        reads: Reads,
        /// The reads made by any thread but the walker's.
        foreground: Reads,
        gate: Arc<Gate>,
        faults: Arc<Faults>,
    }

    #[derive(Clone)]
    struct CountingSnapshot {
        inner: MemoryStoreSnapshot,
        reads: Reads,
        foreground: Reads,
        gate: Arc<Gate>,
        faults: Arc<Faults>,
    }

    impl SnapshotSource for Counting {
        type Snapshot = CountingSnapshot;
        type SnapshotError = Infallible;

        fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
            Ok(CountingSnapshot {
                inner: self.inner.snapshot()?,
                reads: self.reads.clone(),
                foreground: self.foreground.clone(),
                gate: self.gate.clone(),
                faults: self.faults.clone(),
            })
        }
    }

    impl BlobStorePut for Counting {
        type PutError = Infallible;

        fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
        where
            S: BlobEncoding + 'static,
            T: IntoBlob<S>,
            Handle<S>: InlineEncoding,
        {
            self.inner.put(item)
        }
    }

    impl CollectionStore for Counting {
        type InsertError = <MemoryStore as CollectionStore>::InsertError;

        fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
            self.inner.insert(record)
        }
    }

    impl CapabilityProofStore for Counting {
        type InsertError = <MemoryStore as CapabilityProofStore>::InsertError;

        fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
            self.inner.insert_proof(proof)
        }
    }

    impl StoreSnapshot for CountingSnapshot {
        fn changes_since(&self, previous: &Self) -> StoreChanges {
            self.inner.changes_since(&previous.inner)
        }
    }

    impl BlobStoreGet for CountingSnapshot {
        type GetError<E: std::error::Error + Send + Sync + 'static> =
            <MemoryStoreSnapshot as BlobStoreGet>::GetError<E>;

        fn get<V, S>(
            &self,
            handle: Inline<Handle<S>>,
        ) -> Result<V, Self::GetError<<V as TryFromBlob<S>>::Error>>
        where
            S: BlobEncoding + 'static,
            V: TryFromBlob<S>,
            Handle<S>: InlineEncoding,
        {
            self.gate.pass(&handle.raw);
            *self.reads.lock().unwrap().entry(handle.raw).or_default() += 1;
            if std::thread::current().name() != Some("held-blob-walk") {
                *self
                    .foreground
                    .lock()
                    .unwrap()
                    .entry(handle.raw)
                    .or_default() += 1;
            }
            self.inner.get(handle)
        }
    }

    impl BlobStoreList for CountingSnapshot {
        type Iter<'a> = <MemoryStoreSnapshot as BlobStoreList>::Iter<'a>;
        type Err = <MemoryStoreSnapshot as BlobStoreList>::Err;

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

        fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
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

    impl RecordDelta for CountingSnapshot {
        fn for_each_record_since(
            &self,
            since: Option<&Self>,
            each: &mut dyn FnMut(&CollectionRecord),
        ) {
            self.inner
                .for_each_record_since(since.map(|since| &since.inner), each)
        }
    }

    type Lift<V> = fn(Result<V, Infallible>) -> Result<V, Fault>;

    impl CollectionRead for CountingSnapshot {
        type RecordsError = Fault;
        type RecordIter<'a> = std::iter::Map<
            <MemoryStoreSnapshot as CollectionRead>::RecordIter<'a>,
            Lift<CollectionRecord>,
        >;

        fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
            Ok(lift(self.inner.records())?.map(lift as Lift<CollectionRecord>))
        }

        fn collections(&self) -> Result<Vec<CollectionHandle>, Self::RecordsError> {
            lift(self.inner.collections())
        }

        fn select_records(
            &self,
            selectors: &BTreeSet<CollectionRecordSelector>,
        ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
            if self.faults.select.load(Ordering::SeqCst) {
                return Err(Fault);
            }
            lift(self.inner.select_records(selectors))
        }
    }

    impl CapabilityProofRead for CountingSnapshot {
        type ProofsError = Fault;
        type ProofIter<'a> = std::iter::Map<
            <MemoryStoreSnapshot as CapabilityProofRead>::ProofIter<'a>,
            Lift<CapabilityProof>,
        >;

        fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
            if self.faults.proofs.load(Ordering::SeqCst) {
                return Err(Fault);
            }
            Ok(lift(self.inner.proofs())?.map(lift as Lift<CapabilityProof>))
        }

        fn proof(
            &self,
            id: CapabilityProofId,
        ) -> Result<Option<CapabilityProof>, Self::ProofsError> {
            lift(self.inner.proof(id))
        }
    }

    type Store = Covered<Counting>;

    /// Tests that spawn held-index threads run one at a time, so the
    /// process-wide thread counters are theirs to read.
    static WALKER_TESTS: Mutex<()> = Mutex::new(());

    fn walker_guard() -> std::sync::MutexGuard<'static, ()> {
        WALKER_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[41; 32])
    }

    fn blob<S: SnapshotSource + BlobStorePut>(store: &mut S, bytes: &[u8]) -> Raw {
        store
            .put::<UnknownBlob, _>(Bytes::from_source(bytes.to_vec()))
            .unwrap()
            .raw
    }

    /// A blob whose body is `words`, so each is a child once resident.
    fn blob_naming<S: SnapshotSource + BlobStorePut>(
        store: &mut S,
        label: &[u8],
        words: &[Raw],
    ) -> Raw {
        store
            .put::<UnknownBlob, _>(unresident_naming(label, words))
            .unwrap()
            .raw
    }

    fn unresident_naming(label: &[u8], words: &[Raw]) -> Bytes {
        let mut bytes: Vec<u8> = words.iter().flatten().copied().collect();
        // A tail shorter than a word keeps distinct labels distinct.
        bytes.extend_from_slice(&label[..label.len().min(31)]);
        Bytes::from_source(bytes)
    }

    fn handle_of(bytes: &Bytes) -> Raw {
        crate::blob::Blob::<UnknownBlob>::new(bytes.clone())
            .get_handle()
            .raw
    }

    /// A collection handle whose "descriptor" is a resident blob: the index
    /// seeds the descriptor without reading what it declares.
    fn collection<S: SnapshotSource + BlobStorePut>(store: &mut S, name: &str) -> CollectionHandle {
        Inline::new(blob(store, format!("descriptor {name}").as_bytes()))
    }

    /// A collection with a real descriptor whose READ and WRITE policies
    /// have the single root `root`, so proofs from that root over it are
    /// its authorization evidence.
    fn governed(store: &mut Store, name: &str, root: &SigningKey) -> CollectionHandle {
        use crate::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};
        let direct = AdmissionPolicy::direct(root.verifying_key());
        store
            .collection(name, CollectionPolicy::new(direct.clone(), direct))
            .unwrap()
            .handle()
    }

    fn commit<S: CollectionStore>(
        store: &mut S,
        collection: CollectionHandle,
        data: Raw,
        metadata: Raw,
    ) {
        store
            .insert(CollectionRecord::Commit(CollectionCommit::sign(
                &key(),
                collection,
                Inline::new(data),
                Inline::new(metadata),
            )))
            .unwrap();
    }

    fn held_set(snapshot: &impl HeldRead, collection: CollectionHandle) -> BTreeSet<Raw> {
        snapshot
            .held(collection)
            .expect("the collection is tracked")
            .iter_ordered()
            .copied()
            .collect()
    }

    /// Every resident child of a blob `snapshot` holds in `c` is held too:
    /// a held set is closed under the conservative closure, so a reader may
    /// stop at a held blob.
    fn assert_closed(snapshot: &<Store as SnapshotSource>::Snapshot, c: CollectionHandle) {
        let held = held_set(snapshot, c);
        let blobs = &snapshot.inner().inner;
        for parent in &held {
            let Ok(body) = blobs.get::<Bytes, UnknownBlob>(Inline::new(*parent)) else {
                continue;
            };
            for word in body.as_ref().chunks_exact(32) {
                let child: Raw = word.try_into().expect("32-byte word");
                if blobs
                    .contains_blob(Inline::<Handle<UnknownBlob>>::new(child))
                    .unwrap()
                {
                    assert!(
                        held.contains(&child),
                        "held blob {:02x?} lacks its resident child {:02x?}",
                        &parent[..4],
                        &child[..4]
                    );
                }
            }
        }
    }

    /// Take snapshots until `done` holds for one; fail after 30 s.
    fn until(
        store: &mut Store,
        what: &str,
        mut done: impl FnMut(&<Store as SnapshotSource>::Snapshot) -> bool,
    ) -> <Store as SnapshotSource>::Snapshot {
        let start = Instant::now();
        loop {
            let snapshot = store.snapshot().unwrap();
            if done(&snapshot) {
                return snapshot;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn walker_config(interval: Duration) -> HeldWalkConfig {
        HeldWalkConfig {
            interval,
            threads: 1,
        }
    }

    fn reads(store: &Store, handle: &Raw) -> usize {
        store
            .reads
            .lock()
            .unwrap()
            .get(handle)
            .copied()
            .unwrap_or(0)
    }

    #[test]
    fn a_commit_holds_its_descriptor_payload_closure_and_metadata_archive() {
        let mut store = Store::default();
        let c = collection(&mut store, "closure");
        let grandchild = blob(&mut store, b"grandchild");
        let child = blob_naming(&mut store, b"child", &[grandchild]);
        let absent = [7; 32];
        let data = blob_naming(&mut store, b"data", &[child, absent]);
        let described = blob(&mut store, b"named by metadata");
        let metadata = blob_naming(&mut store, b"metadata", &[described]);
        commit(&mut store, c, data, metadata);
        store.track_held([c]);
        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            held_set(&snapshot, c),
            BTreeSet::from([c.raw, data, child, grandchild, metadata, described])
        );
        // Untracked collections have no held set at all.
        assert_eq!(snapshot.held(Inline::new([9; 32])), None);
    }

    #[test]
    fn merge_results_and_blobs_no_record_names_are_never_held() {
        let mut store = Store::default();
        let c = collection(&mut store, "merges");
        let data = blob(&mut store, b"foundation");
        let metadata = blob(&mut store, b"metadata");
        commit(&mut store, c, data, metadata);
        let under_merge = blob(&mut store, b"only a merge result reaches this");
        let result = blob_naming(&mut store, b"merge result", &[under_merge, data]);
        store
            .insert(CollectionRecord::Merge(
                CollectionMerge::sign(
                    &key(),
                    c,
                    [Inline::new(data), Inline::new([3; 32])],
                    Inline::new(result),
                )
                .unwrap(),
            ))
            .unwrap();
        // The shape of an attachment: resident, built from the node, named by
        // no replicated record.
        let attachment = blob_naming(&mut store, b"attachment", &[data]);
        let derived = collection(&mut store, "derived");
        let output_child = blob(&mut store, b"under the output");
        let output = blob_naming(&mut store, b"derive output", &[output_child]);
        store
            .insert(CollectionRecord::Derive(CollectionDerive::sign(
                &key(),
                derived,
                SourceLocator::of(data),
                Inline::new(output),
            )))
            .unwrap();
        store.track_held([c, derived]);
        let snapshot = store.snapshot().unwrap();
        let held = held_set(&snapshot, c);
        assert_eq!(held, BTreeSet::from([c.raw, data, metadata]));
        for never in [result, under_merge, attachment] {
            assert!(!held.contains(&never));
        }
        assert_eq!(
            held_set(&snapshot, derived),
            BTreeSet::from([derived.raw, output, output_child]),
            "a DERIVE holds its output, never its source node"
        );
    }

    #[test]
    fn a_blob_before_its_record_and_a_record_before_its_blob_are_both_held() {
        let mut store = Store::default();
        let c = collection(&mut store, "arrival order");
        let metadata = blob(&mut store, b"metadata");
        store.track_held([c]);
        let child = blob(&mut store, b"early child");
        let early = blob_naming(&mut store, b"early", &[child]);
        let before = store.snapshot().unwrap();
        assert!(!held_set(&before, c).contains(&early));
        commit(&mut store, c, early, metadata);
        let after = store.snapshot().unwrap();
        assert!(held_set(&after, c).is_superset(&BTreeSet::from([early, child])));

        let late_child = blob(&mut store, b"late payload child");
        let late = unresident_naming(b"late payload", &[late_child]);
        let late_handle = handle_of(&late);
        commit(&mut store, c, late_handle, metadata);
        let waiting = store.snapshot().unwrap();
        assert!(!held_set(&waiting, c).contains(&late_handle));
        store.put::<UnknownBlob, _>(late).unwrap();
        let arrived = store.snapshot().unwrap();
        assert!(held_set(&arrived, c).is_superset(&BTreeSet::from([late_handle, late_child])));
        assert_eq!(
            reads(&store, &late_handle),
            2,
            "one failed read, then one scan"
        );
    }

    /// C1 holds P, which names H before H is resident. H then arrives as a
    /// seed of C2. Scanning once, P gains no edge; H joins held(C1) when a
    /// peer reports it there, or at the next walk.
    #[test]
    fn a_late_child_resident_through_another_collection_joins_by_report() {
        let mut store = Store::default();
        let c1 = collection(&mut store, "first");
        let c2 = collection(&mut store, "second");
        let metadata = blob(&mut store, b"metadata");
        let h_bytes = unresident_naming(b"late child", &[]);
        let h = handle_of(&h_bytes);
        let p = blob_naming(&mut store, b"parent", &[h]);
        commit(&mut store, c1, p, metadata);
        store.track_held([c1, c2]);
        let first = store.snapshot().unwrap();
        assert!(held_set(&first, c1).contains(&p));

        store.put::<UnknownBlob, _>(h_bytes).unwrap();
        commit(&mut store, c2, h, metadata);
        let second = store.snapshot().unwrap();
        assert!(held_set(&second, c2).contains(&h));
        assert!(
            !held_set(&second, c1).contains(&h),
            "P was scanned before H arrived"
        );

        // A report for a blob that is not resident is dropped, not kept.
        store.note_held(c1, Inline::new([5; 32]));
        store.note_held(c1, Inline::new(h));
        let reported = store.snapshot().unwrap();
        assert!(held_set(&reported, c1).contains(&h));
        assert!(!held_set(&reported, c1).contains(&[5; 32]));
        assert_eq!(reads(&store, &h), 1, "H was read once, as C2's seed");
        assert_eq!(reads(&store, &p), 1);
    }

    /// Root R names an opaque P that names H; H is absent when P is scanned
    /// and later put locally, with no record naming it and no report. Only a
    /// walk that starts after H arrived finds it.
    #[test]
    fn a_nested_late_local_child_is_caught_by_the_walk_and_not_before() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "nested");
        let metadata = blob(&mut store, b"metadata");
        let h_bytes = unresident_naming(b"nested late child", &[]);
        let h = handle_of(&h_bytes);
        let p = blob_naming(&mut store, b"opaque intermediate", &[h]);
        let r = blob_naming(&mut store, b"root payload", &[p]);
        commit(&mut store, c, r, metadata);
        store.track_held([c]);
        let first = store.snapshot().unwrap();
        assert!(held_set(&first, c).contains(&p));
        store.put::<UnknownBlob, _>(h_bytes).unwrap();
        let mut last = None;
        for _ in 0..3 {
            let snapshot = store.snapshot().unwrap();
            assert!(!held_set(&snapshot, c).contains(&h), "no arrival rescans P");
            last = Some(snapshot);
        }
        let before_walk = last.unwrap();
        let generation = before_walk.held_generation();
        store.walk_held(2).unwrap();
        let walked = store.snapshot().unwrap();
        assert!(held_set(&walked, c).contains(&h));
        assert_ne!(walked.held_generation(), generation);
        assert!(
            !held_set(&before_walk, c).contains(&h),
            "an existing snapshot never changes"
        );
        assert_eq!(before_walk.held_generation(), generation);
    }

    #[test]
    fn a_scanned_shared_intermediate_joins_another_collection_without_a_read() {
        let mut store = Store::default();
        let c1 = collection(&mut store, "one");
        let c2 = collection(&mut store, "two");
        let metadata = blob(&mut store, b"metadata");
        let q = blob(&mut store, b"shared leaf");
        let p = blob_naming(&mut store, b"shared intermediate", &[q]);
        let first_payload = blob_naming(&mut store, b"first payload", &[p]);
        commit(&mut store, c1, first_payload, metadata);
        store.track_held([c1, c2]);
        let first = store.snapshot().unwrap();
        assert!(held_set(&first, c1).is_superset(&BTreeSet::from([p, q])));
        assert!(!held_set(&first, c2).contains(&p));
        let second_payload = blob_naming(&mut store, b"second payload", &[p]);
        commit(&mut store, c2, second_payload, metadata);
        let second = store.snapshot().unwrap();
        assert!(held_set(&second, c2).is_superset(&BTreeSet::from([second_payload, p, q])));
        assert_eq!(reads(&store, &p), 1);
        assert_eq!(reads(&store, &q), 1);
        assert_eq!(reads(&store, &second_payload), 1);
    }

    /// Between walks no blob body is read twice, whatever arrives; a walk
    /// reads every reachable blob once more.
    #[test]
    fn each_blob_is_read_at_most_once_between_walks() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let collections: Vec<_> = (0..3)
            .map(|index| collection(&mut store, &format!("scan-once {index}")))
            .collect();
        let metadata = blob(&mut store, b"shared metadata");
        let shared = blob(&mut store, b"shared everywhere");
        store.track_held(collections.iter().copied());
        let mut payloads = Vec::new();
        for round in 0..5_u8 {
            for (index, collection) in collections.iter().enumerate() {
                let own = blob(&mut store, &[round, index as u8, 1]);
                let payload = blob_naming(&mut store, &[round, index as u8, 2], &[own, shared]);
                commit(&mut store, *collection, payload, metadata);
                payloads.push((payload, own));
                store.note_held(*collection, Inline::new(shared));
            }
            store.snapshot().unwrap();
            store.snapshot().unwrap();
        }
        let counts = store.reads.lock().unwrap().clone();
        assert!(counts.values().all(|count| *count == 1), "{counts:?}");
        let snapshot = store.snapshot().unwrap();
        let reachable: BTreeSet<Raw> = collections
            .iter()
            .flat_map(|collection| held_set(&snapshot, *collection))
            .collect();
        store.walk_held(3).unwrap();
        let counts = store.reads.lock().unwrap().clone();
        for handle in &reachable {
            assert_eq!(counts[handle], 2, "a walk rereads each reachable blob once");
        }
    }

    #[test]
    fn capability_definitions_named_by_proofs_are_seeds_and_may_arrive_later() {
        let mut store = Store::default();
        let root = SigningKey::from_bytes(&[42; 32]);
        let c = governed(&mut store, "proven", &root);
        let delegate = SigningKey::from_bytes(&[43; 32]);
        let definition_bytes = unresident_naming(b"capability definition", &[]);
        let definition: Inline<Handle<SimpleArchive>> = Inline::new(handle_of(&definition_bytes));
        store.track_held([c]);
        store.snapshot().unwrap();
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(c),
                &root,
                definition,
                delegate.verifying_key(),
            ))
            .unwrap();
        let proven = store.snapshot().unwrap();
        assert!(!held_set(&proven, c).contains(&definition.raw));
        store.put::<UnknownBlob, _>(definition_bytes).unwrap();
        let arrived = store.snapshot().unwrap();
        assert!(held_set(&arrived, c).contains(&definition.raw));
    }

    #[test]
    fn a_lost_blob_resets_the_held_sets() {
        let mut store = Store::default();
        let c = collection(&mut store, "removal");
        let metadata = blob(&mut store, b"metadata");
        let child = blob(&mut store, b"disconnected child");
        let parent = blob_naming(&mut store, b"parent", &[child]);
        let data = blob_naming(&mut store, b"data", &[parent]);
        commit(&mut store, c, data, metadata);
        store.track_held([c]);
        let before = store.snapshot().unwrap();
        assert!(held_set(&before, c).contains(&child));
        let kept: Vec<_> = before
            .inner()
            .blobs()
            .map(|info| info.unwrap().handle)
            .filter(|handle| handle.raw != parent)
            .collect();
        (*store).inner.blobs.keep(kept);
        let after = store.snapshot().unwrap();
        let held = held_set(&after, c);
        assert!(!held.contains(&parent));
        assert!(!held.contains(&child), "the child lost its only path");
        assert!(held.contains(&data));
    }

    /// Peer reports are routing evidence held in memory: a reopened store
    /// forgets them, unless one of the collection's records reaches the blob.
    #[test]
    fn a_report_is_lost_on_reopen_unless_a_record_reaches_the_blob() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = crate::repo::pile::Pile::open(file.path()).unwrap();
        let c = collection(&mut pile, "reopen");
        let metadata = blob(&mut pile, b"metadata");
        let reported = blob(&mut pile, b"reported by a peer");
        let data = blob(&mut pile, b"unrelated payload");
        commit(&mut pile, c, data, metadata);
        pile.track_held([c]);
        pile.snapshot().unwrap();
        pile.note_held(c, Inline::new(reported));
        assert!(held_set(&pile.snapshot().unwrap(), c).contains(&reported));
        pile.close().unwrap();

        let mut pile = crate::repo::pile::Pile::open(file.path()).unwrap();
        pile.track_held([c]);
        assert!(!held_set(&pile.snapshot().unwrap(), c).contains(&reported));
        let reaching = blob_naming(&mut pile, b"a payload naming it", &[reported]);
        commit(&mut pile, c, reaching, metadata);
        assert!(held_set(&pile.snapshot().unwrap(), c).contains(&reported));
        pile.close().unwrap();

        let mut pile = crate::repo::pile::Pile::open(file.path()).unwrap();
        pile.track_held([c]);
        assert!(
            held_set(&pile.snapshot().unwrap(), c).contains(&reported),
            "a record reaches it now"
        );
        pile.close().unwrap();
    }

    /// Opening, reading, tracking and a one-thread walk spawn no thread at
    /// all; a multi-threaded walk's scan threads and an explicit walker do,
    /// and dropping the walker stops it.
    #[test]
    fn short_lived_opens_start_no_thread() {
        let _guard = walker_guard();
        let spawned = held_threads_spawned();
        assert_eq!(held_walker_threads(), 0);
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut pile = crate::repo::pile::Pile::open(file.path()).unwrap();
        let c = collection(&mut pile, "short-lived");
        let data = blob(&mut pile, b"payload");
        let metadata = blob(&mut pile, b"metadata");
        commit(&mut pile, c, data, metadata);
        pile.snapshot().unwrap();
        pile.track_held([c]);
        pile.snapshot().unwrap();
        pile.walk_held(1).unwrap();
        assert_eq!(held_threads_spawned(), spawned, "nothing was spawned");
        // The counter sees scan threads, not only walkers.
        pile.walk_held(2).unwrap();
        assert_eq!(held_threads_spawned(), spawned + 2);
        let walker = pile.start_held_walker(HeldWalkConfig::default());
        assert_eq!(held_walker_threads(), 1);
        assert_eq!(held_threads_spawned(), spawned + 3);
        drop(walker);
        assert_eq!(held_walker_threads(), 0);
        pile.close().unwrap();
    }

    /// With a walker attached, the existing closure of a newly tracked
    /// collection is left to the background: the first snapshot is handed
    /// out without it and keeps its answer, later ones fill in. Records new
    /// in an observation are published with their closures regardless.
    #[test]
    fn the_start_up_walk_never_gates_and_new_records_publish_with_their_closures() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "background");
        let metadata = blob(&mut store, b"metadata");
        let mut expected = BTreeSet::from([c.raw, metadata]);
        for index in 0..64_u32 {
            let leaf = blob(&mut store, &index.to_be_bytes());
            let data = blob_naming(&mut store, &index.to_le_bytes(), &[leaf]);
            commit(&mut store, c, data, metadata);
            expected.extend([leaf, data]);
        }
        let walker = store.start_held_walker(HeldWalkConfig {
            interval: Duration::from_secs(3600),
            threads: 2,
        });
        store.track_held([c]);
        let first = store.snapshot().unwrap();
        let first_answer = held_set(&first, c);
        assert!(
            first_answer.is_empty(),
            "nothing was scanned before the walk"
        );
        let mut settled = None;
        for _ in 0..2000 {
            let snapshot = store.snapshot().unwrap();
            if held_set(&snapshot, c) == expected {
                settled = Some(snapshot);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let settled = settled.expect("the start-up walk publishes the whole closure");
        assert_ne!(settled.held_generation(), first.held_generation());
        assert_eq!(held_set(&first, c), first_answer);

        let deep = blob(&mut store, b"deep under a new record");
        let middle = blob_naming(&mut store, b"middle", &[deep]);
        let payload = blob_naming(&mut store, b"new payload", &[middle]);
        commit(&mut store, c, payload, metadata);
        let next = store.snapshot().unwrap();
        assert!(held_set(&next, c).is_superset(&BTreeSet::from([payload, middle, deep])));
        drop(walker);
    }

    /// After a restart, peers report their whole held sets while the
    /// start-up walk runs. Those reports wait for the walk: taking a
    /// snapshot reads none of them, and every blob is read once in all.
    #[test]
    fn peer_reports_wait_for_the_start_up_walk_instead_of_reading_in_the_snapshot() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "restart");
        let metadata = blob(&mut store, b"metadata");
        let mut expected = BTreeSet::from([c.raw, metadata]);
        let mut reported = Vec::new();
        for index in 0..32_u32 {
            let leaf = blob(&mut store, &index.to_be_bytes());
            let data = blob_naming(&mut store, &index.to_le_bytes(), &[leaf]);
            commit(&mut store, c, data, metadata);
            expected.extend([leaf, data]);
            reported.extend([leaf, data]);
        }
        // Resident, but reached by no record here: only a report holds it.
        let fetched_leaf = blob(&mut store, b"fetched leaf");
        let fetched = blob_naming(&mut store, b"fetched by an exact read", &[fetched_leaf]);
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold();
        store.track_held([c]);
        let first = store.snapshot().unwrap();
        store.gate.await_walker();
        for handle in reported.iter().chain([&fetched, &[6; 32]]) {
            store.note_held(c, Inline::new(*handle));
        }
        let during = store.snapshot().unwrap();
        assert!(
            store.reads.lock().unwrap().is_empty(),
            "a snapshot read reported blobs while the start-up walk was owed"
        );
        assert!(held_set(&during, c).is_empty(), "the reports wait");
        store.gate.open();
        expected.extend([fetched, fetched_leaf]);
        until(
            &mut store,
            "the walk and the deferred reports",
            |snapshot| held_set(snapshot, c) == expected,
        );
        let counts = store.reads.lock().unwrap().clone();
        assert_eq!(
            counts.keys().copied().collect::<BTreeSet<_>>(),
            expected,
            "an absent report is never read"
        );
        assert!(counts.values().all(|count| *count == 1), "{counts:?}");
        assert!(held_set(&first, c).is_empty());
        drop(walker);
    }

    /// A seed the start-up walk could not read, arriving while that walk
    /// runs, is in no later difference; it is reached once the walk
    /// publishes, not at the next periodic walk.
    #[test]
    fn a_seed_arriving_during_the_start_up_walk_is_reached_when_it_publishes() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "seed during walk");
        let metadata = blob(&mut store, b"metadata");
        let child = blob(&mut store, b"late payload child");
        let late = unresident_naming(b"late payload", &[child]);
        let late_handle = handle_of(&late);
        commit(&mut store, c, late_handle, metadata);
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold();
        store.track_held([c]);
        store.snapshot().unwrap();
        store.gate.await_walker();
        store.put::<UnknownBlob, _>(late).unwrap();
        let arrived = store.snapshot().unwrap();
        assert!(!held_set(&arrived, c).contains(&late_handle));
        store.gate.open();
        until(&mut store, "the late seed and its child", |snapshot| {
            held_set(snapshot, c) == BTreeSet::from([c.raw, metadata, late_handle, child])
        });
        drop(walker);
    }

    /// A proof over a resource whose descriptor routes to C seeds C only
    /// once that descriptor is resident; its arrival alone re-routes it.
    #[test]
    fn a_proof_routed_by_a_later_resource_descriptor_is_seeded_on_its_arrival() {
        use crate::capability::policy::resource_policy;
        use crate::collection::AdmissionPolicy;

        let mut store = Store::default();
        let root = SigningKey::from_bytes(&[44; 32]);
        let c = governed(&mut store, "routed", &root);
        let other = governed(&mut store, "routed elsewhere", &root);
        let delegate = SigningKey::from_bytes(&[45; 32]).verifying_key();
        let definition: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"routed definition"));
        let elsewhere: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"definition routed elsewhere"));
        let direct = AdmissionPolicy::direct(root.verifying_key());
        let resource_facts = entity! {
            resource_collection: c,
            resource_policy*: direct.binding(definition),
        }
        .facts()
        .clone();
        let resource: Blob<SimpleArchive> = resource_facts.clone().to_blob();
        let other_facts = entity! {
            resource_collection: other,
            resource_policy*: direct.binding(elsewhere),
        }
        .facts()
        .clone();
        let other_resource: Blob<SimpleArchive> = other_facts.clone().to_blob();
        store.track_held([c]);
        store.snapshot().unwrap();
        for (resource, definition) in [
            (resource.get_handle(), definition),
            (other_resource.get_handle(), elsewhere),
        ] {
            store
                .insert_proof(CapabilityProof::new(
                    CapabilityResource::from(resource),
                    &root,
                    definition,
                    delegate,
                ))
                .unwrap();
        }
        let unrouted = store.snapshot().unwrap();
        assert!(!held_set(&unrouted, c).contains(&definition.raw));
        store.put::<SimpleArchive, _>(resource_facts).unwrap();
        store.put::<SimpleArchive, _>(other_facts).unwrap();
        let routed = store.snapshot().unwrap();
        let held = held_set(&routed, c);
        assert!(held.contains(&definition.raw));
        assert!(
            !held.contains(&elsewhere.raw),
            "that resource routes to another collection"
        );
    }

    /// A collection is settled only from a complete selection of its
    /// records: when the store cannot answer, it stays unsettled (absent
    /// from the view, never short in it) and is selected again.
    #[test]
    fn a_failed_selection_leaves_a_collection_unsettled_rather_than_short() {
        let mut store = Store::default();
        let c = collection(&mut store, "selection fails");
        let metadata = blob(&mut store, b"metadata");
        let data = blob(&mut store, b"payload");
        commit(&mut store, c, data, metadata);
        store.faults.select.store(true, Ordering::SeqCst);
        store.track_held([c]);
        let failed = store.snapshot().unwrap();
        assert_eq!(failed.held(c), None);
        store.faults.select.store(false, Ordering::SeqCst);
        let settled = store.snapshot().unwrap();
        assert_eq!(
            held_set(&settled, c),
            BTreeSet::from([c.raw, data, metadata])
        );
    }

    /// A failed read of the proofs is retried at the next snapshot, even
    /// when the store has not changed since.
    #[test]
    fn a_failed_proof_read_is_retried_at_the_next_snapshot() {
        let mut store = Store::default();
        let root = SigningKey::from_bytes(&[46; 32]);
        let c = governed(&mut store, "proofs fail", &root);
        let definition: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"definition"));
        store.track_held([c]);
        store.snapshot().unwrap();
        store.faults.proofs.store(true, Ordering::SeqCst);
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(c),
                &root,
                definition,
                SigningKey::from_bytes(&[47; 32]).verifying_key(),
            ))
            .unwrap();
        let failed = store.snapshot().unwrap();
        assert!(!held_set(&failed, c).contains(&definition.raw));
        store.faults.proofs.store(false, Ordering::SeqCst);
        let retried = store.snapshot().unwrap();
        assert_eq!(retried.changes_since(&failed), StoreChanges::NONE);
        assert!(held_set(&retried, c).contains(&definition.raw));
    }

    /// Blobs no seed, report or held blob reaches cost the index no read,
    /// even when they name held blobs.
    #[test]
    fn unrelated_arrivals_read_nothing() {
        let mut store = Store::default();
        let c = collection(&mut store, "unrelated");
        let metadata = blob(&mut store, b"metadata");
        let child = blob(&mut store, b"child");
        let data = blob_naming(&mut store, b"data", &[child]);
        commit(&mut store, c, data, metadata);
        store.track_held([c]);
        store.snapshot().unwrap();
        let before = store.reads.lock().unwrap().clone();
        for index in 0..16_u8 {
            blob_naming(&mut store, &[b'u', index], &[data, child]);
            blob(&mut store, &[b'v', index]);
            store.snapshot().unwrap();
        }
        assert_eq!(*store.reads.lock().unwrap(), before);
    }

    /// The walker's own timer, with no request and no report, catches a
    /// nested late child within one interval plus one walk.
    #[test]
    fn the_periodic_walk_catches_a_nested_late_child_nobody_reports() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "periodic");
        let metadata = blob(&mut store, b"metadata");
        let h_bytes = unresident_naming(b"periodic late child", &[]);
        let h = handle_of(&h_bytes);
        let p = blob_naming(&mut store, b"periodic intermediate", &[h]);
        let r = blob_naming(&mut store, b"periodic root", &[p]);
        commit(&mut store, c, r, metadata);
        let interval = Duration::from_millis(200);
        let walker = store.start_held_walker(walker_config(interval));
        store.track_held([c]);
        // The start-up walk read P while H was absent.
        until(&mut store, "the start-up walk", |snapshot| {
            held_set(snapshot, c).contains(&p)
        });
        store.put::<UnknownBlob, _>(h_bytes).unwrap();
        let arrived = Instant::now();
        until(&mut store, "a periodic walk", |snapshot| {
            held_set(snapshot, c).contains(&h)
        });
        // Interval plus one (tiny) walk plus scheduling; generous for a
        // loaded test host.
        assert!(arrived.elapsed() < interval + Duration::from_secs(20));
        drop(walker);
    }

    /// Tracking a new collection walks that collection, not every tracked
    /// one again.
    #[test]
    fn a_newly_tracked_collection_is_walked_alone() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let mut sets = Vec::new();
        for name in ["walked first", "walked second"] {
            let c = collection(&mut store, name);
            let metadata = blob(&mut store, format!("{name} metadata").as_bytes());
            let leaf = blob(&mut store, format!("{name} leaf").as_bytes());
            let data = blob_naming(&mut store, name.as_bytes(), &[leaf]);
            commit(&mut store, c, data, metadata);
            sets.push((c, BTreeSet::from([c.raw, metadata, leaf, data])));
        }
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        for (c, expected) in &sets {
            store.track_held([*c]);
            until(&mut store, "the start-up walk", |snapshot| {
                snapshot.held(*c).is_some() && held_set(snapshot, *c) == *expected
            });
        }
        let counts = store.reads.lock().unwrap().clone();
        for handle in &sets[0].1 {
            assert_eq!(
                counts[handle], 1,
                "the first collection was not walked again"
            );
        }
        drop(walker);
    }

    /// A reset makes a walk in progress stale; it stops after the blob it is
    /// reading instead of running to its end.
    #[test]
    fn a_reset_stops_the_walk_it_made_stale() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "stale walk");
        let metadata = blob(&mut store, b"metadata");
        let mut expected = BTreeSet::from([c.raw, metadata]);
        for index in 0..32_u32 {
            let leaf = blob(&mut store, &index.to_be_bytes());
            let data = blob_naming(&mut store, &index.to_le_bytes(), &[leaf]);
            commit(&mut store, c, data, metadata);
            expected.extend([leaf, data]);
        }
        let forgotten = blob(&mut store, b"forgotten");
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold();
        store.track_held([c]);
        let before = store.snapshot().unwrap();
        store.gate.await_walker();
        let kept: Vec<_> = before
            .inner()
            .blobs()
            .map(|info| info.unwrap().handle)
            .filter(|handle| handle.raw != forgotten)
            .collect();
        (*store).inner.blobs.keep(kept);
        store.snapshot().unwrap();
        store.gate.open();
        until(&mut store, "the walk after the reset", |snapshot| {
            held_set(snapshot, c) == expected
        });
        let total: usize = store.reads.lock().unwrap().values().sum();
        assert!(
            total <= expected.len() + 1,
            "{total} reads for {} blobs",
            expected.len()
        );
        drop(walker);
    }

    /// The start-up walk has scanned A but not yet A's resident child B. A
    /// new foundation P naming A is published with P's whole closure, B
    /// included, and no snapshot holds A without B.
    #[test]
    fn a_new_foundation_over_a_blob_the_walk_has_not_finished_holds_its_whole_closure() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "closure during walk");
        let metadata = blob(&mut store, b"metadata");
        let b = blob(&mut store, b"child the walk reads last");
        let a = blob_naming(&mut store, b"scanned before its child", &[b]);
        let root = blob_naming(&mut store, b"walked root", &[a]);
        commit(&mut store, c, root, metadata);
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold_at(b);
        store.track_held([c]);
        store.snapshot().unwrap();
        store.gate.await_walker();
        let during = store.snapshot().unwrap();
        let p = blob_naming(&mut store, b"new foundation over A", &[a]);
        commit(&mut store, c, p, metadata);
        let after = store.snapshot().unwrap();
        let held = held_set(&after, c);
        assert!(held.contains(&p), "a new record publishes with its closure");
        assert!(
            held.contains(&b),
            "P's closure was published without B, the resident child of A"
        );
        assert_closed(&after, c);
        assert_closed(&during, c);
        store.gate.open();
        until(&mut store, "the start-up walk", |snapshot| {
            held_set(snapshot, c) == BTreeSet::from([c.raw, metadata, root, a, b, p])
        });
        drop(walker);
    }

    /// A report that waited for the start-up walk and that no record here
    /// reaches is read by the walker, never by whoever takes the next
    /// snapshot once the walk is done.
    #[test]
    fn deferred_reports_are_read_by_the_walker_and_never_in_a_snapshot() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "deferred walk");
        let metadata = blob(&mut store, b"metadata");
        let data = blob(&mut store, b"payload");
        commit(&mut store, c, data, metadata);
        // Resident, reached by no record here: only the report holds it.
        let leaf = blob(&mut store, b"fetched leaf");
        let middle = blob_naming(&mut store, b"fetched middle", &[leaf]);
        let fetched = blob_naming(&mut store, b"fetched by an exact read", &[middle]);
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold();
        store.track_held([c]);
        store.snapshot().unwrap();
        store.gate.await_walker();
        store.note_held(c, Inline::new(fetched));
        store.snapshot().unwrap();
        store.gate.open();
        let expected = BTreeSet::from([c.raw, metadata, data, fetched, middle, leaf]);
        until(&mut store, "the walk and the deferred report", |snapshot| {
            held_set(snapshot, c) == expected
        });
        for _ in 0..3 {
            store.snapshot().unwrap();
        }
        let foreground = store.foreground.lock().unwrap().clone();
        assert!(
            foreground.is_empty(),
            "a snapshot read {} blobs the walker owed",
            foreground.len()
        );
        let counts = store.reads.lock().unwrap().clone();
        assert!(counts.values().all(|count| *count == 1), "{counts:?}");
        drop(walker);
    }

    /// A proof seeds C only when C's authorization evidence keeps it: over C
    /// itself from one of C's policy roots, or over a subordinate resource
    /// whose own descriptor entity both routes to C and declares the root.
    /// A valid proof irrelevant to C seeds nothing.
    ///
    /// Whether the resource R is itself tracked changes nothing: a proof over
    /// R still counts for C when R's descriptor routes to C.
    #[test]
    fn only_proofs_the_collections_authorization_keeps_are_seeds() {
        for track_resource in [false, true] {
            proofs_the_authorization_keeps(track_resource);
        }
    }

    fn proofs_the_authorization_keeps(track_resource: bool) {
        use crate::capability::policy::resource_policy;
        use crate::collection::{AdmissionPolicy, CollectionPolicy, CollectionStoreExt};

        let collection_root = SigningKey::from_bytes(&[50; 32]);
        let resource_root = SigningKey::from_bytes(&[51; 32]);
        let stranger = SigningKey::from_bytes(&[52; 32]);
        let subject = SigningKey::from_bytes(&[53; 32]).verifying_key();
        let mut store = Store::default();
        let direct = AdmissionPolicy::direct(collection_root.verifying_key());
        let c = store
            .collection("audited", CollectionPolicy::new(direct.clone(), direct))
            .unwrap()
            .handle();
        let mut definition = |name: &str| -> Inline<Handle<SimpleArchive>> {
            Inline::new(blob(&mut store, name.as_bytes()))
        };
        let exact = definition("definition over C");
        let wrong_root = definition("definition from a stranger");
        let routed = definition("definition over a routed resource");
        let split = definition("definition over a split route");
        let foreign_root = definition("definition from C's root over R");
        let resource_policy_of =
            |definition| AdmissionPolicy::direct(resource_root.verifying_key()).binding(definition);
        let resource = store
            .put::<SimpleArchive, _>(
                entity! {
                    resource_collection: c,
                    resource_policy*: resource_policy_of(routed),
                }
                .facts()
                .clone(),
            )
            .unwrap();
        let split_resource = store
            .put::<SimpleArchive, _>(
                (entity! { resource_collection: c }
                    + entity! { resource_policy*: resource_policy_of(split) })
                .facts()
                .clone(),
            )
            .unwrap();
        for (resource, root, definition) in [
            (c, &collection_root, exact),
            (c, &stranger, wrong_root),
            (resource, &resource_root, routed),
            (split_resource, &resource_root, split),
            (resource, &collection_root, foreign_root),
        ] {
            store
                .insert_proof(CapabilityProof::new(
                    CapabilityResource::from(resource),
                    root,
                    definition,
                    subject,
                ))
                .unwrap();
        }
        if track_resource {
            store.track_held([c, resource]);
        } else {
            store.track_held([c]);
        }
        let held = held_set(&store.snapshot().unwrap(), c);
        assert!(held.contains(&exact.raw));
        assert!(
            held.contains(&routed.raw),
            "a routed proof seeds C (resource tracked: {track_resource})"
        );
        for irrelevant in [wrong_root, split, foreign_root] {
            assert!(
                !held.contains(&irrelevant.raw),
                "a proof C's authorization rejects seeded C"
            );
        }
    }

    /// Two views that differ only in what one collection holds are unequal:
    /// a PATCH compares keys only, so the held sets are compared one by one.
    #[test]
    fn views_differing_only_in_one_held_set_are_unequal() {
        let c = [1u8; 32];
        let view = |blob: Raw| {
            let mut held = HeldBlobs::new();
            held.insert(&Entry::new(&blob));
            let mut sets = HeldSets::new();
            sets.replace(&Entry::with_value(&c, held));
            HeldView {
                generation: 1,
                sets,
            }
        };
        assert_eq!(view([2; 32]), view([2; 32]));
        assert_ne!(view([2; 32]), view([3; 32]));
    }

    /// While the start-up walk still owes A and M, a new COMMIT that repeats
    /// A with new metadata M2 is published with A's closure too, not only
    /// with M2's.
    #[test]
    fn a_new_commit_repeating_owed_seeds_publishes_their_closure() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "repeated seeds");
        let metadata = blob(&mut store, b"metadata");
        let leaf = blob(&mut store, b"under A");
        let a = blob_naming(&mut store, b"A", &[leaf]);
        commit(&mut store, c, a, metadata);
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold();
        store.track_held([c]);
        store.snapshot().unwrap();
        store.gate.await_walker();
        let fresh_metadata = blob(&mut store, b"new metadata M2");
        commit(&mut store, c, a, fresh_metadata);
        let after = store.snapshot().unwrap();
        let held = held_set(&after, c);
        assert!(held.contains(&fresh_metadata));
        assert!(
            held.contains(&a) && held.contains(&leaf),
            "a new COMMIT repeating A was published without A's closure"
        );
        assert_closed(&after, c);
        store.gate.open();
        until(&mut store, "the start-up walk", |snapshot| {
            held_set(snapshot, c) == BTreeSet::from([c.raw, metadata, fresh_metadata, a, leaf])
        });
        drop(walker);
    }

    /// A report noted while the start-up walk runs, but not yet moved by an
    /// observation when the walk ends, is still read by the walker.
    #[test]
    fn a_report_noted_as_the_start_up_walk_ends_is_read_by_the_walker() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c = collection(&mut store, "report at the end");
        let metadata = blob(&mut store, b"metadata");
        let data = blob(&mut store, b"payload");
        commit(&mut store, c, data, metadata);
        let leaf = blob(&mut store, b"late report leaf");
        let middle = blob_naming(&mut store, b"late report middle", &[leaf]);
        let fetched = blob_naming(&mut store, b"late report root", &[middle]);
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold();
        store.track_held([c]);
        store.snapshot().unwrap();
        store.gate.await_walker();
        // No observation between the report and the end of the walk.
        store.note_held(c, Inline::new(fetched));
        store.gate.open();
        let start = Instant::now();
        while [c.raw, metadata, data]
            .iter()
            .any(|handle| reads(&store, handle) == 0)
        {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "the walk never ran"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        std::thread::sleep(Duration::from_millis(300));
        let expected = BTreeSet::from([c.raw, metadata, data, fetched, middle, leaf]);
        until(&mut store, "the report", |snapshot| {
            held_set(snapshot, c) == expected
        });
        let foreground = store.foreground.lock().unwrap().clone();
        assert!(
            foreground.is_empty(),
            "a snapshot read {} blobs of a report the walk owed",
            foreground.len()
        );
        drop(walker);
    }

    /// One walk covers C1 and C2. It finds C1's payload R absent; R then
    /// arrives and is reported for C2, where no record names it. The round
    /// that walks C2's reports reads R against the newer observation instead
    /// of reusing the older one's negative answer.
    #[test]
    fn a_report_round_rereads_a_blob_the_older_snapshot_lacked() {
        let _guard = walker_guard();
        let mut store = Store::default();
        let c1 = collection(&mut store, "negative first");
        let c2 = collection(&mut store, "reported second");
        let metadata = blob(&mut store, b"metadata");
        let r_bytes = unresident_naming(b"absent at the walk's start", &[]);
        let r = handle_of(&r_bytes);
        commit(&mut store, c1, r, metadata);
        let leaf = blob(&mut store, b"second leaf");
        let data = blob_naming(&mut store, b"second payload", &[leaf]);
        commit(&mut store, c2, data, metadata);
        let walker = store.start_held_walker(walker_config(Duration::from_secs(3600)));
        let _opener = store.gate.hold_at(leaf);
        store.track_held([c1, c2]);
        store.snapshot().unwrap();
        store.gate.await_walker();
        store.put::<UnknownBlob, _>(r_bytes).unwrap();
        store.snapshot().unwrap();
        store.note_held(c2, Inline::new(r));
        store.snapshot().unwrap();
        store.gate.open();
        until(&mut store, "C2 to hold the reported R", |snapshot| {
            held_set(snapshot, c2).contains(&r)
        });
        drop(walker);
    }

    /// A walk rescans a held blob A and learns a child B that arrived after
    /// A was first scanned. No observation holds A while the edge cache
    /// names a child of A that is not held: a closure stopping at A must not
    /// miss a child the cache knows.
    #[test]
    fn a_held_blob_is_closed_under_the_edges_a_walk_learns() {
        let _guard = walker_guard();
        let mut store = Counting::default();
        let c = collection(&mut store, "edge growth");
        let metadata = blob(&mut store, b"metadata");
        let b_bytes = unresident_naming(b"late child B", &[]);
        let b = handle_of(&b_bytes);
        let a = blob_naming(&mut store, b"A names B", &[b]);
        let root = blob_naming(&mut store, b"root names A", &[a]);
        commit(&mut store, c, root, metadata);
        let index: Arc<HeldIndex<CountingSnapshot>> = Arc::new(HeldIndex::default());
        index.track([c]);
        index.observe(&store.snapshot().unwrap());
        store.put::<UnknownBlob, _>(b_bytes).unwrap();
        let now = store.snapshot().unwrap();
        index.observe(&now);
        let closed = |index: &HeldIndex<CountingSnapshot>| {
            let state = index.lock();
            let held = state.held.get(&c.raw).cloned().unwrap_or_default();
            for parent in held.iter_ordered() {
                for child in related(&state.edges, parent) {
                    assert!(
                        held.has_prefix(&child),
                        "a held blob has a cached child that is not held"
                    );
                }
            }
        };
        let _opener = store.gate.hold_at(b);
        let walk = std::thread::Builder::new()
            .name("held-blob-walk".into())
            .spawn({
                let index = Arc::clone(&index);
                move || index.walk(&now, 1, None)
            })
            .unwrap();
        store.gate.await_walker();
        let p = blob_naming(&mut store, b"new foundation over A", &[a]);
        commit(&mut store, c, p, metadata);
        index.observe(&store.snapshot().unwrap());
        closed(&index);
        store.gate.open();
        walk.join().unwrap();
        let view = index.observe(&store.snapshot().unwrap());
        closed(&index);
        let held = view.held(c).unwrap();
        assert!(held.has_prefix(&b) && held.has_prefix(&p));
    }

    #[test]
    fn the_foundations_selector_matches_commits_and_derives_only() {
        let mut store = crate::repo::memoryrepo::MemoryRepo::default();
        let c: CollectionHandle = Inline::new([1; 32]);
        let commit = CollectionRecord::Commit(CollectionCommit::sign(
            &key(),
            c,
            Inline::new([2; 32]),
            Inline::new([3; 32]),
        ));
        let merge = CollectionRecord::Merge(
            CollectionMerge::sign(
                &key(),
                c,
                [Inline::new([2; 32]), Inline::new([4; 32])],
                Inline::new([5; 32]),
            )
            .unwrap(),
        );
        let derive = CollectionRecord::Derive(CollectionDerive::sign(
            &key(),
            c,
            SourceLocator::of([6; 32]),
            Inline::new([7; 32]),
        ));
        for record in [commit, merge, derive] {
            store.insert(record).unwrap();
        }
        let selected: BTreeSet<_> = store
            .snapshot()
            .unwrap()
            .select_records(&BTreeSet::from([CollectionRecordSelector::Foundations(c)]))
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(selected, BTreeSet::from([commit, derive]));
    }
}
