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
//! the sync host applies: over C from one of C's policy roots; a proof whose
//! collection descriptor arrives later is judged on its arrival). A proof
//! over any other resource, and a valid proof irrelevant to C, seeds
//! nothing. A MERGE never replicates, so its result is never a seed,
//! and a blob no record names (an attachment, a scratch archive) is never
//! one either.
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
//! resident after its parent was scanned is not an edge. Two things catch it:
//!
//! - it is itself a seed (a record names it): seeds are scanned on arrival;
//! - a peer holding it advertises it in C ([`HeldStore::note_held`]): a
//!   resident blob a peer reports in C joins `held(C)` however it arrived.
//!   This is routing evidence, kept in memory only; a reopened store forgets
//!   it unless one of C's own records reaches the blob by then.
//!
//! Otherwise it stays out of `held(C)` until the index resets or the store is
//! reopened, though it stays readable by its hash. Sync states this as a
//! limitation (design 2.9, Astra's R2): between two neighbours that replicate
//! C in full, the one holding the late child through a seed or a report
//! reports it to the other.
//!
//! # Snapshots
//!
//! Every snapshot carries the held sets as they stood when it was taken, and
//! they never change afterwards. A published held set is a collection's
//! whole first closure plus what the collection gained since; it is never a
//! part of one.
//!
//! A held set is closed under the edge cache for readable children: a blob
//! joins only once every child the cache names for it has joined. So every
//! closure computed later stops at a held blob without missing anything
//! readable the cache knows below it, and a closure computation can pause
//! between any two steps without leaving the set open. A blob that cannot be
//! read -- absent, or resident and failing to read -- is unknown on every
//! path: nothing above it joins. A seed is read again when its bytes arrive,
//! a reported blob when a peer reports it again.
//!
//! A tracked collection is *settled* once its seeds are selected. Until its
//! first closure (since tracking began, or since a reset) is whole, it is
//! *building*; afterwards it is *built*. Only a built collection's held set
//! is published: a building one's is unknown, as an unsettled one's is, and
//! [`HeldRead::held`] answers `None` for both.
//!
//! Taking a store snapshot reads no blob for the held sets. (That is the
//! store's own observation; what a consumer builds on a snapshot, such as a
//! sync host's serving view, may read blobs of its own.) It queues what
//! arrived since the previous one -- every seed of a new record (one another record already
//! named included), seeds whose bytes arrived, memberships peers reported --
//! selects the seeds of newly tracked collections from their records, and
//! notes whose proofs are to be judged. The [`HeldWork`] of the store's
//! driver ([`HeldStore::drive_held`]) does the reading, in steps against
//! the latest observed snapshot, checking its time budget between steps:
//! a blob read or a judgement of proofs runs to its end first, so the budget
//! is cooperative, not a hard slice. It judges proofs, which reads the
//! collection descriptors they name, and computes closures, which reads
//! every blob they reach once. It extends built collections first, and
//! building collections take turns, so a small one is published without
//! waiting for a large one's whole first closure. A building collection is
//! published once its first closure is whole and its proofs are judged; a
//! built collection's set grows as the driver reaches what arrived, so a
//! snapshot's held sets can lag the records in that snapshot. A changed
//! [`HeldRead::held_generation`] says the sets grew although the store may
//! not have changed. The driver never holds the index across a read, so
//! taking a snapshot waits for at most a few in-memory updates, never for a
//! read. Without a driver nothing is read and nothing grows: a tracked
//! collection stays unknown until one runs. Nothing here starts a thread: the
//! driver's thread is its caller's.
//!
//! A snapshot that lost a blob its predecessor had (a store that forgets
//! blobs) resets the index: the edges are forgotten and every collection is
//! recomputed as if newly tracked.
//!
//! Nothing is computed before the store has been observed whole once. A
//! step of a climb ([`Covered::snapshot_step`](super::covered::Covered::snapshot_step))
//! observes a prefix, where a parent can be resident before its child; a
//! parent scanned there would make the child a late child. Until a step
//! reaches the end of the store, or a whole snapshot is taken, every held set
//! is unknown.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use anybytes::Bytes;

use crate::blob::encodings::simplearchive::SimpleArchive;
use crate::blob::encodings::UnknownBlob;
use crate::inline::encodings::hash::Handle;
use crate::inline::Inline;
use crate::patch::{Blake3Merkle, Entry, IdentitySchema, PATCH};
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
    /// Every blob `collection` holds in this observation: its whole first
    /// closure plus what it gained since. `None` when the store does not
    /// track it, has not yet been observed whole, has not yet been able to
    /// select its seeds, or has not yet computed its first closure: unknown,
    /// not empty. Absence from the set is not evidence that a blob is
    /// missing.
    fn held(&self, collection: CollectionHandle) -> Option<HeldBlobs>;

    /// Differs between two observations of one store whenever their held sets
    /// may differ, including when only a peer's report added to them.
    fn held_generation(&self) -> u64;
}

/// Tracking and routing evidence for a store's held sets.
pub trait HeldStore {
    /// Keep held sets for `collections` from the next snapshot on. Only a
    /// driver ([`Self::drive_held`]) computes them: in a store nobody drives
    /// they stay unknown.
    fn track_held(&mut self, collections: impl IntoIterator<Item = CollectionHandle>);

    /// A peer reported `handle` in its held set of `collection`. If the blob
    /// is resident when the next snapshot is taken, the driver adds it and
    /// everything it reaches to `held(collection)`; a report of a blob that
    /// is not resident is dropped. Kept in memory only.
    fn note_held(&mut self, collection: CollectionHandle, handle: Inline<Handle<UnknownBlob>>);

    /// The work that computes the held sets: every blob read and every proof
    /// judgement, off the snapshot path. It publishes a collection's held set
    /// once its first closure is whole, and extends published sets as it
    /// reaches what arrived. A store snapshot reads no blob for the held sets
    /// and never waits for a read the work makes. Dropping the work leaves what is queued to
    /// the next driver; until one runs, nothing grows.
    ///
    /// One driver at a time: `None` while an earlier work is alive.
    fn drive_held(&mut self) -> Option<HeldWork>;
}

/// The reads a store's snapshots queue ([`HeldStore::drive_held`]), the
/// only driver of its store while it lives. It refers to the store's index
/// weakly, so it keeps nothing alive; dropping it leaves the queued work for
/// the next driver.
pub struct HeldWork(Weak<dyn Drive>);

/// What [`HeldWork`] asks of the index it drives.
trait Drive: Send + Sync {
    /// Compute for about `budget`; whether work remains.
    fn advance(&self, budget: Duration) -> bool;
    /// Return once work is queued, or after `timeout`.
    fn wait(&self, timeout: Duration);
    /// The work is gone; another may drive the index.
    fn undrive(&self);
}

impl HeldWork {
    /// Compute for about `budget`, or, when nothing is queued, wait up to
    /// `idle` for work. `false` once the store is gone. The budget is checked
    /// between steps only: a blob read or a judgement of proofs in progress
    /// finishes first; the index is not held meanwhile.
    pub fn step(&mut self, budget: Duration, idle: Duration) -> bool {
        let Some(index) = self.0.upgrade() else {
            return false;
        };
        if !index.advance(budget) {
            index.wait(idle);
        }
        true
    }

    /// Compute until nothing queued can run, without waiting for more: every
    /// closure and proof judgement the snapshots so far queued. `false` once
    /// the store is gone. A short-lived owner of a store calls this after a
    /// snapshot, then takes another to see the result.
    ///
    /// Idle is not complete. A judgement whose proofs could not be read
    /// waits for the next observation, a collection whose records could not
    /// be selected is not settled, and a blob that is absent or unreadable
    /// stays out of the set with everything above it.
    pub fn run_until_idle(&mut self) -> bool {
        let Some(index) = self.0.upgrade() else {
            return false;
        };
        while index.advance(Duration::MAX) {}
        true
    }
}

impl Drop for HeldWork {
    fn drop(&mut self) {
        if let Some(index) = self.0.upgrade() {
            index.undrive();
        }
    }
}

impl std::fmt::Debug for HeldWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldWork")
            .field("store", &(self.0.strong_count() > 0))
            .finish()
    }
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

/// Everything the index keeps across observations. A tracked collection is
/// *settled* once its seeds are selected: then it has a held set, until a
/// reset makes it unsettled again.
#[derive(Clone)]
struct State<T> {
    /// The collections held sets are kept for.
    tracked: Handles,
    /// The held set of every settled collection.
    held: HeldSets,
    /// `collection || blob`: every blob C's records and proofs name,
    /// resident or not.
    seeds: Pairs,
    /// `collection || blob`: resident blobs peers reported in C that were not
    /// already held.
    routes: Pairs,
    /// Every blob scanned since the last reset, whether it has children or
    /// not.
    scanned: Handles,
    /// `parent || child`: each scanned blob and every child resident when it
    /// was scanned.
    edges: Pairs,
    /// `blob || collection`: seeds whose bytes were not readable yet, and the
    /// collections waiting for them.
    pending: Pairs,
    /// Collection descriptors that were not resident when proofs were
    /// judged; the arrival of one judges its collection's proofs again.
    unrouted: Handles,
    /// Settled collections whose proofs the driver is to judge.
    unjudged: Handles,
    /// The collections the driver judges with the state unlocked: kept here
    /// so that a reset drops them and a clone judges them again.
    judging: Option<Handles>,
    /// Collections whose proofs could not be read: judged again after the
    /// next observation.
    misjudged: Handles,
    /// `collection || blob`: peer reports not resolved yet.
    candidates: Pairs,
    /// Closure computations not finished yet. The driver runs a built
    /// collection's first and lets building collections take turns.
    jobs: VecDeque<Job>,
    /// Settled collections whose first closure or proof judgement is not
    /// done yet: kept here, published only once built.
    building: Handles,
    /// A driver exists ([`HeldStore::drive_held`]).
    driven: bool,
    /// The driver's job while it reads a blob with the state unlocked, and
    /// the blob: kept here so that a reset drops it and a clone keeps it.
    active: Option<(Job, Raw)>,
    /// An observation of the whole store has been seen. Until then a step
    /// of a climb is only a prefix, in which a parent can precede its child,
    /// so nothing is settled or fed: every held set stays unknown.
    replayed: bool,
    /// The last observation fed in.
    fed: Option<T>,
    /// Counts observations fed in: a read made against an older one is
    /// reconciled with what arrived since.
    fed_count: u64,
    generation: u64,
    view: Arc<HeldView>,
}

/// One closure computation: roots to add to one collection's held set and
/// the depth-first scratch following them, kept so that the computation can
/// pause between any two steps.
#[derive(Clone)]
struct Job {
    collection: CollectionHandle,
    /// Depth first, a blob's children before it: a blob still to enter, or
    /// one entered with its children, decided once they are.
    stack: Vec<(Raw, Option<Vec<Raw>>)>,
    entered: HashSet<Raw>,
    /// Blobs that cannot be read, and every blob above one.
    unknown: HashSet<Raw>,
}

impl Job {
    fn new(collection: CollectionHandle, roots: impl IntoIterator<Item = Raw>) -> Self {
        Self {
            collection,
            stack: roots.into_iter().map(|root| (root, None)).collect(),
            entered: HashSet::new(),
            unknown: HashSet::new(),
        }
    }

    /// The job as it was before `handle` was entered, so it is read again.
    fn reread(mut self, handle: Raw) -> Self {
        self.entered.remove(&handle);
        self.stack.push((handle, None));
        self
    }

    /// Enter `handle`: its children not `held` are decided before it.
    fn descend(&mut self, handle: Raw, children: Vec<Raw>, held: Option<&HeldBlobs>) {
        let unheld: Vec<(Raw, Option<Vec<Raw>>)> = children
            .iter()
            .filter(|child| !held.is_some_and(|held| held.has_prefix(*child)))
            .map(|child| (*child, None))
            .collect();
        // Popped after every child below it has been decided.
        self.stack.push((handle, Some(children)));
        self.stack.extend(unheld);
    }
}

/// Where [`State::follow`] stopped.
enum Step {
    /// The job is done.
    Done,
    /// The job needs this blob read, scanned and fed back through
    /// [`State::read`].
    Read(Raw),
    /// The job was told to pause.
    Paused,
}

/// The shared held-blob index of one store. Its own lock: holding it never
/// blocks a coverage read. A clone is an independent copy, driven by nobody.
pub(crate) struct HeldIndex<T> {
    state: Mutex<State<T>>,
    /// Notified when jobs are left for the driver.
    queued: Condvar,
    /// Lockers other than the driver waiting for the state: the driver
    /// pauses for them.
    waiting: AtomicUsize,
}

impl<T> Default for HeldIndex<T> {
    fn default() -> Self {
        Self::with_state(State {
            tracked: Handles::new(),
            held: HeldSets::new(),
            seeds: Pairs::new(),
            routes: Pairs::new(),
            scanned: Handles::new(),
            edges: Pairs::new(),
            pending: Pairs::new(),
            unrouted: Handles::new(),
            unjudged: Handles::new(),
            judging: None,
            misjudged: Handles::new(),
            candidates: Pairs::new(),
            jobs: VecDeque::new(),
            building: Handles::new(),
            driven: false,
            active: None,
            replayed: false,
            fed: None,
            fed_count: 0,
            generation: 0,
            view: Arc::new(HeldView::default()),
        })
    }
}

impl<T: Clone> Clone for HeldIndex<T> {
    fn clone(&self) -> Self {
        let mut state = self.lock().clone();
        // The driver drives the original; the copy keeps its queue, the job
        // and the judgement the driver is reading for included, for a driver
        // of its own.
        state.driven = false;
        if let Some((job, handle)) = state.active.take() {
            state.jobs.push_front(job.reread(handle));
        }
        if let Some(judging) = state.judging.take() {
            state.unjudged.union(judging);
        }
        Self::with_state(state)
    }
}

impl<T> HeldIndex<T> {
    fn with_state(state: State<T>) -> Self {
        Self {
            state: Mutex::new(state),
            queued: Condvar::new(),
            waiting: AtomicUsize::new(0),
        }
    }

    /// The state, for anyone but the driver, which pauses for this.
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let state = self.state.lock().expect("held-blob index is not poisoned");
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        state
    }

    /// The state, for the driver.
    fn lock_driver(&self) -> MutexGuard<'_, State<T>> {
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

    /// From now on a driver computes the held sets; `false` if one already
    /// does.
    pub(crate) fn drive(&self) -> bool {
        let mut state = self.lock();
        !std::mem::replace(&mut state.driven, true)
    }
}

/// The blobs a replicated record names; `None` for a MERGE or a MAP, which
/// never replicate: a merge result or an attachment is the signing host's own
/// computation, never a seed.
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
        CollectionRecord::Merge(_) | CollectionRecord::Map(_) => None,
    }
}

/// Seeds contributed by proofs, and descriptors not resident yet.
struct ProofSeeds {
    seeds: Vec<(CollectionHandle, Raw)>,
    /// Collection descriptors that are not resident: their arrival lets a
    /// proof over that collection be judged. One that is resident and cannot
    /// be read judges nothing, and nothing arrives to judge it again.
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
        // Only the proof's own resource can keep it, when that resource is a
        // tracked collection; the predicate decides.
        let collection: CollectionHandle = Inline::new(proof.resource().into_bytes());
        if !collections.contains(&collection) {
            continue;
        }
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
        if validate_proof_evidence(collection, descriptor, &proof).is_ok() {
            for handle in proof.blob_references() {
                found.seeds.push((collection, handle.raw));
            }
        }
    }
    Ok(found)
}

/// One blob's scan: its resident children and the edges to them, ready to
/// join the cache. Built without the index state.
struct Scan {
    children: Vec<Raw>,
    edges: Pairs,
}

/// Read one blob and list its resident children, or `None` if it is not
/// readable. Children are probed in the store's index without reading them.
fn scan<T: HeldSource>(snapshot: &T, handle: &Raw) -> Option<Scan> {
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
    let mut edges = Pairs::new();
    for child in &children {
        edges.insert(&Entry::new(&pair(handle, child)));
    }
    Some(Scan { children, edges })
}

impl<T> State<T> {
    /// Forget every edge and held set; every collection is recomputed as if
    /// newly tracked. Seeds and peer reports are kept as roots.
    fn reset(&mut self) {
        self.scanned = Handles::new();
        self.edges = Pairs::new();
        self.pending = Pairs::new();
        self.held = HeldSets::new();
        self.jobs = VecDeque::new();
        self.building = Handles::new();
        self.active = None;
        self.unjudged = Handles::new();
        self.judging = None;
        self.misjudged = Handles::new();
    }

    /// Hand out the held sets of every built collection. A building
    /// collection's set is unknown until its first closure is whole.
    fn publish_view(&mut self) {
        let mut sets = self.held.clone();
        for building in self.building.iter() {
            sets.remove(building);
        }
        self.generation += 1;
        self.view = Arc::new(HeldView {
            generation: self.generation,
            sets,
        });
    }

    /// Record one scan: the blob, and an edge to each resident child.
    fn record_scan(&mut self, handle: Raw, edges: Pairs) {
        self.scanned.insert(&Entry::new(&handle));
        self.edges.union(edges);
    }

    /// Queue everything reachable from `roots` for `collection`'s held set,
    /// in the last job if that one is the collection's and has entered
    /// nothing yet.
    fn enqueue(&mut self, collection: CollectionHandle, roots: impl IntoIterator<Item = Raw>) {
        match self.jobs.back_mut() {
            Some(last) if last.collection == collection && last.entered.is_empty() => {
                last.stack.extend(roots.into_iter().map(|root| (root, None)));
            }
            _ => self.jobs.push_back(Job::new(collection, roots)),
        }
    }

    /// A building collection with no job left, queued or being read for, and
    /// its proofs judged, is built; whether this made it so.
    fn retire(&mut self, collection: CollectionHandle) -> bool {
        let raw = &collection.raw;
        let built = self.building.get(raw).is_some()
            && !self.jobs.iter().any(|job| job.collection == collection)
            && !self
                .active
                .as_ref()
                .is_some_and(|(job, _)| job.collection == collection)
            && self.unjudged.get(raw).is_none()
            && self.misjudged.get(raw).is_none()
            && !self
                .judging
                .as_ref()
                .is_some_and(|judging| judging.get(raw).is_some());
        if built {
            self.building.remove(&collection.raw);
        }
        built
    }

    /// Follow `job` until it is done, needs a blob read, or `pause` (asked
    /// before every step) says to stop; and whether the held set grew.
    ///
    /// A blob joins only after every resident child it has joined, so a held
    /// blob's whole closure is held, at every step, and a later closure stops
    /// at it. A blob never scanned is read ([`Step::Read`]); one that cannot
    /// be read, resident or not, is unknown, and so is everything above it.
    fn follow(&mut self, job: &mut Job, pause: &mut dyn FnMut() -> bool) -> (Step, bool) {
        let Some(mut held) = self.held.get(&job.collection.raw).cloned() else {
            // Not settled (any more): its selection computes it.
            return (Step::Done, false);
        };
        let mut grew = false;
        let step = loop {
            if pause() {
                break Step::Paused;
            }
            let Some((handle, visited)) = job.stack.pop() else {
                break Step::Done;
            };
            if let Some(children) = visited {
                if children.iter().any(|child| job.unknown.contains(child)) {
                    job.unknown.insert(handle);
                } else {
                    held.insert(&Entry::new(&handle));
                    grew = true;
                }
                continue;
            }
            if held.has_prefix(&handle) || !job.entered.insert(handle) {
                continue;
            }
            if self.scanned.get(&handle).is_none() {
                break Step::Read(handle);
            }
            job.descend(handle, related(&self.edges, &handle), Some(&held));
        };
        if grew {
            self.held
                .replace(&Entry::with_value(&job.collection.raw, held));
        }
        (step, grew)
    }

    /// Feed `job` the read [`Self::follow`] asked for: the children of a
    /// readable blob, or `None` for one that is not.
    fn read(&mut self, job: &mut Job, handle: Raw, read: Option<Scan>) {
        match read {
            Some(Scan {
                children, edges, ..
            }) => {
                self.record_scan(handle, edges);
                let held = self.held.get(&job.collection.raw).cloned();
                job.descend(handle, children, held.as_ref());
            }
            None => {
                if self.seeds.get(&pair(&job.collection.raw, &handle)).is_some() {
                    self.pending
                        .insert(&Entry::new(&pair(&handle, &job.collection.raw)));
                }
                // Not readable: absent, or resident and failing to read.
                // Either way nothing above it joins.
                job.unknown.insert(handle);
            }
        }
    }
}

impl<T: HeldSource> State<T> {
    /// Add judged proof seeds to their settled collections and queue the new
    /// ones as roots.
    fn add_proof_seeds(&mut self, seeds: Vec<(CollectionHandle, Raw)>) {
        for (collection, seed) in seeds {
            let key = pair(&collection.raw, &seed);
            if self.held.get(&collection.raw).is_none() || self.seeds.get(&key).is_some() {
                continue;
            }
            self.seeds.insert(&Entry::new(&key));
            self.enqueue(collection, [seed]);
        }
    }
}

impl<T: HeldSource> HeldIndex<T> {
    /// Queue for the driver everything `now` holds that the last observed
    /// snapshot did not, and hand out the held sets as they stand, fixed from
    /// here on. Reads no blob: the records, the proofs' presence and the
    /// store's index only.
    ///
    /// `whole` says that `now` observes the whole store, not a prefix a
    /// climb has reached so far. Until one such observation, `now` is not
    /// fed: a child written after its parent would otherwise be missing
    /// when the parent is scanned, and never join (a late child). Peer
    /// reports are kept for the first whole observation.
    pub(crate) fn observe(&self, now: &T, whole: bool) -> Arc<HeldView> {
        let mut state = self.lock();
        state.replayed |= whole;
        if state.tracked.is_empty() {
            state.candidates = Pairs::new();
            return state.view.clone();
        }
        if !state.replayed {
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
            changed = true;
        }

        // Scratch for this observation: what to reach, per collection.
        let mut roots: BTreeMap<CollectionHandle, Vec<Raw>> = BTreeMap::new();
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
                    // Every seed of a new record is a root, known or not. A
                    // held seed costs the driver one lookup.
                    for seed in named {
                        seeds.insert(&Entry::new(&pair(&collection.raw, &seed)));
                        roots.entry(collection).or_default().push(seed);
                    }
                });
            }
            if changes.contains(StoreChanges::BLOBS)
                && !(state.pending.is_empty() && state.unrouted.is_empty())
            {
                // Seeds whose bytes arrived since, and descriptors whose
                // collections' proofs can be judged now. A store without an
                // indexed difference lists every blob; entries still match
                // once.
                for info in now.blobs_diff(&fed).flatten() {
                    let raw = info.handle.raw;
                    for collection in take_related(&mut state.pending, &raw) {
                        roots.entry(Inline::new(collection)).or_default().push(raw);
                    }
                    if state.unrouted.get(&raw).is_some() {
                        state.unrouted.remove(&raw);
                        if state.held.get(&raw).is_some() {
                            state.unjudged.insert(&Entry::new(&raw));
                        }
                    }
                }
            }
            if changes.contains(StoreChanges::CAPABILITY_PROOFS) {
                let settled: Vec<Raw> = state.held.iter().copied().collect();
                for collection in settled {
                    state.unjudged.insert(&Entry::new(&collection));
                }
            }
        }
        // A judgement that could not read the proofs is tried again now.
        let misjudged = std::mem::replace(&mut state.misjudged, Handles::new());
        state.unjudged.union(misjudged);

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
            if let Ok(records) = now.select_records(&selectors) {
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
                for (collection, list) in seeds {
                    for seed in &list {
                        state
                            .seeds
                            .insert(&Entry::new(&pair(&collection.raw, seed)));
                    }
                    // Every seed known, a proof's judged before a reset
                    // included, and every peer report.
                    let mut list = related(&state.seeds, &collection.raw);
                    list.extend(related(&state.routes, &collection.raw));
                    state
                        .held
                        .replace(&Entry::with_value(&collection.raw, HeldBlobs::new()));
                    state.building.insert(&Entry::new(&collection.raw));
                    state.unjudged.insert(&Entry::new(&collection.raw));
                    roots.entry(collection).or_default().extend(list);
                }
            }
        }
        for (collection, list) in roots {
            state.enqueue(collection, list);
        }

        // Scratch for this observation: the reports to resolve.
        let candidates: Vec<(CollectionHandle, Raw)> = std::mem::take(&mut state.candidates)
            .iter()
            .map(|key| {
                let (collection, handle) = split(key);
                (Inline::new(collection), handle)
            })
            .collect();
        for (collection, handle) in candidates {
            if state.tracked.get(&collection.raw).is_none() {
                continue;
            }
            let settled = state
                .held
                .get(&collection.raw)
                .map(|held| held.has_prefix(&handle));
            // A report of a blob that is not resident is dropped, so a failed
            // fetch stays in the next difference.
            if settled == Some(true)
                || !now
                    .contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
                    .unwrap_or(false)
            {
                continue;
            }
            let key = pair(&collection.raw, &handle);
            if settled.is_none() {
                // The observation that settles the collection resolves it.
                state.candidates.insert(&Entry::new(&key));
                continue;
            }
            // A route even if something under it cannot be read yet: a later
            // report of it reads it again.
            state.routes.insert(&Entry::new(&key));
            state.enqueue(collection, [handle]);
        }
        state.fed = Some(now.clone());
        state.fed_count += 1;
        if changed {
            state.publish_view();
        }
        if state.driven && !(state.jobs.is_empty() && state.unjudged.is_empty()) {
            self.queued.notify_all();
        }
        state.view.clone()
    }

    /// The work a driver of this index runs.
    pub(crate) fn work(self: &Arc<Self>) -> HeldWork
    where
        T: Send + 'static,
    {
        let index: Weak<dyn Drive> = Arc::downgrade(self) as Weak<HeldIndex<T>>;
        HeldWork(index)
    }
}

impl<T: HeldSource + Send> Drive for HeldIndex<T> {
    /// Judge the proofs queued for judging, then run queued jobs against the
    /// latest observed snapshot, for about `budget`: at least one step, then
    /// until the budget is spent or another locker waits. A built
    /// collection's jobs go first, since they extend a published set; then
    /// building collections take turns, a paused job going behind the
    /// others, so a small collection is not held back by a large one's whole
    /// first closure. A building collection is published once its last job
    /// finishes and its proofs are judged, never in between; a built
    /// collection's set whenever it grew.
    ///
    /// Every read happens with the state unlocked: a blob's with its job
    /// parked in [`State::active`], a judgement's with its collections in
    /// [`State::judging`]. A reset meanwhile drops them (it requeued their
    /// collections from scratch), and a clone keeps them. Snapshots may be
    /// fed in meanwhile, so a read is reconciled with them when it returns:
    /// a blob or a descriptor the read missed because it was absent, but that
    /// is resident now, is read again, since the snapshot that saw it arrive
    /// found nothing waiting for it.
    fn advance(&self, budget: Duration) -> bool {
        let started = Instant::now();
        let mut stepped = false;
        let mut pause = || {
            let pause = stepped
                && (started.elapsed() >= budget || self.waiting.load(Ordering::SeqCst) > 0);
            stepped = true;
            pause
        };
        let mut state = self.lock_driver();
        let mut publish = false;
        if let (false, Some(snapshot)) = (state.unjudged.is_empty(), state.fed.clone()) {
            let judging = std::mem::replace(&mut state.unjudged, Handles::new());
            let read_at = state.fed_count;
            state.judging = Some(judging.clone());
            drop(state);
            let collections: BTreeSet<CollectionHandle> = judging
                .iter()
                .map(|collection| Inline::new(*collection))
                .collect();
            let found = proof_seeds(&snapshot, &collections);
            drop(snapshot);
            state = self.lock_driver();
            if state.judging.take().is_some() {
                match found {
                    Ok(found) => {
                        for descriptor in found.unrouted {
                            let arrived = state.fed_count != read_at
                                && state.fed.as_ref().is_some_and(|fed| {
                                    fed.contains_blob(Inline::<Handle<UnknownBlob>>::new(
                                        descriptor,
                                    ))
                                    .unwrap_or(false)
                                });
                            if arrived {
                                state.unjudged.insert(&Entry::new(&descriptor));
                            } else {
                                state.unrouted.insert(&Entry::new(&descriptor));
                            }
                        }
                        state.add_proof_seeds(found.seeds);
                    }
                    // Judged again after the next observation.
                    Err(_) => state.misjudged.union(judging),
                }
                for collection in collections {
                    publish |= state.retire(collection);
                }
            }
            // The judgement is this call's first step.
            pause();
        }
        let more = loop {
            let next = state
                .jobs
                .iter()
                .position(|job| state.building.get(&job.collection.raw).is_none())
                .unwrap_or(0);
            let Some(mut job) = state.jobs.remove(next) else {
                break false;
            };
            // The job and whether it is done, or `None` when a reset
            // dropped it.
            let ended = loop {
                let (step, grew) = state.follow(&mut job, &mut pause);
                // A built collection's set is published as it grows.
                publish |= grew && state.building.get(&job.collection.raw).is_none();
                match step {
                    Step::Done => break Some((job, true)),
                    Step::Paused => break Some((job, false)),
                    Step::Read(handle) => {
                        let Some(snapshot) = state.fed.clone() else {
                            break Some((job.reread(handle), false));
                        };
                        let read_at = state.fed_count;
                        state.active = Some((job, handle));
                        drop(state);
                        let read = scan(&snapshot, &handle);
                        let absent = read.is_none()
                            && !snapshot
                                .contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
                                .unwrap_or(false);
                        drop(snapshot);
                        state = self.lock_driver();
                        let Some((back, _)) = state.active.take() else {
                            break None;
                        };
                        job = back;
                        if absent
                            && state.fed_count != read_at
                            && state.fed.as_ref().is_some_and(|fed| {
                                fed.contains_blob(Inline::<Handle<UnknownBlob>>::new(handle))
                                    .unwrap_or(false)
                            })
                        {
                            job = job.reread(handle);
                        } else {
                            state.read(&mut job, handle, read);
                        }
                    }
                }
            };
            match ended {
                Some((job, true)) => publish |= state.retire(job.collection),
                Some((job, false)) => {
                    if state.building.get(&job.collection.raw).is_some() {
                        state.jobs.push_back(job);
                    } else {
                        state.jobs.push_front(job);
                    }
                    break true;
                }
                None => {}
            }
        };
        let more = more || !state.unjudged.is_empty();
        if publish {
            state.publish_view();
        }
        drop(state);
        // Let a waiting locker in before the next step takes the state.
        while self.waiting.load(Ordering::SeqCst) > 0 {
            std::thread::yield_now();
        }
        more
    }

    fn wait(&self, timeout: Duration) {
        let state = self.lock_driver();
        if state.jobs.is_empty() && state.unjudged.is_empty() {
            drop(
                self.queued
                    .wait_timeout(state, timeout)
                    .expect("held-blob index is not poisoned"),
            );
        }
    }

    fn undrive(&self) {
        self.lock().driven = false;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::{BlobEncoding, IntoBlob, TryFromBlob};
    use crate::capability::{CapabilityProof, CapabilityProofId, CapabilityResource};
    use crate::collection::covered::Covered;
    use crate::collection::{
        CollectionCommit, CollectionDerive, CollectionMap, CollectionMerge, CollectionStore,
        SourceLocator,
    };
    use crate::inline::InlineEncoding;
    use crate::prelude::entity;
    use crate::repo::memoryrepo::{MemoryStore, MemoryStoreSnapshot};
    use crate::repo::{BlobInfo, BlobStorePut, CapabilityProofStore, SnapshotSource};

    type Reads = Arc<Mutex<HashMap<Raw, usize>>>;

    /// Makes a snapshot's record selection or proof enumeration fail.
    #[derive(Default)]
    struct Faults {
        select: AtomicBool,
        proofs: AtomicBool,
        /// Resident blobs whose reads fail (an indexed blob every copy of
        /// which fails validation).
        unreadable: Mutex<std::collections::HashSet<Raw>>,
        /// A blob whose next read blocks until released.
        gate: Mutex<Option<Gate>>,
    }

    /// The read of `blob` says it began on `entered`, then waits on
    /// `release`, for at most half a minute so a stuck test fails.
    struct Gate {
        blob: Raw,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
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
    /// A clone shares the counts and faults.
    #[derive(Clone, Default)]
    struct Counting {
        inner: MemoryStore,
        reads: Reads,
        faults: Arc<Faults>,
    }

    #[derive(Clone)]
    struct CountingSnapshot {
        inner: MemoryStoreSnapshot,
        reads: Reads,
        faults: Arc<Faults>,
    }

    impl SnapshotSource for Counting {
        type Snapshot = CountingSnapshot;
        type SnapshotError = Infallible;

        fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
            Ok(CountingSnapshot {
                inner: self.inner.snapshot()?,
                reads: self.reads.clone(),
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
            if self.faults.unreadable.lock().unwrap().contains(&handle.raw) {
                return Err(crate::blob::MemoryStoreGetError::NotFound(
                    crate::repo::MissingBlob {
                        handle: handle.transmute(),
                    },
                ));
            }
            let gate = {
                let mut gate = self.faults.gate.lock().unwrap();
                if gate.as_ref().is_some_and(|gate| gate.blob == handle.raw) {
                    gate.take()
                } else {
                    None
                }
            };
            if let Some(gate) = gate {
                gate.entered.send(()).unwrap();
                let _ = gate.release.recv_timeout(std::time::Duration::from_secs(30));
            }
            *self.reads.lock().unwrap().entry(handle.raw).or_default() += 1;
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

    /// Take a snapshot, run the driver until it has done what that snapshot
    /// queued, and take another: what a store whose driver keeps up hands
    /// out. Idle is not complete: each test asserts what joined.
    fn settled<S: SnapshotSource + HeldStore>(store: &mut S) -> S::Snapshot {
        store.snapshot().unwrap();
        let mut work = store.drive_held().expect("nobody else drives the store");
        assert!(work.run_until_idle());
        drop(work);
        store.snapshot().unwrap()
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
        let snapshot = settled(&mut store);
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
                    std::iter::once(Inline::new(data)).chain((3..10).map(|byte| Inline::new([byte; 32]))),
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
        let snapshot = settled(&mut store);
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
    fn map_attachments_are_never_held_even_in_a_tracked_attached_collection() {
        // A MAP is the signing host's own attachment of one node and never
        // replicates. Neither the parent's held set nor the attached
        // collection's own, should an operator list it, holds an attachment,
        // whether the MAP was there when tracking began or arrived later.
        let mut store = Store::default();
        let parent = collection(&mut store, "parent");
        let data = blob(&mut store, b"foundation");
        let metadata = blob(&mut store, b"metadata");
        commit(&mut store, parent, data, metadata);
        let attached = collection(&mut store, "attached");
        let under = blob(&mut store, b"only an attachment reaches this");
        let attachment = blob_naming(&mut store, b"attachment", &[under]);
        for target in [attached, parent] {
            store
                .insert(CollectionRecord::Map(CollectionMap::sign(
                    &key(),
                    target,
                    Inline::new(data),
                    Inline::new(attachment),
                )))
                .unwrap();
        }
        store.track_held([parent, attached]);
        let snapshot = settled(&mut store);
        assert_eq!(
            held_set(&snapshot, parent),
            BTreeSet::from([parent.raw, data, metadata])
        );
        assert_eq!(
            held_set(&snapshot, attached),
            BTreeSet::from([attached.raw])
        );

        let later = blob_naming(&mut store, b"a later attachment", &[under]);
        store
            .insert(CollectionRecord::Map(CollectionMap::sign(
                &key(),
                attached,
                Inline::new(data),
                Inline::new(later),
            )))
            .unwrap();
        let after = settled(&mut store);
        assert_eq!(held_set(&after, attached), BTreeSet::from([attached.raw]));
        assert_eq!(
            held_set(&after, parent),
            BTreeSet::from([parent.raw, data, metadata])
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
        let before = settled(&mut store);
        assert!(!held_set(&before, c).contains(&early));
        commit(&mut store, c, early, metadata);
        let after = settled(&mut store);
        assert!(held_set(&after, c).is_superset(&BTreeSet::from([early, child])));

        let late_child = blob(&mut store, b"late payload child");
        let late = unresident_naming(b"late payload", &[late_child]);
        let late_handle = handle_of(&late);
        commit(&mut store, c, late_handle, metadata);
        let waiting = settled(&mut store);
        assert!(!held_set(&waiting, c).contains(&late_handle));
        store.put::<UnknownBlob, _>(late).unwrap();
        let arrived = settled(&mut store);
        assert!(held_set(&arrived, c).is_superset(&BTreeSet::from([late_handle, late_child])));
        assert_eq!(
            reads(&store, &late_handle),
            2,
            "one failed read, then one scan"
        );
    }

    /// C1 holds P, which names H before H is resident. H then arrives as a
    /// seed of C2. Scanning once, P gains no edge; H joins held(C1) when a
    /// peer reports it there.
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
        let first = settled(&mut store);
        assert!(held_set(&first, c1).contains(&p));

        store.put::<UnknownBlob, _>(h_bytes).unwrap();
        commit(&mut store, c2, h, metadata);
        let second = settled(&mut store);
        assert!(held_set(&second, c2).contains(&h));
        assert!(
            !held_set(&second, c1).contains(&h),
            "P was scanned before H arrived"
        );

        // A report for a blob that is not resident is dropped, not kept.
        store.note_held(c1, Inline::new([5; 32]));
        store.note_held(c1, Inline::new(h));
        let reported = settled(&mut store);
        assert!(held_set(&reported, c1).contains(&h));
        assert!(!held_set(&reported, c1).contains(&[5; 32]));
        assert_eq!(reads(&store, &h), 1, "H was read once, as C2's seed");
        assert_eq!(reads(&store, &p), 1);
    }

    /// Astra's R2, a stated limitation: root R names an opaque P that names
    /// H, and H is put locally after P was scanned, with no record naming it
    /// and no report. No later snapshot holds H, though H stays readable by
    /// its hash, until a reset of the index (here, a lost blob) recomputes
    /// P's closure.
    #[test]
    fn a_nested_late_local_child_stays_out_until_a_reset() {
        let mut store = Store::default();
        let c = collection(&mut store, "nested");
        let metadata = blob(&mut store, b"metadata");
        let forgotten = blob(&mut store, b"forgotten by the store");
        let h_bytes = unresident_naming(b"nested late child", &[]);
        let h = handle_of(&h_bytes);
        let p = blob_naming(&mut store, b"opaque intermediate", &[h]);
        let r = blob_naming(&mut store, b"root payload", &[p]);
        commit(&mut store, c, r, metadata);
        store.track_held([c]);
        let first = settled(&mut store);
        assert!(held_set(&first, c).contains(&p));
        store.put::<UnknownBlob, _>(h_bytes).unwrap();
        for _ in 0..3 {
            let snapshot = settled(&mut store);
            assert!(!held_set(&snapshot, c).contains(&h), "no arrival rescans P");
            assert!(BlobStoreGet::get::<Bytes, UnknownBlob>(&snapshot, Inline::new(h)).is_ok());
        }
        let kept: Vec<_> = store
            .snapshot()
            .unwrap()
            .inner()
            .blobs()
            .map(|info| info.unwrap().handle)
            .filter(|handle| handle.raw != forgotten)
            .collect();
        (*store).inner.blobs.keep(kept);
        let reset = settled(&mut store);
        assert!(held_set(&reset, c).contains(&h));
        assert!(
            !held_set(&first, c).contains(&h),
            "an existing snapshot never changes"
        );
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
        let first = settled(&mut store);
        assert!(held_set(&first, c1).is_superset(&BTreeSet::from([p, q])));
        assert!(!held_set(&first, c2).contains(&p));
        let second_payload = blob_naming(&mut store, b"second payload", &[p]);
        commit(&mut store, c2, second_payload, metadata);
        let second = settled(&mut store);
        assert!(held_set(&second, c2).is_superset(&BTreeSet::from([second_payload, p, q])));
        assert_eq!(reads(&store, &p), 1);
        assert_eq!(reads(&store, &q), 1);
        assert_eq!(reads(&store, &second_payload), 1);
    }

    /// No blob body is read twice, whatever arrives.
    #[test]
    fn each_blob_is_read_at_most_once() {
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
            settled(&mut store);
            settled(&mut store);
        }
        let counts = store.reads.lock().unwrap().clone();
        assert!(counts.values().all(|count| *count == 1), "{counts:?}");
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
        settled(&mut store);
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(c),
                &root,
                definition,
                delegate.verifying_key(),
            ))
            .unwrap();
        let proven = settled(&mut store);
        assert!(!held_set(&proven, c).contains(&definition.raw));
        store.put::<UnknownBlob, _>(definition_bytes).unwrap();
        let arrived = settled(&mut store);
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
        let before = settled(&mut store);
        assert!(held_set(&before, c).contains(&child));
        let kept: Vec<_> = before
            .inner()
            .blobs()
            .map(|info| info.unwrap().handle)
            .filter(|handle| handle.raw != parent)
            .collect();
        (*store).inner.blobs.keep(kept);
        let after = settled(&mut store);
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
        settled(&mut pile);
        pile.note_held(c, Inline::new(reported));
        assert!(held_set(&settled(&mut pile), c).contains(&reported));
        pile.close().unwrap();

        let mut pile = crate::repo::pile::Pile::open(file.path()).unwrap();
        pile.track_held([c]);
        assert!(!held_set(&settled(&mut pile), c).contains(&reported));
        let reaching = blob_naming(&mut pile, b"a payload naming it", &[reported]);
        commit(&mut pile, c, reaching, metadata);
        assert!(held_set(&settled(&mut pile), c).contains(&reported));
        pile.close().unwrap();

        let mut pile = crate::repo::pile::Pile::open(file.path()).unwrap();
        pile.track_held([c]);
        assert!(
            held_set(&settled(&mut pile), c).contains(&reported),
            "a record reaches it now"
        );
        pile.close().unwrap();
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
        let failed = settled(&mut store);
        assert_eq!(failed.held(c), None);
        store.faults.select.store(false, Ordering::SeqCst);
        let settled = settled(&mut store);
        assert_eq!(
            held_set(&settled, c),
            BTreeSet::from([c.raw, data, metadata])
        );
    }

    /// A judgement that could not read the proofs is tried again after the
    /// next snapshot, even when the store has not changed since.
    #[test]
    fn a_failed_proof_read_is_retried_at_the_next_snapshot() {
        let mut store = Store::default();
        let root = SigningKey::from_bytes(&[46; 32]);
        let c = governed(&mut store, "proofs fail", &root);
        let definition: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"definition"));
        store.track_held([c]);
        settled(&mut store);
        store.faults.proofs.store(true, Ordering::SeqCst);
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(c),
                &root,
                definition,
                SigningKey::from_bytes(&[47; 32]).verifying_key(),
            ))
            .unwrap();
        let failed = settled(&mut store);
        assert!(!held_set(&failed, c).contains(&definition.raw));
        store.faults.proofs.store(false, Ordering::SeqCst);
        let retried = settled(&mut store);
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
        settled(&mut store);
        let before = store.reads.lock().unwrap().clone();
        for index in 0..16_u8 {
            blob_naming(&mut store, &[b'u', index], &[data, child]);
            blob(&mut store, &[b'v', index]);
            settled(&mut store);
        }
        assert_eq!(*store.reads.lock().unwrap(), before);
    }

    /// A proof seeds C only when C's authorization evidence keeps it: over C
    /// itself from one of C's policy roots, or over a subordinate resource
    /// whose own descriptor entity both routes to C and declares the root.
    /// A valid proof irrelevant to C seeds nothing.
    ///
    /// Whether the resource R is itself tracked changes nothing: a proof over
    /// R never counts for C.
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
        let over_resource = definition("definition over R from R's root");
        let foreign_root = definition("definition from C's root over R");
        let resource = store
            .put::<SimpleArchive, _>(
                entity! {
                    resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key())
                        .binding(over_resource),
                }
                .facts()
                .clone(),
            )
            .unwrap();
        for (resource, root, definition) in [
            (c, &collection_root, exact),
            (c, &stranger, wrong_root),
            (resource, &resource_root, over_resource),
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
        let held = held_set(&settled(&mut store), c);
        assert!(
            held.contains(&exact.raw),
            "a proof over C from C's root seeds C (resource tracked: {track_resource})"
        );
        for irrelevant in [wrong_root, over_resource, foreign_root] {
            assert!(
                !held.contains(&irrelevant.raw),
                "a proof C's authorization rejects seeded C (resource tracked: {track_resource})"
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

    /// A resident blob that cannot be read holds back everything above it,
    /// so no held set lacks a resident child. Once it reads again, nothing
    /// reads it by itself; a peer's report of the blob above it holds both.
    #[test]
    fn an_unreadable_resident_child_holds_back_its_parent_until_a_report() {
        let mut store = Store::default();
        let c = collection(&mut store, "unreadable child");
        let metadata = blob(&mut store, b"metadata");
        let z = blob(&mut store, b"indexed, every copy invalid");
        let data = blob_naming(&mut store, b"names Z", &[z]);
        commit(&mut store, c, data, metadata);
        store.faults.unreadable.lock().unwrap().insert(z);
        store.track_held([c]);
        let first = settled(&mut store);
        assert!(held_set(&first, c).is_superset(&BTreeSet::from([c.raw, metadata])));
        assert_closed(&first, c);
        assert!(!held_set(&first, c).contains(&data));
        store.faults.unreadable.lock().unwrap().remove(&z);
        assert!(!held_set(&settled(&mut store), c).contains(&data));
        store.note_held(c, Inline::new(data));
        let reported = settled(&mut store);
        assert!(held_set(&reported, c).is_superset(&BTreeSet::from([data, z])));
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
                [2, 4, 6, 7, 8, 9, 10, 11].map(|byte| Inline::new([byte; 32])),
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
        // A MAP is a host's attachment of one node; it never replicates.
        let map = CollectionRecord::Map(CollectionMap::sign(
            &key(),
            c,
            Inline::new([2; 32]),
            Inline::new([8; 32]),
        ));
        for record in [commit, merge, derive, map] {
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

    /// The retired routing backlink, declared locally (anchored: anchor and
    /// encoding reproduce the published id) so old-shape resource
    /// descriptors can be written once core no longer exports it.
    mod retired {
        use crate::prelude::attributes;
        attributes! {
            "62E951EC3ABB7F9B7F123BB7DE2F9F99" as pub resource_collection: crate::inline::encodings::hash::Handle<crate::blob::encodings::simplearchive::SimpleArchive>;
        }
    }

    /// Grant gossip redesign: a proof over a resource R whose descriptor
    /// names C through the retired backlink, from R's own root, seeds nothing
    /// in held(C). Its definitions travel with R's grants, by participation,
    /// not as C's blobs. Base: proof_seeds followed the backlink and seeded it.
    #[test]
    fn a_proof_over_a_resource_naming_c_seeds_nothing_in_c() {
        use crate::capability::policy::resource_policy;
        use crate::collection::AdmissionPolicy;

        let mut store = Store::default();
        let root = SigningKey::from_bytes(&[60; 32]);
        let resource_root = SigningKey::from_bytes(&[61; 32]);
        let subject = SigningKey::from_bytes(&[62; 32]).verifying_key();
        let c = governed(&mut store, "backlinked", &root);
        let own: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"definition over C"));
        let routed: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"definition over R naming C"));
        let resource = store
            .put::<SimpleArchive, _>(
                entity! {
                    retired::resource_collection: c,
                    resource_policy*: AdmissionPolicy::direct(resource_root.verifying_key())
                        .binding(routed),
                }
                .facts()
                .clone(),
            )
            .unwrap();
        for (resource, root, definition) in [(c, &root, own), (resource, &resource_root, routed)] {
            store
                .insert_proof(CapabilityProof::new(
                    CapabilityResource::from(resource),
                    root,
                    definition,
                    subject,
                ))
                .unwrap();
        }
        store.track_held([c]);
        let held = held_set(&settled(&mut store), c);
        assert!(
            held.contains(&own.raw),
            "positive control: a proof over C from C's root seeds C"
        );
        assert!(
            !held.contains(&routed.raw),
            "a proof over R seeded C through R's backlink"
        );
    }

    /// One payload naming `fanout` intermediates that each name `fanout`
    /// leaves, committed to `c`: a closure the driver computes in many
    /// steps. Every blob `c` holds once built.
    fn wide(store: &mut Store, c: CollectionHandle, fanout: u8) -> BTreeSet<Raw> {
        let metadata = blob(store, b"wide metadata");
        let (data, mut all) = wide_payload(store, fanout);
        all.extend([c.raw, metadata]);
        commit(store, c, data, metadata);
        all
    }

    /// A payload naming `fanout` intermediates that each name `fanout`
    /// leaves, and every blob under it, itself included.
    fn wide_payload(store: &mut Store, fanout: u8) -> (Raw, BTreeSet<Raw>) {
        let mut all = BTreeSet::new();
        let mids: Vec<Raw> = (0..fanout)
            .map(|mid| {
                let leaves: Vec<Raw> = (0..fanout)
                    .map(|leaf| blob(store, &[b'l', mid, leaf]))
                    .collect();
                all.extend(&leaves);
                blob_naming(store, &[b'm', mid], &leaves)
            })
            .collect();
        all.extend(&mids);
        let data = blob_naming(store, b"wide payload", &mids);
        all.insert(data);
        (data, all)
    }

    fn total_reads(store: &Store) -> usize {
        store.reads.lock().unwrap().values().sum()
    }

    /// Taking a store snapshot reads no blob: not a newly tracked collection's
    /// first closure, not the descriptor its proofs are judged by, not a
    /// peer's report, not the closure of a built collection's new record.
    /// The driver reads each blob once (the descriptor once more, to judge
    /// the proof) and publishes the whole set.
    #[test]
    fn a_snapshot_reads_no_blob() {
        let mut store = Store::default();
        let root = SigningKey::from_bytes(&[48; 32]);
        let c = governed(&mut store, "observed only", &root);
        let definition: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"definition read by the driver"));
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(c),
                &root,
                definition,
                SigningKey::from_bytes(&[49; 32]).verifying_key(),
            ))
            .unwrap();
        let metadata = blob(&mut store, b"metadata");
        let child = blob(&mut store, b"child");
        let data = blob_naming(&mut store, b"data", &[child]);
        commit(&mut store, c, data, metadata);
        let reported = blob(&mut store, b"reported by a peer");
        store.track_held([c]);
        store.note_held(c, Inline::new(reported));
        let mut expected = BTreeSet::from([c.raw, definition.raw, metadata, child, data, reported]);
        for round in 0..3_u8 {
            let snapshot = store.snapshot().unwrap();
            assert_eq!(total_reads(&store), 0, "snapshot {round} read a blob");
            assert_eq!(snapshot.held(c), None, "nobody computed it yet");
            let leaf = blob(&mut store, &[b'r', round]);
            let payload = blob_naming(&mut store, &[b'p', round], &[leaf]);
            commit(&mut store, c, payload, metadata);
            expected.extend([leaf, payload]);
        }
        store.snapshot().unwrap();
        assert_eq!(total_reads(&store), 0, "a snapshot read a blob");

        let mut work = store.drive_held().expect("the only driver");
        assert!(work.run_until_idle());
        let built = store.snapshot().unwrap();
        let held = held_set(&built, c);
        assert!(held.is_superset(&expected), "the whole set is published");
        assert_closed(&built, c);
        let counts = store.reads.lock().unwrap().clone();
        for (blob, count) in &counts {
            let once = if *blob == c.raw { 2 } else { 1 };
            assert_eq!(*count, once, "{:02x?} read {count} times", &blob[..4]);
        }

        // A built collection's new record: the snapshot reads nothing and
        // publishes the set as it stood; the driver extends it.
        let leaf = blob(&mut store, b"leaf of a built collection's record");
        let payload = blob_naming(&mut store, b"payload of it", &[leaf]);
        commit(&mut store, c, payload, metadata);
        let after = store.snapshot().unwrap();
        assert_eq!(
            *store.reads.lock().unwrap(),
            counts,
            "a snapshot read a blob"
        );
        assert_eq!(held_set(&after, c), held, "published as it stood");
        assert!(work.run_until_idle());
        let extended = store.snapshot().unwrap();
        assert!(held_set(&extended, c).is_superset(&BTreeSet::from([payload, leaf])));
        assert!(extended.held_generation() > after.held_generation());
    }

    /// After the first whole replay, a parent arrives in one refresh and its
    /// child, which no record names, in a later one (as a sync can land
    /// them). Whether the child joins depends on when its parent is scanned,
    /// not on the replay latch. When the driver reaches the parent after the
    /// child arrived, the child joins. When it scanned the parent before,
    /// the child is a late child, the stated limitation: it stays out until a
    /// peer reports it in the collection (or the index resets, or the store
    /// reopens).
    #[test]
    fn a_child_appended_after_its_parent_joins_unless_the_parent_was_scanned_first() {
        for scanned_between in [false, true] {
            let file = tempfile::NamedTempFile::new().unwrap();
            let mut pile = crate::repo::pile::Pile::open(file.path()).unwrap();
            let c = collection(&mut pile, "appended in two refreshes");
            let metadata = blob(&mut pile, b"metadata");
            pile.track_held([c]);
            settled(&mut pile);
            let child = unresident_naming(b"a child appended after its parent", &[]);
            let q = handle_of(&child);
            let p = blob_naming(&mut pile, b"a parent appended first", &[q]);
            commit(&mut pile, c, p, metadata);
            if scanned_between {
                settled(&mut pile);
            } else {
                pile.snapshot().unwrap();
            }
            pile.put::<UnknownBlob, _>(child).unwrap();
            let held = held_set(&settled(&mut pile), c);
            assert!(held.contains(&p), "the parent is held");
            assert_eq!(
                held.contains(&q),
                !scanned_between,
                "the child joins exactly when its parent was scanned after it arrived \
                 (scanned between: {scanned_between})"
            );
            if scanned_between {
                pile.note_held(c, Inline::new(q));
                assert!(
                    held_set(&settled(&mut pile), c).contains(&q),
                    "a peer's report brings the late child in"
                );
            }
            pile.close().unwrap();
        }
    }

    /// A store nobody drives computes nothing: a tracked collection stays
    /// unknown, whatever is taken.
    #[test]
    fn without_a_driver_nothing_is_built() {
        let mut store = Store::default();
        let c = collection(&mut store, "undriven");
        let metadata = blob(&mut store, b"metadata");
        let data = blob(&mut store, b"data");
        commit(&mut store, c, data, metadata);
        store.track_held([c]);
        for _ in 0..3 {
            assert_eq!(store.snapshot().unwrap().held(c), None);
        }
        assert_eq!(total_reads(&store), 0);
    }

    /// A driven store publishes nothing for a building collection until its
    /// closure is whole, then exactly the whole closure, each blob read
    /// once, though the driver computed it in many small steps.
    #[test]
    fn a_driven_build_publishes_nothing_until_the_closure_is_whole() {
        let mut store = Store::default();
        let c = collection(&mut store, "driven");
        let whole = wide(&mut store, c, 20);
        let mut work = store.drive_held().expect("the only driver");
        store.track_held([c]);
        assert_eq!(
            store.snapshot().unwrap().held(c),
            None,
            "the snapshot read nothing"
        );
        let mut unknown = 1;
        let mut published = None;
        for _ in 0..100_000 {
            assert!(work.step(Duration::ZERO, Duration::ZERO));
            let snapshot = store.snapshot().unwrap();
            if snapshot.held(c).is_some() {
                published = Some(held_set(&snapshot, c));
                break;
            }
            unknown += 1;
        }
        assert_eq!(published, Some(whole));
        assert!(unknown > 10, "{unknown} snapshots before it was whole");
        let counts = store.reads.lock().unwrap().clone();
        assert!(counts.values().all(|count| *count == 1), "{counts:?}");
    }

    /// Driver steps of zero budget until `c` is published, at most `limit`;
    /// how many it took, or `None`.
    fn steps_until_published(
        store: &mut Store,
        work: &mut HeldWork,
        c: CollectionHandle,
        limit: usize,
    ) -> Option<usize> {
        for steps in 1..=limit {
            assert!(work.step(Duration::ZERO, Duration::ZERO));
            if store.snapshot().unwrap().held(c).is_some() {
                return Some(steps);
            }
        }
        None
    }

    /// Building collections take turns: a small collection tracked after a
    /// large one is published within a few driver steps, long before the
    /// large one's first closure is whole.
    #[test]
    fn a_small_collection_is_not_held_back_by_a_large_ones_build() {
        let mut store = Store::default();
        let large = collection(&mut store, "large, tracked first");
        let whole = wide(&mut store, large, 20);
        let small = collection(&mut store, "small, tracked second");
        let metadata = blob(&mut store, b"small metadata");
        let data = blob(&mut store, b"small data");
        commit(&mut store, small, data, metadata);
        let mut work = store.drive_held().expect("the only driver");
        store.track_held([large]);
        store.snapshot().unwrap();
        assert!(work.step(Duration::ZERO, Duration::ZERO));
        store.track_held([small]);
        store.snapshot().unwrap();
        let steps = steps_until_published(&mut store, &mut work, small, 1_000)
            .expect("the small collection is published");
        assert_eq!(
            held_set(&store.snapshot().unwrap(), small),
            BTreeSet::from([small.raw, data, metadata])
        );
        assert_eq!(
            store.snapshot().unwrap().held(large),
            None,
            "published after {steps} steps, only once the large closure was whole"
        );
        assert!(steps < 30, "{steps} steps for three blobs");
        assert!(work.run_until_idle());
        assert_eq!(held_set(&store.snapshot().unwrap(), large), whole);
    }

    /// A built collection's new record is served before an unfinished
    /// building job continues: its set grows within a few driver steps
    /// while the large build is still running.
    #[test]
    fn a_built_collections_new_record_goes_before_a_build() {
        let mut store = Store::default();
        let built = collection(&mut store, "built first");
        store.track_held([built]);
        settled(&mut store);
        let large = collection(&mut store, "large, building");
        let whole = wide(&mut store, large, 20);
        let mut work = store.drive_held().expect("the only driver");
        store.track_held([large]);
        store.snapshot().unwrap();
        for _ in 0..5 {
            assert!(work.step(Duration::ZERO, Duration::ZERO));
        }
        let metadata = blob(&mut store, b"built metadata");
        let leaf = blob(&mut store, b"built leaf");
        let data = blob_naming(&mut store, b"built payload", &[leaf]);
        commit(&mut store, built, data, metadata);
        store.snapshot().unwrap();
        let mut steps = 0;
        while !held_set(&store.snapshot().unwrap(), built).contains(&data) {
            assert!(work.step(Duration::ZERO, Duration::ZERO));
            steps += 1;
            assert!(steps < 1_000, "the record never joined");
        }
        assert_eq!(
            store.snapshot().unwrap().held(large),
            None,
            "joined after {steps} steps, only once the large closure was whole"
        );
        assert!(steps < 20, "{steps} steps for three blobs");
        assert!(held_set(&store.snapshot().unwrap(), built)
            .is_superset(&BTreeSet::from([data, leaf, metadata])));
        assert!(work.run_until_idle());
        assert_eq!(held_set(&store.snapshot().unwrap(), large), whole);
    }

    /// Dropping the work leaves the build where it stood: snapshots compute
    /// nothing, and the next driver finishes it and publishes it whole.
    #[test]
    fn a_dropped_driver_leaves_the_build_to_the_next_driver() {
        let mut store = Store::default();
        let c = collection(&mut store, "abandoned");
        let whole = wide(&mut store, c, 20);
        let mut work = store.drive_held().expect("the only driver");
        store.track_held([c]);
        assert_eq!(store.snapshot().unwrap().held(c), None);
        assert!(store.drive_held().is_none(), "one driver at a time");
        assert!(work.step(Duration::ZERO, Duration::ZERO));
        let read = total_reads(&store);
        drop(work);
        assert_eq!(
            store.snapshot().unwrap().held(c),
            None,
            "nobody finishes it"
        );
        assert_eq!(total_reads(&store), read, "a snapshot read a blob");
        let mut next = store.drive_held().expect("the store can be driven again");
        assert!(next.run_until_idle());
        assert_eq!(held_set(&store.snapshot().unwrap(), c), whole);
        let counts = store.reads.lock().unwrap().clone();
        assert!(counts.values().all(|count| *count == 1), "{counts:?}");
    }

    /// While the driver waits on a blob read, a snapshot does not wait for
    /// it, and a building collection stays unknown. A built collection's new
    /// record joins once the driver reaches it; the build completes and is
    /// published whole.
    #[test]
    fn a_snapshot_never_waits_for_a_read_the_driver_makes() {
        let mut store = Store::default();
        let built = collection(&mut store, "built beside");
        store.track_held([built]);
        settled(&mut store);
        let c = collection(&mut store, "slow");
        let whole = wide(&mut store, c, 20);
        let work = store.drive_held().expect("the only driver");
        store.track_held([c]);
        assert_eq!(store.snapshot().unwrap().held(c), None);
        let unread = *whole
            .iter()
            .find(|blob| reads(&store, blob) == 0)
            .expect("the snapshot left blobs unread");
        let (release, driver) = block_driver_in(&mut store, work, unread);

        let metadata = blob(&mut store, b"metadata beside");
        let leaf = blob(&mut store, b"leaf beside");
        let data = blob_naming(&mut store, b"payload beside", &[leaf]);
        commit(&mut store, built, data, metadata);
        let started = Instant::now();
        let during = store.snapshot().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the snapshot waited for the read"
        );
        assert!(
            during.held(built).is_some(),
            "a built collection stays known"
        );
        assert_eq!(during.held(c), None, "a building collection is unknown");

        release.send(()).unwrap();
        assert_eq!(published(&mut store, c), whole);
        let mut beside = BTreeSet::new();
        for _ in 0..1000 {
            beside = held_set(&store.snapshot().unwrap(), built);
            if beside.contains(&data) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(beside.is_superset(&BTreeSet::from([data, leaf, metadata])));
        drop(store);
        driver.join().unwrap();
    }

    /// Block the driver of `store` in its read of `blob`, on its own thread
    /// (which ends once the store is gone); the release.
    fn block_driver_in(
        store: &mut Store,
        mut work: HeldWork,
        blob: Raw,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        *store.faults.gate.lock().unwrap() = Some(Gate {
            blob,
            entered,
            release: release_rx,
        });
        let driver = std::thread::spawn(move || {
            while work.step(Duration::from_secs(60), Duration::from_millis(10)) {}
        });
        entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("the driver reads the gated blob");
        (release, driver)
    }

    /// `c`'s held set once published, waiting for the driver.
    fn published(store: &mut Store, c: CollectionHandle) -> BTreeSet<Raw> {
        for _ in 0..1000 {
            let snapshot = store.snapshot().unwrap();
            if snapshot.held(c).is_some() {
                assert_closed(&snapshot, c);
                return held_set(&snapshot, c);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the driver never published the collection");
    }

    /// A seed the driver finds absent, which arrives while that read is in
    /// flight, is read again: the snapshot that saw it arrive found nothing
    /// waiting for it, so nothing else would.
    #[test]
    fn a_seed_arriving_during_the_drivers_read_of_it_is_read_again() {
        let mut store = Store::default();
        let descriptor = unresident_naming(b"late descriptor", &[]);
        let c: CollectionHandle = Inline::new(handle_of(&descriptor));
        let (payload, mut whole) = wide_payload(&mut store, 20);
        let data = blob(&mut store, b"small data");
        commit(&mut store, c, data, payload);
        whole.extend([c.raw, data]);
        let work = store.drive_held().expect("the only driver");
        store.track_held([c]);
        assert_eq!(store.snapshot().unwrap().held(c), None);
        assert_eq!(reads(&store, &c.raw), 0, "the driver reads the descriptor");
        let (release, driver) = block_driver_in(&mut store, work, c.raw);
        store.put::<UnknownBlob, _>(descriptor).unwrap();
        // This snapshot consumes the arrival while the miss is in flight.
        store.snapshot().unwrap();
        release.send(()).unwrap();
        assert_eq!(published(&mut store, c), whole);
        assert_eq!(reads(&store, &c.raw), 2, "the miss, then the read again");
        drop(store);
        driver.join().unwrap();
    }

    /// A collection descriptor the driver finds absent while it judges the
    /// collection's proofs, which arrives during that read, judges them
    /// again: the snapshot that saw it arrive found no judgement waiting for
    /// it, so nothing else would.
    #[test]
    fn a_descriptor_arriving_during_the_drivers_judgement_judges_again() {
        let root = SigningKey::from_bytes(&[56; 32]);
        let mut elsewhere = Store::default();
        let c = governed(&mut elsewhere, "judged late", &root);
        let descriptor: Bytes = BlobStoreGet::get::<Bytes, UnknownBlob>(
            &elsewhere.snapshot().unwrap(),
            Inline::new(c.raw),
        )
        .unwrap();
        let mut store = Store::default();
        let definition: Inline<Handle<SimpleArchive>> =
            Inline::new(blob(&mut store, b"definition judged late"));
        store
            .insert_proof(CapabilityProof::new(
                CapabilityResource::from(c),
                &root,
                definition,
                SigningKey::from_bytes(&[57; 32]).verifying_key(),
            ))
            .unwrap();
        let work = store.drive_held().expect("the only driver");
        store.track_held([c]);
        assert_eq!(store.snapshot().unwrap().held(c), None);
        // The judgement is the driver's first read, and finds no descriptor.
        let (release, driver) = block_driver_in(&mut store, work, c.raw);
        store.put::<UnknownBlob, _>(descriptor).unwrap();
        // This snapshot consumes the arrival while the judgement is in flight.
        store.snapshot().unwrap();
        release.send(()).unwrap();
        let held = published(&mut store, c);
        assert!(held.contains(&c.raw), "the descriptor is held");
        assert!(
            held.contains(&definition.raw),
            "the proof was judged again once its descriptor arrived"
        );
        drop(store);
        driver.join().unwrap();
    }

    /// A clone taken while the driver reads keeps that job: the copy, driven
    /// by nobody, stays unknown until a driver of its own builds it whole,
    /// and the original's driver still publishes it whole.
    #[test]
    fn a_clone_taken_during_a_read_keeps_the_drivers_job() {
        let mut store = Store::default();
        let c = collection(&mut store, "cloned mid-read");
        let whole = wide(&mut store, c, 20);
        let work = store.drive_held().expect("the only driver");
        store.track_held([c]);
        assert_eq!(store.snapshot().unwrap().held(c), None);
        let unread = *whole
            .iter()
            .find(|blob| reads(&store, blob) == 0)
            .expect("the snapshot left blobs unread");
        let (release, driver) = block_driver_in(&mut store, work, unread);
        let mut copy = store.clone();
        assert_eq!(copy.snapshot().unwrap().held(c), None, "nobody drives the copy");
        let mut own = copy.drive_held().expect("nobody drives the copy");
        assert!(own.run_until_idle());
        assert_eq!(held_set(&copy.snapshot().unwrap(), c), whole);
        release.send(()).unwrap();
        assert_eq!(published(&mut store, c), whole);
        drop(store);
        driver.join().unwrap();
    }
}
