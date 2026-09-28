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
//! DERIVE's output, and the capability definitions named by the proofs over C.
//! A MERGE never replicates, so its result is never a seed, and a blob no
//! record names (an attachment, a scratch archive) is never one either.
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
//! When a collection is first tracked, its existing closure is computed
//! synchronously if no walker is attached, and otherwise by the walker in the
//! background, published level by level (a positive set is safe to publish
//! incomplete). The start-up walk and the periodic walk never gate a
//! snapshot. Only a caller that owns a long-running host starts a walker;
//! nothing here starts a thread by itself.
//!
//! A snapshot that lost a blob its predecessor had (a store that forgets
//! blobs) resets the index: the edges are forgotten and every collection is
//! recomputed as if newly tracked.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use super::{CollectionHandle, CollectionRead, CollectionRecord, CollectionRecordSelector};

type Raw = [u8; 32];

/// One collection's held set: positive, and served as a Merkle PATCH.
pub type HeldBlobs = PATCH<32, IdentitySchema, (), Blake3Merkle>;

/// The held sets of one immutable observation.
pub trait HeldRead {
    /// Every blob `collection` holds in this observation, or `None` when the
    /// store does not track it. Absence from the set is not evidence that a
    /// blob is missing.
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
    /// reaches join `held(collection)`. Kept in memory only.
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
    /// Time from one walk's start to the next one's. A walk that takes longer
    /// is followed immediately by the next.
    pub interval: Duration,
    /// Blocking threads that read blobs during one walk.
    pub threads: usize,
}

impl Default for HeldWalkConfig {
    /// Thirty minutes on four threads. Measured on a 41 GB pile copy with a
    /// warm page cache: a full walk of its largest collection (about 108,000
    /// blobs, 16 GB, 500 M aligned words) took about 60 s on 4 threads, so the
    /// late-child bound is about 31 minutes plus scheduling delay.
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30 * 60),
            threads: 4,
        }
    }
}

/// Live walker threads in this process, for tests that a reader starts none.
static WALKER_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Number of walker threads currently running in this process.
pub fn held_walker_threads() -> usize {
    WALKER_THREADS.load(Ordering::SeqCst)
}

/// The held sets as one snapshot sees them.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct HeldView {
    generation: u64,
    sets: BTreeMap<CollectionHandle, HeldBlobs>,
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
                    .map(|(collection, held)| (collection.raw, held.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl HeldView {
    pub(crate) fn held(&self, collection: CollectionHandle) -> Option<HeldBlobs> {
        self.sets.get(&collection).cloned()
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Default)]
struct Tracked {
    /// Every blob C's records and proofs name, resident or not.
    seeds: HashSet<Raw>,
    /// Resident blobs peers reported in C that were not already held.
    routes: BTreeSet<Raw>,
    held: HeldBlobs,
    /// Tracked, but its seeds have not been selected yet.
    fresh: bool,
}

#[derive(Clone, Copy, Debug)]
struct Walker {
    requested: bool,
    stop: bool,
}

#[derive(Clone)]
struct State<T> {
    tracked: BTreeMap<CollectionHandle, Tracked>,
    /// Every scanned blob and its resident children when it was scanned.
    edges: HashMap<Raw, Arc<[Raw]>>,
    /// Seeds whose bytes were not readable yet, and the collections waiting.
    pending: HashMap<Raw, BTreeSet<CollectionHandle>>,
    /// Peer reports since the last observation.
    candidates: Vec<(CollectionHandle, Raw)>,
    /// The last observation fed in.
    fed: Option<T>,
    generation: u64,
    /// Bumped by a reset, so a walk started before it publishes nothing.
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
}

impl<T> Default for HeldIndex<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                tracked: BTreeMap::new(),
                edges: HashMap::new(),
                pending: HashMap::new(),
                candidates: Vec::new(),
                fed: None,
                generation: 0,
                epoch: 0,
                view: Arc::new(HeldView::default()),
                walker: None,
            }),
            wake: Condvar::new(),
            halt: AtomicBool::new(false),
        }
    }
}

impl<T: Clone> HeldIndex<T> {
    /// An independent copy of this index, with no walker attached.
    pub(crate) fn detached_clone(&self) -> Self {
        let mut state = self.lock().clone();
        state.walker = None;
        Self {
            state: Mutex::new(state),
            wake: Condvar::new(),
            halt: AtomicBool::new(false),
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
            state.tracked.entry(collection).or_insert_with(|| Tracked {
                fresh: true,
                ..Tracked::default()
            });
        }
    }

    pub(crate) fn note(&self, collection: CollectionHandle, handle: Raw) {
        let mut state = self.lock();
        if state.tracked.contains_key(&collection) {
            state.candidates.push((collection, handle));
        }
    }

    fn stopping(&self) -> bool {
        self.halt.load(Ordering::Relaxed)
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

/// Capability definitions named by the proofs over each of `collections`:
/// proofs whose resource is the collection, or a resource whose immutable
/// descriptor routes to it.
fn proof_seeds<T: HeldSource>(
    snapshot: &T,
    collections: &BTreeSet<CollectionHandle>,
) -> Vec<(CollectionHandle, Raw)> {
    let mut seeds = Vec::new();
    if collections.is_empty() {
        return seeds;
    }
    let Ok(proofs) = snapshot.proofs() else {
        return seeds;
    };
    for proof in proofs.flatten() {
        let resource: CollectionHandle = Inline::new(proof.resource().into_bytes());
        let mut targets = Vec::new();
        if collections.contains(&resource) {
            targets.push(resource);
        } else if let Ok(facts) = snapshot.get::<TribleSet, SimpleArchive>(resource) {
            for (collection,) in find!(
                (collection: Inline<Handle<SimpleArchive>>),
                pattern!(&facts, [{ _?resource @ resource_collection: ?collection }])
            ) {
                if collections.contains(&collection) {
                    targets.push(collection);
                }
            }
        }
        for collection in targets {
            for handle in proof.blob_references() {
                seeds.push((collection, handle.raw));
            }
        }
    }
    seeds
}

/// Read one blob and list its resident children, or `None` if it is not
/// readable. Children are probed in the store's index without reading them.
fn scan<T: HeldSource>(snapshot: &T, handle: &Raw) -> Option<Arc<[Raw]>> {
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
    Some(children.into())
}

impl<T: HeldSource> State<T> {
    /// Add everything reachable from `roots` to `collection`'s held set. With
    /// a snapshot, a blob never scanned is read now; without one it is left
    /// for the walk that will scan it. Only scanned blobs are held.
    fn reach(
        &mut self,
        snapshot: Option<&T>,
        collection: CollectionHandle,
        roots: impl IntoIterator<Item = Raw>,
    ) -> bool {
        let State {
            tracked,
            edges,
            pending,
            ..
        } = self;
        let Some(tracked) = tracked.get_mut(&collection) else {
            return false;
        };
        let mut changed = false;
        let mut stack: Vec<Raw> = roots.into_iter().collect();
        while let Some(handle) = stack.pop() {
            if tracked.held.has_prefix(&handle) {
                continue;
            }
            let children = match (edges.get(&handle), snapshot) {
                (Some(children), _) => children.clone(),
                (None, Some(snapshot)) => match scan(snapshot, &handle) {
                    Some(children) => {
                        edges.insert(handle, children.clone());
                        children
                    }
                    None => {
                        if tracked.seeds.contains(&handle) {
                            pending.entry(handle).or_default().insert(collection);
                        }
                        continue;
                    }
                },
                (None, None) => continue,
            };
            tracked.held.insert(&Entry::new(&handle));
            changed = true;
            stack.extend(
                children
                    .iter()
                    .copied()
                    .filter(|child| !tracked.held.has_prefix(child)),
            );
        }
        changed
    }

    /// Forget every edge and held set; every collection is recomputed as if
    /// newly tracked. Seeds and peer reports are kept as roots.
    fn reset(&mut self) {
        self.edges.clear();
        self.pending.clear();
        self.epoch += 1;
        for tracked in self.tracked.values_mut() {
            tracked.held = HeldBlobs::new();
            tracked.fresh = true;
        }
    }

    fn publish_view(&mut self) {
        self.generation += 1;
        self.view = Arc::new(HeldView {
            generation: self.generation,
            sets: self
                .tracked
                .iter()
                .filter(|(_, tracked)| !tracked.fresh)
                .map(|(collection, tracked)| (*collection, tracked.held.clone()))
                .collect(),
        });
    }

    /// Roots of one full walk: the seeds and peer reports of every collection
    /// whose seeds are known.
    fn walk_roots(&self) -> Vec<(CollectionHandle, Vec<Raw>)> {
        self.tracked
            .iter()
            .filter(|(_, tracked)| !tracked.fresh)
            .map(|(collection, tracked)| {
                let mut roots: Vec<Raw> = tracked.seeds.iter().copied().collect();
                roots.extend(tracked.routes.iter().copied());
                roots.sort_unstable();
                roots.dedup();
                (*collection, roots)
            })
            .collect()
    }
}

impl<T: HeldSource> HeldIndex<T> {
    /// Extend the held sets by everything `now` holds that the last observed
    /// snapshot did not, and hand out the result, fixed from here on.
    pub(crate) fn observe(&self, now: &T) -> Arc<HeldView> {
        let mut state = self.lock();
        if state.tracked.is_empty() {
            state.candidates.clear();
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

        let mut roots: BTreeMap<CollectionHandle, Vec<Raw>> = BTreeMap::new();
        if let Some(fed) = state.fed.take() {
            if changes.contains(StoreChanges::COLLECTION_RECORDS) {
                let tracked = &mut state.tracked;
                now.for_each_record_since(Some(&fed), &mut |record| {
                    let collection = record.collection();
                    let Some(entry) = tracked.get_mut(&collection) else {
                        return;
                    };
                    if entry.fresh {
                        return;
                    }
                    let Some(seeds) = seeds_of(record) else {
                        return;
                    };
                    for seed in seeds {
                        if entry.seeds.insert(seed) {
                            roots.entry(collection).or_default().push(seed);
                        }
                    }
                });
            }
            if changes.contains(StoreChanges::CAPABILITY_PROOFS) {
                let settled: BTreeSet<_> = state
                    .tracked
                    .iter()
                    .filter(|(_, tracked)| !tracked.fresh)
                    .map(|(collection, _)| *collection)
                    .collect();
                for (collection, seed) in proof_seeds(now, &settled) {
                    let entry = state.tracked.get_mut(&collection).expect("tracked");
                    if entry.seeds.insert(seed) {
                        roots.entry(collection).or_default().push(seed);
                    }
                }
            }
            if changes.contains(StoreChanges::BLOBS) && !state.pending.is_empty() {
                // Seeds whose bytes arrived since. A store without an indexed
                // difference lists every blob; pending entries still match once.
                for info in now.blobs_diff(&fed).flatten() {
                    if let Some(waiting) = state.pending.remove(&info.handle.raw) {
                        for collection in waiting {
                            roots.entry(collection).or_default().push(info.handle.raw);
                        }
                    }
                }
            }
        }

        let fresh: BTreeSet<_> = state
            .tracked
            .iter()
            .filter(|(_, tracked)| tracked.fresh)
            .map(|(collection, _)| *collection)
            .collect();
        if !fresh.is_empty() {
            let selectors = fresh
                .iter()
                .map(|collection| CollectionRecordSelector::Foundations(*collection))
                .collect();
            let mut seeds: BTreeMap<CollectionHandle, Vec<Raw>> = fresh
                .iter()
                .map(|collection| (*collection, vec![collection.raw]))
                .collect();
            if let Ok(records) = now.select_records(&selectors) {
                for record in records {
                    if let (Some(list), Some(named)) =
                        (seeds.get_mut(&record.collection()), seeds_of(&record))
                    {
                        list.extend(named);
                    }
                }
            }
            for (collection, seed) in proof_seeds(now, &fresh) {
                seeds.get_mut(&collection).expect("fresh").push(seed);
            }
            let background = state.walker.is_some();
            for (collection, mut list) in seeds {
                let entry = state.tracked.get_mut(&collection).expect("fresh");
                entry.seeds.extend(list.iter().copied());
                list.extend(entry.routes.iter().copied());
                entry.fresh = false;
                if background {
                    // The start-up walk reads these; only what is already
                    // scanned joins now.
                    state.reach(None, collection, list);
                } else {
                    roots.entry(collection).or_default().extend(list);
                }
            }
            changed = true;
            if let Some(walker) = &mut state.walker {
                walker.requested = true;
                self.wake.notify_all();
            }
        }

        for (collection, list) in roots {
            changed |= state.reach(Some(now), collection, list);
        }
        let candidates = std::mem::take(&mut state.candidates);
        for (collection, handle) in candidates {
            let Some(entry) = state.tracked.get(&collection) else {
                continue;
            };
            if entry.held.has_prefix(&handle) {
                continue;
            }
            if state.reach(Some(now), collection, [handle]) {
                state
                    .tracked
                    .get_mut(&collection)
                    .expect("tracked")
                    .routes
                    .insert(handle);
                changed = true;
            }
        }
        state.fed = Some(now.clone());
        if changed {
            state.publish_view();
        }
        state.view.clone()
    }

    /// Publish one level of a walk: its scanned edges, the blobs it reached
    /// per collection, and the seeds it could not read.
    fn publish(
        &self,
        epoch: u64,
        scanned: Vec<(Raw, Option<Arc<[Raw]>>)>,
        reached: Vec<(CollectionHandle, Vec<Raw>)>,
        unreadable: Vec<(CollectionHandle, Raw)>,
    ) {
        let mut state = self.lock();
        if state.epoch != epoch {
            return;
        }
        for (handle, children) in scanned {
            let Some(children) = children else {
                continue;
            };
            match state.edges.get_mut(&handle) {
                Some(known) if **known == *children => {}
                Some(known) => {
                    let mut merged: Vec<Raw> =
                        known.iter().chain(children.iter()).copied().collect();
                    merged.sort_unstable();
                    merged.dedup();
                    *known = merged.into();
                }
                None => {
                    state.edges.insert(handle, children);
                }
            }
        }
        for (collection, handle) in unreadable {
            let Some(entry) = state.tracked.get(&collection) else {
                continue;
            };
            if entry.seeds.contains(&handle) && !entry.held.has_prefix(&handle) {
                state.pending.entry(handle).or_default().insert(collection);
            }
        }
        let mut changed = false;
        for (collection, nodes) in reached {
            changed |= state.reach(None, collection, nodes);
        }
        if changed {
            state.publish_view();
        }
    }

    /// One full walk against `snapshot`: rescan every blob reachable from
    /// every tracked collection's seeds and peer reports, refresh the edge
    /// cache, and publish level by level.
    pub(crate) fn walk(&self, snapshot: &T, threads: usize) {
        let (mut frontier, epoch) = {
            let state = self.lock();
            (state.walk_roots(), state.epoch)
        };
        let threads = threads.max(1);
        let mut known: HashMap<Raw, Option<Arc<[Raw]>>> = HashMap::new();
        let mut seen: BTreeMap<CollectionHandle, HashSet<Raw>> = BTreeMap::new();
        while frontier.iter().any(|(_, nodes)| !nodes.is_empty()) {
            if self.stopping() {
                return;
            }
            let mut need: Vec<Raw> = frontier
                .iter()
                .flat_map(|(_, nodes)| nodes.iter().copied())
                .filter(|handle| !known.contains_key(handle))
                .collect();
            need.sort_unstable();
            need.dedup();
            let scanned = scan_all(snapshot, &need, threads, &self.halt);
            if self.stopping() {
                // A partial level is not published.
                return;
            }
            for (handle, children) in &scanned {
                known.insert(*handle, children.clone());
            }
            let mut reached = Vec::with_capacity(frontier.len());
            let mut unreadable = Vec::new();
            let mut next = Vec::with_capacity(frontier.len());
            for (collection, nodes) in frontier {
                let seen = seen.entry(collection).or_default();
                let mut here = Vec::new();
                let mut after = Vec::new();
                for handle in nodes {
                    if !seen.insert(handle) {
                        continue;
                    }
                    match &known[&handle] {
                        Some(children) => {
                            here.push(handle);
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
                reached.push((collection, here));
                next.push((collection, after));
            }
            // Published in bounded pieces, so a snapshot taken meanwhile waits
            // for one piece, never for a whole level of a large start-up walk.
            let mut scanned = scanned.into_iter().peekable();
            while scanned.peek().is_some() {
                let piece: Vec<_> = scanned.by_ref().take(PUBLISH_PIECE).collect();
                self.publish(epoch, piece, Vec::new(), Vec::new());
            }
            self.publish(epoch, Vec::new(), Vec::new(), unreadable);
            for (collection, nodes) in reached {
                for piece in nodes.chunks(PUBLISH_PIECE) {
                    self.publish(
                        epoch,
                        Vec::new(),
                        vec![(collection, piece.to_vec())],
                        Vec::new(),
                    );
                }
            }
            frontier = next;
        }
    }
}

/// Blobs published per lock hold by a walk.
const PUBLISH_PIECE: usize = 16_384;

/// Scan `handles` on `threads` blocking threads, stopping early once `halt`
/// is set.
fn scan_all<T: HeldSource>(
    snapshot: &T,
    handles: &[Raw],
    threads: usize,
    halt: &AtomicBool,
) -> Vec<(Raw, Option<Arc<[Raw]>>)> {
    let scan_part = |part: &[Raw]| {
        part.iter()
            .take_while(|_| !halt.load(Ordering::Relaxed))
            .map(|handle| (*handle, scan(snapshot, handle)))
            .collect::<Vec<_>>()
    };
    if threads <= 1 || handles.len() < 2 {
        return scan_part(handles);
    }
    let chunk = handles.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let workers: Vec<_> = handles
            .chunks(chunk)
            .map(|part| scope.spawn(move || scan_part(part)))
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
            state.walker = Some(Walker {
                requested: false,
                stop: false,
            });
        }
        WALKER_THREADS.fetch_add(1, Ordering::SeqCst);
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
            let snapshot = {
                let mut state = self.lock();
                loop {
                    let Some(walker) = state.walker else {
                        return;
                    };
                    if walker.stop {
                        state.walker = None;
                        return;
                    }
                    let now = Instant::now();
                    if walker.requested || now >= due {
                        break;
                    }
                    state = self
                        .wake
                        .wait_timeout(state, due - now)
                        .expect("held-blob index is not poisoned")
                        .0;
                }
                if let Some(walker) = &mut state.walker {
                    walker.requested = false;
                }
                due = Instant::now() + config.interval;
                state.fed.clone()
            };
            if let Some(snapshot) = snapshot {
                self.walk(&snapshot, config.threads);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::{BlobEncoding, IntoBlob, TryFromBlob};
    use crate::capability::{CapabilityProof, CapabilityProofId, CapabilityResource};
    use crate::collection::covered::Covered;
    use crate::collection::{
        CollectionCommit, CollectionDerive, CollectionMerge, CollectionStore, SourceLocator,
    };
    use crate::inline::InlineEncoding;
    use crate::repo::memoryrepo::{MemoryStore, MemoryStoreSnapshot};
    use crate::repo::{BlobInfo, BlobStorePut, CapabilityProofStore, SnapshotSource};

    type Reads = Arc<Mutex<HashMap<Raw, usize>>>;

    /// A memory store whose snapshots count every blob body read, per blob.
    #[derive(Default)]
    struct Counting {
        inner: MemoryStore,
        reads: Reads,
    }

    #[derive(Clone)]
    struct CountingSnapshot {
        inner: MemoryStoreSnapshot,
        reads: Reads,
    }

    impl SnapshotSource for Counting {
        type Snapshot = CountingSnapshot;
        type SnapshotError = Infallible;

        fn snapshot(&mut self) -> Result<Self::Snapshot, Self::SnapshotError> {
            Ok(CountingSnapshot {
                inner: self.inner.snapshot()?,
                reads: self.reads.clone(),
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

    impl CollectionRead for CountingSnapshot {
        type RecordsError = <MemoryStoreSnapshot as CollectionRead>::RecordsError;
        type RecordIter<'a> = <MemoryStoreSnapshot as CollectionRead>::RecordIter<'a>;

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
    }

    impl CapabilityProofRead for CountingSnapshot {
        type ProofsError = <MemoryStoreSnapshot as CapabilityProofRead>::ProofsError;
        type ProofIter<'a> = <MemoryStoreSnapshot as CapabilityProofRead>::ProofIter<'a>;

        fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
            self.inner.proofs()
        }

        fn proof(
            &self,
            id: CapabilityProofId,
        ) -> Result<Option<CapabilityProof>, Self::ProofsError> {
            self.inner.proof(id)
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
        let c = collection(&mut store, "proven");
        let root = SigningKey::from_bytes(&[42; 32]);
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

    static WALKER_TESTS: Mutex<()> = Mutex::new(());

    fn walker_guard() -> std::sync::MutexGuard<'static, ()> {
        WALKER_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Opening, reading and even tracking start no thread; only an explicit
    /// walker does, and dropping it stops it.
    #[test]
    fn short_lived_opens_start_no_walker() {
        let _guard = walker_guard();
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
        assert_eq!(held_walker_threads(), 0);
        let walker = pile.start_held_walker(HeldWalkConfig::default());
        assert_eq!(held_walker_threads(), 1);
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
