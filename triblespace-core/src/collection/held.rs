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
//! resource whose descriptor entity routes to C and declares the root,
//! whether or not that resource is tracked too; a proof whose descriptors
//! arrive later is judged on their arrival). A valid proof irrelevant to C
//! seeds nothing. A MERGE never replicates, so its result is never a seed,
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
//! they never change afterwards. Taking a snapshot first extends the sets by
//! the closures of what arrived since the previous one -- every seed of a new
//! record (one another record already named included), seeds whose bytes
//! arrived, memberships peers reported -- computed against that snapshot.
//! That is the publication barrier: an observation is never handed out ahead
//! of its new records' closures. A changed [`HeldRead::held_generation`] says
//! the sets grew although the store may not have changed, as a report does.
//!
//! A held set is *closed* under the edge cache for readable children: a blob
//! joins only once every child the cache names for it has joined. So every
//! closure computed later stops at a held blob without missing anything
//! readable the cache knows below it. A blob that cannot be read -- absent,
//! or resident and failing to read -- is unknown on every path: nothing above
//! it joins. A seed is read again when its bytes arrive, a reported blob when
//! a peer reports it again.
//!
//! When a collection is first tracked, its existing closure is computed by
//! the next snapshot, which reads every blob it reaches once. Nothing here
//! starts a thread.
//!
//! A snapshot that lost a blob its predecessor had (a store that forgets
//! blobs) resets the index: the edges are forgotten and every collection is
//! recomputed as if newly tracked.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

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
    /// may differ, including when only a peer's report added to them.
    fn held_generation(&self) -> u64;
}

/// Tracking and routing evidence for a store's held sets.
pub trait HeldStore {
    /// Keep held sets for `collections` from the next snapshot on.
    fn track_held(&mut self, collections: impl IntoIterator<Item = CollectionHandle>);

    /// A peer reported `handle` in its held set of `collection`. If the blob
    /// is resident when the next snapshot is taken, it and everything it
    /// reaches join `held(collection)`; a report of a blob that is not
    /// resident is dropped. Kept in memory only.
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
    /// Collection and resource descriptors that were not resident when
    /// proofs were judged; the arrival of one judges the proofs again.
    unrouted: Handles,
    /// Proof seeds are recomputed at the next observation: reading the proofs
    /// failed, or a descriptor arrived.
    proofs_stale: bool,
    /// `collection || blob`: peer reports not resolved yet.
    candidates: Pairs,
    /// The last observation fed in.
    fed: Option<T>,
    generation: u64,
    view: Arc<HeldView>,
}

/// The shared held-blob index of one store. Its own lock: holding it never
/// blocks a coverage read. A clone is an independent copy.
pub(crate) struct HeldIndex<T> {
    state: Mutex<State<T>>,
}

impl<T> Default for HeldIndex<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                tracked: Handles::new(),
                held: HeldSets::new(),
                seeds: Pairs::new(),
                routes: Pairs::new(),
                scanned: Handles::new(),
                edges: Pairs::new(),
                pending: Pairs::new(),
                unrouted: Handles::new(),
                proofs_stale: false,
                candidates: Pairs::new(),
                fed: None,
                generation: 0,
                view: Arc::new(HeldView::default()),
            }),
        }
    }
}

impl<T: Clone> Clone for HeldIndex<T> {
    fn clone(&self) -> Self {
        Self {
            state: Mutex::new(self.lock().clone()),
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
    /// Collection and resource descriptors that are not resident: their
    /// arrival may let a proof be judged for one of the collections. One
    /// that is resident and cannot be read judges nothing, and nothing
    /// arrives to judge it again.
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
        self.held = HeldSets::new();
    }

    fn publish_view(&mut self) {
        self.generation += 1;
        self.view = Arc::new(HeldView {
            generation: self.generation,
            sets: self.held.clone(),
        });
    }

    /// Record one scan: the blob, and an edge to each resident child.
    fn record_scan(&mut self, handle: Raw, children: &[Raw]) {
        self.scanned.insert(&Entry::new(&handle));
        for child in children {
            self.edges.insert(&Entry::new(&pair(&handle, child)));
        }
    }
}

impl<T: HeldSource> State<T> {
    /// Add everything reachable from `roots` to `collection`'s held set.
    ///
    /// A blob joins only after every resident child it has joined, so a held
    /// blob's whole closure is held and a later closure stops at it. A blob
    /// never scanned is read now; one that cannot be read, resident or not,
    /// is unknown, and so is everything above it.
    fn reach(
        &mut self,
        snapshot: &T,
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
            } else {
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
                        // Not readable: absent, or resident and failing to
                        // read. Either way nothing above it joins.
                        unknown.insert(handle);
                        continue;
                    }
                }
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
                    // Every seed of a new record is a root, known or not: the
                    // record is published with its whole closure. A held seed
                    // costs one lookup.
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
                    roots.entry(collection).or_default().extend(list);
                }
                changed = true;
            }
        }

        for (collection, list) in roots {
            changed |= state.reach(now, collection, list);
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
            changed |= state.reach(now, collection, [handle]);
        }
        state.fed = Some(now.clone());
        if changed {
            state.publish_view();
        }
        state.view.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use anybytes::Bytes;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::blob::{Blob, BlobEncoding, IntoBlob, TryFromBlob};
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
        let snapshot = store.snapshot().unwrap();
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
        let after = store.snapshot().unwrap();
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
        let first = store.snapshot().unwrap();
        assert!(held_set(&first, c).contains(&p));
        store.put::<UnknownBlob, _>(h_bytes).unwrap();
        for _ in 0..3 {
            let snapshot = store.snapshot().unwrap();
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
        let reset = store.snapshot().unwrap();
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
            store.snapshot().unwrap();
            store.snapshot().unwrap();
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
        let settled = store.snapshot().unwrap();
        assert!(held_set(&settled, c).is_superset(&BTreeSet::from([c.raw, metadata])));
        assert_closed(&settled, c);
        assert!(!held_set(&settled, c).contains(&data));
        store.faults.unreadable.lock().unwrap().remove(&z);
        assert!(!held_set(&store.snapshot().unwrap(), c).contains(&data));
        store.note_held(c, Inline::new(data));
        let reported = store.snapshot().unwrap();
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
}
