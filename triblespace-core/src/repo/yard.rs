//! Generational collection of piles for lazy-retention blob storage plus
//! generation-independent native collection-record and complete-proof unions.
//!
//! A [`Yard`](crate::repo::yard::Yard) keeps an ordered young-to-old sequence of [`Pile`](crate::repo::pile::Pile)
//! generations. Writes land in the youngest generation, reads search the union
//! of each generation's live PATCH set, and retention/compaction update those
//! PATCH sets without changing Pile's append-only storage contract. Call
//! [`Yard::reclaim`](crate::repo::yard::Yard::reclaim) after collection when the logically evicted blobs should
//! also be physically removed from disk.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::blob::encodings::UnknownBlob;
use crate::blob::{Blob, BlobEncoding, IntoBlob, TryFromBlob};
use crate::capability::{CapabilityProof, CapabilityProofId};
use crate::collection::{
    CollectionRead, CollectionRecord, CollectionRecordFingerprint, CollectionRecordSelector,
    CollectionStore,
};
#[cfg(test)]
use crate::id::Id;
use crate::inline::encodings::hash::Handle;
use crate::inline::{Inline, InlineEncoding, INLINE_LEN};
use crate::patch::{Entry, IdentitySchema, PATCH};
use anybytes::Bytes;

#[cfg(test)]
use super::pile::assert_record_kind_description_resident;
use super::pile::{
    blob_record_kind, capability_proof_record_kind, collection_record_kind, want_record_kind,
    CapabilityProofInsertError, CollectionInsertError, GetBlobError, InsertError, Pile,
    PileSnapshot, PileWriteError, ReadError,
};
use super::proof::{CapabilityProofRead, CapabilityProofStore};
use super::{
    transfer, BlobChildren, BlobInfo, BlobStoreGet, BlobStoreList, BlobStoreMeta, BlobStorePut,
    RetentionRoots, SnapshotSource, StorageClose, StoreChanges, StoreSnapshot, TransferError,
    WantRead, WantRequest, WantStore, WANT_REQUEST_BYTES_LEN,
};

type HandleSet = PATCH<INLINE_LEN, IdentitySchema>;
type WantIndex = PATCH<WANT_REQUEST_BYTES_LEN, IdentitySchema>;

fn retain_kind_if_present(
    retention: &mut RetentionRoots,
    present: &HandleSet,
    kind: super::pile::RecordKind,
) {
    if present.get(&kind.raw).is_some() {
        retention.retain_recursive(kind);
    }
}

#[derive(Debug, Default)]
struct WantState {
    /// Every request is keyed by its complete canonical identity.
    requests: WantIndex,
}

impl WantState {
    fn want(&mut self, request: WantRequest) {
        self.requests.insert(&Entry::new(&request.to_bytes()));
    }

    fn requests(&self) -> Vec<WantRequest> {
        self.requests
            .iter_ordered()
            .map(|bytes| {
                WantRequest::from_bytes(*bytes)
                    .expect("Yard WANT index contains canonical request bytes")
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct YardConfig {
    /// Strong survivor budget for the youngest level.
    pub strong_level_budget: usize,
    /// Per-level strong budget multiplier.
    pub fanout: usize,
}

impl Default for YardConfig {
    fn default() -> Self {
        Self {
            strong_level_budget: 1024,
            fanout: 10,
        }
    }
}

#[derive(Debug)]
struct Segment {
    path: PathBuf,
    pile: Option<Pile>,
    live: HandleSet,
}

impl Segment {
    fn pile_mut(&mut self) -> &mut Pile {
        self.pile
            .as_mut()
            .expect("yard segment pile already closed")
    }
}

/// A generation (tier): an ordered list of segments. The youngest segment is
/// the active write target; reads union across all segments. (Today every
/// generation holds exactly one segment; multi-segment tiers land next.)
#[derive(Debug)]
struct Generation {
    segments: Vec<Segment>,
}

impl Generation {
    fn one(segment: Segment) -> Self {
        Self {
            segments: vec![segment],
        }
    }

    /// The active write segment — the youngest in the tier.
    fn active_mut(&mut self) -> &mut Segment {
        self.segments
            .last_mut()
            .expect("yard generation has no segment")
    }

    /// Total live blobs across the tier's segments.
    fn live_len(&self) -> usize {
        self.segments.iter().map(|s| s.live.len() as usize).sum()
    }
}

/// Generational, LSM-style collection of piles.
#[derive(Debug)]
pub struct Yard {
    generations: Vec<Generation>,
    config: YardConfig,
    want_state: Arc<Mutex<WantState>>,
}

impl Yard {
    fn opaque_record_count(&mut self) -> Result<usize, ReadError> {
        let mut count = 0usize;
        for generation in &mut self.generations {
            for segment in &mut generation.segments {
                count = count
                    .checked_add(segment.pile_mut().opaque_record_count()?)
                    .expect("yard opaque-record count overflow");
            }
        }
        Ok(count)
    }

    /// Create a fresh yard, truncating/creating one pile file per generation.
    pub fn create<P>(
        paths: impl IntoIterator<Item = P>,
        config: YardConfig,
    ) -> Result<Self, YardOpenError>
    where
        P: AsRef<Path>,
    {
        let mut generations = Vec::new();
        for path in paths {
            let path = path.as_ref().to_path_buf();
            File::create(&path).map_err(YardOpenError::Io)?;
            let pile = Pile::open(&path).map_err(|err| YardOpenError::Pile {
                path: path.clone(),
                err,
            })?;
            generations.push(Generation::one(Segment {
                path,
                pile: Some(pile),
                live: HandleSet::new(),
            }));
        }
        if generations.is_empty() {
            return Err(YardOpenError::NoGenerations);
        }
        Ok(Self {
            generations,
            config,
            want_state: Arc::new(Mutex::new(WantState::default())),
        })
    }

    /// Open an existing yard and treat all blobs in each pile as live.
    ///
    /// Fails loud on corruption: a generation pile with an invalid tail
    /// surfaces as [`YardOpenError::Pile`] naming the file, and **nothing is
    /// truncated**. Repair is an explicit opt-in via [`Yard::amputate`]
    /// (mirroring [`Pile::refresh`] vs [`Pile::amputate`]).
    ///
    /// The wanted set is the union of the grow-only markers in every
    /// generation. Retired assertion/retraction frames are inert; deployments
    /// preserving their final active projection run the explicit one-time
    /// `monotone-wants` pile migration before switching binaries.
    pub fn open<P>(
        paths: impl IntoIterator<Item = P>,
        config: YardConfig,
    ) -> Result<Self, YardOpenError>
    where
        P: AsRef<Path>,
    {
        Self::open_impl(paths, config, false)
    }

    /// Open an existing yard, **amputating** each generation pile first:
    /// every generation file is **TRUNCATED at its first invalid record,
    /// destroying everything after it**, exactly like [`Pile::amputate`].
    /// This is the explicit opt-in counterpart to the fail-loud [`Yard::open`] — reach for it only after `open` reported
    /// corruption and losing the invalid tail is acceptable.
    pub fn amputate<P>(
        paths: impl IntoIterator<Item = P>,
        config: YardConfig,
    ) -> Result<Self, YardOpenError>
    where
        P: AsRef<Path>,
    {
        Self::open_impl(paths, config, true)
    }

    fn open_impl<P>(
        paths: impl IntoIterator<Item = P>,
        config: YardConfig,
        repair: bool,
    ) -> Result<Self, YardOpenError>
    where
        P: AsRef<Path>,
    {
        let mut generations = Vec::new();
        for path in paths {
            let path = path.as_ref().to_path_buf();
            let mut pile = Pile::open(&path).map_err(|err| YardOpenError::Pile {
                path: path.clone(),
                err,
            })?;
            let load = if repair {
                pile.amputate()
            } else {
                pile.refresh()
            };
            load.map_err(|err| YardOpenError::Pile {
                path: path.clone(),
                err,
            })?;
            let reader = pile.snapshot().map_err(|err| YardOpenError::Pile {
                path: path.clone(),
                err,
            })?;
            let live = collect_list(reader.blobs()).map_err(YardOpenError::List)?;
            generations.push(Generation::one(Segment {
                path,
                pile: Some(pile),
                live,
            }));
        }
        if generations.is_empty() {
            return Err(YardOpenError::NoGenerations);
        }
        // WANT is a grow-only set, so generation order is irrelevant to
        // membership and every generation may contribute safely. Visit old to
        // young only so a duplicate young blob request receives the newest
        // in-memory cache-recency value.
        let mut want_state = WantState::default();
        for generation in generations.iter_mut().rev() {
            for segment in &mut generation.segments {
                let path = segment.path.clone();
                let requests = segment
                    .pile_mut()
                    .snapshot()
                    .map_err(|err| YardOpenError::Pile { path, err })?
                    .wants()
                    .map_err(update_err_io)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(update_err_io)?;
                for request in requests {
                    want_state.want(request);
                }
            }
        }
        Ok(Self {
            generations,
            config,
            want_state: Arc::new(Mutex::new(want_state)),
        })
    }

    /// Number of generations in young-to-old order.
    pub fn generation_count(&self) -> usize {
        self.generations.len()
    }

    /// Number of live blobs in a generation.
    pub fn generation_len(&self, level: usize) -> Option<usize> {
        self.generations.get(level).map(|g| g.live_len())
    }

    /// Returns whether a live handle is currently associated with `level`.
    pub fn contains_in_generation<S>(&self, level: usize, handle: Inline<Handle<S>>) -> bool
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        let handle: Inline<Handle<UnknownBlob>> = handle.transmute();
        self.generations
            .get(level)
            .is_some_and(|g| g.segments.iter().any(|s| s.live.get(&handle.raw).is_some()))
    }

    /// Anchor the complete surviving WANT union in the young pile before an
    /// old-only rewrite can destroy its last older marker. A young rewrite
    /// instead writes this union into its replacement before atomic rename.
    fn anchor_wants_in_young(&mut self) -> Result<(), std::io::Error> {
        let wants: Vec<WantRequest> = {
            let want_state = self.want_state.lock().expect("want mutex poisoned");
            want_state.requests()
        };
        let pile = self.generations[0].active_mut().pile_mut();
        for request in wants {
            pile.want(request).map_err(|err| match err {
                PileWriteError::IoError(io) => io,
            })?;
        }
        pile.flush().map_err(|err| match err {
            super::pile::FlushError::IoError(io) => io,
        })?;
        Ok(())
    }

    /// Recompute the keep set with explicit policy roots and logically collect
    /// unowned blobs.
    ///
    /// The supplied roots are strong for this pass. Direct roots retain only
    /// themselves; recursive roots retain their resident descendants. Every
    /// retained native collection record and WANT adds all of its resident
    /// direct references as recursive roots; self-contained capability proofs
    /// add none. This structural ownership is independent of signatures,
    /// admission, or algebraic usefulness. Missing references remain missing
    /// and never trigger a fetch or prevent resident siblings from surviving.
    /// Pass an empty [`RetentionRoots`] explicitly when native records supply
    /// the only roots.
    pub fn collect(&mut self, retention: &RetentionRoots) -> Result<(), YardCollectError> {
        let (_snapshot, keep) = self.retention_observation(retention)?;
        for generation in &mut self.generations {
            for segment in &mut generation.segments {
                segment.live = segment.live.intersect(&keep);
            }
        }
        Ok(())
    }

    /// Run one compaction pass with explicit policy roots.
    ///
    /// Strong survivors descend when a level exceeds its strong budget. The
    /// whole surviving tier moves together. WANT references are ordinary
    /// strong survivors for as long as their record is retained. Pass an empty
    /// [`RetentionRoots`] explicitly when native evidence supplies the only
    /// desired strong roots.
    pub fn compact(&mut self, retention: &RetentionRoots) -> Result<(), YardCollectError> {
        self.collect(retention)?;
        let last = self.generations.len().saturating_sub(1);
        let mut dumped = Vec::new();

        {
            let (snapshot, strong_keep) = self.retention_observation(retention)?;

            for level in 0..last {
                let strong_here = self.generations[level].segments[0]
                    .live
                    .intersect(&strong_keep);
                if strong_here.len() as usize <= self.strong_budget_for(level) {
                    continue;
                }

                // Overflow: dump the whole tier down. `collect(retention)`
                // above already dropped dead, so the segment's `live` is
                // exactly the structural survivors.
                let movers = self.generations[level].segments[0].live.clone();
                let handles: Vec<_> = movers
                    .clone()
                    .into_iter()
                    .map(Inline::<Handle<UnknownBlob>>::new)
                    .collect();

                let mut copied = Vec::new();
                {
                    let target = self.generations[level + 1].active_mut().pile_mut();
                    for result in transfer(&snapshot, target, handles.clone()) {
                        let (source, _target) = result.map_err(YardCollectError::Transfer)?;
                        copied.push(source);
                    }
                }

                {
                    let target = self.generations[level + 1].active_mut();
                    for source in copied {
                        target.live.insert(&Entry::new(&source.raw));
                    }
                }

                for raw in movers {
                    self.generations[level].segments[0].live.remove(&raw);
                }

                // Make the moved blobs durable in the target before the source
                // pile is recycled below, so a crash can't drop content that
                // would briefly live in neither place.
                self.generations[level + 1]
                    .active_mut()
                    .pile_mut()
                    .flush()
                    .map_err(YardCollectError::Flush)?;
                dumped.push(level);
            }
        }

        // Fold reclamation into the merge: each dumped tier is now empty, so
        // recycle its segment in place (crash-safe write-empty + atomic rename)
        // rather than leaving dead bytes for a separate reclaim() pass. If the
        // young tier itself stays put, first anchor the full surviving WANT
        // union there; an older tier may hold its only durable copy.
        if !dumped.is_empty() && !dumped.contains(&0) {
            self.anchor_wants_in_young()
                .map_err(YardCollectError::WantMarkers)?;
        }
        for level in dumped {
            self.reclaim_segment(level, 0)
                .map_err(YardCollectError::Reclaim)?;
        }

        self.collect(retention)
    }

    /// Physically rewrite each generation's pile to contain only its live set.
    ///
    /// Collection and compaction are logical operations: they update each
    /// generation's live PATCH set, so evicted blobs stop being readable through
    /// Yard readers, but they do not mutate the underlying append-only pile
    /// files. `reclaim` is the explicit physical step. For each generation it
    /// writes the current live handles, every native collection record, and
    /// every canonical complete proof to a sibling temporary pile. The active
    /// young replacement also receives the complete surviving WANT union. It
    /// then closes both piles, atomically renames the temporary file over the
    /// original on the same filesystem, and reopens the generation. Recognized
    /// retired PEER and STORE_SCOPE records are deliberately omitted.
    pub fn reclaim(&mut self) -> Result<(), YardReclaimError> {
        let opaque_records = self.opaque_record_count().map_err(YardReclaimError::Pile)?;
        if opaque_records != 0 {
            return Err(YardReclaimError::OpaqueRecords {
                count: opaque_records,
            });
        }
        for level in 0..self.generations.len() {
            for index in 0..self.generations[level].segments.len() {
                self.reclaim_segment(level, index)?;
            }
        }
        Ok(())
    }

    /// Rewrite the segment at `(level, index)` down to its live set via
    /// [`reclaim_generation`]. If the rewrite fails, reopen the generation
    /// file as-is (fail-loud: [`Pile::refresh`], no repair, no truncation)
    /// so the yard stays usable and the rewrite error propagates. If even
    /// the reopen fails — for example the file is corrupt — both errors
    /// propagate together via [`YardReclaimError::Reopen`] and the segment
    /// is left closed.
    fn reclaim_segment(&mut self, level: usize, index: usize) -> Result<(), YardReclaimError> {
        // Put the complete surviving WANT union in the active young segment's
        // replacement *before* its atomic rename. A post-rename append would
        // leave a crash window in which the only durable marker was lost.
        let wants = if level == 0 && index + 1 == self.generations[level].segments.len() {
            self.want_state
                .lock()
                .expect("want mutex poisoned")
                .requests()
        } else {
            Vec::new()
        };
        let segment = &mut self.generations[level].segments[index];
        let path = segment.path.clone();
        let temp_path = reclaim_temp_path(&path, level);
        let live = segment.live.clone();
        let pile = segment
            .pile
            .take()
            .expect("yard segment pile already closed");

        match reclaim_generation(&path, &temp_path, &live, &wants, pile) {
            Ok(pile) => {
                self.generations[level].segments[index].pile = Some(pile);
                Ok(())
            }
            Err(primary) => {
                let reopen = Pile::open(&path).and_then(|mut pile| {
                    pile.refresh()?;
                    Ok(pile)
                });
                match reopen {
                    Ok(pile) => {
                        self.generations[level].segments[index].pile = Some(pile);
                        Err(primary)
                    }
                    Err(err) => Err(YardReclaimError::Reopen {
                        path,
                        primary: Box::new(primary),
                        err,
                    }),
                }
            }
        }
    }

    fn strong_budget_for(&self, level: usize) -> usize {
        let multiplier = self.config.fanout.max(1).saturating_pow(level as u32);
        self.config.strong_level_budget.saturating_mul(multiplier)
    }

    /// Freeze the one coherent prefix used by an entire retention-planning
    /// phase. Unknown-record refusal, native commits, complete proofs, and
    /// live blob membership must never be sampled from different prefixes.
    fn retention_observation(
        &mut self,
        retention: &RetentionRoots,
    ) -> Result<(YardSnapshot, HandleSet), YardCollectError> {
        let snapshot = self.snapshot().map_err(YardCollectError::Snapshot)?;
        let opaque_records = snapshot.opaque_record_count();
        if opaque_records != 0 {
            return Err(YardCollectError::OpaqueRecords {
                count: opaque_records,
            });
        }
        let present = snapshot.live_set();
        let retention = self
            .retention_with_collection_records(&snapshot, &present, retention)
            .map_err(YardCollectError::CollectionRecords)?;
        let retention = self
            .retention_with_capability_proofs(&snapshot, &present, &retention)
            .map_err(YardCollectError::CapabilityProofs)?;
        let mut retention = self.retention_with_wants(&present, &retention);
        let mut strong_keep = self.strong_keep_set(&snapshot, &retention);
        if strong_keep.intersect(&present).len() != 0 {
            retain_kind_if_present(&mut retention, &present, blob_record_kind());
            strong_keep = self.strong_keep_set(&snapshot, &retention);
        }
        Ok((snapshot, strong_keep))
    }

    /// Add every resident direct reference and physical kind description of
    /// every native collection record.
    fn retention_with_collection_records(
        &self,
        snapshot: &YardSnapshot,
        present: &HandleSet,
        retention: &RetentionRoots,
    ) -> Result<RetentionRoots, YardCollectionRecordsError> {
        let mut combined = retention.clone();
        let records = snapshot.records()?.collect::<Result<Vec<_>, _>>()?;
        for record in records {
            retain_kind_if_present(&mut combined, present, collection_record_kind(record));
            for handle in record.blob_references() {
                if present.get(&handle.raw).is_some() {
                    combined.retain_recursive(handle);
                }
            }
        }
        // Retired unsigned equations remain inert, but their evidence owns
        // resident dependencies across every generation until explicit writer
        // endorsement is possible. Do not project these as current records.
        for generation in &snapshot.generations {
            for handle in generation.snapshot.legacy_unsigned_collection_references() {
                if present.get(&handle.raw).is_some() {
                    combined.retain_recursive(handle);
                }
            }
        }
        Ok(combined)
    }

    /// Retain physical kind and resident capability definitions of native proofs.
    /// The opaque resource is not a blob reference; missing definitions remain
    /// missing rather than causing acquisition during GC.
    fn retention_with_capability_proofs(
        &self,
        snapshot: &YardSnapshot,
        present: &HandleSet,
        retention: &RetentionRoots,
    ) -> Result<RetentionRoots, YardCapabilityProofError> {
        let mut combined = retention.clone();
        let proofs = snapshot
            .proofs()?
            .collect::<Result<Vec<_>, YardCapabilityProofError>>()?;
        if !proofs.is_empty() {
            retain_kind_if_present(&mut combined, present, capability_proof_record_kind());
        }
        for proof in proofs {
            for handle in proof.blob_references() {
                if present.get(&handle.raw).is_some() {
                    combined.retain_recursive(handle);
                }
            }
        }
        Ok(combined)
    }

    /// Add every resident direct reference and physical kind description of
    /// every retained WANT record.
    fn retention_with_wants(
        &self,
        present: &HandleSet,
        retention: &RetentionRoots,
    ) -> RetentionRoots {
        let mut combined = retention.clone();
        let requests = self
            .want_state
            .lock()
            .expect("want mutex poisoned")
            .requests();
        if !requests.is_empty() {
            retain_kind_if_present(&mut combined, present, want_record_kind());
        }
        for request in requests {
            for handle in request.blob_references() {
                if present.get(&handle.raw).is_some() {
                    combined.retain_recursive(handle);
                }
            }
        }
        combined
    }

    fn strong_keep_set(&self, reader: &YardSnapshot, retention: &RetentionRoots) -> HandleSet {
        let mut keep = HandleSet::new();
        // Explicit policy and native-record roots share the same structural
        // ownership law after root discovery.
        for handle in retention.expanded(reader) {
            keep.insert(&Entry::new(&handle.raw));
        }
        keep
    }

    #[cfg(test)]
    fn put_in_generation<S, T>(
        &mut self,
        level: usize,
        item: T,
    ) -> Result<Inline<Handle<S>>, InsertError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let handle = self.generations[level]
            .active_mut()
            .pile_mut()
            .put::<S, T>(item)?;
        let unknown: Inline<Handle<UnknownBlob>> = handle.transmute();
        self.generations[level]
            .active_mut()
            .live
            .insert(&Entry::new(&unknown.raw));
        Ok(handle)
    }
}

/// Deterministic owned snapshot of the native collection records visible
/// across all yard generations.
pub struct YardCollectionRecordIter {
    inner: std::collections::btree_map::IntoValues<CollectionRecordFingerprint, CollectionRecord>,
}

impl Iterator for YardCollectionRecordIter {
    type Item = Result<CollectionRecord, YardCollectionRecordsError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Ok)
    }
}

/// Failure while replaying the native collection-record union of a yard.
#[derive(Debug)]
pub enum YardCollectionRecordsError {
    /// One generation could not refresh or decode its pile.
    Pile(ReadError),
    /// Two generations presented different canonical records under one
    /// full-width storage fingerprint.
    FingerprintCollision {
        fingerprint: CollectionRecordFingerprint,
    },
}

impl fmt::Display for YardCollectionRecordsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pile(error) => write!(f, "failed to replay yard collection records: {error}"),
            Self::FingerprintCollision { fingerprint } => {
                write!(
                    f,
                    "collection record fingerprint {fingerprint:X} names different fields"
                )
            }
        }
    }
}

impl Error for YardCollectionRecordsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pile(error) => Some(error),
            Self::FingerprintCollision { .. } => None,
        }
    }
}

/// Deterministic owned snapshot of complete proofs visible across a yard.
pub struct YardCapabilityProofIter {
    inner: std::collections::btree_map::IntoValues<[u8; 32], CapabilityProof>,
}

impl Iterator for YardCapabilityProofIter {
    type Item = Result<CapabilityProof, YardCapabilityProofError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Ok)
    }
}

/// Failure while replaying the complete-proof union of a yard.
#[derive(Debug)]
pub enum YardCapabilityProofError {
    /// One generation could not refresh or decode its pile.
    Pile(ReadError),
    /// An infeasible BLAKE3 collision named different canonical proof bytes.
    IdCollision { id: CapabilityProofId },
}

impl fmt::Display for YardCapabilityProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pile(error) => write!(f, "failed to replay yard proof records: {error}"),
            Self::IdCollision { id } => write!(
                f,
                "capability proof id {} names different bytes across generations",
                hex::encode_upper(id.raw)
            ),
        }
    }
}

impl Error for YardCapabilityProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pile(error) => Some(error),
            Self::IdCollision { .. } => None,
        }
    }
}

impl CapabilityProofRead for YardSnapshot {
    type ProofsError = YardCapabilityProofError;
    type ProofIter<'a> = YardCapabilityProofIter;

    fn proofs<'a>(&'a self) -> Result<Self::ProofIter<'a>, Self::ProofsError> {
        let mut proofs = BTreeMap::<[u8; 32], CapabilityProof>::new();
        for generation in &self.generations {
            for proof in generation
                .snapshot
                .proofs()
                .map_err(YardCapabilityProofError::Pile)?
            {
                let proof = proof.map_err(YardCapabilityProofError::Pile)?;
                let id = proof.id();
                match proofs.entry(id.raw) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(proof);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get().as_bytes() == proof.as_bytes() => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(YardCapabilityProofError::IdCollision { id });
                    }
                }
            }
        }
        Ok(YardCapabilityProofIter {
            inner: proofs.into_values(),
        })
    }

    fn proof(&self, id: CapabilityProofId) -> Result<Option<CapabilityProof>, Self::ProofsError> {
        let mut found: Option<CapabilityProof> = None;
        for generation in &self.generations {
            let Some(candidate) = generation
                .snapshot
                .proof(id)
                .map_err(YardCapabilityProofError::Pile)?
            else {
                continue;
            };
            match &found {
                None => found = Some(candidate),
                Some(existing) if existing.as_bytes() == candidate.as_bytes() => {}
                Some(_) => return Err(YardCapabilityProofError::IdCollision { id }),
            }
        }
        Ok(found)
    }
}

impl CapabilityProofStore for Yard {
    type InsertError = CapabilityProofInsertError;

    fn insert_proof(&mut self, proof: CapabilityProof) -> Result<(), Self::InsertError> {
        self.generations[0]
            .active_mut()
            .pile_mut()
            .insert_proof(proof)
    }
}

impl CollectionRead for YardSnapshot {
    type RecordsError = YardCollectionRecordsError;
    type RecordIter<'a> = YardCollectionRecordIter;

    fn records<'a>(&'a self) -> Result<Self::RecordIter<'a>, Self::RecordsError> {
        let mut records = BTreeMap::new();
        for generation in &self.generations {
            let replay = generation
                .snapshot
                .records()
                .map_err(YardCollectionRecordsError::Pile)?;
            for result in replay {
                let record = result.map_err(YardCollectionRecordsError::Pile)?;
                let fingerprint = record.fingerprint();
                match records.get(&fingerprint) {
                    Some(existing) if existing != &record => {
                        return Err(YardCollectionRecordsError::FingerprintCollision {
                            fingerprint,
                        });
                    }
                    Some(_) => {}
                    None => {
                        records.insert(fingerprint, record);
                    }
                }
            }
        }
        Ok(YardCollectionRecordIter {
            inner: records.into_values(),
        })
    }

    fn select_records(
        &self,
        selectors: &BTreeSet<CollectionRecordSelector>,
    ) -> Result<Vec<CollectionRecord>, Self::RecordsError> {
        if selectors.is_empty() {
            return Ok(Vec::new());
        }
        let mut records = BTreeMap::new();
        for generation in &self.generations {
            let selected = generation
                .snapshot
                .select_records(selectors)
                .map_err(YardCollectionRecordsError::Pile)?;
            for record in selected {
                let fingerprint = record.fingerprint();
                match records.get(&fingerprint) {
                    Some(existing) if existing != &record => {
                        return Err(YardCollectionRecordsError::FingerprintCollision {
                            fingerprint,
                        });
                    }
                    Some(_) => {}
                    None => {
                        records.insert(fingerprint, record);
                    }
                }
            }
        }
        Ok(records.into_values().collect())
    }
}

impl CollectionStore for Yard {
    type InsertError = CollectionInsertError;

    fn insert(&mut self, record: CollectionRecord) -> Result<(), Self::InsertError> {
        self.generations[0].active_mut().pile_mut().insert(record)
    }
}

impl WantStore for Yard {
    type WantError = PileWriteError;

    /// Assert one exact request and persist its marker to the young
    /// generation's pile, so it survives a restart ([`Yard::open`] reloads
    /// it).
    ///
    /// Calling this for an already-resident reference is still meaningful:
    /// the assertion is persisted and owns every resident handle named by the
    /// request recursively. Ordinary reads never mint WANT records.
    fn want(&mut self, request: WantRequest) -> Result<(), Self::WantError> {
        self.generations[0].active_mut().pile_mut().want(request)?;
        self.want_state
            .lock()
            .expect("want mutex poisoned")
            .want(request);
        Ok(())
    }
}

impl Drop for Yard {
    fn drop(&mut self) {
        for generation in &mut self.generations {
            for segment in &mut generation.segments {
                if let Some(pile) = segment.pile.take() {
                    let _ = pile.close();
                }
            }
        }
    }
}

impl BlobStorePut for Yard {
    type PutError = InsertError;

    fn put<S, T>(&mut self, item: T) -> Result<Inline<Handle<S>>, Self::PutError>
    where
        S: BlobEncoding + 'static,
        T: IntoBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let handle = self.generations[0]
            .active_mut()
            .pile_mut()
            .put::<S, T>(item)?;
        let unknown: Inline<Handle<UnknownBlob>> = handle.transmute();
        self.generations[0]
            .active_mut()
            .live
            .insert(&Entry::new(&unknown.raw));
        Ok(handle)
    }
}

impl SnapshotSource for Yard {
    type Snapshot = YardSnapshot;
    type SnapshotError = ReadError;

    fn snapshot_at(
        &mut self,
        instant: hifitime::Epoch,
    ) -> Result<Self::Snapshot, Self::SnapshotError> {
        let mut generations = Vec::new();
        for generation in &mut self.generations {
            for segment in &mut generation.segments {
                generations.push(YardGenerationSnapshot {
                    snapshot: segment.pile_mut().snapshot_at(instant)?,
                    live: segment.live.clone(),
                });
            }
        }
        let wants = self
            .want_state
            .lock()
            .expect("want mutex poisoned")
            .requests();
        Ok(YardSnapshot {
            instant,
            generations,
            wants,
        })
    }
}

impl super::StorageFlush for Yard {
    type Error = super::pile::FlushError;

    /// Flush every open generation pile. Want markers and fresh
    /// writes land in the young generation, but older generations can
    /// hold unsynced rewrites from `reclaim`/`compact`, so sync them all.
    fn flush(&mut self) -> Result<(), Self::Error> {
        for generation in &mut self.generations {
            for segment in &mut generation.segments {
                if let Some(pile) = segment.pile.as_mut() {
                    pile.flush()?;
                }
            }
        }
        Ok(())
    }
}

impl StorageClose for Yard {
    type Error = YardCloseError;

    fn close(mut self) -> Result<(), Self::Error> {
        for generation in &mut self.generations {
            for segment in &mut generation.segments {
                if let Some(pile) = segment.pile.take() {
                    pile.close().map_err(YardCloseError::Pile)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct YardGenerationSnapshot {
    snapshot: PileSnapshot,
    live: HandleSet,
}

/// One immutable observation of a yard's segment union.
#[derive(Debug, Clone)]
pub struct YardSnapshot {
    instant: hifitime::Epoch,
    generations: Vec<YardGenerationSnapshot>,
    wants: Vec<WantRequest>,
}

impl WantRead for YardSnapshot {
    type WantsError = std::convert::Infallible;
    type WantIter<'a> = std::iter::Map<
        std::slice::Iter<'a, WantRequest>,
        fn(&WantRequest) -> Result<WantRequest, Self::WantsError>,
    >;

    fn wants<'a>(&'a self) -> Result<Self::WantIter<'a>, Self::WantsError> {
        Ok(self.wants.iter().map(|request| Ok(*request)))
    }
}

impl YardSnapshot {
    fn opaque_record_count(&self) -> usize {
        self.generations
            .iter()
            .map(|generation| generation.snapshot.opaque_record_count())
            .try_fold(0usize, usize::checked_add)
            .expect("yard opaque-record count overflow")
    }

    fn live_set(&self) -> HandleSet {
        let mut live = HandleSet::new();
        for generation in &self.generations {
            live.union(generation.live.clone());
        }
        live
    }

    /// Union read across the frozen generations (young -> old), returning
    /// `None` on a clean miss.
    fn get_local<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Option<Result<T, YardGetError<<T as TryFromBlob<S>>::Error>>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let unknown: Inline<Handle<UnknownBlob>> = handle.transmute();
        for generation in &self.generations {
            if generation.live.get(&unknown.raw).is_none() {
                continue;
            }
            match generation.snapshot.get::<T, S>(handle) {
                Ok(value) => return Some(Ok(value)),
                Err(GetBlobError::BlobNotFound(_)) => continue,
                Err(err) => return Some(Err(YardGetError::Pile(err))),
            }
        }
        None
    }
}

impl StoreSnapshot for YardSnapshot {
    fn instant(&self) -> hifitime::Epoch {
        self.instant
    }

    fn changes_since(&self, previous: &Self) -> StoreChanges {
        if previous.generations.len() != self.generations.len() {
            return StoreChanges::ALL;
        }

        previous
            .generations
            .iter()
            .zip(&self.generations)
            .fold(StoreChanges::NONE, |mut changes, (previous, current)| {
                changes = changes.union(current.snapshot.changes_since(&previous.snapshot));
                if previous.live != current.live {
                    changes = changes.union(StoreChanges::BLOBS);
                }
                changes
            })
            .union(if previous.wants != self.wants {
                StoreChanges::WANTS
            } else {
                StoreChanges::NONE
            })
    }
}

impl BlobStoreGet for YardSnapshot {
    type GetError<E: Error + Send + Sync + 'static> = YardGetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        self.get_local::<T, S>(handle)
            .unwrap_or(Err(YardGetError::NotFound))
    }
}

impl BlobChildren for YardSnapshot {
    fn children(&self, handle: Inline<Handle<UnknownBlob>>) -> Vec<Inline<Handle<UnknownBlob>>> {
        // Structural scan: use the non-minting read so reference
        // discovery never floods the wanted set with speculative wants. Wanted
        // cache policy is intentionally absent here: callers such as explicit
        // retention need the complete resident ownership graph.
        let Some(Ok(blob)) = self.get_local::<Blob<UnknownBlob>, UnknownBlob>(handle) else {
            return Vec::new();
        };
        let bytes = blob.bytes.as_ref();
        let mut result = Vec::new();
        let mut offset = 0usize;
        while offset + INLINE_LEN <= bytes.len() {
            let mut raw = [0u8; INLINE_LEN];
            raw.copy_from_slice(&bytes[offset..offset + INLINE_LEN]);

            let candidate = Inline::<Handle<UnknownBlob>>::new(raw);
            if matches!(self.get_local::<Bytes, UnknownBlob>(candidate), Some(Ok(_))) {
                result.push(candidate);
            }
            offset += INLINE_LEN;
        }
        result
    }
}

impl BlobStoreList for YardSnapshot {
    type Iter<'a> = YardListIter;
    type Err = Infallible;

    fn blobs(&self) -> Self::Iter<'_> {
        YardListIter {
            inner: self.live_set().into_iter(),
            generations: self.generations.clone(),
        }
    }

    /// PATCH-level difference across the immutable live unions of two Yard
    /// observations. This keeps locator/publication refresh proportional to
    /// the changed handles instead of relisting both complete inventories.
    fn blobs_diff(&self, old: &Self) -> Self::Iter<'_> {
        let current = self.live_set();
        let previous = old.live_set();
        YardListIter {
            inner: current.difference(&previous).into_iter(),
            generations: self.generations.clone(),
        }
    }

    fn contains_blob<S>(&self, handle: Inline<Handle<S>>) -> Result<bool, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        let handle: Inline<Handle<UnknownBlob>> = handle.transmute();
        Ok(self
            .generations
            .iter()
            .any(|generation| generation.live.get(&handle.raw).is_some()))
    }

    fn blob_info<S>(&self, handle: Inline<Handle<S>>) -> Result<Option<BlobInfo>, Self::Err>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        let handle: Inline<Handle<UnknownBlob>> = handle.transmute();
        Ok(self.generations.iter().find_map(|generation| {
            generation
                .live
                .get(&handle.raw)
                .and_then(|_| generation.snapshot.unvalidated_blob_info(handle))
        }))
    }
}

impl BlobStoreMeta for YardSnapshot {
    type MetaError = Infallible;

    fn metadata<S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<Option<super::BlobMetadata>, Self::MetaError>
    where
        S: BlobEncoding + 'static,
        Handle<S>: InlineEncoding,
    {
        let unknown: Inline<Handle<UnknownBlob>> = handle.transmute();
        for generation in &self.generations {
            if generation.live.get(&unknown.raw).is_none() {
                continue;
            }
            if let Some(metadata) = generation.snapshot.metadata(handle)? {
                return Ok(Some(metadata));
            }
        }
        Ok(None)
    }
}

pub struct YardListIter {
    inner: crate::patch::PATCHIntoIterator<INLINE_LEN, IdentitySchema, ()>,
    generations: Vec<YardGenerationSnapshot>,
}

impl Iterator for YardListIter {
    type Item = Result<BlobInfo, Infallible>;

    fn next(&mut self) -> Option<Self::Item> {
        let handle = Inline::<Handle<UnknownBlob>>::new(self.inner.next()?);
        let info = self
            .generations
            .iter()
            .find_map(|generation| generation.snapshot.unvalidated_blob_info(handle))
            .expect("live Yard handle must resolve in one generation snapshot");
        Some(Ok(info))
    }
}

fn update_err_io(err: PileWriteError) -> YardOpenError {
    match err {
        PileWriteError::IoError(io) => YardOpenError::Io(io),
    }
}

fn collect_list<E>(iter: impl IntoIterator<Item = Result<BlobInfo, E>>) -> Result<HandleSet, E> {
    let mut set = HandleSet::new();
    for result in iter {
        let info = result?;
        set.insert(&Entry::new(&info.handle.raw));
    }
    Ok(set)
}

fn reclaim_generation(
    path: &Path,
    temp_path: &Path,
    live: &HandleSet,
    wants: &[WantRequest],
    old_pile: Pile,
) -> Result<Pile, YardReclaimError> {
    reclaim_generation_with_hooks(path, temp_path, live, wants, old_pile, || {}, || {})
}

fn reclaim_generation_with_hooks<F, G>(
    path: &Path,
    temp_path: &Path,
    live: &HandleSet,
    wants: &[WantRequest],
    mut old_pile: Pile,
    before_final_guard: F,
    after_rename: G,
) -> Result<Pile, YardReclaimError>
where
    F: FnOnce(),
    G: FnOnce(),
{
    let reader = old_pile.snapshot().map_err(YardReclaimError::Pile)?;
    let opaque_records = reader.opaque_record_count();
    if opaque_records != 0 {
        return Err(YardReclaimError::OpaqueRecords {
            count: opaque_records,
        });
    }

    match fs::remove_file(temp_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(YardReclaimError::Io(err)),
    }

    let collection_records = reader
        .records()
        .map_err(YardReclaimError::Pile)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(YardReclaimError::Pile)?;
    let capability_proofs = reader
        .proofs()
        .map_err(YardReclaimError::Pile)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(YardReclaimError::Pile)?;
    File::create(temp_path).map_err(YardReclaimError::Io)?;
    let mut new_pile = Pile::open(temp_path).map_err(YardReclaimError::Pile)?;
    let handles: Vec<_> = live
        .clone()
        .into_iter()
        .map(Inline::<Handle<UnknownBlob>>::new)
        .collect();

    for result in transfer(&reader, &mut new_pile, handles) {
        result.map_err(YardReclaimError::Transfer)?;
    }
    old_pile
        .preserve_legacy_collection_headers_into(&mut new_pile)
        .map_err(YardReclaimError::CollectionRecord)?;
    before_final_guard();
    // Opaque-record refusal must come from one final source refresh. An opaque
    // addition observed here must not escape an earlier count and then be
    // projected away by the rewrite. Retired team records are known inert and
    // are intentionally dropped.
    let opaque_records = match old_pile.physical_rewrite_guard() {
        Ok(guard) => guard,
        Err(error) => {
            let _ = new_pile.close();
            let _ = old_pile.close();
            return Err(YardReclaimError::Pile(error));
        }
    };
    if opaque_records != 0 {
        let _ = new_pile.close();
        let _ = old_pile.close();
        return Err(YardReclaimError::OpaqueRecords {
            count: opaque_records,
        });
    }
    for record in collection_records {
        new_pile
            .insert(record)
            .map_err(YardReclaimError::CollectionRecord)?;
    }
    for proof in capability_proofs {
        new_pile
            .insert_proof(proof)
            .map_err(YardReclaimError::CapabilityProof)?;
    }
    for request in wants {
        new_pile.want(*request).map_err(|err| match err {
            PileWriteError::IoError(io) => YardReclaimError::WantMarkers(io),
        })?;
    }
    new_pile.close().map_err(YardReclaimError::Close)?;
    drop(reader);
    old_pile.close().map_err(YardReclaimError::Close)?;
    fs::rename(temp_path, path).map_err(YardReclaimError::Io)?;
    after_rename();

    let mut reopened = Pile::open(path).map_err(YardReclaimError::Pile)?;
    // The rewritten pile was just written and closed by us; fail loud on
    // any validation error rather than repair-truncating it.
    reopened.refresh().map_err(YardReclaimError::Pile)?;
    Ok(reopened)
}

fn reclaim_temp_path(path: &Path, level: usize) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "generation".into());
    path.with_file_name(format!(
        ".{file_name}.reclaim-{}-{level}.tmp",
        std::process::id()
    ))
}

#[derive(Debug)]
pub enum YardOpenError {
    NoGenerations,
    Io(std::io::Error),
    /// A generation pile failed to open or validate. A
    /// [`ReadError::CorruptPile`] here means the named generation file has
    /// an invalid tail; nothing was truncated — repair explicitly with
    /// [`Yard::amputate`] if losing the tail is acceptable.
    Pile {
        /// The generation pile file that failed.
        path: PathBuf,
        /// The underlying pile error.
        err: ReadError,
    },
    List(GetBlobError<Infallible>),
}

impl fmt::Display for YardOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoGenerations => write!(f, "yard requires at least one generation"),
            Self::Io(err) => write!(f, "failed to create yard pile file: {err}"),
            Self::Pile { path, err } => {
                write!(
                    f,
                    "failed to open yard generation pile {}: {err}",
                    path.display()
                )
            }
            Self::List(err) => write!(f, "failed to list yard pile: {err}"),
        }
    }
}

impl Error for YardOpenError {}

#[derive(Debug)]
pub enum YardGetError<E: Error> {
    NotFound,
    Pile(GetBlobError<E>),
}

impl<E: Error> fmt::Display for YardGetError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "blob not found in yard"),
            Self::Pile(err) => write!(f, "yard generation read failed: {err}"),
        }
    }
}

impl<E: Error + 'static> Error for YardGetError<E> {}

#[derive(Debug)]
#[non_exhaustive]
pub enum YardCollectError {
    Snapshot(ReadError),
    /// At least one generation contains opaque records. Collection cannot know
    /// whether they own otherwise-unrooted blobs, so it refuses before
    /// changing any generation's live set.
    OpaqueRecords {
        /// Total opaque records found across all generations.
        count: usize,
    },
    CollectionRecords(YardCollectionRecordsError),
    CapabilityProofs(YardCapabilityProofError),
    Transfer(TransferError<Infallible, YardGetError<Infallible>, InsertError>),
    Flush(super::pile::FlushError),
    Reclaim(YardReclaimError),
    WantMarkers(std::io::Error),
}

impl fmt::Display for YardCollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(err) => write!(f, "failed to create yard snapshot: {err}"),
            Self::OpaqueRecords { count } => write!(
                f,
                "refusing to collect a yard containing {count} opaque record(s)"
            ),
            Self::CollectionRecords(err) => {
                write!(f, "failed to replay yard collection records: {err}")
            }
            Self::CapabilityProofs(err) => {
                write!(f, "failed to replay yard capability proofs: {err}")
            }
            Self::Transfer(err) => write!(f, "failed to compact yard generation: {err}"),
            Self::Flush(err) => write!(f, "failed to flush yard generation pile: {err}"),
            Self::Reclaim(err) => {
                write!(f, "failed to recycle compacted yard generation: {err}")
            }
            Self::WantMarkers(err) => {
                write!(f, "failed to preserve want markers: {err}")
            }
        }
    }
}

impl Error for YardCollectError {}

#[derive(Debug)]
pub enum YardCloseError {
    Pile(super::pile::FlushError),
}

impl fmt::Display for YardCloseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pile(err) => write!(f, "failed to close yard pile: {err}"),
        }
    }
}

impl Error for YardCloseError {}

#[derive(Debug)]
#[non_exhaustive]
pub enum YardReclaimError {
    Io(std::io::Error),
    Pile(ReadError),
    /// One or more generations contain opaque records. Reclaim cannot infer
    /// their retention semantics and refuses before replacing any file.
    OpaqueRecords {
        /// Number of opaque records found by the refusing scan.
        count: usize,
    },
    Transfer(TransferError<Infallible, GetBlobError<Infallible>, InsertError>),
    CollectionRecord(CollectionInsertError),
    CapabilityProof(CapabilityProofInsertError),
    Close(super::pile::FlushError),
    WantMarkers(std::io::Error),
    /// A generation rewrite failed (`primary`) and the subsequent
    /// fail-loud reopen of the generation file also failed (`err`). The
    /// segment is left closed; nothing was truncated.
    Reopen {
        /// The generation pile file that could not be reopened.
        path: PathBuf,
        /// The rewrite error that triggered the reopen.
        primary: Box<YardReclaimError>,
        /// The reopen/validation error.
        err: ReadError,
    },
}

impl fmt::Display for YardReclaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to replace yard generation pile: {err}"),
            Self::Pile(err) => write!(f, "failed to read yard generation pile: {err}"),
            Self::OpaqueRecords { count } => write!(
                f,
                "refusing to reclaim a yard containing {count} opaque record(s)"
            ),
            Self::Transfer(err) => write!(f, "failed to copy live yard blobs: {err}"),
            Self::CollectionRecord(err) => {
                write!(f, "failed to copy a yard collection record: {err}")
            }
            Self::CapabilityProof(err) => {
                write!(f, "failed to copy a yard capability proof: {err}")
            }
            Self::Close(err) => write!(f, "failed to close yard generation pile: {err}"),
            Self::WantMarkers(err) => {
                write!(f, "failed to preserve want markers: {err}")
            }
            Self::Reopen { path, primary, err } => write!(
                f,
                "failed to reopen yard generation pile {} after failed rewrite ({primary}): {err}",
                path.display()
            ),
        }
    }
}

impl Error for YardReclaimError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::encodings::rawbytes::RawBytes;
    use crate::blob::encodings::simplearchive::SimpleArchive;
    use crate::capability::{Capability, CapabilityMode, CapabilityProof, CapabilityResource};
    use crate::collection::descriptor::{identity_for_tests, named_for_tests};
    use crate::collection::{
        empty_metadata_handle, CollectionCommit, CollectionDerive, CollectionMerge,
    };
    use crate::repo::pile::{description_blobs, PileRecordContent, PileRecords};
    use crate::trible::TribleSet;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeSet;
    use std::fs::OpenOptions;
    use std::io::Write;

    fn yard_with_paths(
        generations: usize,
        config: YardConfig,
    ) -> (tempfile::TempDir, Vec<PathBuf>, Yard) {
        let dir = tempfile::tempdir().unwrap();
        let paths = (0..generations)
            .map(|i| dir.path().join(format!("gen-{i}.pile")))
            .collect::<Vec<_>>();
        let yard = Yard::create(paths.clone(), config).unwrap();
        (dir, paths, yard)
    }

    fn yard_with(generations: usize, config: YardConfig) -> (tempfile::TempDir, Yard) {
        let (dir, _paths, yard) = yard_with_paths(generations, config);
        (dir, yard)
    }

    fn raw_blob(bytes: &'static [u8]) -> Bytes {
        Bytes::from_source(bytes.to_vec())
    }

    fn publish_record_kind_descriptions(yard: &mut Yard) {
        for blob in description_blobs() {
            let expected = blob.get_handle();
            let actual = yard.put::<UnknownBlob, _>(blob).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn yard_snapshot_lifts_physical_and_live_set_changes() {
        let (_dir, mut yard) = yard_with(1, YardConfig::default());
        let instant = hifitime::Epoch::from_tai_seconds(10.0);
        let empty = yard.snapshot_at(instant).unwrap();
        let later_instant = hifitime::Epoch::from_tai_seconds(20.0);
        let unchanged = yard.snapshot_at(later_instant).unwrap();
        assert_eq!(empty.clone().instant(), instant);
        assert_eq!(unchanged.instant(), later_instant);
        for generation in &unchanged.generations {
            assert_eq!(generation.snapshot.instant(), later_instant);
        }
        assert_eq!(unchanged.changes_since(&empty), StoreChanges::NONE);

        yard.want(WantRequest::blob(Inline::<Handle<UnknownBlob>>::new(
            [0x51; INLINE_LEN],
        )))
        .unwrap();
        let after_want = yard.snapshot().unwrap();
        assert!(empty.wants().unwrap().next().is_none());
        assert_eq!(after_want.wants().unwrap().count(), 1);
        assert_eq!(after_want.changes_since(&empty), StoreChanges::WANTS);

        yard.put::<RawBytes, _>(raw_blob(b"revision fixture"))
            .unwrap();
        let after_blob = yard.snapshot().unwrap();
        assert_eq!(after_blob.changes_since(&after_want), StoreChanges::BLOBS,);

        yard.collect(&RetentionRoots::new()).unwrap();
        let after_collect = yard.snapshot().unwrap();
        assert_eq!(
            after_collect.changes_since(&after_blob),
            StoreChanges::BLOBS,
        );
    }

    #[test]
    fn yard_snapshots_are_frozen_and_misses_do_not_record_wants() {
        let (_dir, mut yard) = yard_with(1, YardConfig::default());
        let bytes = raw_blob(b"snapshot boundary");
        let handle = Blob::<RawBytes>::new(bytes.clone()).get_handle();
        let before = yard.snapshot().unwrap();

        assert!(matches!(
            before.get::<Bytes, RawBytes>(handle),
            Err(YardGetError::NotFound)
        ));
        assert!(yard.snapshot().unwrap().wants().unwrap().next().is_none());

        assert_eq!(yard.put::<RawBytes, _>(bytes).unwrap(), handle);
        assert!(matches!(
            before.get::<Bytes, RawBytes>(handle),
            Err(YardGetError::NotFound)
        ));

        let after = yard.snapshot().unwrap();
        assert_eq!(
            after.get::<Bytes, RawBytes>(handle).unwrap().as_ref(),
            b"snapshot boundary"
        );
        assert!(yard.snapshot().unwrap().wants().unwrap().next().is_none());
    }

    #[test]
    fn yard_blob_difference_returns_only_new_live_handles() {
        let (_dir, mut yard) = yard_with(2, YardConfig::default());
        let empty = yard.snapshot().unwrap();
        let first = yard
            .put::<RawBytes, _>(raw_blob(b"first delta blob"))
            .unwrap();
        let after_first = yard.snapshot().unwrap();
        let second = yard
            .put::<RawBytes, _>(raw_blob(b"second delta blob"))
            .unwrap();
        let after_second = yard.snapshot().unwrap();

        let first_delta = after_first
            .blobs_diff(&empty)
            .map(|info| info.unwrap().handle.raw)
            .collect::<Vec<_>>();
        let second_delta = after_second
            .blobs_diff(&after_first)
            .map(|info| info.unwrap().handle.raw)
            .collect::<Vec<_>>();
        assert_eq!(first_delta, vec![first.raw]);
        assert_eq!(second_delta, vec![second.raw]);
    }

    #[test]
    fn want_state_enumerates_canonical_request_order_without_sorting() {
        let blob_low = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([1; INLINE_LEN]));
        let blob_high = WantRequest::blob(Inline::<Handle<UnknownBlob>>::new([2; INLINE_LEN]));
        let merge_low = WantRequest::merge(
            Inline::new([3; INLINE_LEN]),
            Inline::new([5; INLINE_LEN]),
            Inline::new([4; INLINE_LEN]),
        );
        let merge_high = WantRequest::merge(
            Inline::new([4; INLINE_LEN]),
            Inline::new([6; INLINE_LEN]),
            Inline::new([5; INLINE_LEN]),
        );
        let derive_low =
            WantRequest::derive(Inline::new([5; INLINE_LEN]), Inline::new([7; INLINE_LEN]));
        let derive_high =
            WantRequest::derive(Inline::new([6; INLINE_LEN]), Inline::new([8; INLINE_LEN]));
        let expected = vec![
            blob_low,
            blob_high,
            merge_low,
            merge_high,
            derive_low,
            derive_high,
        ];

        let mut state = WantState::default();
        for request in expected.iter().rev().copied() {
            state.want(request);
        }
        state.want(merge_low);

        let actual = state.requests();
        assert_eq!(actual, expected);
        assert!(actual
            .windows(2)
            .all(|pair| pair[0].to_bytes() < pair[1].to_bytes()));
    }

    fn pin_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn merge_record(tag: u8) -> CollectionRecord {
        let descriptor = named_for_tests(&format!("tagged-{tag}"), pin_id(tag.wrapping_add(1)));
        CollectionRecord::Merge(CollectionMerge::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            identity_for_tests(&descriptor),
            Inline::new([tag.wrapping_add(3); 32]),
            Inline::new([tag.wrapping_add(4); 32]),
            Inline::new([tag.wrapping_add(5); 32]),
        ))
    }

    fn invalidate_collection_commit(commit: CollectionCommit) -> CollectionCommit {
        let (signature_r, signature_s) = commit.signature();
        let mut forged_r = signature_r.raw;
        forged_r[0] ^= 1;
        let forged = CollectionCommit::from_parts(
            commit.collection(),
            commit.data(),
            commit.metadata(),
            commit.public_key(),
            Inline::new(forged_r),
            signature_s,
        );
        assert!(forged.verify_strict().is_err());
        forged
    }

    fn get_raw(
        reader: &YardSnapshot,
        handle: Inline<Handle<RawBytes>>,
    ) -> Result<Bytes, YardGetError<Infallible>> {
        reader.get::<Bytes, RawBytes>(handle)
    }

    fn pile_blob_count(path: &Path) -> usize {
        let mut pile = Pile::open(path).unwrap();
        pile.refresh().unwrap();
        let reader = pile.snapshot().unwrap();
        let count = reader.blobs().collect::<Result<Vec<_>, _>>().unwrap().len();
        drop(reader);
        pile.close().unwrap();
        count
    }

    #[test]
    fn generation_union_read_finds_older_generation() {
        let (_dir, mut yard) = yard_with(2, YardConfig::default());
        let old = yard
            .put_in_generation::<RawBytes, _>(1, raw_blob(b"old generation"))
            .unwrap();

        let reader = yard.snapshot().unwrap();

        assert_eq!(get_raw(&reader, old).unwrap(), raw_blob(b"old generation"));
        let info = reader
            .blobs()
            .find_map(|result| {
                let info = result.unwrap();
                (info.handle.raw == old.raw).then_some(info)
            })
            .expect("older generation is listed");
        assert_eq!(info.length, b"old generation".len() as u64);
    }

    #[test]
    fn collection_records_form_a_deterministic_generation_union_and_write_young() {
        let config = YardConfig::default();
        let (_dir, paths, mut yard) = yard_with_paths(2, config);
        let first = merge_record(21);
        let second = merge_record(27);
        let third = merge_record(33);

        yard.generations[1]
            .active_mut()
            .pile_mut()
            .insert(first)
            .unwrap();
        yard.generations[1]
            .active_mut()
            .pile_mut()
            .insert(second)
            .unwrap();
        yard.generations[0]
            .active_mut()
            .pile_mut()
            .insert(first)
            .unwrap();
        yard.insert(third).unwrap();

        let mut expected = vec![first, second, third];
        expected.sort_by_key(CollectionRecord::fingerprint);
        let snapshot = yard.snapshot().unwrap();
        assert_eq!(
            snapshot
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            expected
        );
        let young = yard.generations[0]
            .active_mut()
            .pile_mut()
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(young.contains(&third));

        yard.close().unwrap();
        let mut reopened = Yard::open(&paths, config).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(
            snapshot
                .records()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            expected
        );
        reopened.close().unwrap();
    }

    #[test]
    fn capability_proofs_retain_definitions_not_resources_and_survive_reclaim() {
        let config = YardConfig::default();
        let (_dir, paths, mut yard) = yard_with_paths(2, config);
        publish_record_kind_descriptions(&mut yard);
        let coincident_resource_blob = yard
            .put::<RawBytes, _>(raw_blob(b"resource bytes are not proof closure"))
            .unwrap();
        let root = SigningKey::from_bytes(&[71; 32]);
        let leaf = SigningKey::from_bytes(&[72; 32]);
        let definition = yard.put::<SimpleArchive, _>(TribleSet::new()).unwrap();
        let proof = CapabilityProof::issue_root(
            &root,
            CapabilityResource::new(coincident_resource_blob.raw),
            Capability::new(definition, CapabilityMode::Invoke),
            None,
            leaf.verifying_key(),
        );

        yard.generations[1]
            .active_mut()
            .pile_mut()
            .insert_proof(proof.clone())
            .unwrap();
        yard.insert_proof(proof.clone()).unwrap();
        let snapshot = yard.snapshot().unwrap();
        assert_eq!(snapshot.proof(proof.id()).unwrap(), Some(proof.clone()));
        assert_eq!(snapshot.proof(Inline::new([0; 32])).unwrap(), None);
        assert_eq!(
            snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![proof.clone()]
        );

        yard.collect(&RetentionRoots::new()).unwrap();
        let reader = yard.snapshot().unwrap();
        assert!(reader.get::<Blob<SimpleArchive>, _>(definition).is_ok());
        assert!(reader
            .get::<Blob<RawBytes>, _>(coincident_resource_blob)
            .is_err());
        assert_record_kind_description_resident(&reader, capability_proof_record_kind());
        assert_record_kind_description_resident(&reader, blob_record_kind());
        drop(reader);

        yard.reclaim().unwrap();
        let snapshot = yard.snapshot().unwrap();
        assert!(snapshot.get::<Blob<SimpleArchive>, _>(definition).is_ok());
        assert_record_kind_description_resident(&snapshot, capability_proof_record_kind());
        assert_record_kind_description_resident(&snapshot, blob_record_kind());
        assert_eq!(
            snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![proof.clone()]
        );
        yard.close().unwrap();

        let mut reopened = Yard::open(&paths, config).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(
            snapshot
                .proofs()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![proof]
        );
        let reader = reopened.snapshot().unwrap();
        assert!(reader
            .get::<Blob<RawBytes>, _>(coincident_resource_blob)
            .is_err());
        drop(reader);
        reopened.close().unwrap();
    }

    #[test]
    fn collection_selection_unions_generations_without_choosing_an_output() {
        let config = YardConfig::default();
        let (_dir, paths, mut yard) = yard_with_paths(2, config);
        let target = Inline::new([42; 32]);
        let input = Inline::new([43; 32]);
        let first = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            input,
            Inline::new([44; 32]),
        ));
        let conflicting = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            target,
            input,
            Inline::new([45; 32]),
        ));
        let unrelated = CollectionRecord::Derive(CollectionDerive::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            Inline::new([46; 32]),
            input,
            Inline::new([47; 32]),
        ));
        yard.generations[1]
            .active_mut()
            .pile_mut()
            .insert(first)
            .unwrap();
        yard.generations[0]
            .active_mut()
            .pile_mut()
            .insert(first)
            .unwrap();
        yard.generations[0]
            .active_mut()
            .pile_mut()
            .insert(conflicting)
            .unwrap();
        yard.generations[0]
            .active_mut()
            .pile_mut()
            .insert(unrelated)
            .unwrap();
        let selectors = [CollectionRecordSelector::Operation(WantRequest::derive(
            target, input,
        ))]
        .into_iter()
        .collect();
        let mut expected = vec![first, conflicting];
        expected.sort_unstable_by_key(CollectionRecord::fingerprint);

        assert_eq!(
            yard.snapshot().unwrap().select_records(&selectors).unwrap(),
            expected
        );
        yard.close().unwrap();

        let mut reopened = Yard::open(&paths, config).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(snapshot.select_records(&selectors).unwrap(), expected);
        assert!(!snapshot
            .select_records(&selectors)
            .unwrap()
            .contains(&unrelated));
        reopened.close().unwrap();
    }

    #[test]
    fn unsigned_equation_retention_crosses_generation_boundaries() {
        let (_dir, paths, mut yard) = yard_with_paths(2, YardConfig::default());
        let child = yard
            .put_in_generation::<RawBytes, _>(0, raw_blob(b"unsigned equation child"))
            .unwrap();
        let input = yard
            .put_in_generation::<RawBytes, _>(0, Bytes::from_source(child.raw.to_vec()))
            .unwrap();
        let orphan = yard
            .put_in_generation::<RawBytes, _>(0, raw_blob(b"unowned old cache"))
            .unwrap();
        yard.close().unwrap();

        // Exact published unenveloped unsigned MERGE V4 layout. It is inert
        // and lives in a different generation from every resident dependency.
        let mut header = [0u8; 256];
        header[..16].copy_from_slice(&hex_literal::hex!("9F5D028D4C423620D6957A5F726FA727"));
        header[16..48].fill(91); // Absent collection descriptor.
        header[80..112].copy_from_slice(&input.raw); // low stays zero.
        header[112..144].fill(92); // Absent output.
        {
            let mut file = OpenOptions::new().append(true).open(&paths[1]).unwrap();
            file.write_all(&header).unwrap();
            file.sync_all().unwrap();
        }
        let mut yard = Yard::open(paths.clone(), YardConfig::default()).unwrap();
        assert!(yard.snapshot().unwrap().records().unwrap().next().is_none());
        yard.collect(&RetentionRoots::new()).unwrap();
        yard.reclaim().unwrap();
        let reader = yard.snapshot().unwrap();
        assert!(get_raw(&reader, child).is_ok());
        assert!(get_raw(&reader, input).is_ok());
        assert!(get_raw(&reader, orphan).is_err());
        assert!(reader.records().unwrap().next().is_none());
        drop(reader);
        yard.close().unwrap();
        assert!(std::fs::read(&paths[1])
            .unwrap()
            .windows(header.len())
            .any(|bytes| bytes == header));
        let mut old = Pile::open(&paths[1]).unwrap();
        assert_eq!(
            old.snapshot()
                .unwrap()
                .legacy_unsigned_collection_equations()
                .count(),
            1
        );
        old.close().unwrap();
    }

    #[test]
    fn native_commits_root_owned_blobs_and_reclaim_preserves_every_record_kind() {
        let (_dir, mut yard) = yard_with(1, YardConfig::default());
        publish_record_kind_descriptions(&mut yard);
        let attachment = yard
            .put::<RawBytes, _>(raw_blob(b"commit-owned attachment"))
            .unwrap();
        let data = yard
            .put::<RawBytes, _>(Bytes::from_source(attachment.raw.to_vec()))
            .unwrap();
        let metadata = yard
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        assert_eq!(metadata, empty_metadata_handle());
        let equation_owned = yard
            .put::<RawBytes, _>(raw_blob(b"owned by signed equations"))
            .unwrap();

        let descriptor = named_for_tests("retained", pin_id(32));
        let collection = yard
            .put::<SimpleArchive, _>(crate::blob::IntoBlob::<SimpleArchive>::to_blob(
                descriptor.into_facts(),
            ))
            .unwrap();
        let key = SigningKey::from_bytes(&[34; 32]);
        let commit = CollectionCommit::sign(&key, collection, Inline::new(data.raw), metadata);
        commit.verify_strict().unwrap();
        let records = vec![
            CollectionRecord::Commit(commit),
            CollectionRecord::Merge(CollectionMerge::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                collection,
                Inline::new(equation_owned.raw),
                Inline::new([35; 32]),
                Inline::new([36; 32]),
            )),
            CollectionRecord::Derive(CollectionDerive::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                identity_for_tests(&named_for_tests("derived", pin_id(38))),
                Inline::new([36; 32]),
                Inline::new(equation_owned.raw),
            )),
        ];
        for record in records.iter().copied() {
            yard.insert(record).unwrap();
        }

        yard.collect(&RetentionRoots::new()).unwrap();
        let reader = yard.snapshot().unwrap();
        assert!(reader.get::<Bytes, RawBytes>(attachment).is_ok());
        assert!(reader.get::<Bytes, RawBytes>(data).is_ok());
        assert!(reader
            .get::<Blob<SimpleArchive>, SimpleArchive>(metadata)
            .is_ok());
        assert!(reader
            .get::<Blob<SimpleArchive>, SimpleArchive>(collection)
            .is_ok());
        assert!(reader.get::<Bytes, RawBytes>(equation_owned).is_ok());
        for record in records.iter().copied() {
            assert_record_kind_description_resident(&reader, collection_record_kind(record));
        }
        assert_record_kind_description_resident(&reader, blob_record_kind());
        drop(reader);

        yard.reclaim().unwrap();
        let snapshot = yard.snapshot().unwrap();
        for record in records.iter().copied() {
            assert_record_kind_description_resident(&snapshot, collection_record_kind(record));
        }
        assert_record_kind_description_resident(&snapshot, blob_record_kind());
        let actual = snapshot
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut expected = records;
        expected.sort_by_key(CollectionRecord::fingerprint);
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_native_commit_still_owns_its_resident_blob_references() {
        let (dir, mut yard) = yard_with(1, YardConfig::default());
        let forged_data = yard
            .put::<RawBytes, _>(raw_blob(b"invalid commit data"))
            .unwrap();
        let forged_metadata = yard
            .put::<SimpleArchive, _>(TribleSet::new().to_blob())
            .unwrap();
        let descriptor = named_for_tests("forged", pin_id(39));
        let collection = yard
            .put::<SimpleArchive, _>(crate::blob::IntoBlob::<SimpleArchive>::to_blob(
                descriptor.into_facts(),
            ))
            .unwrap();
        let invalid = invalidate_collection_commit(CollectionCommit::sign(
            &SigningKey::from_bytes(&[41; 32]),
            collection,
            Inline::new(forged_data.raw),
            forged_metadata,
        ));
        let records = vec![CollectionRecord::Commit(invalid)];
        for record in records.iter().copied() {
            yard.insert(record).unwrap();
        }

        yard.collect(&RetentionRoots::new()).unwrap();
        let reader = yard.snapshot().unwrap();
        assert!(reader.contains_blob(forged_data).unwrap());
        assert!(reader.contains_blob(forged_metadata).unwrap());
        assert!(reader.contains_blob(collection).unwrap());
        drop(reader);

        yard.reclaim().unwrap();
        assert_eq!(pile_blob_count(&dir.path().join("gen-0.pile")), 3);
        let mut actual = yard
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        actual.sort_by_key(CollectionRecord::fingerprint);
        let mut expected = records;
        expected.sort_by_key(CollectionRecord::fingerprint);
        assert_eq!(actual, expected);
    }

    #[test]
    fn valid_dangling_native_commit_survives_yard_collection_and_reclaim() {
        let (dir, mut yard) = yard_with(1, YardConfig::default());
        let descriptor = named_for_tests("dangling", pin_id(43));
        let collection = yard
            .put::<SimpleArchive, _>(crate::blob::IntoBlob::<SimpleArchive>::to_blob(
                descriptor.into_facts(),
            ))
            .unwrap();
        let missing_data = Inline::new([45; 32]);
        let missing_metadata = Inline::<Handle<SimpleArchive>>::new([46; 32]);
        let commit = CollectionCommit::sign(
            &SigningKey::from_bytes(&[47; 32]),
            collection,
            missing_data,
            missing_metadata,
        );
        commit.verify_strict().unwrap();
        let records = vec![CollectionRecord::Commit(commit)];
        for record in records.iter().copied() {
            yard.insert(record).unwrap();
        }

        yard.collect(&RetentionRoots::new()).unwrap();
        yard.reclaim().unwrap();
        assert_eq!(pile_blob_count(&dir.path().join("gen-0.pile")), 1);
        let mut actual = yard
            .snapshot()
            .unwrap()
            .records()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        actual.sort_by_key(CollectionRecord::fingerprint);
        let mut expected = records;
        expected.sort_by_key(CollectionRecord::fingerprint);
        assert_eq!(actual, expected);
    }

    #[test]
    fn explicit_keep_and_want_both_root_resident_blobs() {
        let (_dir, mut yard) = yard_with(1, YardConfig::default());
        let strong = yard.put::<RawBytes, _>(raw_blob(b"strong")).unwrap();
        let wanted = Blob::<RawBytes>::new(raw_blob(b"wanted")).get_handle();
        yard.want(WantRequest::blob(wanted)).unwrap();
        yard.put::<RawBytes, _>(raw_blob(b"wanted")).unwrap();

        let mut roots = RetentionRoots::new();
        roots.retain_recursive(strong);
        yard.collect(&roots).unwrap();
        let reader = yard.snapshot().unwrap();

        assert_eq!(get_raw(&reader, strong).unwrap(), raw_blob(b"strong"));
        assert_eq!(get_raw(&reader, wanted).unwrap(), raw_blob(b"wanted"));
    }

    #[test]
    fn explicit_retention_distinguishes_owned_and_descriptive_edges() {
        let (_dir, mut yard) = yard_with(1, YardConfig::default());
        let owned_child =
            Blob::<UnknownBlob>::new(Bytes::from_source(b"owned child".to_vec())).get_handle();
        yard.want(WantRequest::blob(owned_child)).unwrap();
        yard.put::<UnknownBlob, _>(Bytes::from_source(b"owned child".to_vec()))
            .unwrap();
        let owned_parent = yard
            .put::<UnknownBlob, _>(Bytes::from_source(owned_child.raw.to_vec()))
            .unwrap();

        let described_input = yard
            .put::<UnknownBlob, _>(Bytes::from_source(b"described input".to_vec()))
            .unwrap();
        let ledger_record = yard
            .put::<UnknownBlob, _>(Bytes::from_source(described_input.raw.to_vec()))
            .unwrap();
        let orphan = yard
            .put::<UnknownBlob, _>(Bytes::from_source(b"orphan".to_vec()))
            .unwrap();

        let mut roots = RetentionRoots::new();
        roots.retain_recursive(owned_parent);
        roots.retain_direct(ledger_record);
        yard.collect(&roots).unwrap();
        let reader = yard.snapshot().unwrap();

        for retained in [owned_parent, owned_child, ledger_record] {
            assert!(reader.get::<Blob<UnknownBlob>, _>(retained).is_ok());
        }
        for collected in [described_input, orphan] {
            assert!(matches!(
                reader.get::<Blob<UnknownBlob>, _>(collected),
                Err(YardGetError::NotFound)
            ));
        }
    }

    #[test]
    fn hole_safe_walk_prunes_wanted_absent_child() {
        let (_dir, mut yard) = yard_with(1, YardConfig::default());
        let absent =
            Blob::<UnknownBlob>::new(Bytes::from_source(b"not stored".to_vec())).get_handle();
        let parent = yard
            .put::<UnknownBlob, _>(Bytes::from_source(absent.raw.to_vec()))
            .unwrap();

        let mut roots = RetentionRoots::new();
        roots.retain_recursive(parent);
        yard.want(WantRequest::blob(absent)).unwrap();

        yard.collect(&roots).unwrap();
        let reader = yard.snapshot().unwrap();

        assert!(reader.get::<Blob<UnknownBlob>, UnknownBlob>(parent).is_ok());
        assert!(matches!(
            reader.get::<Blob<UnknownBlob>, UnknownBlob>(absent),
            Err(YardGetError::NotFound)
        ));
    }

    #[test]
    fn compaction_tenures_explicit_and_want_owned_blobs() {
        let (_dir, mut yard) = yard_with(
            3,
            YardConfig {
                strong_level_budget: 0,
                fanout: 1,
            },
        );
        let strong = yard.put::<RawBytes, _>(raw_blob(b"tenured")).unwrap();
        let wanted = Blob::<RawBytes>::new(raw_blob(b"cache")).get_handle();
        yard.want(WantRequest::blob(wanted)).unwrap();
        yard.put::<RawBytes, _>(raw_blob(b"cache")).unwrap();
        let mut roots = RetentionRoots::new();
        roots.retain_recursive(strong);

        yard.compact(&roots).unwrap();

        // With a zero strong budget everything overflows downward; the WANT
        // reference obeys the same strong ownership and tiering law.
        assert!(!yard.contains_in_generation(0, strong));
        assert!(!yard.contains_in_generation(1, strong));
        assert!(yard.contains_in_generation(2, strong));
        assert!(!yard.contains_in_generation(0, wanted));
        assert!(!yard.contains_in_generation(1, wanted));
        assert!(yard.contains_in_generation(2, wanted));
    }

    #[test]
    fn compact_recycles_dumped_generations_without_a_separate_reclaim() {
        let (_dir, paths, mut yard) = yard_with_paths(
            2,
            YardConfig {
                strong_level_budget: 0,
                fanout: 1,
            },
        );
        // A strong blob lands in gen 0 and, with a zero budget, overflows on
        // compaction — the whole of gen 0 dumps into gen 1.
        let strong = yard
            .put::<RawBytes, _>(Bytes::from_source(vec![b'S'; 512]))
            .unwrap();
        let mut roots = RetentionRoots::new();
        roots.retain_recursive(strong);
        // Dead bytes physically present in gen 0, so there is genuinely
        // something for the merge to reclaim.
        let _dead = yard
            .put::<RawBytes, _>(Bytes::from_source(vec![b'D'; 4096]))
            .unwrap();
        assert_eq!(pile_blob_count(&paths[0]), 2);
        let strong_before = {
            let reader = yard.snapshot().unwrap();
            get_raw(&reader, strong).unwrap()
        };

        yard.compact(&roots).unwrap();

        // No separate reclaim(): the merge itself recycled gen 0's pile, so it
        // is physically empty, while the live blob moved down to gen 1 and
        // stays readable.
        assert_eq!(pile_blob_count(&paths[0]), 0);
        assert!(yard.contains_in_generation(1, strong));
        let reader = yard.snapshot().unwrap();
        assert_eq!(get_raw(&reader, strong).unwrap(), strong_before);
    }

    #[test]
    fn compact_reanchors_old_only_wants_before_reclaiming_an_old_tier() {
        let config = YardConfig {
            strong_level_budget: 1,
            fanout: 1,
        };
        let (_dir, paths, mut yard) = yard_with_paths(3, config);
        let operation =
            WantRequest::derive(Inline::new([81; INLINE_LEN]), Inline::new([82; INLINE_LEN]));
        yard.generations[1]
            .active_mut()
            .pile_mut()
            .want(operation)
            .unwrap();
        drop(yard);

        let mut yard = Yard::open(paths.clone(), config).unwrap();
        let first = yard
            .put_in_generation::<RawBytes, _>(1, raw_blob(b"old-tier strong one"))
            .unwrap();
        let second = yard
            .put_in_generation::<RawBytes, _>(1, raw_blob(b"old-tier strong two"))
            .unwrap();
        let mut roots = RetentionRoots::new();
        roots.retain_recursive(first);
        roots.retain_recursive(second);

        // Level 0 stays in place while level 1 exceeds its budget and is
        // recycled. The old-only operation marker must be anchored in level 0
        // before that rewrite removes its original bytes.
        yard.compact(&roots).unwrap();
        assert!(yard.contains_in_generation(2, first));
        assert!(yard.contains_in_generation(2, second));
        drop(yard);

        let mut reopened = Yard::open(paths, config).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![operation]
        );
    }

    #[test]
    fn reclaim_rewrites_generation_to_live_blobs_only() {
        let (_dir, paths, mut yard) = yard_with_paths(1, YardConfig::default());

        let live = yard
            .put::<RawBytes, _>(Bytes::from_source(vec![b'L'; 512]))
            .unwrap();
        let evicted = yard
            .put::<RawBytes, _>(Bytes::from_source(vec![b'E'; 4096]))
            .unwrap();

        let mut roots = RetentionRoots::new();
        roots.retain_recursive(live);
        yard.collect(&roots).unwrap();
        let before_size = fs::metadata(&paths[0]).unwrap().len();
        let before_count = pile_blob_count(&paths[0]);
        let before_reader = yard.snapshot().unwrap();
        let live_before = get_raw(&before_reader, live).unwrap();

        assert!(matches!(
            get_raw(&before_reader, evicted),
            Err(YardGetError::NotFound)
        ));
        assert_eq!(before_count, 2);

        yard.reclaim().unwrap();

        let after_size = fs::metadata(&paths[0]).unwrap().len();
        let after_count = pile_blob_count(&paths[0]);
        let after_reader = yard.snapshot().unwrap();

        assert!(after_size < before_size);
        assert_eq!(after_count, 1);
        assert_eq!(get_raw(&after_reader, live).unwrap(), live_before);
        assert!(matches!(
            get_raw(&after_reader, evicted),
            Err(YardGetError::NotFound)
        ));

        let mut fresh_pile = Pile::open(&paths[0]).unwrap();
        fresh_pile.refresh().unwrap();
        let fresh_reader = fresh_pile.snapshot().unwrap();
        assert_eq!(
            fresh_reader.get::<Bytes, RawBytes>(live).unwrap(),
            live_before
        );
        assert!(matches!(
            fresh_reader.get::<Bytes, RawBytes>(evicted),
            Err(GetBlobError::BlobNotFound(_))
        ));
        drop(fresh_reader);
        fresh_pile.close().unwrap();

        yard.reclaim().unwrap();
        assert_eq!(fs::metadata(&paths[0]).unwrap().len(), after_size);
        assert_eq!(pile_blob_count(&paths[0]), after_count);
    }

    #[test]
    fn reclaim_final_guard_refuses_opaque_record_appended_during_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opaque-during-reclaim.pile");
        File::create(&path).unwrap();
        let temp_path = reclaim_temp_path(&path, 0);
        let mut pile = Pile::open(&path).unwrap();
        let handle = pile
            .put::<RawBytes, _>(Bytes::from_source(b"still owned".to_vec()))
            .unwrap();
        crate::repo::StorageFlush::flush(&mut pile).unwrap();

        let mut live = HandleSet::new();
        let unknown: Inline<Handle<UnknownBlob>> = handle.transmute();
        live.insert(&Entry::new(&unknown.raw));

        let mut opaque = [0u8; 256];
        opaque[..28].copy_from_slice(&hex_literal::hex!(
            "0371B249F0626B2ABDDB80E23EA969059D9656A5EA5A497320351F3B"
        ));
        opaque[28..32].copy_from_slice(&1u32.to_le_bytes());
        opaque[32..64].fill(0xA5);

        let result = reclaim_generation_with_hooks(
            &path,
            &temp_path,
            &live,
            &[],
            pile,
            || {
                let mut external = OpenOptions::new().append(true).open(&path).unwrap();
                external.write_all(&opaque).unwrap();
                external.sync_all().unwrap();
            },
            || {},
        );

        assert!(matches!(
            result,
            Err(YardReclaimError::OpaqueRecords { count: 1 })
        ));
        assert!(fs::read(&path).unwrap().ends_with(&opaque));

        let mut reopened = Pile::open(&path).unwrap();
        assert_eq!(reopened.opaque_record_count().unwrap(), 1);
        let stored: Bytes = reopened.snapshot().unwrap().get(handle).unwrap();
        assert_eq!(stored.as_ref(), b"still owned");
        reopened.close().unwrap();
    }

    #[test]
    fn young_rewrite_contains_wants_at_the_atomic_rename_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("atomic-wants.pile");
        File::create(&path).unwrap();
        let temp_path = reclaim_temp_path(&path, 0);
        let pile = Pile::open(&path).unwrap();
        let request =
            WantRequest::derive(Inline::new([91; INLINE_LEN]), Inline::new([92; INLINE_LEN]));

        // Panic exactly after the replacement became visible but before Yard
        // can reopen it. This models process death at the old post-rename
        // re-recording window: the replacement itself must already carry the
        // complete wanted set.
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = reclaim_generation_with_hooks(
                &path,
                &temp_path,
                &HandleSet::new(),
                &[request],
                pile,
                || {},
                || panic!("simulated crash after atomic rename"),
            );
        }));
        assert!(crashed.is_err());

        let mut reopened = Pile::open(&path).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![request]
        );
        reopened.close().unwrap();
    }

    /// The amnesia regression: wants are durable pile records, so
    /// reopening a yard rebuilds the want state instead of resetting it.
    #[test]
    fn yard_open_reloads_wants() {
        let (_dir, paths, mut yard) = yard_with_paths(2, YardConfig::default());

        // A pure want: asserted while absent, never fetched.
        let want = Blob::<RawBytes>::new(raw_blob(b"still wanted after restart")).get_handle();
        yard.want(WantRequest::blob(want)).unwrap();
        // A demand-fetched cache entry: wanted while absent, then put.
        let cached = Blob::<RawBytes>::new(raw_blob(b"cached")).get_handle();
        yard.want(WantRequest::blob(cached)).unwrap();
        yard.put::<RawBytes, _>(raw_blob(b"cached")).unwrap();
        drop(yard); // closes (and flushes) the generation piles

        let mut reopened = Yard::open(paths, YardConfig::default()).unwrap();
        let wanted: BTreeSet<_> = reopened
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .map(|result| match result.unwrap() {
                WantRequest::Blob { handle } => handle.raw,
                _ => panic!("test only inserted blob requests"),
            })
            .collect();
        assert!(
            wanted.contains(&want.raw),
            "wanted want lost across restart — the amnesia bug"
        );
        assert!(
            wanted.contains(&cached.raw),
            "wanted cache-retention marker lost across restart"
        );
        // The reloaded want still works as a retention marker: the
        // cached blob survives collection under the default budget.
        reopened.collect(&RetentionRoots::new()).unwrap();
        let reader = reopened.snapshot().unwrap();
        assert_eq!(get_raw(&reader, cached).unwrap(), raw_blob(b"cached"));
    }

    /// A young-pile rewrite (reclaim) must not drop the durable wanted set:
    /// surviving want markers are re-recorded into the rewritten pile.
    #[test]
    fn want_markers_survive_reclaim() {
        let (_dir, paths, mut yard) = yard_with_paths(1, YardConfig::default());
        publish_record_kind_descriptions(&mut yard);

        let want = Blob::<RawBytes>::new(raw_blob(b"wanted, absent")).get_handle();
        yard.want(WantRequest::blob(want)).unwrap();
        let cached = Blob::<RawBytes>::new(raw_blob(b"cached blob")).get_handle();
        yard.want(WantRequest::blob(cached)).unwrap();
        yard.put::<RawBytes, _>(raw_blob(b"cached blob")).unwrap();

        yard.collect(&RetentionRoots::new()).unwrap();
        let reader = yard.snapshot().unwrap();
        assert_record_kind_description_resident(&reader, want_record_kind());
        assert_record_kind_description_resident(&reader, blob_record_kind());
        drop(reader);

        // Rewrite the young pile: only live blobs are transferred, so the
        // marker records are dropped — and must be re-recorded.
        yard.reclaim().unwrap();

        drop(yard);
        let mut reopened = Yard::open(paths, YardConfig::default()).unwrap();
        let wanted: BTreeSet<_> = reopened
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .map(|result| match result.unwrap() {
                WantRequest::Blob { handle } => handle.raw,
                _ => panic!("test only inserted blob requests"),
            })
            .collect();
        assert!(
            wanted.contains(&want.raw),
            "want marker lost by reclaim rewrite"
        );
        assert!(
            wanted.contains(&cached.raw),
            "cache marker lost by reclaim rewrite"
        );
        let reader = reopened.snapshot().unwrap();
        assert_eq!(get_raw(&reader, cached).unwrap(), raw_blob(b"cached blob"));
        assert_record_kind_description_resident(&reader, want_record_kind());
        assert_record_kind_description_resident(&reader, blob_record_kind());
    }

    #[test]
    fn operation_wants_survive_reclaim_and_retain_resident_references() {
        let config = YardConfig::default();
        let (_dir, paths, mut yard) = yard_with_paths(1, config);
        let input_blob = yard
            .put::<RawBytes, _>(raw_blob(b"an operation input digest is not a blob root"))
            .unwrap();
        let source = Inline::new([51; INLINE_LEN]);
        let target = Inline::new([52; INLINE_LEN]);
        let input = Inline::new(input_blob.raw);
        let merge = WantRequest::merge(source, input, Inline::new([53; INLINE_LEN]));
        let derive = WantRequest::derive(target, input);
        yard.want(merge).unwrap();
        yard.want(derive).unwrap();

        yard.collect(&RetentionRoots::new()).unwrap();
        assert!(yard.contains_in_generation(0, input_blob));
        yard.reclaim().unwrap();
        drop(yard);

        let mut reopened = Yard::open(paths, config).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![merge, derive]
        );
        assert!(reopened.contains_in_generation(0, input_blob));
    }

    #[test]
    fn collect_then_reclaim_preserves_grow_only_wants_and_their_resident_closure() {
        let config = YardConfig::default();
        let (_dir, paths, mut yard) = yard_with_paths(1, config);
        let cached = Blob::<RawBytes>::new(raw_blob(b"evict this cached value")).get_handle();
        yard.want(WantRequest::blob(cached)).unwrap();
        yard.put::<RawBytes, _>(raw_blob(b"evict this cached value"))
            .unwrap();
        let operation = WantRequest::derive(Inline::new([59; INLINE_LEN]), Inline::new([60; 32]));
        yard.want(operation).unwrap();

        yard.collect(&RetentionRoots::new()).unwrap();
        assert_eq!(
            yard.snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![WantRequest::blob(cached), operation]
        );

        yard.reclaim().unwrap();
        drop(yard);
        let mut reopened = Yard::open(paths.clone(), config).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![WantRequest::blob(cached), operation]
        );
        assert!(reopened.contains_in_generation(0, cached));
        drop(reopened);

        let records = PileRecords::open(&paths[0])
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(record.content, PileRecordContent::Want { .. }))
                .count(),
            2
        );
        assert!(!records.iter().any(|record| matches!(
            record.content,
            PileRecordContent::RetiredWantAssert { .. }
                | PileRecordContent::RetiredWantRetract { .. }
        )));
    }

    #[test]
    fn yard_open_unions_wants_from_every_generation() {
        let (_dir, paths, yard) = yard_with_paths(2, YardConfig::default());
        drop(yard);

        let young_request =
            WantRequest::derive(Inline::new([62; INLINE_LEN]), Inline::new([63; INLINE_LEN]));
        let old_request = WantRequest::merge(
            Inline::new([64; INLINE_LEN]),
            Inline::new([65; INLINE_LEN]),
            Inline::new([66; INLINE_LEN]),
        );
        let mut young = Pile::open(&paths[0]).unwrap();
        young.want(young_request).unwrap();
        young.close().unwrap();
        let mut old = Pile::open(&paths[1]).unwrap();
        old.want(old_request).unwrap();
        old.want(young_request).unwrap();
        old.close().unwrap();

        let mut reopened = Yard::open(paths, YardConfig::default()).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![old_request, young_request]
        );
    }

    #[test]
    fn yard_ignores_stale_retired_wants_appended_after_cutover() {
        let (_dir, paths, mut yard) = yard_with_paths(1, YardConfig::default());
        let current_handle = Inline::<Handle<UnknownBlob>>::new([73; INLINE_LEN]);
        let current = WantRequest::blob(current_handle);
        yard.want(current).unwrap();
        drop(yard);

        for (marker, request) in [
            (
                hex_literal::hex!("8F3EEFEDECD491F63F6EAAA5FD6F3D5E"),
                Inline::<Handle<UnknownBlob>>::new([74; INLINE_LEN]),
            ),
            (
                hex_literal::hex!("2D76662DFF0187EC36A8C90B12BB8B0D"),
                current_handle,
            ),
        ] {
            let mut retired = [0u8; 256];
            retired[..16].copy_from_slice(&marker);
            retired[16..48].copy_from_slice(&request.raw);
            let mut file = OpenOptions::new().append(true).open(&paths[0]).unwrap();
            file.write_all(&retired).unwrap();
            file.sync_all().unwrap();
        }

        let mut reopened = Yard::open(paths, YardConfig::default()).unwrap();
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .wants()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![current]
        );
    }

    /// The fail-loud posture: opening a yard whose generation pile has a
    /// corrupt tail must surface the corruption (naming the file) WITHOUT
    /// truncating anything; `Yard::amputate` is the explicit opt-in repair.
    #[test]
    fn open_fails_loud_on_corrupt_generation_without_truncating() {
        use std::io::Write;

        let (_dir, paths, mut yard) = yard_with_paths(1, YardConfig::default());
        let live = yard.put::<RawBytes, _>(raw_blob(b"survivor")).unwrap();
        drop(yard); // closes (and flushes) the generation pile

        // Tear the tail before a complete record marker lands.
        {
            let mut file = fs::OpenOptions::new().append(true).open(&paths[0]).unwrap();
            file.write_all(&[0xFF; 8]).unwrap();
            file.sync_all().unwrap();
        }
        let corrupt_len = fs::metadata(&paths[0]).unwrap().len();

        // Fail-loud open: the corruption propagates, names the file, and
        // the file is NOT truncated.
        match Yard::open(paths.clone(), YardConfig::default()) {
            Err(YardOpenError::Pile { path, err }) => {
                assert_eq!(path, paths[0]);
                assert!(
                    matches!(err, ReadError::CorruptPile { .. }),
                    "expected CorruptPile, got: {err}"
                );
            }
            other => panic!("expected fail-loud corrupt open, got {other:?}"),
        }
        assert_eq!(
            fs::metadata(&paths[0]).unwrap().len(),
            corrupt_len,
            "fail-loud open must not truncate the generation pile"
        );

        // Explicit repair: amputate truncates the invalid tail and the
        // valid prefix stays readable.
        let mut repaired = Yard::amputate(paths.clone(), YardConfig::default()).unwrap();
        assert!(fs::metadata(&paths[0]).unwrap().len() < corrupt_len);
        let reader = repaired.snapshot().unwrap();
        assert_eq!(get_raw(&reader, live).unwrap(), raw_blob(b"survivor"));
    }
}
