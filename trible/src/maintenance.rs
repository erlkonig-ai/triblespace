//! Caller-owned collection maintenance, shared by native applications and the CLI.
//!
//! This module does not create a runtime, spawn tasks, open a store or select
//! application policy. The caller owns scheduling, cancellation and store closure.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use triblespace_core::blob::encodings::entity_id_set::EntityIdSetBlob;
use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
use triblespace_core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace_core::blob::encodings::utf8string::UTF8String;
use triblespace_core::blob::IntoBlob;
#[cfg(test)]
use triblespace_core::blob::{Blob, TryFromBlob};
use triblespace_core::collection::records::{CollectionHandle, CollectionRecord};
use triblespace_core::collection::CollectionRead;
use triblespace_core::collection::{
    descriptor, Collection, CollectionRecordSelector, CollectionStoreExt,
};
#[cfg(test)]
use triblespace_core::collection::{grant_collection_read, AdmissionPolicy, CollectionPolicy};
use triblespace_core::id::Id;
use triblespace_core::inline::encodings::hash::{Blake3, Handle, Hash};
use triblespace_core::inline::Inline;
use triblespace_core::metadata::{self, MetaDescribe};
use triblespace_core::repo::async_store::AsyncBlobStoreAcquire;
#[cfg(test)]
use triblespace_core::repo::pile::{Pile, PileSnapshot};
#[cfg(test)]
use triblespace_core::repo::BlobStoreMeta;
use triblespace_core::repo::{
    BlobStoreGet, ObservedStore, SnapshotSource, Store, StoreDependencies, StoreRead, StoreSnapshot,
};
use triblespace_core::trible::Fragment;
use triblespace_core::trible::TribleSet;

#[path = "maintenance/telemetry.rs"]
pub mod telemetry;
use telemetry as maintenance_telemetry;
pub use telemetry::Publications;

#[cfg(test)]
#[path = "maintenance/counts.rs"]
mod maintenance_counts;
#[cfg(test)]
#[path = "maintenance/tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum SuccinctBackend {
    #[default]
    Cpu,
    /// CUDA wavelet packing; requires the succinct-cuda build feature and a
    /// separately reserved device/shared-memory budget. Rank9 stays on CPU.
    Cuda,
}

impl SuccinctBackend {
    pub fn check_available(self) -> Result<()> {
        match self {
            Self::Cpu => Ok(()),
            Self::Cuda => {
                #[cfg(feature = "succinct-cuda")]
                {
                    Ok(())
                }
                #[cfg(not(feature = "succinct-cuda"))]
                {
                    Err(anyhow!(
                        "CUDA Succinct maintenance requires the succinct-cuda build feature"
                    ))
                }
            }
        }
    }
}

/// A native collection selection. Handles need no inventory scan.
#[derive(Clone, Debug)]
pub enum Target {
    Handle(CollectionHandle),
    Name(String),
}

enum Reference {
    Native(Target),
    Cli(String),
}

impl Reference {
    fn resolve<R: StoreRead>(&self, snapshot: &R) -> Result<CollectionHandle> {
        match self {
            Self::Native(Target::Handle(handle)) => Ok(*handle),
            Self::Native(Target::Name(name)) => resolve_maintenance_name(snapshot, name),
            Self::Cli(reference) => resolve_maintenance_target(snapshot, reference),
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Native(Target::Handle(handle)) => format!("blake3:{}", handle_hex(*handle)),
            Self::Native(Target::Name(name)) => format!("name:{name}"),
            Self::Cli(reference) => reference.clone(),
        }
    }
}

/// Record counts before or after a completed maintenance hop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Census {
    pub commits: usize,
    pub merges: usize,
    pub derives: usize,
    pub maps: usize,
}

impl From<(usize, usize, usize, usize)> for Census {
    fn from(value: (usize, usize, usize, usize)) -> Self {
        Self {
            commits: value.0,
            merges: value.1,
            derives: value.2,
            maps: value.3,
        }
    }
}

/// Actual operation boundaries, never inferred activity or a timer heartbeat.
/// Publication counts are successful insert calls, not unique or transferred bytes.
#[derive(Clone, Debug)]
pub enum Event {
    HopStarted {
        collection: CollectionHandle,
    },
    HopFinished {
        collection: CollectionHandle,
        elapsed: Duration,
        census: Option<(Census, Census)>,
        publications: Publications,
        error: Option<String>,
    },
    /// The caller dropped an in-flight tick. Earlier append-only writes remain valid.
    HopCancelled {
        collection: CollectionHandle,
        elapsed: Duration,
    },
    Failure {
        reference: String,
        error: String,
    },
    PassFinished {
        sequence: u64,
        elapsed: Duration,
        pass: Pass,
    },
}

struct HopObservation<'a> {
    observer: &'a mut (dyn FnMut(Event) + Send),
    collection: CollectionHandle,
    started: Instant,
    finished: bool,
}

impl<'a> HopObservation<'a> {
    fn start(observer: &'a mut (dyn FnMut(Event) + Send), collection: CollectionHandle) -> Self {
        observer(Event::HopStarted { collection });
        Self {
            observer,
            collection,
            started: Instant::now(),
            finished: false,
        }
    }

    fn finish(mut self, result: &Result<(Census, Census, Duration)>, publications: Publications) {
        self.finished = true;
        (self.observer)(Event::HopFinished {
            collection: self.collection,
            elapsed: result
                .as_ref()
                .map(|(_, _, elapsed)| *elapsed)
                .unwrap_or_else(|_| self.started.elapsed()),
            census: result
                .as_ref()
                .ok()
                .map(|(before, after, _)| (*before, *after)),
            publications,
            error: result.as_ref().err().map(|error| format!("{error:#}")),
        });
    }
}

impl Drop for HopObservation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            (self.observer)(Event::HopCancelled {
                collection: self.collection,
                elapsed: self.started.elapsed(),
            });
        }
    }
}

/// Incremental maintenance on a caller-owned store, without tasks or runtime ownership.
///
/// Call `tick` at the desired cadence; it returns `None` and emits no work events
/// when no relevant input changed. The caller selects cancellation against that
/// future, then closes its own Peer/Pile. Dropping the future cancels its work;
/// no worker is detached. A subsequent tick retries incomplete work. Synchronous
/// encoding operations are cooperative and cannot be preempted mid-call.
///
/// Retained snapshots are dependency invalidation boundaries, not a domain model.
/// Drop this driver before closing the store to release those immutable snapshots.
pub struct Driver<R> {
    references: Vec<Reference>,
    dependencies: bool,
    backend: SuccinctBackend,
    state: MaintenanceState<R>,
    baseline: Option<R>,
    catch_up: bool,
    interests: StoreDependencies,
    passes: u64,
    telemetry: Option<maintenance_telemetry::Telemetry>,
}

impl<R: StoreSnapshot> Driver<R> {
    pub fn new(
        targets: impl IntoIterator<Item = Target>,
        dependencies: bool,
        backend: SuccinctBackend,
    ) -> Result<Self> {
        Self::with_references(
            targets.into_iter().map(Reference::Native).collect(),
            dependencies,
            backend,
        )
    }

    /// CLI selection adapter, preserving literal `name:`, bare and prefixed handles.
    pub fn from_references(
        references: Vec<String>,
        dependencies: bool,
        backend: SuccinctBackend,
    ) -> Result<Self> {
        Self::with_references(
            references.into_iter().map(Reference::Cli).collect(),
            dependencies,
            backend,
        )
    }

    fn with_references(
        references: Vec<Reference>,
        dependencies: bool,
        backend: SuccinctBackend,
    ) -> Result<Self> {
        backend.check_available()?;
        Ok(Self {
            references,
            dependencies,
            backend,
            state: MaintenanceState::default(),
            baseline: None,
            catch_up: true,
            interests: StoreDependencies::default(),
            passes: 0,
            telemetry: None,
        })
    }

    /// Opt-in pile-backed worker observations; not required for in-process events.
    pub fn with_telemetry(mut self, telemetry: maintenance_telemetry::Telemetry) -> Self {
        self.telemetry = Some(telemetry);
        self
    }

    /// Emit an optional final telemetry sample before the caller closes its store.
    pub fn finish<S: Store>(&mut self, store: &mut S) {
        if let Some(telemetry) = self.telemetry.as_mut() {
            telemetry.finish(store);
        }
    }

    pub async fn tick<S: Store<Snapshot = R> + AsyncBlobStoreAcquire + Send>(
        &mut self,
        store: &mut S,
        signer: &SigningKey,
        observer: &mut (impl FnMut(Event) + Send),
    ) -> Result<Option<Pass>> {
        if let Some(telemetry) = self.telemetry.as_mut() {
            telemetry.emit_due(store);
        }
        let before = store
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
        if !self.catch_up
            && !self
                .baseline
                .as_ref()
                .is_some_and(|previous| maintenance_changed(previous, &before, &self.interests))
        {
            self.state.rebase_unchanged(&before);
            self.baseline = Some(before);
            return Ok(None);
        }
        // If the future is dropped or a snapshot fails, incomplete work stays dirty.
        self.catch_up = true;
        let started = Instant::now();
        let pass = maintenance_pass_events(
            store,
            &self.references,
            signer,
            self.dependencies,
            self.backend,
            &mut self.state,
            self.telemetry.as_mut(),
            observer,
        )
        .await?;
        self.passes += 1;
        self.interests = self.state.interests();
        let after = store
            .snapshot()
            .map_err(|error| anyhow!("pile snapshot after maintenance: {error:?}"))?;
        self.catch_up = maintenance_changed(&before, &after, &self.interests);
        self.baseline = Some(after);
        observer(Event::PassFinished {
            sequence: self.passes,
            elapsed: started.elapsed(),
            pass,
        });
        Ok(Some(pass))
    }
}

/// How many records of each kind name one collection, using its record index.
fn cover_census<R: CollectionRead>(
    snapshot: &R,
    collection: CollectionHandle,
) -> Result<(usize, usize, usize, usize)> {
    let mut commits = 0usize;
    let mut merges = 0usize;
    let mut derives = 0usize;
    let mut maps = 0usize;
    let records = snapshot
        .select_records(&BTreeSet::from([CollectionRecordSelector::Collection(
            collection,
        )]))
        .map_err(|error| anyhow!("select collection records: {error:?}"))?;
    for record in records {
        match record {
            CollectionRecord::Commit(_) => commits += 1,
            CollectionRecord::Merge(_) => merges += 1,
            CollectionRecord::Derive(_) => derives += 1,
            CollectionRecord::Map(_) => maps += 1,
        }
    }
    Ok((commits, merges, derives, maps))
}

/// Maintain `handle` under whichever encoding its descriptor names.
///
/// The descriptor is the whole of the information needed: a root names its
/// blob representation, a derivation names its source and mapping as well,
/// an attached collection its parent and mapping, and `Collection::open`
/// checks the typed handle against those facts. What a binary cannot do is
/// maintain an encoding it was not compiled with, so the dispatch asks each
/// encoding this binary implements for its own id, exactly as
/// the CLI's representation display does, and reports an unknown one rather than
/// guessing. An attached collection carries its parent first and then
/// attaches the parent's new frontier.
async fn maintain_by_representation<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    snapshot: &S::Snapshot,
    handle: CollectionHandle,
    representation: Id,
    algorithm: Option<Id>,
    attached: bool,
    signer: &SigningKey,
    succinct_backend: SuccinctBackend,
) -> Result<S::Snapshot> {
    use triblespace_core::collection::latest::LatestBlob;
    use triblespace_core::collection::lww_register::LwwRegisterBlob;
    use triblespace_core::collection::{CollectionAttachment, CollectionRealization};
    use triblespace_search::portable_bm25::PortableBM25Blob;

    async fn attach<S, T>(
        pile: &mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        signer: &SigningKey,
    ) -> Result<S::Snapshot>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
        T: CollectionAttachment + MetaDescribe,
        Handle<T>: triblespace_core::inline::InlineEncoding,
    {
        let collection: Collection<T> = Collection::open(snapshot, handle)
            .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
        pile.maintain_attached(collection, signer)
            .await
            .map_err(|error| anyhow!("maintain attached collection: {error}"))
    }

    if attached {
        return if representation == <SuccinctArchiveBlob as MetaDescribe>::id() {
            #[cfg(feature = "succinct-cuda")]
            if matches!(succinct_backend, SuccinctBackend::Cuda) {
                let collection = Collection::<SuccinctArchiveBlob>::open(snapshot, handle)
                    .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
                return pile
                    .maintain_attached_with::<triblespace_gpu::CudaSuccinctMapping>(
                        collection, signer,
                    )
                    .await
                    .map_err(|error| anyhow!("maintain CUDA Succinct attachments: {error}"));
            }
            #[cfg(not(feature = "succinct-cuda"))]
            succinct_backend.check_available()?;
            attach::<S, SuccinctArchiveBlob>(pile, snapshot, handle, signer).await
        } else if representation == <Rank9AcceleratedSuccinctArchiveBlob as MetaDescribe>::id() {
            attach::<S, Rank9AcceleratedSuccinctArchiveBlob>(pile, snapshot, handle, signer).await
        } else if representation == <EntityIdSetBlob as MetaDescribe>::id() {
            attach::<S, EntityIdSetBlob>(pile, snapshot, handle, signer).await
        } else if representation == <LatestBlob as MetaDescribe>::id() {
            attach::<S, LatestBlob>(pile, snapshot, handle, signer).await
        } else if representation == <LwwRegisterBlob as MetaDescribe>::id() {
            attach::<S, LwwRegisterBlob>(pile, snapshot, handle, signer).await
        } else if representation == <triblespace_paths::PathSummaryBlob as MetaDescribe>::id() {
            attach::<S, triblespace_paths::PathSummaryBlob>(pile, snapshot, handle, signer).await
        } else if representation == <PortableBM25Blob as MetaDescribe>::id() {
            attach::<S, PortableBM25Blob>(pile, snapshot, handle, signer).await
        } else {
            Err(anyhow!(
                "attached representation {representation:X} is not implemented by this binary; \
                 nothing here can maintain it"
            ))
        };
    }

    async fn go<S, T>(
        pile: &mut S,
        snapshot: &S::Snapshot,
        handle: CollectionHandle,
        signer: &SigningKey,
    ) -> Result<S::Snapshot>
    where
        S: Store + AsyncBlobStoreAcquire + Send,
        T: CollectionRealization + MetaDescribe,
        Handle<T>: triblespace_core::inline::InlineEncoding,
    {
        let collection: Collection<T> = Collection::open(snapshot, handle)
            .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
        pile.maintain(collection, signer)
            .await
            .map_err(|error| anyhow!("maintain collection: {error}"))
    }

    if representation == <SimpleArchive as MetaDescribe>::id() {
        if algorithm.is_some() {
            return Err(anyhow!(
                "derived SimpleArchive mappings are not implemented by this binary"
            ));
        }
        go::<S, SimpleArchive>(pile, snapshot, handle, signer).await
    } else if nvfp4_embedding_set_id().is_some_and(|nvfp4| representation == nvfp4) {
        // Both the ordinary embedding conversion and model inference produce
        // this encoding. Its algorithm, not just its representation, chooses
        // the executable mapping.
        maintain_nvfp4_embedding_set(pile, snapshot, handle, algorithm, signer).await
    } else {
        Err(anyhow!(
            "representation {representation:X} is not implemented by this binary; \
             nothing here can maintain it"
        ))
    }
}

/// Resolve an explicit maintenance selection without materializing a catalogue.
///
/// In particular, a descriptor handle does not need any record to name it yet:
/// `derive` registers its blob before its first maintenance publishes equations.
fn resolve_maintenance_target<R: StoreRead>(
    snapshot: &R,
    reference: &str,
) -> Result<CollectionHandle> {
    let reference = reference.trim();
    if reference.starts_with("blake3:") {
        return parse_collection_handle(reference);
    }
    let (name, explicit_name) = match reference.strip_prefix("name:") {
        Some(name) => (name, true),
        None => (reference, false),
    };
    // Bare handles, like explicit ones, are independent of the historical
    // record inventory. `name:` selects a literal hexadecimal name instead.
    if !explicit_name {
        if let Ok(handle) = parse_collection_handle(reference) {
            return Ok(handle);
        }
    }

    resolve_maintenance_name(snapshot, name)
}

fn resolve_maintenance_name<R: StoreRead>(snapshot: &R, name: &str) -> Result<CollectionHandle> {
    use triblespace_core::collection::records::{collection_name, KIND_COLLECTION_DESCRIPTOR};
    use triblespace_core::macros::{find, pattern};

    let mut candidates = BTreeSet::new();
    for record in snapshot
        .records()
        .map_err(|error| anyhow!("enumerate collection names: {error:?}"))?
    {
        let record = record.map_err(|error| anyhow!("read collection record: {error:?}"))?;
        candidates.insert(record.collection());
    }
    let mut matches = BTreeSet::new();
    for handle in candidates {
        let Ok(facts) = snapshot.get::<TribleSet, SimpleArchive>(handle) else {
            continue;
        };
        for label in find!(
            label: Inline<Handle<UTF8String>>,
            pattern!(&facts, [{
                metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_name: ?label,
            }])
        ) {
            let Ok(label) = snapshot.get::<anybytes::View<str>, UTF8String>(label) else {
                continue;
            };
            if label.as_ref() == name {
                matches.insert(handle);
            }
        }
    }
    match matches.len() {
        1 => Ok(*matches.first().expect("one matching collection")),
        0 => Err(anyhow!(
            "no resident referenced collection named {name:?}; use its exact descriptor handle \
             for a newly registered collection"
        )),
        _ => Err(anyhow!(
            "multiple collections are named {name:?}; select an exact descriptor handle"
        )),
    }
}

/// A temporary call order, not a second model of the collection descriptors.
/// Source, parent and sibling links are queried in one immutable observation
/// and discarded: a derived collection after its source, an attached one
/// after its parent and after the attached siblings its mapping reads.
fn maintenance_order<R: BlobStoreGet>(
    snapshot: &R,
    target: CollectionHandle,
    dependencies: bool,
    attempted: &BTreeSet<CollectionHandle>,
) -> Result<Vec<CollectionHandle>> {
    fn visit<R: BlobStoreGet>(
        snapshot: &R,
        current: CollectionHandle,
        dependencies: bool,
        attempted: &BTreeSet<CollectionHandle>,
        visiting: &mut BTreeSet<CollectionHandle>,
        order: &mut Vec<CollectionHandle>,
    ) -> Result<()> {
        if attempted.contains(&current) || order.contains(&current) {
            return Ok(());
        }
        if !visiting.insert(current) {
            return Err(anyhow!("cyclic collection source dependency"));
        }
        if dependencies {
            let facts: TribleSet = snapshot.get(current).map_err(|error| {
                anyhow!("read descriptor blake3:{}: {error}", handle_hex(current))
            })?;
            let mut upstream: Vec<CollectionHandle> = Vec::new();
            upstream.extend(descriptor::source(&facts)?);
            upstream.extend(descriptor::parents(&facts)?);
            upstream.extend(descriptor::reads_attached(&facts)?);
            for dependency in upstream {
                visit(snapshot, dependency, true, attempted, visiting, order)?;
            }
        }
        visiting.remove(&current);
        order.push(current);
        Ok(())
    }
    let mut order = Vec::new();
    visit(
        snapshot,
        target,
        dependencies,
        attempted,
        &mut BTreeSet::new(),
        &mut order,
    )?;
    Ok(order)
}

/// Ephemeral recomputation boundaries, never interpreted collection answers.
struct MaintenanceHop<R> {
    before: R,
    interests: StoreDependencies,
    // Preserve the old retry opportunity whenever any selected input wakes
    // this worker. An Err is not a valid cached answer, especially when its
    // cause is runtime/provider state outside the stored dependency model.
    retry_on_pass: bool,
}

struct MaintenanceState<R> {
    planning: StoreDependencies,
    hops: BTreeMap<CollectionHandle, MaintenanceHop<R>>,
}

impl<R> Default for MaintenanceState<R> {
    fn default() -> Self {
        Self {
            planning: StoreDependencies::default(),
            hops: BTreeMap::new(),
        }
    }
}

fn extend_maintenance_interests(into: &mut StoreDependencies, from: &StoreDependencies) {
    into.records.extend(from.records.iter().copied());
    into.blobs.extend(from.blobs.iter().copied());
    into.capability_proofs |= from.capability_proofs;
    into.all_records |= from.all_records;
    into.all_blobs |= from.all_blobs;
}

impl<R: StoreSnapshot> MaintenanceState<R> {
    fn interests(&self) -> StoreDependencies {
        let mut interests = self.planning.clone();
        // A pass triggered by one chain must not forget skipped chains' misses
        // or record interests. Name lookup stays broad only at planning scope.
        for hop in self.hops.values() {
            extend_maintenance_interests(&mut interests, &hop.interests);
        }
        interests
    }

    fn rebase_unchanged(&mut self, current: &R) {
        for hop in self.hops.values_mut() {
            if !maintenance_changed(&hop.before, current, &hop.interests) {
                hop.before = current.clone();
            }
        }
    }

    fn needs_work(&mut self, handle: CollectionHandle, current: &R) -> bool {
        let Some(hop) = self.hops.get_mut(&handle) else {
            return true;
        };
        if hop.retry_on_pass || maintenance_changed(&hop.before, current, &hop.interests) {
            return true;
        }
        // Rebase only after proving this hop unchanged, releasing older shared
        // index versions without swallowing an unconsumed relevant arrival.
        hop.before = current.clone();
        false
    }
}

/// What one completed pass did: the targets it selected, the hops that
/// maintained (one `maintained` line each), the hops that published a MERGE,
/// DERIVE or MAP, and the selections that failed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Pass {
    pub targets: usize,
    pub maintained: usize,
    /// Number of hops that successfully inserted at least one equation.
    pub published: usize,
    pub failures: usize,
}

#[cfg(test)]
async fn maintenance_pass<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    references: &[String],
    signer: &SigningKey,
    dependencies: bool,
    succinct_backend: SuccinctBackend,
    state: &mut MaintenanceState<S::Snapshot>,
) -> Result<usize> {
    maintenance_pass_observed(
        pile,
        references,
        signer,
        dependencies,
        succinct_backend,
        state,
        None,
    )
    .await
    .map(|pass| pass.failures)
}

#[cfg(test)]
async fn maintenance_pass_observed<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    references: &[String],
    signer: &SigningKey,
    dependencies: bool,
    succinct_backend: SuccinctBackend,
    state: &mut MaintenanceState<S::Snapshot>,
    telemetry: Option<&mut maintenance_telemetry::Telemetry>,
) -> Result<Pass> {
    maintenance_pass_events(
        pile,
        &references
            .iter()
            .cloned()
            .map(Reference::Cli)
            .collect::<Vec<_>>(),
        signer,
        dependencies,
        succinct_backend,
        state,
        telemetry,
        &mut |_| {},
    )
    .await
}

async fn maintenance_pass_events<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    references: &[Reference],
    signer: &SigningKey,
    dependencies: bool,
    succinct_backend: SuccinctBackend,
    state: &mut MaintenanceState<S::Snapshot>,
    mut telemetry: Option<&mut maintenance_telemetry::Telemetry>,
    observer: &mut (dyn FnMut(Event) + Send),
) -> Result<Pass> {
    let started = telemetry
        .as_deref_mut()
        .map(|telemetry| telemetry.begin_pass());
    let result = maintenance_pass_inner(
        pile,
        references,
        signer,
        dependencies,
        succinct_backend,
        state,
        telemetry.as_deref_mut(),
        observer,
    )
    .await;
    if let (Some(telemetry), Some(started)) = (telemetry, started) {
        telemetry.finish_pass(
            started,
            result.as_ref().is_ok_and(|pass| pass.failures == 0),
        );
        telemetry.emit_due(pile);
    }
    result
}

async fn maintenance_pass_inner<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    references: &[Reference],
    signer: &SigningKey,
    dependencies: bool,
    succinct_backend: SuccinctBackend,
    state: &mut MaintenanceState<S::Snapshot>,
    mut telemetry: Option<&mut maintenance_telemetry::Telemetry>,
    observer: &mut (dyn FnMut(Event) + Send),
) -> Result<Pass> {
    let snapshot = ObservedStore::new(
        pile.snapshot()
            .map_err(|error| anyhow!("pile snapshot: {error:?}"))?,
    );
    let mut selected = BTreeSet::new();
    let mut pass = Pass::default();
    for reference in references {
        match reference.resolve(&snapshot) {
            Ok(handle) => {
                selected.insert(handle);
            }
            Err(error) => {
                observer(Event::Failure {
                    reference: reference.label(),
                    error: format!("{error:#}"),
                });
                pass.failures += 1;
            }
        }
    }
    pass.targets = selected.len();
    state.planning = snapshot.dependencies();
    drop(snapshot);

    // Give independent authors different stable priorities over the same
    // explicit selection. This is local scheduling, not exclusive ownership:
    // nodes may still choose the same first target or perform overlapping work.
    // Only the outer chain order changes; the dependency walk and canonical
    // per-collection merge/derive plans below remain untouched.
    let author = signer.verifying_key();
    let mut targets: Vec<_> = selected.iter().copied().collect();
    targets.sort_by_cached_key(|target| {
        let mut hash = blake3::Hasher::new();
        hash.update(b"trible/maintenance-target-order");
        hash.update(author.as_bytes());
        hash.update(&target.raw);
        (*hash.finalize().as_bytes(), target.raw)
    });

    let mut attempted = BTreeSet::new();
    for target in targets {
        let snapshot = ObservedStore::new(
            pile.snapshot()
                .map_err(|error| anyhow!("pile snapshot: {error:?}"))?,
        );
        let order = maintenance_order(&snapshot, target, dependencies, &attempted);
        extend_maintenance_interests(&mut state.planning, &snapshot.dependencies());
        let order = match order {
            Ok(order) => order,
            Err(error) => {
                observer(Event::Failure {
                    reference: format!("blake3:{}", handle_hex(target)),
                    error: format!("{error:#}"),
                });
                pass.failures += 1;
                continue;
            }
        };
        drop(snapshot);
        for handle in order {
            attempted.insert(handle);
            // Give shutdown and the runtime's I/O driver a boundary between
            // one-edge operations, including immediately-ready local stores.
            tokio::task::yield_now().await;
            let before = match pile.snapshot() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    if let Some(hop) = state.hops.get_mut(&handle) {
                        hop.retry_on_pass = true;
                    }
                    observer(Event::Failure {
                        reference: format!("blake3:{}", handle_hex(handle)),
                        error: format!("pile snapshot: {error:?}"),
                    });
                    pass.failures += 1;
                    continue;
                }
            };
            if !state.needs_work(handle, &before) {
                continue;
            }
            let observation = HopObservation::start(observer, handle);
            let hop_started = telemetry.as_deref_mut().map(|telemetry| {
                let started = telemetry.begin_hop();
                telemetry.emit_due(pile);
                started
            });
            // Publications are counted at the insert call, the count telemetry
            // keeps; without telemetry the hop keeps its own.
            let mut untracked = maintenance_telemetry::Publications::default();
            let publications = match telemetry.as_deref_mut() {
                Some(telemetry) => &mut telemetry.publications,
                None => &mut untracked,
            };
            let published_before = *publications;
            let mut observed = ObservedStore::new(&mut *pile);
            let result = async {
                let snapshot = observed
                    .snapshot()
                    .map_err(|error| anyhow!("pile snapshot: {error:?}"))?;
                let facts: TribleSet = snapshot
                    .get(handle)
                    .map_err(|error| anyhow!("read collection descriptor: {error}"))?;
                let representation = descriptor::representation(&facts)?;
                let algorithm = descriptor::mapping_algorithm(&facts)?;
                let attached = !descriptor::parents(&facts)?.is_empty();
                let before = cover_census(&snapshot, handle)?;
                let started = Instant::now();
                let mut counted = maintenance_telemetry::CountedStore {
                    inner: &mut observed,
                    counts: &mut *publications,
                };
                let after = maintain_by_representation(
                    &mut counted,
                    &snapshot,
                    handle,
                    representation,
                    algorithm,
                    attached,
                    signer,
                    succinct_backend,
                )
                .await?;
                let after = cover_census(&after, handle)?;
                Ok::<_, anyhow::Error>((
                    Census::from(before),
                    Census::from(after),
                    started.elapsed(),
                ))
            }
            .await;
            // A hop that failed after publishing still published.
            let published = Publications {
                merges: publications.merges - published_before.merges,
                derives: publications.derives - published_before.derives,
                maps: publications.maps - published_before.maps,
            };
            if *publications != published_before {
                pass.published += 1;
            }
            let interests = observed.dependencies();
            drop(observed);
            if let (Some(telemetry), Some(started)) = (telemetry.as_deref_mut(), hop_started) {
                telemetry.finish_hop(started, result.is_ok());
                telemetry.emit_due(pile);
            }
            // Retain the start boundary even after an error or partial write.
            // A later snapshot can contain records/proofs that the operation's
            // frozen frontier did not consume. Its own writes also request one
            // local catch-up; an unchanged sibling need not run again.
            state.hops.insert(
                handle,
                MaintenanceHop {
                    before,
                    interests,
                    retry_on_pass: result.is_err(),
                },
            );
            observation.finish(&result, published);
            match result {
                Ok(_) => pass.maintained += 1,
                Err(_) => {
                    pass.failures += 1;
                    // Failed upkeep does not retract its existing resident nodes.
                    // A downstream target can still consume that available input.
                }
            }
        }
    }
    // Entries no longer reachable from this selection hold no useful work.
    // Failed planning retains its exact misses above; when that route becomes
    // available, absent entries run afresh rather than reusing an old answer.
    state.hops.retain(|handle, _| attempted.contains(handle));
    Ok(pass)
}

fn maintenance_changed<S: StoreSnapshot>(
    previous: &S,
    current: &S,
    interests: &StoreDependencies,
) -> bool {
    !current.changes_for(previous, interests).is_empty()
}

fn parse_collection_handle(handle: &str) -> Result<CollectionHandle> {
    use triblespace::prelude::TryToInline;

    let trimmed = handle.trim();
    let owned;
    let normalized = if trimmed.contains(':') {
        trimmed
    } else {
        owned = format!("blake3:{trimmed}");
        owned.as_str()
    };
    let hash: Inline<Hash<Blake3>> = normalized.try_to_inline().map_err(|e| {
        anyhow!(
            "parse collection handle {handle:?}: {e:?} (expected `blake3:<64 hex>` or bare hex)"
        )
    })?;
    Ok(hash.into())
}

fn handle_hex(handle: CollectionHandle) -> String {
    hex::encode(handle.raw)
}
fn nvfp4_embedding_set_id() -> Option<Id> {
    #[cfg(feature = "search")]
    {
        Some(<triblespace_search::nvfp4::NvFp4CosineSet<
            triblespace_search::schemas::Embedding,
        > as MetaDescribe>::id())
    }
    #[cfg(not(feature = "search"))]
    {
        None
    }
}

#[cfg(feature = "search")]
async fn maintain_nvfp4_embedding_set<S: Store + AsyncBlobStoreAcquire + Send>(
    pile: &mut S,
    snapshot: &S::Snapshot,
    handle: CollectionHandle,
    algorithm: Option<Id>,
    signer: &SigningKey,
) -> Result<S::Snapshot> {
    use triblespace_core::collection::CollectionStoreExt as _;
    use triblespace_search::nvfp4::EMBEDDING_ATTRIBUTE_TO_NVFP4;
    use triblespace_search::schemas::Embedding;
    use triblespace_search::semantic::{SemanticIndex, NOMIC_ATTRIBUTES_TO_NVFP4};
    let collection: Collection<
        triblespace_search::nvfp4::NvFp4CosineSet<triblespace_search::schemas::Embedding>,
    > = Collection::open(snapshot, handle)
        .map_err(|error| anyhow!("open collection descriptor: {error}"))?;
    if algorithm == Some(EMBEDDING_ATTRIBUTE_TO_NVFP4) {
        pile.maintain(collection, signer)
            .await
            .map_err(|error| anyhow!("maintain NVFP4 embedding collection: {error}"))
    } else if algorithm == Some(NOMIC_ATTRIBUTES_TO_NVFP4) {
        pile.maintain_with::<SemanticIndex<Embedding>>(collection, signer)
            .await
            .map_err(|error| anyhow!("maintain semantic index: {error}"))
    } else {
        Err(anyhow!(
            "NVFP4 mapping algorithm {} is not implemented by this binary; \
             historical or unknown mappings are not rebound to another algorithm",
            algorithm
                .map(|id| format!("{id:X}"))
                .unwrap_or_else(|| "<absent>".to_owned())
        ))
    }
}

#[cfg(not(feature = "search"))]
async fn maintain_nvfp4_embedding_set<S: Store + AsyncBlobStoreAcquire + Send>(
    _pile: &mut S,
    _snapshot: &S::Snapshot,
    _handle: CollectionHandle,
    _algorithm: Option<Id>,
    _signer: &SigningKey,
) -> Result<S::Snapshot> {
    unreachable!("the NVFP4 representation is only recognised with the search feature")
}
