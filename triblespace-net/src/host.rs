//! Collection-scoped network host.
//!
//! TLS authenticates endpoint identities, but establishing a transport
//! connection grants no team or collection authority. Each semantic repair is
//! one stream admitted from the server's complete local READ(C) closure.
//! Grants reach their subjects by the grant exchange on `recon/1`
//! ([`crate::grants`]). DHT routing and provider-directory
//! operations discover exact blob holders through opaque KDF(H) locators.
//! Descriptor holders and scoped authority keys are collection gossip bootstrap
//! hints, never declarations of membership or authority.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use anybytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::{FutureExt as _, StreamExt as _, stream::FuturesUnordered};
use iroh_base::{EndpointAddr, EndpointId};
use tokio::io::AsyncReadExt as _;
use tracing::{debug, warn};
use triblespace_core::blob::Blob;
use triblespace_core::blob::encodings::UnknownBlob;
use triblespace_core::collection::selection::{Selection, config_facts, sync_selection};
use triblespace_core::collection::{
    CollectionHandle, CollectionRecordSelector, HeldBlobs, HeldRead,
};
use triblespace_core::inline::Inline;
use triblespace_core::inline::encodings::hash::Handle;
use triblespace_core::patch::{Entry as PatchEntry, IdentitySchema, PATCH};
use triblespace_core::repo::{
    BlobStoreGet, ObservedStore, StoreChanges, StoreDependencies, StoreRead,
};
use triblespace_core::trible::TribleSet;

use crate::bearer::{BearerLocatorIndex, blob_locator, locator_index, update_locator_index};
use crate::channel::{NetEvent, NetEventBatch};
use crate::collection_activation::{CollectionRepairOverlay, CollectionRepairOverlayError};
use crate::collection_delta::update_collection_record_patch;
use crate::collection_wire::manifest;
use crate::connection::{ConnectionTable, RESET_UNKNOWN, ReconEvent, Service};
use crate::health::{CollectionHealth, Health, HealthSnapshot, StoreHealth};
use crate::identity::iroh_secret;
use crate::inventory::ReconcileQos;
use crate::landing::{Land, LandSlot};
use crate::protocol::{
    OP_FIND_VALUE, OP_PROVIDER_PUT, PILE_SYNC_ALPN, PROVIDER_PUT_FULL, PROVIDER_PUT_OK, RawHash,
    TAG_BLOB, TAG_DHT, op_find_value, op_get_blob_with_limit, op_provider_put, recv_hash, recv_u8,
    send_u8, serve_find_value, serve_get_blob,
};
use crate::provider::{
    ProviderDirectory, ProviderKey, ProviderObservation, ProviderPublication, ProviderPublisher,
    ProviderPutResult, ProviderToken, PublicationResult, blob_provider_token,
};
use crate::recon::Frame;
use crate::routing::{ALPHA, IterativeLookup, K, RoutingKey, RoutingTable};
use crate::transport::{Conn, Harness, PeerId, RecvStream, SendStream, Transport};
use crate::wake::{
    CollectionWakeEvent, CollectionWakeNetwork, CollectionWakePlane, CollectionWakeRoot,
    CollectionWakeSubscription, ReceivedCollectionWake,
};
use crate::wake_schedule::WakeSchedule;
use crate::walk::PullKind;

/// Ephemeral local collection interest. It is deliberately not a durable
/// marker or ambient registry.
pub(crate) type ActiveCollections = PATCH<32, IdentitySchema>;

/// Transport and local scheduling configuration.
///
/// Collection authority is intentionally absent. A connection is ordinary
/// mutually authenticated TLS; READ authority is supplied on each collection
/// repair stream.
#[derive(Clone)]
pub struct PeerConfig {
    /// Bootstrap endpoint routes.
    pub peers: Vec<EndpointAddr>,
    /// Local pull/serve scheduling choices. Never sent as authority.
    pub qos: ReconcileQos,
    /// Maximum DHT provider-announcement attempts during this process.
    ///
    /// `None` preserves the ordinary unlimited scheduler. `Some(0)` disables
    /// announcements without disabling exact H-authorized serving or query-time
    /// resident self hints. Retries and renewals consume the same budget as
    /// first publication.
    pub provider_publication_budget: Option<u64>,
    /// The one local socket the endpoint binds, for example `127.0.0.1:7001`.
    ///
    /// `None` keeps iroh's ordinary sockets (every IPv4 interface on a free
    /// port, and IPv6 where available). `Some` binds this address and no
    /// other, so a peer's route can be written down before it starts.
    pub bind: Option<SocketAddr>,
}

/// What a started production host hands back from its thread.
#[derive(Clone)]
pub struct HostStarted {
    /// The stock gossip wake plane on the host's endpoint.
    pub wake_plane: CollectionWakePlane,
    /// The local sockets the endpoint bound.
    pub bound: Vec<SocketAddr>,
}

trait BlobSnapshotReader: Send + Sync + 'static {
    fn get_blob(&self, hash: RawHash) -> Option<Bytes>;
}

struct CloneableBlobSnapshotReader<R>(Mutex<R>);

impl<R> BlobSnapshotReader for CloneableBlobSnapshotReader<R>
where
    R: BlobStoreGet + Clone + Send + 'static,
{
    fn get_blob(&self, hash: RawHash) -> Option<Bytes> {
        let reader = self.0.lock().unwrap().clone();
        reader
            .get::<Bytes, UnknownBlob>(Inline::<Handle<UnknownBlob>>::new(hash))
            .ok()
    }
}

/// A clone of one resident snapshot behind the host's existing erased reader.
/// Point reads never fetch, record demand, or copy a catalogue of its blobs.
#[derive(Clone)]
pub(crate) struct ResidentBlobReader(Arc<dyn BlobSnapshotReader>);

impl ResidentBlobReader {
    pub(crate) fn new<R>(reader: &R) -> Self
    where
        R: BlobStoreGet + Clone + Send + 'static,
    {
        Self(Arc::new(CloneableBlobSnapshotReader(Mutex::new(
            reader.clone(),
        ))))
    }
}

impl std::fmt::Debug for ResidentBlobReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResidentBlobReader")
    }
}

impl BlobStoreGet for ResidentBlobReader {
    type GetError<E: std::error::Error + Send + Sync + 'static> =
        triblespace_core::blob::MemoryStoreGetError<E>;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> Result<T, Self::GetError<<T as triblespace_core::blob::TryFromBlob<S>>::Error>>
    where
        S: triblespace_core::blob::BlobEncoding,
        T: triblespace_core::blob::TryFromBlob<S>,
    {
        use triblespace_core::blob::MemoryStoreGetError;
        let bytes = self
            .0
            .get_blob(handle.raw)
            .ok_or(MemoryStoreGetError::NotFound(
                triblespace_core::repo::MissingBlob {
                    handle: handle.transmute(),
                },
            ))?;
        // The snapshot returned these bytes for this exact handle. Preserve
        // that store invariant instead of hashing its output again.
        T::try_from_blob(Blob::with_handle(bytes, handle))
            .map_err(MemoryStoreGetError::ConversionFailed)
    }
}

/// One collection's immutable server overlay.
pub(crate) struct CollectionSnapshot {
    repair: Arc<CollectionRepairOverlay>,
}

impl CollectionSnapshot {
    #[cfg(test)]
    pub(crate) fn collection(&self) -> CollectionHandle {
        self.repair.collection()
    }

    /// The collection's records and authorization evidence.
    pub(crate) fn repair(&self) -> &CollectionRepairOverlay {
        &self.repair
    }

    fn wake_root(&self) -> [u8; 32] {
        self.repair.wake_root()
    }

    /// Bind the collection's held set, fixed by the same store observation
    /// as the repair evidence. The store's held-blob index computed it: no
    /// blob is scanned while publishing.
    fn with_held(repair: CollectionRepairOverlay, held: HeldBlobs) -> Self {
        Self {
            repair: Arc::new(repair.with_blob_inventory(Arc::new(held))),
        }
    }
}

/// Bounded, rotating sample of the collection's peering candidates, as
/// topic contacts. Neither an AUTH edge nor a descriptor asserts residency.
fn collection_topic_contacts(snapshot: &CollectionSnapshot, local: PeerId) -> Vec<EndpointId> {
    crate::peering::candidate_order(snapshot, &[], local, &rand::random())
        .into_iter()
        .filter_map(|peer| EndpointId::from_bytes(&peer).ok())
        .take(MAX_COLLECTION_PARTICIPANTS)
        .collect()
}

/// Fixed results and their raw lookup interests, including a missing descriptor.
/// Pending entries remain local observations, never serving advertisements.
struct CollectionObservation {
    value: Option<Arc<CollectionSnapshot>>,
    dependencies: StoreDependencies,
}

type CollectionSnapshotIndex = PATCH<32, IdentitySchema, Arc<CollectionObservation>>;

/// Resume after the last issued lookup, not the first collection on each turn.
/// Slow early lookups must not repeatedly consume every discovery slot.
fn discovery_order(
    collections: &CollectionSnapshotIndex,
    after: Option<RawHash>,
) -> impl Iterator<Item = &RawHash> {
    collections
        .iter_ordered()
        .filter(move |raw| after.is_none_or(|after| **raw > after))
        .chain(
            collections
                .iter_ordered()
                .take_while(move |raw| after.is_some_and(|after| **raw <= after)),
        )
}

/// Immutable host observation indexed exactly by active collection handle.
///
/// Each value pins record, native authorization-evidence, and positive resident
/// blob PATCHes. There is no global team or plaintext payload inventory.
pub(crate) struct StoreSnapshot {
    collections: CollectionSnapshotIndex,
    local: VerifyingKey,
    blobs: Arc<dyn BlobSnapshotReader>,
    bearer_locators: Arc<BearerLocatorIndex>,
    /// This pile's configuration collection, where its sync selection lives.
    config: Arc<TribleSet>,
}

impl StoreSnapshot {
    pub(crate) fn from_store_changes<R>(
        snapshot: R,
        active: &ActiveCollections,
        local: VerifyingKey,
        previous_store: Option<&R>,
        previous: Option<&Self>,
        changes: StoreChanges,
    ) -> anyhow::Result<Self>
    where
        R: StoreRead + HeldRead + Clone,
    {
        let mut collections = CollectionSnapshotIndex::new();
        let bearer_locators = match (previous_store, previous) {
            (Some(previous_store), Some(previous)) if changes.contains(StoreChanges::BLOBS) => {
                Arc::new(update_locator_index(
                    &snapshot,
                    previous_store,
                    &previous.bearer_locators,
                )?)
            }
            (_, Some(previous)) => previous.bearer_locators.clone(),
            _ => Arc::new(locator_index(&snapshot)?),
        };
        // The selection lives in the configuration collection, whose writes
        // are records.
        let config = match previous {
            Some(previous)
                if previous_store.is_some()
                    && previous.local == local
                    && !changes.contains(StoreChanges::COLLECTION_RECORDS) =>
            {
                previous.config.clone()
            }
            _ => Arc::new(config_facts(&snapshot, local).unwrap_or_else(|error| {
                warn!(%error, "configuration unreadable; no collection is selected for sync");
                TribleSet::new()
            })),
        };
        // This unobserved reader advances even when fixed per-C products do
        // not change. A later peer request may name a previously unseen R or
        // capability definition, outside any construction-time read set.
        let reader = ResidentBlobReader::new(&snapshot);
        for raw in active.iter_ordered() {
            let collection = CollectionHandle::new(*raw);
            // Positive, possibly incomplete while a start-up walk runs; an
            // untracked collection holds nothing.
            let held = snapshot.held(collection).unwrap_or_default();
            let prior = previous.and_then(|prior| prior.collections.get(&collection.raw));
            let relevant = match (previous_store, prior) {
                (Some(before), Some(prior)) => snapshot.changes_for(before, &prior.dependencies),
                _ => StoreChanges::ALL,
            };
            if let Some(prior) = prior.filter(|_| relevant.is_empty()) {
                let value = prior.value.as_ref().map(|prior| {
                    Arc::new(CollectionSnapshot::with_held(
                        prior.repair.as_ref().clone().with_reader(reader.clone()),
                        held.clone(),
                    ))
                });
                collections.insert(&PatchEntry::with_value(
                    raw,
                    Arc::new(CollectionObservation {
                        value,
                        dependencies: prior.dependencies.clone(),
                    }),
                ));
                continue;
            }
            let observed = ObservedStore::new(snapshot.clone());
            let prior_value = prior.and_then(|prior| prior.value.as_ref());
            let updated_records = match (previous_store, prior_value) {
                (Some(before), Some(prior))
                    if relevant.contains(StoreChanges::COLLECTION_RECORDS) =>
                {
                    Some(update_collection_record_patch(
                        &observed,
                        &ObservedStore::new(before.clone()),
                        prior.repair.records(),
                    )?)
                }
                _ => None,
            };
            let records = updated_records.as_ref().or_else(|| {
                prior_value
                    .filter(|_| !relevant.contains(StoreChanges::COLLECTION_RECORDS))
                    .map(|prior| prior.repair.records())
            });
            let authorization = prior_value
                .filter(|_| {
                    !relevant.contains(StoreChanges::BLOBS)
                        && !relevant.contains(StoreChanges::CAPABILITY_PROOFS)
                })
                .map(|prior| prior.repair.authorization_evidence());
            let repair = match CollectionRepairOverlay::observe(
                &observed,
                collection,
                records,
                authorization,
            ) {
                Ok(repair) => repair,
                Err(CollectionRepairOverlayError::Descriptor(error)) => {
                    warn!(collection = %hex::encode(&collection.raw[..4]), %error, "active collection descriptor is unavailable or invalid; isolating collection");
                    collections.insert(&PatchEntry::with_value(
                        raw,
                        Arc::new(CollectionObservation {
                            value: None,
                            dependencies: observed.dependencies(),
                        }),
                    ));
                    continue;
                }
                Err(error) => return Err(anyhow::Error::new(error)),
            };
            // Reused components keep their interests. In particular, reusing
            // the record PATCH must not lose its foundations selector merely
            // because this pass read only authority inputs.
            let mut dependencies = if authorization.is_some() {
                prior.unwrap().dependencies.clone()
            } else {
                observed.dependencies()
            };
            dependencies
                .records
                .insert(CollectionRecordSelector::Foundations(collection));
            let value = Arc::new(CollectionSnapshot::with_held(
                repair.with_reader(reader.clone()),
                held,
            ));
            collections.insert(&PatchEntry::with_value(
                raw,
                Arc::new(CollectionObservation {
                    value: Some(value),
                    dependencies,
                }),
            ));
        }
        Ok(Self {
            collections,
            local,
            blobs: reader.0,
            bearer_locators,
            config,
        })
    }

    pub(crate) fn collection(
        &self,
        collection: CollectionHandle,
    ) -> Option<Arc<CollectionSnapshot>> {
        self.collections.get(&collection.raw)?.value.clone()
    }

    /// The collection, if it is active here and the pile selects it for
    /// sync. A conflicted or unset register selects nothing.
    pub(crate) fn selected(&self, collection: CollectionHandle) -> Option<Arc<CollectionSnapshot>> {
        let selected = sync_selection(&*self.config, collection) == Selection::Selected;
        self.collection(collection).filter(|_| selected)
    }

    /// The active collections, selected or not.
    pub(crate) fn active(&self) -> impl Iterator<Item = CollectionHandle> + '_ {
        self.collections
            .iter_ordered()
            .map(|raw| CollectionHandle::new(*raw))
    }

    #[cfg(test)]
    pub(crate) fn collections(&self) -> impl Iterator<Item = Arc<CollectionSnapshot>> + '_ {
        self.collections
            .iter_ordered()
            .filter_map(move |key| self.collections.get(key)?.value.clone())
    }

    pub(crate) fn get_blob(&self, hash: &RawHash) -> Option<Bytes> {
        self.blobs.get_blob(*hash)
    }

    fn bearer_handle(&self, locator: RawHash) -> Option<RawHash> {
        self.bearer_locators.get(&locator).copied()
    }

    pub(crate) fn bearer_locators(&self) -> &BearerLocatorIndex {
        &self.bearer_locators
    }
}

type SharedSnapshot = Arc<StoreSnapshot>;
type SnapshotSlot = tokio::sync::watch::Receiver<Option<SharedSnapshot>>;

/// The async capability cloned into lazy readers.
/// Implementations return Blobs constructed from the received bytes, with the
/// cached handle preserved. The wire implementation also binds that handle to
/// the request; NetSender repeats only the cheap handle comparison here.
pub(crate) trait NetCapability: Send + Sync {
    fn fetch_blob(
        &self,
        hash: RawHash,
    ) -> futures::future::BoxFuture<'static, Option<Blob<UnknownBlob>>>;
}

type RoutingCandidates = Arc<Mutex<RoutingTable>>;
const MAX_COLLECTION_PARTICIPANTS: usize = 128;
const COLLECTION_PARTICIPANT_LEASE: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Bounded descriptor-holder rediscovery. A healthy subset must not prevent
/// eventual contact with another disconnected subset of the same collection.
#[derive(Clone, Copy, Debug)]
struct DiscoveryState {
    in_flight: bool,
    healthy: bool,
    attempts: u32,
    retry_at: crate::clock::Mono,
}

impl DiscoveryState {
    fn new(now: crate::clock::Mono) -> Self {
        Self {
            in_flight: false,
            healthy: false,
            attempts: 0,
            retry_at: now,
        }
    }

    fn start_if_due(&mut self, now: crate::clock::Mono, has_candidate: bool) -> bool {
        if self.in_flight {
            return false;
        }
        if self.healthy && !has_candidate {
            self.healthy = false;
            self.attempts = 0;
            self.retry_at = now;
        }
        if now < self.retry_at {
            return false;
        }
        self.healthy = has_candidate;
        self.in_flight = true;
        true
    }

    fn finish_attempt(&mut self, now: crate::clock::Mono) {
        self.in_flight = false;
        let shift = self.attempts.min(6);
        self.attempts = self.attempts.saturating_add(1);
        self.retry_at = now
            + if self.healthy {
                COLLECTION_RECONNECT_PERIOD
            } else {
                crate::RETRY_BACKOFF_BASE
                    .saturating_mul(1u32 << shift)
                    .min(crate::RETRY_BACKOFF_CAP)
            };
    }

    fn observe_success(&mut self, now: crate::clock::Mono) {
        if !self.healthy {
            self.healthy = true;
            self.attempts = 0;
            self.retry_at = now + COLLECTION_RECONNECT_PERIOD;
        }
    }
}

/// Configured peers remain permanent bootstrap routes. Recently learned DHT
/// candidates are a bounded, recency-ordered supplement which survives a
/// stock-gossip topic resubscription.
struct WakeBootstrapPeers {
    configured: Vec<EndpointId>,
    learned: VecDeque<EndpointId>,
}

impl WakeBootstrapPeers {
    fn new(configured: Vec<EndpointId>) -> Self {
        let mut unique = Vec::with_capacity(configured.len());
        for peer in configured {
            if !unique.contains(&peer) {
                unique.push(peer);
            }
        }
        Self {
            configured: unique,
            learned: VecDeque::new(),
        }
    }

    fn remember(&mut self, peers: impl IntoIterator<Item = EndpointId>) {
        for peer in peers {
            if self.configured.contains(&peer) {
                continue;
            }
            if let Some(position) = self.learned.iter().position(|known| *known == peer) {
                self.learned.remove(position);
            }
            self.learned.push_back(peer);
            if self.learned.len() > MAX_COLLECTION_PARTICIPANTS {
                self.learned.pop_front();
            }
        }
    }

    fn current(&self) -> Vec<EndpointId> {
        self.configured
            .iter()
            .chain(self.learned.iter())
            .copied()
            .collect()
    }

    /// Whether reopening the topic has any bootstrap route to retry.
    ///
    /// Configured endpoints remain generic topology seeds rather than repair
    /// participants; they are nevertheless valid routes through which the
    /// collection topic can reconnect to its mesh.
    fn has_recovery_route(&self) -> bool {
        !self.configured.is_empty() || !self.learned.is_empty()
    }
}

#[derive(Clone, Copy)]
struct Participant {
    seen: crate::clock::Mono,
    root: Option<CollectionWakeRoot>,
}

fn observe_participant(
    participants: &mut HashMap<[u8; 32], HashMap<PeerId, Participant>>,
    collection: [u8; 32],
    peer: PeerId,
    now: crate::clock::Mono,
) {
    let peers = participants.entry(collection).or_default();
    peers.retain(|_, observed| now.duration_since(observed.seen) <= COLLECTION_PARTICIPANT_LEASE);
    if !peers.contains_key(&peer)
        && peers.len() >= MAX_COLLECTION_PARTICIPANTS
        && let Some(oldest) = peers
            .iter()
            .min_by_key(|(peer, observed)| (observed.seen, **peer))
            .map(|(peer, _)| *peer)
    {
        peers.remove(&oldest);
    }
    peers
        .entry(peer)
        .and_modify(|observed| observed.seen = now)
        .or_insert(Participant {
            seen: now,
            root: None,
        });
}

fn live_participants(
    participants: &mut HashMap<[u8; 32], HashMap<PeerId, Participant>>,
    collection: [u8; 32],
    now: crate::clock::Mono,
) -> Vec<PeerId> {
    let Some(peers) = participants.get_mut(&collection) else {
        return Vec::new();
    };
    peers.retain(|_, observed| now.duration_since(observed.seen) <= COLLECTION_PARTICIPANT_LEASE);
    let mut live = peers.keys().copied().collect::<Vec<_>>();
    live.sort_unstable();
    live
}

fn forget_participant(
    participants: &mut HashMap<[u8; 32], HashMap<PeerId, Participant>>,
    collection: [u8; 32],
    peer: PeerId,
) -> bool {
    let empty = participants.get_mut(&collection).is_some_and(|peers| {
        peers.remove(&peer);
        peers.is_empty()
    });
    if empty {
        participants.remove(&collection);
    }
    empty
}

#[derive(Clone)]
struct ProviderClient<T: Transport> {
    connections: ConnectionTable<T, SnapshotHandler>,
    providers: Arc<Mutex<ProviderDirectory>>,
    candidates: RoutingCandidates,
    my_id: PeerId,
    /// Drawn once per requester and never sent; see [`provider_rank`].
    salt: [u8; 32],
}

#[cfg(test)]
impl<T: Transport> ProviderClient<T> {
    /// A client whose own connections serve an empty snapshot.
    fn for_test(transport: T, routes: RoutingTable) -> Self {
        let handler = SnapshotHandler::for_test(transport.local_id(), routes);
        Self {
            providers: handler.providers.clone(),
            candidates: handler.candidates.clone(),
            my_id: handler.local_id,
            salt: rand::random(),
            connections: ConnectionTable::new(transport, handler),
        }
    }
}

struct NetCap<T: Transport> {
    client: ProviderClient<T>,
}

impl<T: Transport> NetCapability for NetCap<T> {
    fn fetch_blob(
        &self,
        hash: RawHash,
    ) -> futures::future::BoxFuture<'static, Option<Blob<UnknownBlob>>> {
        let client = self.client.clone();
        Box::pin(async move {
            match client.fetch_blob(hash, None).await {
                Ok(Some(bytes)) => {
                    debug!("exact blob fetch completed");
                    Some(bytes)
                }
                Ok(None) => {
                    debug!("responding DHT replicas or providers had no exact blob available");
                    None
                }
                Err(error) => {
                    debug!(%error, "exact blob fetch failed before availability could be established");
                    None
                }
            }
        })
    }
}

/// Default end-to-end budget for an interactive exact blob read.
pub const INTERACTIVE_FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Clone)]
pub struct NetSender {
    snapshot: tokio::sync::watch::Sender<Option<SharedSnapshot>>,
    cap: tokio::sync::watch::Receiver<Option<Arc<dyn NetCapability>>>,
    /// Where the store side installs the landing of what walks receive.
    lander: tokio::sync::watch::Sender<Option<Arc<dyn Land>>>,
    id: EndpointId,
    health: Health,
}

impl NetSender {
    pub fn id(&self) -> EndpointId {
        self.id
    }

    /// Read bounded runtime evidence without starting work or refreshing its age.
    pub fn health(&self) -> Arc<HealthSnapshot> {
        self.health.snapshot()
    }

    pub(crate) fn observe_store(&self, update: impl FnOnce(&mut StoreHealth)) {
        self.health.update(|health| update(&mut health.store));
    }

    pub(crate) fn observe_direction(&self, direction: crate::inventory::ReconcileDirection) {
        self.health
            .update(|health| health.direction = Some(direction));
    }

    pub(crate) fn observe_active_collections(&self, active: &ActiveCollections) {
        self.health.update(|health| {
            health
                .collections
                .retain(|entry| active.get(&entry.collection.raw).is_some());
            for raw in active.iter_ordered() {
                if !health
                    .collections
                    .iter()
                    .any(|entry| entry.collection.raw == *raw)
                {
                    health.collections.push(CollectionHealth {
                        collection: CollectionHandle::new(*raw),
                        local_frontier: None,
                        last_local_change_at: None,
                        peers: Vec::new(),
                    });
                }
            }
            health
                .collections
                .sort_unstable_by_key(|entry| entry.collection.raw);
        });
    }

    pub(crate) fn current_snapshot(&self) -> Option<SharedSnapshot> {
        self.snapshot.borrow().clone()
    }

    /// Hand the host's landing task the store side's [`Land`].
    pub(crate) fn install_lander(&self, lander: Arc<dyn Land>) {
        self.lander.send_replace(Some(lander));
    }

    pub(crate) fn update_snapshot(&self, snapshot: StoreSnapshot, active: &ActiveCollections) {
        self.observe_active_collections(active);
        let snapshot = Arc::new(snapshot);
        // Serving and the coordinator observe exactly the same generation.
        // Slow consumers skip obsolete observations, never authenticated data.
        let retired = self.snapshot.send_replace(Some(snapshot.clone()));
        drop(retired);
        let now = crate::clock::mono_now();
        self.health.update(|health| {
            health.store.serving_snapshot = true;
            health.store.resident_blobs = snapshot.bearer_locators().len();
            health.store.last_snapshot_published_at = Some(now);
            for entry in &mut health.collections {
                let frontier = snapshot
                    .collection(entry.collection)
                    .map(|collection| manifest(&collection.repair).into());
                let changed = match (entry.local_frontier, frontier) {
                    (Some(before), Some(after)) => !before.same_evidence(&after),
                    (None, None) => false,
                    _ => true,
                };
                if changed {
                    entry.last_local_change_at = Some(now);
                }
                entry.local_frontier = frontier;
            }
        });
    }

    pub fn clear_snapshot(&self) {
        self.health.update(|health| {
            if health.store.serving_snapshot {
                health.store.withdrawn_at = Some(crate::clock::mono_now());
            }
            health.store.serving_snapshot = false;
            for collection in &mut health.collections {
                collection.local_frontier = None;
            }
        });
        // Fail closed immediately; neither the server nor the next scheduler
        // observation can pair a withdrawn snapshot with old provider state.
        let retired = self.snapshot.send_replace(None);
        drop(retired);
    }

    async fn ready_capability(&self) -> anyhow::Result<Arc<dyn NetCapability>> {
        let mut slot = self.cap.clone();
        loop {
            if let Some(capability) = slot.borrow().clone() {
                return Ok(capability);
            }
            slot.changed()
                .await
                .map_err(|_| anyhow::anyhow!("network host stopped before becoming ready"))?;
        }
    }

    pub async fn fetch_blob(
        &self,
        hash: RawHash,
        budget: std::time::Duration,
    ) -> Option<Blob<UnknownBlob>> {
        let fetch = async {
            match self.ready_capability().await {
                Ok(capability) => match capability.fetch_blob(hash).await {
                    Some(verified) if verified.get_handle().raw == hash => Some(verified),
                    Some(verified) => {
                        // The cached content handle need not answer this
                        // request. One cheap equality keeps a valid Blob for
                        // B from landing as the answer for A.
                        warn!(
                            requested = %hex::encode(&hash[..4]),
                            returned = %hex::encode(&verified.get_handle().raw[..4]),
                            "network capability answered with a payload for a different handle"
                        );
                        None
                    }
                    None => None,
                },
                Err(error) => {
                    debug!(%error, "exact blob fetch could not start");
                    None
                }
            }
        };
        match tokio::time::timeout(budget, fetch).await {
            Ok(bytes) => bytes,
            Err(_) => {
                debug!(
                    ?budget,
                    "exact blob fetch exhausted its end-to-end deadline"
                );
                None
            }
        }
    }
}

pub struct NetReceiver {
    evt_rx: tokio::sync::mpsc::Receiver<NetEventBatch>,
}

impl NetReceiver {
    pub(crate) fn try_recv(&mut self) -> Option<NetEventBatch> {
        self.evt_rx.try_recv().ok()
    }
}

pub struct HostWiring {
    evt_tx: tokio::sync::mpsc::Sender<NetEventBatch>,
    snapshot: SnapshotSlot,
    cap_tx: tokio::sync::watch::Sender<Option<Arc<dyn NetCapability>>>,
    lander: LandSlot,
    health: Health,
}

#[cfg(test)]
impl HostWiring {
    pub(crate) async fn send_admission(&self, batch: NetEventBatch) {
        self.evt_tx.send(batch).await.unwrap();
    }

    pub(crate) fn install_test_capability(&self, capability: Arc<dyn NetCapability>) {
        assert!(self.cap_tx.send(Some(capability)).is_ok());
    }
}

pub fn wire(id: EndpointId) -> (NetSender, NetReceiver, HostWiring) {
    let (evt_tx, evt_rx) = tokio::sync::mpsc::channel(crate::channel::MAX_ADMISSION_BRIDGE_BATCHES);
    let (snapshot_tx, snapshot) = tokio::sync::watch::channel(None);
    let (cap_tx, cap_rx) = tokio::sync::watch::channel(None);
    let (lander_tx, lander) = tokio::sync::watch::channel(None);
    let health = Health::new(id);
    (
        NetSender {
            snapshot: snapshot_tx,
            cap: cap_rx,
            lander: lander_tx,
            id,
            health: health.clone(),
        },
        NetReceiver { evt_rx },
        HostWiring {
            evt_tx,
            snapshot,
            cap_tx,
            lander,
            health,
        },
    )
}

pub async fn run_host<T: Transport>(harness: Harness<T>, config: PeerConfig, wiring: HostWiring) {
    host_loop(harness, config, wiring).await;
}

pub fn spawn(
    key: SigningKey,
    config: PeerConfig,
) -> anyhow::Result<(NetSender, NetReceiver, HostStarted)> {
    let id: EndpointId = iroh_secret(&key).public().into();
    let (sender, receiver, wiring) = wire(id);
    let started = start(key, config, wiring)?;
    Ok((sender, receiver, started))
}

/// Start a production host over previously allocated, inert wiring.
///
/// Separating this boundary from [`wire`] lets a local store defer the thread,
/// runtime, endpoint, and discovery services until a live acquisition needs them.
pub(crate) fn start(
    key: SigningKey,
    config: PeerConfig,
    wiring: HostWiring,
) -> anyhow::Result<HostStarted> {
    let secret = iroh_secret(&key);
    let (startup_tx, startup_rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("triblespace-net".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = startup_tx.send(Err(anyhow::Error::new(error)));
                    return;
                }
            };
            runtime.block_on(async move {
                let harness = match crate::transport::iroh::bind(secret, &config).await {
                    Ok(harness) => harness,
                    Err(error) => {
                        let _ = startup_tx.send(Err(error));
                        return;
                    }
                };
                let started = HostStarted {
                    wake_plane: harness.transport.wake_plane(),
                    bound: harness.transport.bound_sockets(),
                };
                if startup_tx.send(Ok(started)).is_ok() {
                    run_host(harness, config, wiring).await;
                }
            });
        })?;
    startup_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("network host stopped during startup"))?
}

const BACKGROUND_LOOKUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
const OP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const REPAIR_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);
const COLLECTION_RECONNECT_PERIOD: std::time::Duration = std::time::Duration::from_secs(300);
const HOST_POLL_PERIOD: std::time::Duration = std::time::Duration::from_millis(10);
const PROVIDER_PROGRESS_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_CONCURRENT_REPAIRS: usize = 8;
const MAX_PENDING_REPAIRS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RepairTarget {
    collection: CollectionHandle,
    peer: PeerId,
}

struct RepairOutcome {
    target: RepairTarget,
    success: bool,
}

struct PublicationOutcome {
    work: ProviderPublication,
    result: PublicationResult,
    completed_at: crate::clock::Mono,
}

// Warmup policy, not descriptor validity or ordinary exact-read limits.
pub(crate) const METADATA_BLOB_BYTES: u64 = 1024 * 1024;
const METADATA_DEPENDENCIES: usize = 64;
const METADATA_CANDIDATES: usize = 256;
const METADATA_SELECTIONS_PER_ROUND: usize = 256;
const METADATA_COLLECTIONS_IN_FLIGHT: usize = 4;
const METADATA_CHILDREN_IN_FLIGHT: usize = 4;
const METADATA_FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const METADATA_CHILD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

/// One owned warmup per pull-selected collection, including pending admission.
/// No detached fetch survives removal, host shutdown, or the attempt deadline.
#[derive(Default)]
struct DescriptorFetches {
    pending: PATCH<32, IdentitySchema, Mutex<futures::future::BoxFuture<'static, ()>>>,
    after: Option<RawHash>,
}

impl DescriptorFetches {
    fn start(&mut self, collection: RawHash, fetch: impl Future<Output = ()> + Send + 'static) {
        if self.pending.get(&collection).is_none()
            && self.pending.len() < METADATA_COLLECTIONS_IN_FLIGHT as u64
        {
            self.pending.insert(&PatchEntry::with_value(
                &collection,
                Mutex::new(
                    async move {
                        let _ = tokio::time::timeout(METADATA_FETCH_DEADLINE, fetch).await;
                    }
                    .boxed(),
                ),
            ));
            self.after = Some(collection);
        }
    }

    fn poll(&mut self, mut is_active: impl FnMut(&RawHash) -> bool) {
        // Scratch removal list only; the retained owner index is PATCH.
        let removed: Vec<_> = self
            .pending
            .iter_ordered()
            .filter(|collection| {
                !is_active(collection)
                    || self
                        .pending
                        .get(*collection)
                        .unwrap()
                        .lock()
                        .unwrap()
                        .as_mut()
                        .now_or_never()
                        .is_some()
            })
            .copied()
            .collect();
        for collection in removed {
            self.pending.remove(&collection);
        }
    }

    fn selected_round<V>(
        &self,
        active: &PATCH<32, IdentitySchema, V>,
        pulls: bool,
    ) -> Vec<RawHash> {
        if !pulls {
            return Vec::new();
        }
        // A bounded observation of the selected relation, not a second
        // collection catalogue. Resume after the last admitted attempt.
        active
            .iter_ordered()
            .filter(|raw| self.after.is_none_or(|after| **raw > after))
            .chain(
                active
                    .iter_ordered()
                    .take_while(|raw| self.after.is_some_and(|after| **raw <= after)),
            )
            .take(METADATA_SELECTIONS_PER_ROUND)
            .copied()
            .collect()
    }
}

fn descriptor_metadata(bytes: Bytes) -> Vec<RawHash> {
    use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace_core::blob::encodings::utf8string::UTF8String;
    use triblespace_core::capability::CapabilityHandle;
    use triblespace_core::capability::policy::{capability_handle, resource_policy};
    use triblespace_core::collection::{KIND_COLLECTION_DESCRIPTOR, collection_name};
    use triblespace_core::prelude::{find, pattern};
    use triblespace_core::trible::TribleSet;

    // Bound resident input too, before archive decoding or typed joins. Unknown
    // facts are ignored; a warmup limit never declares a descriptor invalid.
    if bytes.len() as u64 > METADATA_BLOB_BYTES {
        return Vec::new();
    }
    let Ok(facts) = Blob::<SimpleArchive>::new(bytes).try_from_blob::<TribleSet>() else {
        return Vec::new();
    };
    let names = find!(
        (name: Inline<Handle<UTF8String>>),
        pattern!(&facts, [{
            triblespace_core::metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_name: ?name,
        }])
    )
    .map(|(name,)| name.raw);
    // Acquire associated definition bytes, not policy authority. Bound raw
    // linked rows without interpreting policy (a rejecting policy iterator
    // can perform arbitrarily many joins before yielding one supported row).
    let definitions = find!(
        (binding: triblespace_core::id::Id, handle: CapabilityHandle),
        pattern!(&facts, [
            { triblespace_core::metadata::tag: KIND_COLLECTION_DESCRIPTOR,
              resource_policy: ?binding },
            { ?binding @ capability_handle: ?handle },
        ])
    )
    .map(|(_, handle)| handle.raw);
    // Ephemeral de-duplication of this bounded descriptor observation only.
    let mut seen = BTreeSet::new();
    names
        .chain(definitions)
        .take(METADATA_CANDIDATES)
        .filter(|handle| seen.insert(*handle))
        .take(METADATA_DEPENDENCIES)
        .collect()
}

async fn warm_descriptor<R, F>(
    collection: RawHash,
    resident: R,
    fetch: F,
    events: tokio::sync::mpsc::Sender<NetEventBatch>,
) where
    R: Fn(RawHash) -> Option<Bytes>,
    F: Fn(RawHash) -> futures::future::BoxFuture<'static, Option<Blob<UnknownBlob>>>,
{
    let bytes = match resident(collection) {
        Some(bytes) => bytes,
        None => {
            let Ok(Some(verified)) =
                tokio::time::timeout(INTERACTIVE_FETCH_DEADLINE, fetch(collection)).await
            else {
                return;
            };
            let bytes = verified.bytes.clone();
            let mut batch = NetEventBatch::default();
            if batch.try_push(NetEvent::Blob(verified)).is_err()
                || events.send(batch).await.is_err()
            {
                return;
            }
            bytes
        }
    };
    let dependencies = descriptor_metadata(bytes);
    let mut pending = futures::stream::iter(
        dependencies
            .into_iter()
            .filter(|handle| resident(*handle).is_none()),
    )
    .map(|handle| {
        let future = fetch(handle);
        async move {
            tokio::time::timeout(METADATA_CHILD_DEADLINE, future)
                .await
                .ok()
                .flatten()
        }
    })
    .buffer_unordered(METADATA_CHILDREN_IN_FLIGHT);
    while let Some(answer) = pending.next().await {
        let Some(verified) = answer else {
            continue;
        };
        let mut batch = NetEventBatch::default();
        if batch.try_push(NetEvent::Blob(verified)).is_err() || events.send(batch).await.is_err() {
            return;
        }
    }
}

/// Own the actual discovery futures, not detached tasks counted by soft state.
/// Removing an interest drops its attempt before that handle can be reactivated;
/// no old completion remains in a channel to finish the replacement attempt.
#[derive(Default)]
struct CollectionDiscoveries {
    pending: HashMap<RawHash, futures::future::BoxFuture<'static, Vec<PeerId>>>,
}

impl CollectionDiscoveries {
    fn len(&self) -> usize {
        self.pending.len()
    }

    fn start(
        &mut self,
        collection: RawHash,
        lookup: impl Future<Output = Vec<PeerId>> + Send + 'static,
    ) -> bool {
        if self.pending.len() >= ALPHA || self.pending.contains_key(&collection) {
            return false;
        }
        self.pending.insert(collection, lookup.boxed());
        true
    }

    fn poll(
        &mut self,
        mut is_active: impl FnMut(&RawHash) -> bool,
    ) -> Vec<(CollectionHandle, Vec<PeerId>)> {
        let mut completed = Vec::new();
        self.pending.retain(|collection, lookup| {
            if !is_active(collection) {
                return false;
            }
            if let Some(peers) = lookup.as_mut().now_or_never() {
                completed.push((CollectionHandle::new(*collection), peers));
                false
            } else {
                true
            }
        });
        completed
    }
}

/// Process-lifetime admission gate for DHT provider announcements.
///
/// This sits outside [`ProviderPublisher`], so installing a newer resident
/// snapshot cannot refill a canary's network budget.
struct ProviderPublicationBudget {
    remaining: Option<u64>,
}

impl ProviderPublicationBudget {
    fn new(limit: Option<u64>) -> Self {
        Self { remaining: limit }
    }

    fn permits_attempt(&self) -> bool {
        self.remaining != Some(0)
    }

    fn consume_attempt(&mut self) {
        if let Some(remaining) = &mut self.remaining {
            debug_assert!(*remaining > 0);
            *remaining -= 1;
        }
    }

    fn is_exhausted(&self) -> bool {
        self.remaining == Some(0)
    }
}

fn enqueue_repair(
    queue: &mut VecDeque<RepairTarget>,
    pending: &mut HashSet<RepairTarget>,
    target: RepairTarget,
) {
    if pending.len() < MAX_PENDING_REPAIRS && pending.insert(target) {
        queue.push_back(target);
    }
}

/// A signed equal-root hint can avoid ordinary work, but cannot clear a failed
/// repair's confirmation obligation. Only an actual successful RPC supersedes
/// the retained failure evidence used by health reporting.
fn can_skip_repair(
    local_root: RawHash,
    advertised_root: Option<CollectionWakeRoot>,
    previously_failed: bool,
) -> bool {
    !previously_failed && advertised_root.is_some_and(|root| root.as_bytes() == &local_root)
}

fn has_repair_candidate(
    collection: CollectionHandle,
    peers: &[PeerId],
    failures: &HashMap<RepairTarget, (u32, crate::clock::Mono)>,
    local_peer: PeerId,
) -> bool {
    peers.iter().any(|peer| {
        *peer != local_peer
            && !failures.contains_key(&RepairTarget {
                collection,
                peer: *peer,
            })
    })
}

fn retain_active_repair_state<T>(
    state: &mut HashMap<RepairTarget, T>,
    mut is_active: impl FnMut(&RawHash) -> bool,
) {
    state.retain(|target, _| is_active(&target.collection.raw));
}

enum WakeCommand {
    Join(Vec<EndpointId>),
    Resubscribe,
}

/// A topic has one current root, not a backlog of superseded broadcasts.
/// Operational join/recovery commands retain their delivery semantics; they
/// carry no store snapshots. Dropping the owner closes both paths and stops
/// the topic.
struct WakeTopic {
    root: tokio::sync::watch::Sender<Option<CollectionWakeRoot>>,
    commands: tokio::sync::mpsc::UnboundedSender<WakeCommand>,
}

impl WakeTopic {
    fn observe(&self, root: Option<CollectionWakeRoot>) {
        self.root.send_replace(root);
    }

    fn send(
        &self,
        command: WakeCommand,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<WakeCommand>> {
        self.commands.send(command)
    }
}

enum WakeNotice {
    Received {
        collection: CollectionHandle,
        received: ReceivedCollectionWake,
    },
    Lagged {
        collection: CollectionHandle,
    },
}

fn spawn_wake_topic<P: CollectionWakeNetwork>(
    plane: P,
    collection: CollectionHandle,
    advertise: bool,
    bootstrap: Vec<EndpointId>,
    notices: tokio::sync::mpsc::Sender<WakeNotice>,
) -> WakeTopic {
    let (commands, mut command_rx) = tokio::sync::mpsc::unbounded_channel();
    let (root, mut root_rx) = tokio::sync::watch::channel(None);
    tokio::spawn(async move {
        let mut bootstrap = WakeBootstrapPeers::new(bootstrap);
        loop {
            if root_rx.has_changed().is_err() {
                return;
            }
            let mut topic = loop {
                match plane
                    .subscribe_network(collection, bootstrap.current())
                    .await
                {
                    Ok(topic) => break topic,
                    Err(error) => {
                        debug!(%error, "collection gossip subscription failed; retrying");
                        tokio::select! {
                            changed = root_rx.changed() => {
                                if changed.is_err() { return; }
                            },
                            command = command_rx.recv() => match command {
                                Some(WakeCommand::Join(peers)) => bootstrap.remember(peers),
                                Some(WakeCommand::Resubscribe) => {}
                                None => return,
                            },
                            () = tokio::time::sleep(crate::RETRY_BACKOFF_BASE) => {}
                        }
                    }
                }
            };
            let _ = root_rx.borrow_and_update();
            let mut schedule = WakeSchedule::<()>::new(crate::clock::mono_now(), rand::random());
            let mut relay = crate::wake_relay::WakeRelay::default();
            'events: loop {
                let deadline = relay
                    .deadline()
                    .map_or(schedule.deadline(), |at| at.min(schedule.deadline()));
                tokio::select! {
                    changed = root_rx.changed() => {
                        if changed.is_err() { return; }
                        let current = *root_rx.borrow_and_update();
                        let now = crate::clock::mono_now();
                        schedule.local_changed(now, rand::random());
                        // A changed union root is an honest new local offer,
                        // not a claim to serve the exact upstream root.
                        schedule.neighbor_joined(now, rand::random(), ());
                        relay.refreshed(current.filter(|_| advertise), now);
                    },
                    () = tokio::time::sleep(deadline.duration_since(crate::clock::mono_now())) => {
                        let now = crate::clock::mono_now();
                        let serving = (*root_rx.borrow()).filter(|_| advertise);
                        let mut offered_local = false;
                        for offer in relay.poll(serving, now) {
                            let result = match offer {
                                crate::wake_relay::RelayOffer::Local(root) => {
                                    offered_local = true;
                                    topic.broadcast_wake(root).await.map(|_| ())
                                }
                                crate::wake_relay::RelayOffer::Original(wake) => topic.relay_wake(&wake).await,
                            };
                            if let Err(error) = result {
                                debug!(%error, "collection state hint relay failed");
                            }
                        }
                        if !schedule.poll(now, rand::random(), [()]).is_empty() && !offered_local
                            && let Some(root) = serving
                            && let Err(error) = topic.broadcast_wake(root).await
                        {
                            debug!(%error, "periodic collection wake broadcast failed");
                        }
                    },
                    command = command_rx.recv() => match command {
                        Some(WakeCommand::Join(peers)) => {
                            bootstrap.remember(peers.iter().copied());
                            if let Err(error) = topic.join_wake_peers(peers).await {
                                debug!(%error, "joining candidate collection wake peers failed");
                            }
                        }
                        Some(WakeCommand::Resubscribe) => {
                            if bootstrap.has_recovery_route() {
                                debug!("reopening collection wake subscription for recovery");
                                break 'events;
                            }
                        }
                        None => return,
                    },
                    event = topic.next_wake_event() => match event {
                        Ok(Some(CollectionWakeEvent::Received(received))) => {
                        bootstrap.remember([received.wake.origin()]);
                        let now = crate::clock::mono_now();
                        let current = *root_rx.borrow();
                        relay.received_from(&received.wake, received.delivered_from);
                        relay.observe(&received.wake, current.filter(|_| advertise), now);
                        if let Some(root) = current {
                            if root == received.wake.root() {
                                schedule.consistent_root(now, ());
                            } else {
                                schedule.different_root(now, rand::random());
                            }
                        }
                        // Wakes are repeatable hints. Dropping one under load
                        // preserves correctness while keeping a nonce flood
                        // behind a hard process-wide memory bound.
                        let _ = notices.try_send(WakeNotice::Received { collection, received });
                        }
                        Ok(Some(CollectionWakeEvent::Lagged)) => {
                            let _ = notices.try_send(WakeNotice::Lagged { collection });
                            let now = crate::clock::mono_now();
                            schedule.neighbor_joined(now, rand::random(), ());
                            relay.neighbor_joined(now);
                        }
                        Ok(Some(CollectionWakeEvent::Rejected { error, .. })) => {
                            debug!(%error, "rejected invalid collection wake");
                        }
                        Ok(Some(CollectionWakeEvent::NeighborUp(peer))) => {
                            let now = crate::clock::mono_now();
                            schedule.neighbor_joined(now, rand::random(), ());
                            relay.neighbor_up(peer, now);
                        }
                        Ok(Some(CollectionWakeEvent::NeighborDown(peer))) => { relay.neighbor_down(peer); }
                        Ok(None) => {
                            debug!("collection wake subscription ended; retrying");
                            break 'events;
                        },
                        Err(error) => {
                            debug!(%error, "collection wake subscription failed; retrying");
                            break 'events;
                        }
                    }
                }
            }
        }
    });
    WakeTopic { root, commands }
}

async fn host_loop<T: Transport>(harness: Harness<T>, config: PeerConfig, mut wiring: HostWiring) {
    let Harness {
        transport,
        mut incoming,
    } = harness;
    let my_id = transport.local_id();
    wiring.health.update(|health| {
        let now = crate::clock::mono_now();
        health.direction = Some(config.qos.direction);
        health.started_at = Some(now);
        health.observed_at = Some(now);
    });
    let configured: Vec<_> = config
        .peers
        .iter()
        .map(|address| *address.id.as_bytes())
        .filter(|peer| *peer != my_id)
        .collect();
    let candidates = Arc::new(Mutex::new(RoutingTable::new(
        my_id,
        configured.iter().copied(),
    )));
    let participants = Arc::new(Mutex::new(HashMap::new()));
    let providers = Arc::new(Mutex::new(ProviderDirectory::new(my_id)));
    let (recon_tx, recon_rx) = tokio::sync::mpsc::channel(crate::peering::RECON_EVENTS);
    let (walks_tx, walks_rx) = tokio::sync::mpsc::channel(crate::walk::WALK_EVENTS);
    let handler = SnapshotHandler {
        snapshot: wiring.snapshot.clone(),
        health: wiring.health.clone(),
        candidates: candidates.clone(),
        providers: providers.clone(),
        local_id: my_id,
        recon: Some(recon_tx),
        walks: Some(walks_tx),
    };
    // One table holds the connections of both directions; each serves the
    // same handler, whichever side dialled it.
    let connections = ConnectionTable::new(transport.clone(), handler);
    // Walks pull what this node lacks over recon/1 and land it through one
    // task, which also reobserves the store for appends made elsewhere.
    let (pulls, mut pulled) = crate::walk::spawn(
        connections.clone(),
        wiring.snapshot.clone(),
        crate::walk::Walks::new(config.qos.direction.serves(), wiring.health.clone()),
        walks_rx,
        wiring.lander.clone(),
    );
    // Peerings and announcements ride the connections' recon/1 streams
    // beside the wake path below. Announcements start record pulls, and hear
    // every record pull end, whoever started it.
    let (found_tx, found_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ended_tx, ended_rx) = tokio::sync::mpsc::unbounded_channel();
    let record_pulls = pulls.clone();
    tokio::spawn(crate::peering::run(
        connections.clone(),
        wiring.snapshot.clone(),
        recon_rx,
        found_rx,
        move |peer, collection| record_pulls.start(peer, collection, PullKind::Records),
        ended_rx,
        wiring.health.clone(),
        wiring.evt_tx.clone(),
    ));
    let provider_client = ProviderClient {
        connections: connections.clone(),
        providers: providers.clone(),
        candidates: candidates.clone(),
        my_id,
        salt: rand::random(),
    };
    let cap = Arc::new(NetCap {
        client: provider_client.clone(),
    });
    let _ = wiring.cap_tx.send(Some(cap as Arc<dyn NetCapability>));

    tokio::spawn(async move {
        while let Some(accepted) = incoming.recv().await {
            debug!(
                target: "triblespace_net::handoff",
                peer = %hex::encode(accepted.conn.remote_id()),
                "host received forwarded connection"
            );
            // Production forwards only this ALPN; the simulator forwards any.
            if accepted.alpn != PILE_SYNC_ALPN {
                accepted.conn.close(1, b"unknown protocol");
                continue;
            }
            connections.accept(accepted.conn);
        }
    });

    let wake_plane = transport.collection_wake_plane();
    let bootstrap_ids = config.peers.iter().map(|peer| peer.id).collect::<Vec<_>>();
    let (wake_tx, mut wake_rx) = tokio::sync::mpsc::channel::<WakeNotice>(256);
    let mut wake_topics: HashMap<[u8; 32], WakeTopic> = HashMap::new();
    let mut discovery_attempts = CollectionDiscoveries::default();
    let mut immediate = VecDeque::<RepairTarget>::new();
    let mut pending = HashSet::<RepairTarget>::new();
    let mut in_flight = HashSet::new();
    let mut failures: HashMap<RepairTarget, (u32, crate::clock::Mono)> = HashMap::new();
    let mut discovery: HashMap<[u8; 32], DiscoveryState> = HashMap::new();
    // Retain the last observation accounted for, not a second root catalog.
    // Its PATCH values pin the roots against which the next observation is
    // compared. ProviderPublisher separately retains genuinely pending work.
    let mut processed_snapshot: Option<SharedSnapshot> = None;
    let empty_collections = CollectionSnapshotIndex::new();
    let mut descriptor_fetches = DescriptorFetches::default();
    let mut next_period = crate::clock::mono_now();
    let mut next_discovery = crate::clock::mono_now();
    let mut discovery_cursor = None;
    let mut publisher = ProviderPublisher::new(crate::clock::mono_now());
    let publication_limit = config.provider_publication_budget;
    let mut publication_budget = ProviderPublicationBudget::new(publication_limit);
    let mut publication_budget_reported = false;
    if publication_budget.is_exhausted() {
        warn!(
            "provider publication disabled by zero process budget; exact H-authorized serving remains enabled"
        );
        publication_budget_reported = true;
    }
    let (publication_tx, mut publication_rx) =
        tokio::sync::mpsc::unbounded_channel::<PublicationOutcome>();
    let mut publications_in_flight = HashSet::new();
    let mut next_publication_progress = crate::clock::mono_now() + PROVIDER_PROGRESS_PERIOD;
    let mut publication_attempts = 0u64;
    let mut remote_acknowledged_attempts = 0u64;
    let mut remote_rejected_attempts = 0u64;
    let mut unavailable_attempts = 0u64;

    loop {
        match wiring.snapshot.has_changed() {
            Ok(true) => {
                // Exactly one current observation per turn, even if refresh
                // published many generations while the host was busy. Clone
                // before doing work so no watch read lock crosses a wait.
                let next = wiring.snapshot.borrow_and_update().clone();
                let before = processed_snapshot
                    .as_ref()
                    .map_or(&empty_collections, |snapshot| &snapshot.collections);
                let after = next
                    .as_ref()
                    .map_or(&empty_collections, |snapshot| &snapshot.collections);
                for raw in after.iter_ordered() {
                    let collection = CollectionHandle::new(*raw);
                    if before.get(raw).is_none() {
                        let now = crate::clock::mono_now();
                        discovery.insert(*raw, DiscoveryState::new(now));
                        next_discovery = next_discovery.min(now);
                        // A cold activation needs descriptor bytes, not just
                        // provider contacts. Do not wait for the retry tick.
                        next_period = next_period.min(now);
                    }
                    let root = after
                        .get(raw)
                        .and_then(|entry| entry.value.as_ref())
                        .map(|entry| CollectionWakeRoot::new(entry.wake_root()));
                    let prior = before
                        .get(raw)
                        .and_then(|entry| entry.value.as_ref())
                        .map(|entry| CollectionWakeRoot::new(entry.wake_root()));
                    let topic = wake_topics.entry(*raw).or_insert_with(|| {
                        spawn_wake_topic(
                            wake_plane.clone(),
                            collection,
                            config.qos.direction.serves(),
                            bootstrap_ids.clone(),
                            wake_tx.clone(),
                        )
                    });
                    if root != prior {
                        topic.observe(root);
                    }
                    if let Some(entry) = after.get(raw).and_then(|entry| entry.value.as_ref()) {
                        let changed_authority = before
                            .get(raw)
                            .and_then(|entry| entry.value.as_ref())
                            .is_none_or(|previous| {
                                previous.repair.authorization_evidence().summary()
                                    != entry.repair.authorization_evidence().summary()
                            });
                        if changed_authority {
                            let peers = collection_topic_contacts(entry, my_id);
                            let _ = topic.send(WakeCommand::Join(peers));
                        }
                    }
                }
                // PATCH difference skips unchanged active subtries. A cold
                // descriptor remains an active entry with no root, not a
                // deactivated collection.
                for raw in before.difference(after).iter_ordered() {
                    if let Some(topic) = wake_topics.remove(raw) {
                        drop(topic);
                    }
                }
                discovery.retain(|collection, _| after.get(collection).is_some());
                retain_active_repair_state(&mut failures, |raw| after.get(raw).is_some());
                participants
                    .lock()
                    .unwrap()
                    .retain(|collection, _| after.get(collection).is_some());
                immediate.retain(|target| after.get(&target.collection.raw).is_some());
                pending.retain(|target| after.get(&target.collection.raw).is_some());
                let providers = next
                    .as_ref()
                    .map_or_else(ProviderObservation::default, |snapshot| {
                        ProviderObservation::from_locators(snapshot.bearer_locators())
                    });
                publisher.install(providers.into_set(), crate::clock::mono_now());
                processed_snapshot = next;
            }
            Ok(false) => {}
            Err(_) => {
                drop(descriptor_fetches);
                drop(discovery_attempts);
                transport.shutdown().await;
                return;
            }
        }
        let current_collections = processed_snapshot
            .as_ref()
            .map_or(&empty_collections, |snapshot| &snapshot.collections);

        descriptor_fetches.poll(|raw| current_collections.get(raw).is_some());

        while let Ok(notice) = wake_rx.try_recv() {
            let (collection, received) = match notice {
                WakeNotice::Received {
                    collection,
                    received,
                } => (collection, received),
                WakeNotice::Lagged { collection } => {
                    if current_collections.get(&collection.raw).is_some() {
                        let now = crate::clock::mono_now();
                        next_period = next_period.min(now);
                        next_discovery = next_discovery.min(now);
                    }
                    continue;
                }
            };
            let wake = received.wake;
            if wake.origin().as_bytes() == &my_id {
                continue;
            }
            if current_collections.get(&collection.raw).is_none() {
                continue;
            }
            observe_participant(
                &mut participants.lock().unwrap(),
                collection.raw,
                *wake.origin().as_bytes(),
                crate::clock::mono_now(),
            );
            if let Some(observed) = participants
                .lock()
                .unwrap()
                .get_mut(&collection.raw)
                .and_then(|peers| peers.get_mut(wake.origin().as_bytes()))
            {
                observed.root = Some(wake.root());
            }
            if current_collections
                .get(&collection.raw)
                .and_then(|entry| entry.value.as_ref())
                .is_some_and(|entry| &entry.wake_root() != wake.root().as_bytes())
                && !pending.iter().any(|target| target.collection == collection)
                && !in_flight
                    .iter()
                    .any(|target: &RepairTarget| target.collection == collection)
            {
                // A forwarded notice proves only its signed origin's state.
                // Prefer any fresh origin advertising the same root, spreading
                // pulls without mistaking a forwarding hop for a holder.
                let peers = participants.lock().unwrap();
                let sources = peers
                    .get(&collection.raw)
                    .unwrap()
                    .iter()
                    .filter(|(peer, observed)| {
                        observed.root == Some(wake.root())
                            && !failures
                                .get(&RepairTarget {
                                    collection,
                                    peer: **peer,
                                })
                                .is_some_and(|(_, retry)| crate::clock::mono_now() < *retry)
                    })
                    .map(|(peer, _)| *peer)
                    .collect::<Vec<_>>();
                let peer = sources
                    .get(rand::random::<usize>() % sources.len().max(1))
                    .copied();
                let Some(peer) = peer else {
                    continue;
                };
                enqueue_repair(
                    &mut immediate,
                    &mut pending,
                    RepairTarget { collection, peer },
                );
            }
        }
        while let Ok(pulled) = pulled.try_recv() {
            let _ = ended_tx.send(pulled);
            if pulled.kind == PullKind::References {
                continue;
            }
            // The walks keep the pair's health; this keeps its retry state.
            let outcome = RepairOutcome {
                target: RepairTarget {
                    collection: pulled.collection,
                    peer: pulled.peer,
                },
                success: pulled.completed,
            };
            in_flight.remove(&outcome.target);
            if current_collections
                .get(&outcome.target.collection.raw)
                .is_none()
            {
                failures.remove(&outcome.target);
                continue;
            }
            if outcome.target.peer == my_id {
                failures.remove(&outcome.target);
                continue;
            }
            if outcome.success {
                failures.remove(&outcome.target);
                let now = crate::clock::mono_now();
                observe_participant(
                    &mut participants.lock().unwrap(),
                    outcome.target.collection.raw,
                    outcome.target.peer,
                    now,
                );
                discovery
                    .entry(outcome.target.collection.raw)
                    .or_insert_with(|| DiscoveryState::new(now))
                    .observe_success(now);
            } else {
                let now = crate::clock::mono_now();
                let peers = live_participants(
                    &mut participants.lock().unwrap(),
                    outcome.target.collection.raw,
                    now,
                );
                let had_candidate =
                    has_repair_candidate(outcome.target.collection, &peers, &failures, my_id);
                let attempts = failures
                    .get(&outcome.target)
                    .map_or(1, |(attempts, _)| attempts.saturating_add(1));
                let shift = attempts.saturating_sub(1).min(6);
                if failures.len() < MAX_PENDING_REPAIRS || failures.contains_key(&outcome.target) {
                    failures.insert(
                        outcome.target,
                        (
                            attempts,
                            now + crate::RETRY_BACKOFF_BASE.saturating_mul(1u32 << shift),
                        ),
                    );
                    // Keep the original participant lease across a transient
                    // failure. A healthy second replica need not hold this
                    // peer's latest records. Periodic
                    // repair can retry after backoff; failure never renews it.
                } else {
                    // Without room for a failure marker this peer would look
                    // healthy to discovery. Preserve the existing hard bound.
                    forget_participant(
                        &mut participants.lock().unwrap(),
                        outcome.target.collection.raw,
                        outcome.target.peer,
                    );
                }
                let peers = live_participants(
                    &mut participants.lock().unwrap(),
                    outcome.target.collection.raw,
                    now,
                );
                if had_candidate
                    && !has_repair_candidate(outcome.target.collection, &peers, &failures, my_id)
                    && let Some(topic) = wake_topics.get(&outcome.target.collection.raw)
                {
                    let _ = topic.send(WakeCommand::Resubscribe);
                }
                next_discovery = next_discovery.min(now);
            }
        }
        while let Ok(outcome) = publication_rx.try_recv() {
            publications_in_flight.remove(&outcome.work.key);
            wiring.health.update(|health| {
                health
                    .publication
                    .completed(outcome.completed_at, outcome.result);
            });
            match outcome.result {
                PublicationResult::Published => {
                    remote_acknowledged_attempts = remote_acknowledged_attempts.saturating_add(1);
                }
                PublicationResult::RemoteRejected => {
                    remote_rejected_attempts = remote_rejected_attempts.saturating_add(1);
                }
                PublicationResult::NoAuthenticatedRemoteReplica => {
                    unavailable_attempts = unavailable_attempts.saturating_add(1);
                }
            }
            let effect = publisher.complete(outcome.work, outcome.result, crate::clock::mono_now());
            if effect.topology_outage_started {
                warn!(
                    "no authenticated remote DHT replica is reachable; provider publication is paused behind one bounded topology probe"
                );
            }
            if effect.topology_recovered {
                debug!("authenticated remote DHT replica reached; provider publication resumed");
            }
            if effect.retry_budget_full {
                warn!(
                    "provider retry budget full after an authenticated remote rejected the announcement; exact discovery is degraded until the renewal cursor returns"
                );
            }
        }
        for (collection, peers) in
            discovery_attempts.poll(|raw| current_collections.get(raw).is_some())
        {
            let now = crate::clock::mono_now();
            let Some(state) = discovery.get_mut(&collection.raw) else {
                continue;
            };
            state.finish_attempt(now);
            next_discovery = next_discovery.min(state.retry_at);
            if current_collections.get(&collection.raw).is_none() {
                continue;
            }
            let peers = peers
                .into_iter()
                .filter(|peer| *peer != my_id)
                .collect::<Vec<_>>();
            // The providers are the last tier of the collection's candidates.
            let _ = found_tx.send((collection, peers.clone()));
            if !peers.is_empty()
                && let Some(topic) = wake_topics.get(&collection.raw)
            {
                let joined = peers
                    .iter()
                    .filter_map(|peer| EndpointId::from_bytes(peer).ok())
                    .collect();
                let _ = topic.send(WakeCommand::Join(joined));
            }
            // A descriptor holder may be only a cache. It becomes a repair
            // source after its own signed root advertisement, not this lookup.
        }

        let now = crate::clock::mono_now();
        if now >= next_period {
            next_period = now + REPAIR_PERIOD;
            // The anti-entropy tick also notices expired participant leases,
            // but DHT recovery keeps its own backoff and in-flight state.
            next_discovery = next_discovery.min(now);
            for raw in descriptor_fetches
                .selected_round(current_collections, config.qos.direction.pulls())
                .into_iter()
                .take(METADATA_SELECTIONS_PER_ROUND)
            {
                if descriptor_fetches.pending.len() >= METADATA_COLLECTIONS_IN_FLIGHT as u64 {
                    break;
                }
                let snapshot = wiring.snapshot.borrow().clone();
                let client = provider_client.clone();
                let events = wiring.evt_tx.clone();
                descriptor_fetches.start(
                    raw,
                    warm_descriptor(
                        raw,
                        move |handle| {
                            snapshot
                                .as_ref()
                                .and_then(|snapshot| snapshot.get_blob(&handle))
                        },
                        move |handle| {
                            let client = client.clone();
                            async move {
                                client
                                    .fetch_blob_with_limit(
                                        handle,
                                        Some(BACKGROUND_LOOKUP_DEADLINE),
                                        METADATA_BLOB_BYTES,
                                    )
                                    .await
                                    .ok()
                                    .flatten()
                            }
                            .boxed()
                        },
                        events,
                    ),
                );
                // A resident/no-work attempt must not occupy a scarce owner
                // slot until the next thirty-second anti-entropy period.
                // Bound how many such ready observations this round performs.
                descriptor_fetches.poll(|raw| current_collections.get(raw).is_some());
            }
            for raw in current_collections.iter_ordered() {
                if config.qos.direction.pulls() {
                    let collection = CollectionHandle::new(*raw);
                    // Periodic gossip replaces blind pulls of every remembered
                    // participant. Only incomplete/failed work needs a retry;
                    // ordinary new work is derived from advertised roots.
                    for peer in live_participants(&mut participants.lock().unwrap(), *raw, now) {
                        let target = RepairTarget { collection, peer };
                        if failures
                            .get(&target)
                            .is_some_and(|(_, retry_at)| now >= *retry_at)
                        {
                            enqueue_repair(&mut immediate, &mut pending, target);
                        }
                    }
                }
            }
        }

        if config.qos.direction.pulls() && now >= next_discovery {
            next_discovery = now + REPAIR_PERIOD;
            for raw in discovery_order(current_collections, discovery_cursor) {
                if discovery_attempts.len() >= ALPHA {
                    next_discovery = now + HOST_POLL_PERIOD;
                    break;
                }
                let collection = CollectionHandle::new(*raw);
                let peers = live_participants(&mut participants.lock().unwrap(), *raw, now);
                let has_candidate = has_repair_candidate(collection, &peers, &failures, my_id);
                let state = discovery
                    .entry(*raw)
                    .or_insert_with(|| DiscoveryState::new(now));
                if state.start_if_due(now, has_candidate) {
                    discovery_cursor = Some(*raw);
                    if let Some(snapshot) = current_collections
                        .get(raw)
                        .and_then(|entry| entry.value.as_ref())
                        && let Some(topic) = wake_topics.get(raw)
                    {
                        let mut peers = collection_topic_contacts(snapshot, my_id);
                        peers.extend(bootstrap_ids.iter().copied());
                        let _ = topic.send(WakeCommand::Join(peers));
                    }
                    let client = provider_client.clone();
                    let started = discovery_attempts.start(collection.raw, async move {
                        client
                            .find_key(
                                blob_locator(collection.raw),
                                blob_provider_token,
                                collection.raw,
                                Some(BACKGROUND_LOOKUP_DEADLINE),
                            )
                            .await
                            .unwrap_or_else(|error| {
                                debug!(%error, "collection provider lookup failed");
                                Vec::new()
                            })
                    });
                    debug_assert!(started, "discovery state and owned attempt must agree");
                } else if !has_candidate && !state.in_flight {
                    next_discovery = next_discovery.min(state.retry_at);
                }
            }
        }

        if config.qos.direction.pulls() {
            while in_flight.len() < MAX_CONCURRENT_REPAIRS {
                let Some(target) = immediate.pop_front() else {
                    break;
                };
                pending.remove(&target);
                if in_flight.contains(&target)
                    || failures
                        .get(&target)
                        .is_some_and(|(_, retry_at)| now < *retry_at)
                {
                    continue;
                }
                let Some(local) = wiring
                    .snapshot
                    .borrow()
                    .as_ref()
                    .and_then(|snapshot| snapshot.collection(target.collection))
                else {
                    continue;
                };
                let advertised_root = participants
                    .lock()
                    .unwrap()
                    .get(&target.collection.raw)
                    .and_then(|peers| peers.get(&target.peer))
                    .and_then(|observed| observed.root);
                if can_skip_repair(
                    local.wake_root(),
                    advertised_root,
                    failures.contains_key(&target),
                ) {
                    continue;
                }
                in_flight.insert(target);
                pulls.start(target.peer, target.collection, PullKind::Records);
            }
        }

        while publications_in_flight.len() < ALPHA && publication_budget.permits_attempt() {
            let Some(work) = publisher.next(now) else {
                break;
            };
            let key = work.key;
            if !publications_in_flight.insert(key) {
                let _ = publisher.retry(key, now);
                break;
            }
            publication_budget.consume_attempt();
            publication_attempts = publication_attempts.saturating_add(1);
            wiring
                .health
                .update(|health| health.publication.last_started_at = Some(now));
            if publication_budget.is_exhausted() && !publication_budget_reported {
                warn!(
                    limit = publication_limit.expect("a finite budget can be exhausted"),
                    "provider publication budget reached; this is the final permitted announcement attempt, and later additions, retries, and renewals remain suppressed"
                );
                publication_budget_reported = true;
            }
            let client = provider_client.clone();
            let publication_tx = publication_tx.clone();
            let token = blob_provider_token(work.identity, my_id);
            tokio::spawn(async move {
                let result = client.announce_key(key, token).await;
                let _ = publication_tx.send(PublicationOutcome {
                    work,
                    result,
                    completed_at: crate::clock::mono_now(),
                });
            });
        }

        if now >= next_publication_progress {
            let progress = publisher.progress();
            // These O(1) soft-state counts may include unpruned expiry. Never
            // wait for a directory RPC's lock just to emit diagnostics.
            let directory = providers
                .try_lock()
                .ok()
                .map(|directory| directory.retained_counts());
            tracing::info!(
                resident = progress.resident,
                startup_pending = progress.startup_pending,
                incremental_pending = progress.incremental_pending,
                retry_pending = progress.retry_pending,
                renewal_remaining = progress.renewal_remaining,
                in_flight = publications_in_flight.len(),
                topology_paused = progress.topology_paused,
                publication_budget_exhausted = publication_budget.is_exhausted(),
                publication_attempts,
                remote_acknowledged_attempts,
                remote_rejected_attempts,
                unavailable_attempts,
                directory_memberships = ?directory.map(|counts| counts.0),
                directory_locators = ?directory.map(|counts| counts.1),
                "provider publication progress; acknowledgements count attempts, not unique lease coverage"
            );
            next_publication_progress = now + PROVIDER_PROGRESS_PERIOD;
        }

        let progress = publisher.progress();
        wiring.health.update(|health| {
            health.observed_at = Some(crate::clock::mono_now());
            let publication = &mut health.publication;
            publication.resident = progress.resident;
            publication.startup_pending = progress.startup_pending;
            publication.incremental_pending = progress.incremental_pending;
            publication.retry_pending = progress.retry_pending;
            publication.renewal_remaining = progress.renewal_remaining;
            publication.in_flight = publications_in_flight.len();
            publication.topology_paused = progress.topology_paused;
            publication.budget_exhausted = publication_budget.is_exhausted();
            publication.attempts = publication_attempts;
            publication.acknowledged = remote_acknowledged_attempts;
            publication.rejected = remote_rejected_attempts;
            publication.unavailable = unavailable_attempts;
        });
        tokio::time::sleep(HOST_POLL_PERIOD).await;
    }
}

/// One `FIND_VALUE` reply: the replica's routes nearer the key and its
/// provider hints, whose tokens only the requester can check.
type FoundValue = (Vec<PeerId>, Vec<(PeerId, ProviderToken)>);

impl<T: Transport> ProviderClient<T> {
    async fn find_value(&self, peer: PeerId, key: ProviderKey) -> anyhow::Result<FoundValue> {
        let connection = self.connections.connect(peer).await?;
        let response = tokio::time::timeout(OP_DEADLINE, op_find_value(&connection, &key))
            .await
            .map_err(|_| anyhow::anyhow!("FIND_VALUE deadline exceeded"))?;
        match response {
            Ok(found) => {
                self.candidates.lock().unwrap().promote_authenticated(peer);
                Ok(found)
            }
            Err(error) => {
                self.connections.invalidate(&connection);
                Err(error)
            }
        }
    }

    /// Look up the K replicas nearest `key` with one `FIND_VALUE` per hop,
    /// keeping the hints each authenticated responder returns on the way.
    ///
    /// A foreground fetch's end-to-end deadline bounds cold bootstrap. Start
    /// the short routing window only after an authenticated reply, so a slow
    /// secondary route cannot consume all the remaining time.
    /// Background work starts its short lookup window immediately.
    async fn lookup(
        &self,
        key: ProviderKey,
        limit: Option<std::time::Duration>,
    ) -> (ReplicaLookup, Vec<(PeerId, ProviderToken)>) {
        let seeds = self.candidates.lock().unwrap().closest(key, K);
        let mut lookup = ReplicaLookup::new(self.my_id, key, seeds, limit);
        let mut hints = Vec::new();
        let mut pending: FuturesUnordered<
            futures::future::BoxFuture<'_, (PeerId, anyhow::Result<FoundValue>)>,
        > = FuturesUnordered::new();
        loop {
            for peer in lookup.machine.next_batch() {
                pending.push(Box::pin(async move {
                    let reply = self.find_value(peer, key).await;
                    (peer, reply)
                }));
            }
            let reply = match lookup.deadline {
                Some(deadline) => match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(reply) => reply,
                    Err(_) => {
                        lookup.expire(&mut self.candidates.lock().unwrap());
                        break;
                    }
                },
                None => pending.next().await,
            };
            let Some((peer, reply)) = reply else {
                break;
            };
            if let Some(found) = lookup.observe(peer, reply, &mut self.candidates.lock().unwrap()) {
                hints.extend(found);
            }
            if lookup.machine.is_finished() && pending.is_empty() {
                break;
            }
        }
        drop(pending);
        (lookup, hints)
    }

    async fn put(&self, peer: PeerId, key: ProviderKey, token: ProviderToken) -> ProviderPutResult {
        if peer == self.my_id {
            return if self.providers.lock().unwrap().put(
                key,
                self.my_id,
                token,
                crate::clock::mono_now(),
            ) {
                ProviderPutResult::Accepted
            } else {
                ProviderPutResult::ExplicitlyRejected
            };
        }
        let Ok(connection) = self.connections.connect(peer).await else {
            return ProviderPutResult::Unavailable;
        };
        match tokio::time::timeout(OP_DEADLINE, op_provider_put(&connection, &key, &token)).await {
            Ok(Ok(stored)) => {
                self.candidates.lock().unwrap().promote_authenticated(peer);
                if stored {
                    ProviderPutResult::Accepted
                } else {
                    ProviderPutResult::ExplicitlyRejected
                }
            }
            Ok(Err(_)) => {
                self.connections.invalidate(&connection);
                ProviderPutResult::Unavailable
            }
            // A slow reply says nothing against the shared connection.
            Err(_) => ProviderPutResult::Unavailable,
        }
    }

    async fn announce_key(&self, key: ProviderKey, token: ProviderToken) -> PublicationResult {
        let (lookup, _) = self.lookup(key, Some(BACKGROUND_LOOKUP_DEADLINE)).await;
        let mut attempts = futures::stream::iter(lookup.replicas())
            .map(|peer| async move { (peer, self.put(peer, key, token).await) })
            .buffer_unordered(ALPHA);
        let mut publication = PublicationResult::NoAuthenticatedRemoteReplica;
        while let Some((peer, result)) = attempts.next().await {
            publication = publication.observe_put(self.my_id, peer, result);
        }
        // A local directory copy is useful for single-node reads but cannot
        // make this endpoint discoverable after an isolated startup. Preserve
        // that topology failure separately from a rejection by a remote which
        // authenticated during this exact lookup.
        publication
    }

    /// The verified providers of one key: hints from every authenticated
    /// lookup responder, and from our own directory when we are among the
    /// key's replicas, whose tokens prove knowledge of `identity`.
    async fn find_key(
        &self,
        key: ProviderKey,
        token_for: fn([u8; 32], PeerId) -> ProviderToken,
        identity: [u8; 32],
        lookup_limit: Option<std::time::Duration>,
    ) -> anyhow::Result<Vec<PeerId>> {
        let (lookup, mut hints) = self.lookup(key, lookup_limit).await;
        if lookup.replicas().contains(&self.my_id) {
            hints.extend(
                self.providers
                    .lock()
                    .unwrap()
                    .get(key, crate::clock::mono_now()),
            );
        }
        let providers = hints
            .into_iter()
            .filter(|(provider, token)| token_for(identity, *provider) == *token)
            .map(|(provider, _)| provider)
            .collect::<Vec<_>>();
        if providers.is_empty() {
            lookup.miss()?;
        }
        Ok(canonical_provider_subset(
            &self.salt,
            key,
            providers,
            crate::provider::MAX_PROVIDERS_PER_REPLY,
        ))
    }

    async fn fetch_from_provider(
        &self,
        hash: RawHash,
        peer: PeerId,
    ) -> anyhow::Result<Option<Blob<UnknownBlob>>> {
        self.fetch_from_provider_with_limit(hash, peer, crate::protocol::MAX_EXACT_BLOB_BYTES)
            .await
    }

    async fn fetch_from_provider_with_limit(
        &self,
        hash: RawHash,
        peer: PeerId,
        max_bytes: u64,
    ) -> anyhow::Result<Option<Blob<UnknownBlob>>> {
        let connection = self.connections.connect(peer).await?;
        let response = tokio::time::timeout(
            OP_DEADLINE,
            op_get_blob_with_limit(&connection, self.my_id, &hash, max_bytes),
        )
        .await
        .map_err(|_| anyhow::anyhow!("exact blob provider request deadline exceeded"))?;
        match response {
            Ok(Some(bytes)) => {
                self.candidates.lock().unwrap().promote_authenticated(peer);
                Ok(Some(bytes))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                // Local receive saturation says nothing about the authenticated
                // provider or this connection. Keep it warm for a later retry.
                if !error.is::<crate::protocol::ExactBlobReceiveResourceError>()
                    && !error.is::<crate::protocol::ExactBlobReceivePolicyError>()
                {
                    self.connections.invalidate(&connection);
                }
                Err(error)
            }
        }
    }

    /// Discover candidates only from H and start verified providers as soon
    /// as a lookup reply names them, without waiting for routing to finish.
    /// Lookup requests and bodies share ALPHA slots, with one slot reserved
    /// for routing while it remains open.
    async fn fetch_blob(
        &self,
        hash: RawHash,
        lookup_limit: Option<std::time::Duration>,
    ) -> anyhow::Result<Option<Blob<UnknownBlob>>> {
        self.fetch_blob_with_limit(hash, lookup_limit, crate::protocol::MAX_EXACT_BLOB_BYTES)
            .await
    }

    async fn fetch_blob_with_limit(
        &self,
        hash: RawHash,
        lookup_limit: Option<std::time::Duration>,
        max_bytes: u64,
    ) -> anyhow::Result<Option<Blob<UnknownBlob>>> {
        enum Progress {
            Routing(PeerId, anyhow::Result<FoundValue>),
            RoutingExpired,
            Blob(anyhow::Result<Option<Blob<UnknownBlob>>>),
        }

        let key = blob_locator(hash);
        let seeds = self.candidates.lock().unwrap().closest(key, K);
        let mut lookup = ReplicaLookup::new(self.my_id, key, seeds, lookup_limit);
        let mut routing: FuturesUnordered<
            futures::future::BoxFuture<'_, (PeerId, anyhow::Result<FoundValue>)>,
        > = FuturesUnordered::new();
        let mut routing_closed = false;
        // Our own directory answers like a replica's when the first
        // authenticated reply, or the closed lookup, places us among the
        // key's replicas. Later responders can only push us out.
        let mut local_decided = false;
        let mut candidates = ProgressiveBlobProviders::new(hash, self.my_id, self.salt);
        let mut bodies: FuturesUnordered<
            futures::future::BoxFuture<'_, anyhow::Result<Option<Blob<UnknownBlob>>>>,
        > = FuturesUnordered::new();
        let mut provider_failure = None;
        loop {
            // Closing the routing window never cancels an already progressing
            // body, nor manufactures a connection error. record_timeouts alone
            // does not seal the lookup machine.
            if !routing_closed {
                let expired = lookup
                    .deadline
                    .is_some_and(|deadline| tokio::time::Instant::now() >= deadline);
                if expired || lookup.machine.is_finished() {
                    if expired {
                        lookup.expire(&mut self.candidates.lock().unwrap());
                        routing.clear();
                    }
                    routing_closed = true;
                }
            }
            if !local_decided && (routing_closed || lookup.remote_responded) {
                local_decided = true;
                if lookup.replicas().contains(&self.my_id) {
                    candidates.observe(
                        self.providers
                            .lock()
                            .unwrap()
                            .get(key, crate::clock::mono_now()),
                    );
                }
            }
            while routing.len() + bodies.len() < ALPHA {
                // Two slow provider attempts must not occupy every routing
                // slot. This reserves capacity, not extra concurrency, and
                // cannot promise progress when the routing peer itself stalls.
                let body_limit = if routing_closed { ALPHA } else { ALPHA - 1 };
                if bodies.len() < body_limit
                    && let Some(peer) = candidates.next()
                {
                    bodies.push(Box::pin(async move {
                        if max_bytes == crate::protocol::MAX_EXACT_BLOB_BYTES {
                            self.fetch_from_provider(hash, peer).await
                        } else {
                            self.fetch_from_provider_with_limit(hash, peer, max_bytes)
                                .await
                        }
                    }));
                    continue;
                }
                if routing_closed {
                    break;
                }
                let batch = lookup
                    .machine
                    .next_batch_up_to(ALPHA - routing.len() - bodies.len());
                if batch.is_empty() {
                    break;
                }
                for peer in batch {
                    routing.push(Box::pin(
                        async move { (peer, self.find_value(peer, key).await) },
                    ));
                }
            }
            if routing.is_empty() && bodies.is_empty() {
                debug_assert!(routing_closed);
                break;
            }
            let progress = tokio::select! {
                reply = routing.next(), if !routing.is_empty() => {
                    let (peer, reply) = reply.expect("nonempty routing requests");
                    Progress::Routing(peer, reply)
                }
                body = bodies.next(), if !bodies.is_empty() => {
                    Progress::Blob(body.expect("nonempty provider requests"))
                }
                () = async {
                    match lookup.deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                }, if !routing_closed => Progress::RoutingExpired,
            };
            match progress {
                Progress::RoutingExpired => {}
                Progress::Routing(peer, reply) => {
                    if let Some(hints) =
                        lookup.observe(peer, reply, &mut self.candidates.lock().unwrap())
                    {
                        candidates.observe(hints);
                    }
                }
                Progress::Blob(Ok(Some(bytes))) => return Ok(Some(bytes)),
                Progress::Blob(Ok(None)) => {}
                Progress::Blob(Err(error)) => {
                    provider_failure.get_or_insert(error);
                }
            }
        }
        if let Some(error) = provider_failure {
            return Err(error);
        }
        if !candidates.verified {
            lookup.miss()?;
        }
        Ok(None)
    }
}

/// Lookup-local scheduling state shared by final-union discovery and the
/// progressive exact-H fetch. No result cache or detached work is kept.
struct ReplicaLookup {
    local: PeerId,
    target: RoutingKey,
    machine: IterativeLookup,
    deadline: Option<tokio::time::Instant>,
    /// Some remote answered a request of this lookup.
    remote_responded: bool,
    /// The first request that failed or was left unanswered.
    failure: Option<anyhow::Error>,
}

impl ReplicaLookup {
    fn new(
        local: PeerId,
        target: RoutingKey,
        seeds: Vec<PeerId>,
        limit: Option<std::time::Duration>,
    ) -> Self {
        Self {
            local,
            target,
            machine: IterativeLookup::new(local, target, seeds),
            deadline: limit.map(|limit| tokio::time::Instant::now() + limit),
            remote_responded: false,
            failure: None,
        }
    }

    /// Record one `FIND_VALUE` outcome. Returns the reply's hints when it
    /// answers a request this lookup issued.
    fn observe(
        &mut self,
        peer: PeerId,
        reply: anyhow::Result<FoundValue>,
        routes: &mut RoutingTable,
    ) -> Option<Vec<(PeerId, ProviderToken)>> {
        match reply {
            Ok((referrals, hints)) => {
                self.deadline.get_or_insert_with(|| {
                    tokio::time::Instant::now() + BACKGROUND_LOOKUP_DEADLINE
                });
                let issued = self.machine.record_authenticated_response(
                    peer,
                    referrals
                        .into_iter()
                        .filter(|candidate| EndpointId::from_bytes(candidate).is_ok()),
                    routes,
                );
                self.remote_responded |= issued;
                issued.then_some(hints)
            }
            Err(error) => {
                debug!(%error, "DHT lookup request failed");
                self.machine.record_failure(peer, routes);
                self.failure.get_or_insert(error);
                None
            }
        }
    }

    fn expire(&mut self, routes: &mut RoutingTable) {
        let timed_out = self.machine.record_timeouts(routes);
        debug!(timed_out, "DHT lookup routing window exhausted");
        if timed_out != 0 {
            self.failure.get_or_insert_with(|| {
                anyhow::anyhow!("{timed_out} DHT lookup requests unanswered when its window closed")
            });
        }
    }

    fn replicas(&self) -> Vec<PeerId> {
        let mut replicas = self.machine.closest_authenticated_responders().to_vec();
        replicas.push(self.local);
        replicas.sort_unstable_by(|a, b| crate::routing::distance_cmp(self.target, *a, *b));
        replicas.dedup();
        replicas.truncate(K);
        replicas
    }

    /// Why a lookup that yielded no verified provider is not a plain miss:
    /// no remote answered, or some request failed or went unanswered.
    fn miss(self) -> anyhow::Result<()> {
        if !self.remote_responded {
            anyhow::bail!("DHT provider lookup reached no remote replica");
        }
        match self.failure {
            Some(error) => Err(error.context("DHT provider lookup incomplete")),
            None => Ok(()),
        }
    }
}

/// Per-fetch scheduling only. At most 64 distinct providers can be attempted;
/// pending slots are ranked by [`provider_rank`] among the verified hints
/// which have arrived so far. A later reply may replace a pending candidate,
/// never an already-started attempt. Thus transient attempts deliberately
/// need not equal the canonical final union used by collection discovery,
/// and remain bounded under hint floods.
struct ProgressiveBlobProviders {
    hash: RawHash,
    local: PeerId,
    salt: [u8; 32],
    attempted: BTreeSet<PeerId>,
    pending: Vec<PeerId>,
    /// Some hint so far carried a valid token, our own included.
    verified: bool,
}

impl ProgressiveBlobProviders {
    fn new(hash: RawHash, local: PeerId, salt: [u8; 32]) -> Self {
        Self {
            hash,
            local,
            salt,
            attempted: BTreeSet::new(),
            pending: Vec::new(),
            verified: false,
        }
    }

    /// Keep the hints whose token proves knowledge of H, other than our own,
    /// that have not been attempted, within the remaining attempt budget.
    fn observe(&mut self, hints: impl IntoIterator<Item = (PeerId, ProviderToken)>) {
        let mut arrived = Vec::new();
        for (provider, token) in hints {
            if blob_provider_token(self.hash, provider) != token {
                continue;
            }
            self.verified = true;
            if provider != self.local && !self.attempted.contains(&provider) {
                arrived.push(provider);
            }
        }
        self.pending = canonical_provider_subset(
            &self.salt,
            blob_locator(self.hash),
            self.pending.drain(..).chain(arrived),
            crate::provider::MAX_PROVIDERS_PER_REPLY - self.attempted.len(),
        );
    }

    fn next(&mut self) -> Option<PeerId> {
        if self.pending.is_empty() {
            return None;
        }
        let peer = self.pending.remove(0);
        let newly_attempted = self.attempted.insert(peer);
        debug_assert!(newly_attempted);
        Some(peer)
    }
}

/// A requester's rank of one provider for one key: `keyed(salt; key ||
/// provider)`, under a salt it draws once and never sends. A public rank, such
/// as the provider's XOR distance from the key, would let a provider grind an
/// identity that every requester tries first.
fn provider_rank(salt: &[u8; 32], key: ProviderKey, provider: PeerId) -> [u8; 32] {
    let mut block = [0; 64];
    block[..32].copy_from_slice(&key);
    block[32..].copy_from_slice(&provider);
    *blake3::keyed_hash(salt, &block).as_bytes()
}

/// Canonical union of the supplied replies for one exact key, bounded by `limit`.
///
/// Each queried DHT replica independently bounds its response, but their union
/// may still be `K` times larger. Ranking the deduplicated union by
/// [`provider_rank`] makes the selected subset independent of asynchronous
/// reply order. Collection discovery supplies all replies; progressive exact
/// fetches use the same ranking for their currently available,
/// not-yet-attempted hints.
fn canonical_provider_subset(
    salt: &[u8; 32],
    key: ProviderKey,
    providers: impl IntoIterator<Item = PeerId>,
    limit: usize,
) -> Vec<PeerId> {
    providers
        .into_iter()
        .map(|provider| (provider_rank(salt, key, provider), provider))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(limit)
        .map(|(_, provider)| provider)
        .collect()
}

#[derive(Clone)]
struct SnapshotHandler {
    snapshot: SnapshotSlot,
    health: Health,
    candidates: RoutingCandidates,
    providers: Arc<Mutex<ProviderDirectory>>,
    local_id: PeerId,
    /// Where `recon/1` events go: the host's peering task.
    recon: Option<tokio::sync::mpsc::Sender<ReconEvent>>,
    /// Where walk frames and ended streams go: the host's walk task.
    walks: Option<tokio::sync::mpsc::Sender<ReconEvent>>,
}

#[cfg(test)]
impl SnapshotHandler {
    /// A handler serving an empty snapshot and an empty directory.
    fn for_test(local_id: PeerId, routes: RoutingTable) -> Self {
        Self {
            snapshot: tokio::sync::watch::channel(None).1,
            health: Health::new(EndpointId::from_bytes(&local_id).unwrap()),
            candidates: Arc::new(Mutex::new(routes)),
            providers: Arc::new(Mutex::new(ProviderDirectory::new(local_id))),
            local_id,
            recon: None,
            walks: None,
        }
    }
}

/// The request streams of every connection, answered from the current
/// serving snapshot.
impl Service for SnapshotHandler {
    async fn serve<W, R>(
        &self,
        peer: PeerId,
        tag: u8,
        send: &mut W,
        recv: &mut R,
    ) -> anyhow::Result<()>
    where
        W: SendStream,
        R: RecvStream,
    {
        let peer = VerifyingKey::from_bytes(&peer)
            .map_err(|error| anyhow::anyhow!("invalid transport peer key: {error}"))?;
        match tag {
            TAG_BLOB => {
                let activity = self.health.begin_blob_serve();
                let snapshot = self.snapshot.borrow().clone();
                let blob_snapshot = snapshot.clone();
                let mut payload_bytes = None;
                serve_get_blob(
                    recv,
                    send,
                    peer.to_bytes(),
                    self.local_id,
                    move |locator| {
                        snapshot
                            .as_ref()
                            .and_then(|snapshot| snapshot.bearer_handle(locator))
                    },
                    |handle| {
                        let bytes = blob_snapshot
                            .as_ref()
                            .and_then(|snapshot| snapshot.get_blob(&handle));
                        payload_bytes = bytes.as_ref().map(|bytes| bytes.len() as u64);
                        bytes
                    },
                )
                .await?;
                activity.complete(payload_bytes);
            }
            TAG_DHT => self.serve_dht(peer, send, recv).await?,
            other => anyhow::bail!("not a request stream tag {other:#x}"),
        }
        self.candidates
            .lock()
            .unwrap()
            .promote_authenticated(peer.to_bytes());
        Ok(())
    }

    async fn recon(&self, event: ReconEvent) {
        let (walks, peering) = match event {
            ReconEvent::Frame(_, Frame::Walk(_)) | ReconEvent::Ended(_) => (Some(event), None),
            // Both hear a connection close.
            ReconEvent::Closed(link) => (
                Some(ReconEvent::Closed(link.clone())),
                Some(ReconEvent::Closed(link)),
            ),
            event => (None, Some(event)),
        };
        if let (Some(walks), Some(event)) = (&self.walks, walks) {
            let _ = walks.send(event).await;
        }
        if let (Some(recon), Some(event)) = (&self.recon, peering) {
            let _ = recon.send(event).await;
        }
    }
}

impl SnapshotHandler {
    /// Serve one `dht/1` operation.
    async fn serve_dht<W, R>(
        &self,
        peer: VerifyingKey,
        send: &mut W,
        recv: &mut R,
    ) -> anyhow::Result<()>
    where
        W: SendStream,
        R: RecvStream,
    {
        let op = recv_u8(recv).await?;
        tracing::trace!(target: "triblespace_net::handoff", op = op_name(op), "host received DHT operation");
        match op {
            OP_PROVIDER_PUT => {
                let key = recv_hash(recv).await?;
                let token = recv_hash(recv).await?;
                require_stream_eof(recv).await?;
                let stored = self.providers.lock().unwrap().put(
                    key,
                    peer.to_bytes(),
                    token,
                    crate::clock::mono_now(),
                );
                send_u8(
                    send,
                    if stored {
                        PROVIDER_PUT_OK
                    } else {
                        PROVIDER_PUT_FULL
                    },
                )
                .await?;
            }
            OP_FIND_VALUE => {
                let requester = peer.to_bytes();
                let routes = |key| {
                    let mut routes = self.candidates.lock().unwrap().closest_verified(key, K);
                    routes.retain(|route| *route != requester);
                    routes
                };
                let hints = |key| self.provider_hints(key);
                serve_find_value(recv, send, routes, hints).await?;
            }
            _ => {
                // Like an unknown tag, an unknown operation resets only its
                // own stream.
                send.reset(RESET_UNKNOWN);
                recv.stop(RESET_UNKNOWN);
                anyhow::bail!("unknown DHT operation {op:#x}")
            }
        }
        Ok(())
    }

    /// The directory's hints for one exact key, led by our own current hint
    /// when the blob is resident. Residency comes from the same index as
    /// bearer GET, without reading bytes or installing a lease.
    fn provider_hints(&self, key: ProviderKey) -> Vec<(PeerId, ProviderToken)> {
        let resident = self
            .snapshot
            .borrow()
            .as_ref()
            .and_then(|snapshot| snapshot.bearer_handle(key));
        self.providers
            .lock()
            .unwrap()
            .hints(key, crate::clock::mono_now(), resident)
    }
}

async fn require_stream_eof<R: tokio::io::AsyncRead + Unpin>(recv: &mut R) -> anyhow::Result<()> {
    let mut trailing = [0u8; 1];
    if recv.read(&mut trailing).await? != 0 {
        anyhow::bail!("request contains trailing bytes");
    }
    Ok(())
}

fn op_name(op: u8) -> &'static str {
    match op {
        OP_PROVIDER_PUT => "PROVIDER_PUT",
        OP_FIND_VALUE => "FIND_VALUE",
        _ => "UNKNOWN",
    }
}

#[cfg(all(test, feature = "sim"))]
mod acquisition_tests;

#[cfg(test)]
mod directory_rpc_tests;

#[cfg(test)]
mod observation_tests;

#[cfg(all(test, feature = "sim"))]
mod pool_tests;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use crate::provider::{
        MAX_PROVIDERS_PER_REPLY, ProviderObservation, ProviderPublisher, ProviderPutResult,
        PublicationResult,
    };
    use crate::routing::K;
    use crate::transport::PeerId;
    use ed25519_dalek::SigningKey;
    use iroh_base::EndpointId;
    use triblespace_core::blob::Blob;
    use triblespace_core::blob::encodings::UnknownBlob;
    use triblespace_core::collection::CollectionHandle;

    use super::{
        COLLECTION_PARTICIPANT_LEASE, CollectionDiscoveries, DescriptorFetches, DiscoveryState,
        MAX_COLLECTION_PARTICIPANTS, MAX_PENDING_REPAIRS, ProgressiveBlobProviders,
        ProviderPublicationBudget, RepairTarget, WakeBootstrapPeers, blob_provider_token,
        canonical_provider_subset, enqueue_repair, forget_participant, has_repair_candidate,
        live_participants, observe_participant, provider_rank, retain_active_repair_state,
    };

    fn endpoint(byte: u8) -> EndpointId {
        EndpointId::from_bytes(
            SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn owned_discoveries_bound_actual_futures_and_release_completed_slots() {
        let mut lookups = CollectionDiscoveries::default();
        let mut senders = Vec::new();
        for index in 0..super::ALPHA + 2 {
            let (send, receive) = tokio::sync::oneshot::channel::<Vec<PeerId>>();
            let started = lookups.start([index as u8; 32], async move {
                receive.await.unwrap_or_default()
            });
            assert_eq!(started, index < super::ALPHA);
            assert_eq!(send.is_closed(), !started);
            senders.push(send);
        }
        assert_eq!(lookups.len(), super::ALPHA);
        assert!(lookups.poll(|_| true).is_empty());
        assert!(!lookups.start([0; 32], async { Vec::new() }));

        senders.remove(0).send(vec![[91; 32]]).unwrap();
        assert_eq!(
            lookups.poll(|_| true),
            vec![(CollectionHandle::new([0; 32]), vec![[91; 32]])]
        );
        assert_eq!(lookups.len(), super::ALPHA - 1);
        let (send, receive) = tokio::sync::oneshot::channel::<Vec<PeerId>>();
        assert!(lookups.start([99; 32], async move { receive.await.unwrap_or_default() }));
        assert_eq!(lookups.len(), super::ALPHA);

        drop(lookups);
        assert!(send.is_closed());
        assert!(senders.iter().all(|send| send.is_closed()));
    }

    #[test]
    fn deactivation_cancels_discovery_before_same_handle_reactivation() {
        let collection = [31; 32];
        let mut lookups = CollectionDiscoveries::default();
        let (old_send, old_receive) = tokio::sync::oneshot::channel::<Vec<PeerId>>();
        assert!(lookups.start(
            collection,
            async move { old_receive.await.unwrap_or_default() }
        ));
        assert!(lookups.poll(|_| true).is_empty());
        assert!(lookups.poll(|_| false).is_empty());
        assert!(old_send.is_closed(), "deactivation drops the actual lookup");
        assert_eq!(lookups.len(), 0);

        let (new_send, new_receive) = tokio::sync::oneshot::channel::<Vec<PeerId>>();
        assert!(lookups.start(
            collection,
            async move { new_receive.await.unwrap_or_default() }
        ));
        assert!(old_send.send(vec![[71; 32]]).is_err());
        assert!(lookups.poll(|_| true).is_empty());
        assert_eq!(lookups.len(), 1, "old completion cannot finish new work");
        new_send.send(vec![[72; 32]]).unwrap();
        assert_eq!(
            lookups.poll(|_| true),
            vec![(CollectionHandle::new(collection), vec![[72; 32]])]
        );
    }

    #[test]
    fn deactivation_discards_discovery_even_when_its_result_is_ready() {
        let collection = [31; 32];
        let mut lookups = CollectionDiscoveries::default();
        assert!(lookups.start(collection, async { vec![[71; 32]] }));
        assert!(lookups.poll(|_| false).is_empty());
        assert!(lookups.start(collection, async { vec![[72; 32]] }));
        assert_eq!(
            lookups.poll(|_| true),
            vec![(CollectionHandle::new(collection), vec![[72; 32]])]
        );
    }

    #[test]
    fn equal_advertisement_does_not_cancel_failed_repair_confirmation() {
        let local = [81; 32];
        let equal = Some(super::CollectionWakeRoot::new(local));
        let target = RepairTarget {
            collection: CollectionHandle::new([82; 32]),
            peer: [83; 32],
        };
        let mut failures = HashMap::from([(target, (1, crate::clock::mono_now()))]);
        assert!(!super::can_skip_repair(
            local,
            equal,
            failures.contains_key(&target),
        ));
        // This is the successful-outcome transition, not an equality hint.
        failures.remove(&target);
        assert!(super::can_skip_repair(
            local,
            equal,
            failures.contains_key(&target)
        ));
        assert!(!super::can_skip_repair(local, None, false));
        assert!(!super::can_skip_repair(
            local,
            Some(super::CollectionWakeRoot::new([84; 32])),
            false,
        ));
    }

    #[tokio::test]
    async fn descriptor_fetch_is_coalesced_until_admission_handoff_completes() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let collection = [31; 32];
        let active = HashMap::from([(collection, [0; 32])]);
        let attempts = Arc::new(AtomicUsize::new(0));
        let (events, mut received) = tokio::sync::mpsc::channel(1);
        events.try_send(super::NetEventBatch::default()).unwrap();
        let mut fetches = DescriptorFetches::default();

        // Model many repair periods with a full admission bridge. Starting a
        // new period must not repeat the fetch or retain another result.
        for _ in 0..100 {
            let attempts = attempts.clone();
            let events = events.clone();
            fetches.start(collection, async move {
                attempts.fetch_add(1, Ordering::Relaxed);
                let mut batch = super::NetEventBatch::default();
                let bytes = anybytes::Bytes::from_source(b"descriptor".to_vec());
                let verified = Blob::<UnknownBlob>::new(bytes);
                batch.try_push(super::NetEvent::Blob(verified)).unwrap();
                let _ = events.send(batch).await;
            });
            fetches.poll(|raw| active.contains_key(raw));
            assert_eq!(fetches.pending.len(), 1);
        }
        assert_eq!(attempts.load(Ordering::Relaxed), 1);

        assert_eq!(received.recv().await.unwrap().len(), 0);
        fetches.poll(|raw| active.contains_key(raw));
        assert!(fetches.pending.is_empty());
        assert_eq!(received.recv().await.unwrap().len(), 1);
        assert!(received.try_recv().is_err());
    }

    #[tokio::test]
    async fn descriptor_fetches_release_removed_collections_and_host_ownership() {
        let first = [31; 32];
        let second = [32; 32];
        let mut active = HashMap::from([(first, [0; 32]), (second, [0; 32])]);
        let mut fetches = DescriptorFetches::default();
        let (first_owner, mut first_observer) = tokio::sync::oneshot::channel::<()>();
        let (second_owner, mut second_observer) = tokio::sync::oneshot::channel::<()>();
        fetches.start(first, async move {
            let _owner = first_owner;
            std::future::pending::<()>().await;
        });
        fetches.start(second, async move {
            let _owner = second_owner;
            std::future::pending::<()>().await;
        });
        fetches.poll(|raw| active.contains_key(raw));
        assert_eq!(fetches.pending.len(), 2);

        active.remove(&first);
        fetches.poll(|raw| active.contains_key(raw));
        assert_eq!(fetches.pending.len(), 1);
        assert_eq!(
            first_observer.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
        assert_eq!(
            second_observer.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );

        drop(fetches);
        assert_eq!(
            second_observer.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
    }

    #[tokio::test]
    async fn completed_descriptor_attempt_allows_a_later_retry() {
        let collection = [31; 32];
        let active = HashMap::from([(collection, [0; 32])]);
        let mut fetches = DescriptorFetches::default();
        for _ in 0..2 {
            let (complete, completion) = tokio::sync::oneshot::channel();
            fetches.start(collection, async move {
                complete.send(()).unwrap();
            });
            fetches.poll(|raw| active.contains_key(raw));
            assert!(fetches.pending.is_empty());
            completion.await.unwrap();
        }
    }

    fn metadata_fixture(
        name: &str,
    ) -> (
        Blob<UnknownBlob>,
        super::PATCH<32, super::IdentitySchema, anybytes::Bytes>,
    ) {
        use triblespace_core::blob::IntoBlob;
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::capability::policy::resource_policy;
        use triblespace_core::collection::{
            AdmissionPolicy, CollectionPolicy, KIND_COLLECTION_DESCRIPTOR, collection_name,
        };
        use triblespace_core::prelude::{BlobStoreGet, BlobStoreList, SnapshotSource, entity};

        let fragment = entity! {
            triblespace_core::metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            collection_name: name.to_owned(),
            resource_policy*: CollectionPolicy::new(AdmissionPolicy::Open, AdmissionPolicy::Open).fragment(),
            // A real attached blob, but not part of this typed warmup grammar.
            triblespace_core::metadata::description: "do not prefetch this annotation".to_owned(),
        };
        let descriptor: Blob<SimpleArchive> = fragment.facts().to_blob();
        let mut answers = super::PATCH::new();
        let reader = fragment.blobs().clone().snapshot().unwrap();
        for info in reader.blobs() {
            let handle = info.unwrap().handle;
            let bytes = reader.get::<anybytes::Bytes, _>(handle).unwrap();
            answers.insert(&super::PatchEntry::with_value(&handle.raw, bytes));
        }
        answers.insert(&super::PatchEntry::with_value(
            &descriptor.get_handle().raw,
            descriptor.bytes.clone(),
        ));
        (descriptor.transmute(), answers)
    }

    #[tokio::test]
    async fn selected_empty_descriptor_warmup_lands_name_but_not_annotations_or_other_collections()
    {
        use futures::FutureExt;
        use std::sync::{Arc, Mutex};
        use triblespace_core::repo::{BlobStoreGet, BlobStorePut, SnapshotSource};
        let (descriptor, answers) = metadata_fixture("selected empty");
        let (other, _) = metadata_fixture("unselected empty");
        let collection = descriptor.get_handle().raw;
        let dependencies = super::descriptor_metadata(descriptor.bytes.clone());
        let name = dependencies[0];
        let answers = Arc::new(answers);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let (events, mut received) = tokio::sync::mpsc::channel(16);
        let mut owners = DescriptorFetches::default();
        owners.start(
            collection,
            super::warm_descriptor(
                collection,
                |_| None,
                move |hash| {
                    observed.lock().unwrap().push(hash);
                    let answer = answers.get(&hash).cloned();
                    async move { answer.map(Blob::<UnknownBlob>::new) }.boxed()
                },
                events,
            ),
        );
        owners.poll(|raw| *raw == collection);
        assert!(owners.pending.is_empty());

        let mut store = triblespace_core::repo::memoryrepo::MemoryRepo::default();
        while let Ok(batch) = received.try_recv() {
            for event in batch.into_events() {
                let super::NetEvent::Blob(blob) = event else {
                    panic!("only blobs");
                };
                store.put::<UnknownBlob, _>(blob).unwrap();
            }
        }
        let snapshot = store.snapshot().unwrap();
        assert!(
            snapshot
                .get::<anybytes::Bytes, UnknownBlob>(super::Inline::new(collection))
                .is_ok()
        );
        assert_eq!(
            &*snapshot
                .get::<anybytes::Bytes, UnknownBlob>(super::Inline::new(name))
                .unwrap(),
            b"selected empty"
        );
        let calls = calls.lock().unwrap();
        assert!(calls.contains(&collection));
        assert!(dependencies.iter().all(|hash| calls.contains(hash)));
        assert_eq!(calls.len(), dependencies.len() + 1);
        assert!(!calls.contains(&other.get_handle().raw));
    }

    #[tokio::test(start_paused = true)]
    async fn slow_metadata_child_does_not_starve_a_later_sibling() {
        use futures::FutureExt;
        use std::sync::Arc;
        let (descriptor, answers) = metadata_fixture("reachable sibling");
        let collection = descriptor.get_handle().raw;
        let dependencies = super::descriptor_metadata(descriptor.bytes.clone());
        let name = dependencies[0];
        let answers = Arc::new(answers);
        let (events, mut received) = tokio::sync::mpsc::channel(16);
        let warmup = super::warm_descriptor(
            collection,
            move |hash| (hash == collection).then(|| descriptor.bytes.clone()),
            move |hash| {
                let answer = answers.get(&hash).cloned();
                async move {
                    if hash == name {
                        std::future::pending::<()>().await;
                    }
                    answer.map(Blob::<UnknownBlob>::new)
                }
                .boxed()
            },
            events,
        );
        warmup.await;
        // The name times out, but another recognized dependency was attempted
        // and the whole attempt finishes within its warmup-only child budget.
        assert_eq!(dependencies.len(), 3);
        assert!(received.try_recv().is_ok());
        assert!(received.try_recv().is_ok());
        assert!(received.try_recv().is_err());
    }

    #[tokio::test]
    async fn metadata_owners_bound_fanout_rotate_and_skip_push_only() {
        let mut active = super::PATCH::<32, super::IdentitySchema>::new();
        for byte in 1..=9 {
            active.insert(&super::PatchEntry::new(&[byte; 32]));
        }
        let mut owners = DescriptorFetches::default();
        assert!(owners.selected_round(&active, false).is_empty());
        for raw in owners.selected_round(&active, true) {
            owners.start(raw, std::future::pending());
        }
        assert_eq!(
            owners.pending.len(),
            super::METADATA_COLLECTIONS_IN_FLIGHT as u64
        );
        assert_eq!(owners.selected_round(&active, true)[0], [5; 32]);
        owners.poll(|_| false);
        assert!(owners.pending.is_empty());
        for raw in owners.selected_round(&active, true) {
            owners.start(raw, std::future::pending());
        }
        assert_eq!(owners.selected_round(&active, true)[0], [9; 32]);
    }

    #[tokio::test]
    async fn resident_metadata_prefix_releases_owner_slots_in_the_same_selection_round() {
        use futures::FutureExt;
        use std::sync::Arc;
        let mut resident: super::PATCH<32, super::IdentitySchema, anybytes::Bytes> =
            super::PATCH::new();
        let mut active = super::PATCH::<32, super::IdentitySchema>::new();
        for ordinal in 0..12 {
            let (descriptor, answers) = metadata_fixture(&format!("warm prefix {ordinal}"));
            let collection = descriptor.get_handle().raw;
            for raw in answers.iter_ordered() {
                resident.insert(&super::PatchEntry::with_value(
                    raw,
                    answers.get(raw).unwrap().clone(),
                ));
            }
            active.insert(&super::PatchEntry::new(&collection));
        }
        let cold = *active.iter_ordered().max().unwrap();
        resident.remove(&cold);
        let resident = Arc::new(resident);
        let (events, _received) = tokio::sync::mpsc::channel(16);
        let mut owners = DescriptorFetches::default();
        for raw in owners
            .selected_round(&active, true)
            .into_iter()
            .take(super::METADATA_SELECTIONS_PER_ROUND)
        {
            let resident = resident.clone();
            owners.start(
                raw,
                super::warm_descriptor(
                    raw,
                    move |hash| resident.get(&hash).cloned(),
                    |_| std::future::pending().boxed(),
                    events.clone(),
                ),
            );
            owners.poll(|raw| active.get(raw).is_some());
        }
        assert_eq!(owners.pending.len(), 1);
        assert!(
            owners.pending.get(&cold).is_some(),
            "warm prefix cannot consume all launch slots"
        );
    }

    #[tokio::test]
    async fn selected_metadata_warmup_is_cancelled_while_real_admission_handoff_is_blocked() {
        use futures::FutureExt;
        let (descriptor, _) = metadata_fixture("blocked handoff");
        let collection = descriptor.get_handle().raw;
        let (events, mut received) = tokio::sync::mpsc::channel(1);
        events.try_send(super::NetEventBatch::default()).unwrap();
        let (owned, mut observer) = tokio::sync::oneshot::channel::<()>();
        let mut owners = DescriptorFetches::default();
        owners.start(collection, async move {
            let _owned = owned;
            super::warm_descriptor(
                collection,
                |_| None,
                move |_| {
                    let descriptor = descriptor.clone();
                    async move { Some(descriptor) }.boxed()
                },
                events,
            )
            .await;
        });
        owners.poll(|raw| *raw == collection);
        assert_eq!(owners.pending.len(), 1);
        assert_eq!(
            observer.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
        owners.poll(|_| false);
        assert!(owners.pending.is_empty());
        assert_eq!(
            observer.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
        assert_eq!(received.try_recv().unwrap().len(), 0);
        assert!(
            received.try_recv().is_err(),
            "cancelled metadata must not land later"
        );
    }

    #[test]
    fn resident_oversized_descriptor_is_not_decoded_and_typed_fanout_is_bounded() {
        use triblespace_core::blob::IntoBlob;
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::collection::{KIND_COLLECTION_DESCRIPTOR, collection_name};
        use triblespace_core::prelude::entity;
        assert!(
            super::descriptor_metadata(anybytes::Bytes::from_source(vec![
                0_u8;
                super::METADATA_BLOB_BYTES
                    as usize
                    + 1
            ]))
            .is_empty()
        );
        let mut fragment = triblespace_core::trible::Fragment::empty();
        for ordinal in 0..512 {
            fragment += entity! {
                triblespace_core::metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                collection_name: format!("name-{ordinal}"),
            };
        }
        let blob: Blob<SimpleArchive> = fragment.facts().to_blob();
        assert_eq!(
            super::descriptor_metadata(blob.bytes).len(),
            super::METADATA_DEPENDENCIES
        );
    }

    #[test]
    fn rejected_policy_cross_product_is_not_interpreted_before_the_raw_row_bound() {
        use triblespace_core::blob::IntoBlob;
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::capability::policy::{
            KIND_ADMISSION_POLICY_QUORUM, admission_invoke_threshold, capability_handle,
            resource_policy,
        };
        use triblespace_core::collection::KIND_COLLECTION_DESCRIPTOR;
        use triblespace_core::prelude::{entity, rngid};
        let binding = rngid();
        let handles = (0_u32..5000).map(|ordinal| {
            let mut raw = [0; 32];
            raw[..4].copy_from_slice(&ordinal.to_be_bytes());
            super::Inline::<super::Handle<SimpleArchive>>::new(raw)
        });
        let mut fragment = entity! { &binding @
            triblespace_core::metadata::tag: KIND_ADMISSION_POLICY_QUORUM,
            admission_invoke_threshold: 0_u32,
            capability_handle*: handles,
        };
        for _ in 0..5000 {
            let descriptor = rngid();
            fragment += entity! { &descriptor @
                triblespace_core::metadata::tag: KIND_COLLECTION_DESCRIPTOR,
                resource_policy: &binding,
            };
        }
        let blob: Blob<SimpleArchive> = fragment.facts().to_blob();
        assert!(blob.bytes.len() as u64 <= super::METADATA_BLOB_BYTES);
        // Twenty-five million potential unsupported interpretations remain
        // ordinary facts. Only a bounded prefix of typed associated handles
        // is observed, without attempting to decide this quorum's authority.
        assert_eq!(
            super::descriptor_metadata(blob.bytes).len(),
            super::METADATA_DEPENDENCIES
        );
    }

    #[cfg(feature = "sim")]
    #[tokio::test]
    async fn warmup_byte_rejection_preserves_shared_provider_connection_and_concurrent_exact_read()
    {
        use crate::transport::Conn;
        use crate::transport::sim::{SimConfig, SimNet};
        // Its two ordinary receives hold process-wide receive credit that
        // other tests' budget assertions would otherwise observe.
        let _guard = crate::protocol::exact_blob_receive_test_guard();
        let requester_key = SigningKey::from_bytes(&[91; 32]);
        let provider_key = SigningKey::from_bytes(&[92; 32]);
        let requester = requester_key.verifying_key().to_bytes();
        let provider = provider_key.verifying_key().to_bytes();
        let net = SimNet::new(0xB10B_CAFE, SimConfig::default());
        let requester_harness = net.join(&requester_key);
        let mut provider_harness = net.join(&provider_key);
        let bytes =
            anybytes::Bytes::from_source(vec![19_u8; super::METADATA_BLOB_BYTES as usize + 1]);
        let hash = Blob::<UnknownBlob>::new(bytes.clone()).get_handle().raw;
        let serving = tokio::spawn(async move {
            let connection = provider_harness.incoming.recv().await.unwrap().conn;
            while let Some((mut send, mut recv)) = connection.accept_bi().await {
                let bytes = bytes.clone();
                tokio::spawn(async move {
                    // The dialler's own recon/1 stream carries no request.
                    match crate::protocol::recv_u8(&mut recv).await.unwrap() {
                        crate::protocol::TAG_RECON => return,
                        tag => assert_eq!(tag, crate::protocol::TAG_BLOB),
                    }
                    let _ = crate::protocol::serve_get_blob(
                        &mut recv,
                        &mut send,
                        requester,
                        provider,
                        |locator| (locator == super::blob_locator(hash)).then_some(hash),
                        |requested| (requested == hash).then_some(bytes),
                    )
                    .await;
                });
            }
        });
        let client = super::ProviderClient::for_test(
            requester_harness.transport,
            super::RoutingTable::new(requester, [provider]),
        );
        let before = client.connections.connect(provider).await.unwrap();
        let (limited, ordinary) = tokio::join!(
            client.fetch_from_provider_with_limit(hash, provider, super::METADATA_BLOB_BYTES),
            client.fetch_from_provider(hash, provider),
        );
        assert!(
            limited
                .unwrap_err()
                .is::<crate::protocol::ExactBlobReceivePolicyError>()
        );
        assert_eq!(
            ordinary.unwrap().unwrap().bytes.len() as u64,
            super::METADATA_BLOB_BYTES + 1
        );
        assert!(
            client.connections.current(provider) == Some(before.clone()),
            "local warmup policy must not evict a shared connection"
        );
        let exact = crate::protocol::op_get_blob(&before, requester, &hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exact.bytes.len() as u64, super::METADATA_BLOB_BYTES + 1);
        serving.abort();
    }

    #[test]
    fn arriving_definition_refreshes_admission_and_inventory_without_semantic_changes() {
        use std::sync::Arc;
        use triblespace_core::blob::encodings::simplearchive::SimpleArchive;
        use triblespace_core::capability::policy::resource_policy;
        use triblespace_core::capability::{
            CapabilityProof, CapabilityResource, capability_action,
        };
        use triblespace_core::collection::{
            ACTION_READ, AdmissionPolicy, KIND_COLLECTION_DESCRIPTOR, read_capability,
        };
        use triblespace_core::metadata;
        use triblespace_core::prelude::entity;
        use triblespace_core::repo::memoryrepo::MemoryRepo;
        use triblespace_core::repo::{
            BlobStorePut, CapabilityProofStore, SnapshotSource, StoreChanges, StoreSnapshot as _,
        };

        let root = SigningKey::from_bytes(&[99; 32]);
        let reader = SigningKey::from_bytes(&[100; 32]).verifying_key();
        let mut store = MemoryRepo::default();
        let descriptor = entity! {
            metadata::tag: KIND_COLLECTION_DESCRIPTOR,
            resource_policy*: AdmissionPolicy::direct(root.verifying_key()).binding(read_capability()),
        };
        let collection = store
            .put::<SimpleArchive, _>(descriptor.facts().clone())
            .unwrap();
        // The definition a proof names is a seed of the held set; it is held
        // once it arrives.
        triblespace_core::collection::HeldStore::track_held(&mut store, [collection]);
        let proof = CapabilityProof::new(
            CapabilityResource::from(collection),
            &root,
            read_capability(),
            reader,
        );
        store.insert_proof(proof).unwrap();
        let mut active = super::ActiveCollections::new();
        active.insert(&super::PatchEntry::new(&collection.raw));
        let before = store.snapshot().unwrap();
        let serving_before = super::StoreSnapshot::from_store_changes(
            before.clone(),
            &active,
            reader,
            None,
            None,
            StoreChanges::ALL,
        )
        .unwrap();
        let before_collection = serving_before.collection(collection).unwrap();

        store
            .put::<SimpleArchive, _>(entity! { capability_action: ACTION_READ }.facts().clone())
            .unwrap();
        let after = store.snapshot().unwrap();
        let changes = after.changes_since(&before);
        assert!(changes.contains(StoreChanges::BLOBS));
        let serving_after = super::StoreSnapshot::from_store_changes(
            after,
            &active,
            reader,
            Some(&before),
            Some(&serving_before),
            changes,
        )
        .unwrap();
        let after_collection = serving_after.collection(collection).unwrap();
        assert_eq!(
            after_collection.repair.records().summary(),
            before_collection.repair.records().summary()
        );
        assert_eq!(
            after_collection.repair.authorization_evidence().summary(),
            before_collection.repair.authorization_evidence().summary()
        );
        assert_ne!(after_collection.wake_root(), before_collection.wake_root());
        assert!(
            after_collection
                .repair
                .blob_inventory()
                .get(&read_capability().raw)
                .is_some()
        );
        assert!(!Arc::ptr_eq(
            &before_collection.repair,
            &after_collection.repair
        ));
    }

    #[test]
    fn typed_put_results_separate_topology_loss_from_explicit_rejection() {
        let local = [1; 32];
        let remote = [2; 32];
        assert_eq!(
            PublicationResult::from_put_results(
                local,
                [
                    (local, ProviderPutResult::Accepted),
                    (remote, ProviderPutResult::Unavailable),
                ],
            ),
            PublicationResult::NoAuthenticatedRemoteReplica,
            "local acceptance and a vanished FIND_NODE responder prove no remote publication"
        );
        assert_eq!(
            PublicationResult::from_put_results(
                local,
                [(remote, ProviderPutResult::ExplicitlyRejected)],
            ),
            PublicationResult::RemoteRejected
        );
        assert_eq!(
            PublicationResult::from_put_results(local, [(remote, ProviderPutResult::Accepted)],),
            PublicationResult::Published
        );
    }

    #[test]
    fn zero_provider_publication_budget_permits_no_attempts() {
        let budget = ProviderPublicationBudget::new(Some(0));
        assert!(!budget.permits_attempt());
        assert!(budget.is_exhausted());
    }

    #[test]
    fn finite_provider_publication_budget_survives_resident_snapshot_updates() {
        let now = crate::clock::mono_now();
        let first = triblespace_core::collection::CollectionHandle::new([0x61; 32]);
        let second = triblespace_core::collection::CollectionHandle::new([0x62; 32]);
        let third = triblespace_core::collection::CollectionHandle::new([0x63; 32]);
        let mut publisher = ProviderPublisher::new(now);
        let mut budget = ProviderPublicationBudget::new(Some(2));

        publisher.install(
            ProviderObservation::from_blob_handles([first.raw]).into_set(),
            now,
        );
        assert!(budget.permits_attempt());
        assert!(publisher.next(now).is_some());
        budget.consume_attempt();

        publisher.install(
            ProviderObservation::from_blob_handles([first.raw, second.raw]).into_set(),
            now,
        );
        assert!(budget.permits_attempt());
        assert!(publisher.next(now).is_some());
        budget.consume_attempt();
        assert!(budget.is_exhausted());

        publisher.install(
            ProviderObservation::from_blob_handles([first.raw, second.raw, third.raw]).into_set(),
            now,
        );
        assert!(
            !budget.permits_attempt(),
            "installing a later resident snapshot must not refill a process budget"
        );
    }

    #[test]
    fn absent_provider_publication_budget_remains_unlimited() {
        let mut budget = ProviderPublicationBudget::new(None);
        for _ in 0..10_000 {
            assert!(budget.permits_attempt());
            budget.consume_attempt();
        }
        assert!(!budget.is_exhausted());
    }

    #[cfg(feature = "sim")]
    #[tokio::test(start_paused = true)]
    async fn replica_lookup_deadline_starts_once_and_never_restarts() {
        use super::{BACKGROUND_LOOKUP_DEADLINE, ReplicaLookup};
        use crate::routing::RoutingTable;
        let local = SigningKey::from_bytes(&[101; 32])
            .verifying_key()
            .to_bytes();
        let first = SigningKey::from_bytes(&[102; 32])
            .verifying_key()
            .to_bytes();
        let second = SigningKey::from_bytes(&[103; 32])
            .verifying_key()
            .to_bytes();
        let mut routes = RoutingTable::new(local, [first, second]);
        let mut lookup = ReplicaLookup::new(local, local, vec![first, second], None);
        assert!(lookup.deadline.is_none());
        assert_eq!(lookup.machine.next_batch().len(), 2);
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        assert!(
            lookup
                .observe(first, Ok((vec![], vec![])), &mut routes)
                .is_some()
        );
        let deadline = lookup.deadline.unwrap();
        assert_eq!(
            deadline,
            tokio::time::Instant::now() + BACKGROUND_LOOKUP_DEADLINE
        );
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(
            lookup
                .observe(second, Ok((vec![], vec![])), &mut routes)
                .is_some()
        );
        assert_eq!(lookup.deadline, Some(deadline));

        let mut background =
            ReplicaLookup::new(local, local, vec![first], Some(BACKGROUND_LOOKUP_DEADLINE));
        let deadline = background.deadline.unwrap();
        assert_eq!(background.machine.next_batch(), vec![first]);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(
            background
                .observe(first, Ok((vec![], vec![])), &mut routes)
                .is_some()
        );
        assert_eq!(background.deadline, Some(deadline));
    }

    #[test]
    fn progressive_provider_attempts_are_verified_deduplicated_bounded_and_arrival_sensitive() {
        let peer = |ordinal: u16| {
            let mut id = [0; 32];
            id[30..].copy_from_slice(&ordinal.to_be_bytes());
            id
        };
        let hash = [7; 32];
        let local = peer(0);
        let hint = |provider| (provider, blob_provider_token(hash, provider));
        let mut candidates = ProgressiveBlobProviders::new(hash, local, [0; 32]);
        // A forged token names no candidate; our own valid hint verifies the
        // lookup but names none either.
        candidates.observe([(peer(1), [0; 32])]);
        assert!(!candidates.verified);
        candidates.observe([hint(local)]);
        assert!(candidates.verified);
        assert_eq!(candidates.next(), None);

        candidates.observe((100..164).map(peer).map(hint));
        let early = candidates.next().unwrap();
        candidates.observe([early, peer(1), peer(1)].map(hint));
        let second = candidates.next().unwrap();
        assert_ne!(second, early);
        // The first requests remain part of this fetch whatever later hints
        // the final union would rank ahead of them.
        let mut attempts = BTreeSet::from([early, second]);
        while let Some(next) = candidates.next() {
            assert!(attempts.insert(next));
            candidates.observe((1..=64).map(peer).map(hint));
            assert!(candidates.attempted.len() + candidates.pending.len() <= 64);
        }
        assert_eq!(attempts.len(), MAX_PROVIDERS_PER_REPLY);
        assert_eq!(candidates.attempted, attempts);
        candidates.observe((200..264).map(peer).map(hint));
        assert!(
            candidates.next().is_none(),
            "later replies cannot refill the attempt cap"
        );
    }

    #[test]
    fn aggregated_provider_replies_are_canonical_deduplicated_and_globally_bounded() {
        fn provider(index: u16) -> PeerId {
            let mut peer = [0; 32];
            peer[30..].copy_from_slice(&index.to_be_bytes());
            peer
        }

        let key_index = 0x0234_u16;
        let mut key = [0; 32];
        key[30..].copy_from_slice(&key_index.to_be_bytes());
        let replies = (0..K)
            .map(|replica| {
                // Every replica repeats the same 16 providers and contributes
                // 48 providers disjoint from every other replica.
                (1..=16)
                    .chain(100 + replica as u16 * 48..148 + replica as u16 * 48)
                    .map(provider)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(replies.len(), K);
        assert!(
            replies
                .iter()
                .all(|reply| reply.len() == MAX_PROVIDERS_PER_REPLY)
        );

        let salt = [0x5A; 32];
        let forward = canonical_provider_subset(
            &salt,
            key,
            replies.iter().flatten().copied(),
            MAX_PROVIDERS_PER_REPLY,
        );
        let reversed = canonical_provider_subset(
            &salt,
            key,
            replies
                .iter()
                .rev()
                .flat_map(|reply| reply.iter().rev().copied()),
            MAX_PROVIDERS_PER_REPLY,
        );
        let mut expected = (1..=16)
            .chain(100..100 + K as u16 * 48)
            .map(provider)
            .collect::<Vec<_>>();
        expected.sort_unstable_by_key(|peer| provider_rank(&salt, key, *peer));
        expected.truncate(MAX_PROVIDERS_PER_REPLY);

        assert_eq!(forward.len(), MAX_PROVIDERS_PER_REPLY);
        assert_eq!(forward, expected);
        assert_eq!(reversed, forward);
        assert_eq!(
            forward.iter().copied().collect::<BTreeSet<_>>().len(),
            forward.len()
        );
    }

    #[test]
    fn providers_near_a_key_gain_no_rank_and_requesters_rank_independently() {
        fn provider(index: u16) -> PeerId {
            let mut peer = [0; 32];
            peer[30..].copy_from_slice(&index.to_be_bytes());
            peer
        }
        // Under a public XOR rank the 64 identities nearest this key would be
        // every requester's choice among 1000, so a provider would grind an
        // identity near the keys it wants to be asked for.
        let key = [0; 32];
        let nearest = (1..=64).map(provider).collect::<BTreeSet<_>>();
        let choices = [[1; 32], [2; 32]].map(|salt| {
            canonical_provider_subset(
                &salt,
                key,
                (1..=1000).map(provider),
                MAX_PROVIDERS_PER_REPLY,
            )
        });
        for choice in &choices {
            assert_eq!(choice.len(), MAX_PROVIDERS_PER_REPLY);
            // About 64 * 64 / 1000, or four, of them by chance.
            assert!(choice.iter().filter(|peer| nearest.contains(*peer)).count() < 16);
        }
        assert_ne!(choices[0], choices[1]);
    }

    #[test]
    fn collection_participant_hints_are_bounded_under_signed_wake_flood() {
        let collection = [0x41; 32];
        let now = crate::clock::mono_now();
        let mut participants = HashMap::new();
        for index in 0..(MAX_COLLECTION_PARTICIPANTS * 2) {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(index as u64).to_be_bytes());
            observe_participant(&mut participants, collection, peer, now);
        }
        let live = live_participants(&mut participants, collection, now);
        assert_eq!(live.len(), MAX_COLLECTION_PARTICIPANTS);
        assert!(live.contains(&{
            let mut newest = [0u8; 32];
            newest[..8]
                .copy_from_slice(&((MAX_COLLECTION_PARTICIPANTS * 2 - 1) as u64).to_be_bytes());
            newest
        }));
    }

    #[test]
    fn discovery_slots_rotate_even_when_every_earlier_lookup_is_due_again() {
        let mut collections = super::CollectionSnapshotIndex::new();
        for byte in 1..=9 {
            collections.insert(&super::PatchEntry::with_value(
                &[byte; 32],
                std::sync::Arc::new(super::CollectionObservation {
                    value: None,
                    dependencies: Default::default(),
                }),
            ));
        }
        let mut cursor = None;
        let mut issued = Vec::new();
        // Model three slow waves: by each completion all older lookups can
        // already be due again, but none may overtake an unvisited interest.
        for _ in 0..3 {
            let wave = super::discovery_order(&collections, cursor)
                .take(super::ALPHA)
                .copied()
                .collect::<Vec<_>>();
            cursor = wave.last().copied();
            issued.extend(wave);
        }
        assert_eq!(issued, (1..=9).map(|byte| [byte; 32]).collect::<Vec<_>>());
        assert_eq!(
            super::discovery_order(&collections, cursor).next(),
            Some(&[1; 32])
        );
        assert_eq!(
            super::discovery_order(&collections, Some([5; 32]))
                .copied()
                .collect::<Vec<_>>(),
            [6, 7, 8, 9, 1, 2, 3, 4, 5].map(|byte| [byte; 32])
        );
    }

    #[test]
    fn healthy_subset_does_not_suppress_descriptor_rediscovery_forever() {
        let started = crate::clock::mono_now();
        let mut discovery = DiscoveryState::new(started);
        let mut lookups = 0;

        assert!(discovery.start_if_due(started, false));
        lookups += 1;
        discovery.finish_attempt(started);
        discovery.observe_success(started);

        for period in 1..=100 {
            let now = started + super::REPAIR_PERIOD.saturating_mul(period);
            if discovery.start_if_due(now, true) {
                lookups += 1;
                discovery.finish_attempt(now);
            }
        }
        assert_eq!(
            lookups, 11,
            "healthy subsets still retry bootstrap every five minutes"
        );
    }

    #[test]
    fn expired_or_all_failed_candidates_reenter_bounded_discovery() {
        let started = crate::clock::mono_now();
        let mut discovery = DiscoveryState::new(started);
        assert!(discovery.start_if_due(started, false));
        discovery.finish_attempt(started);
        assert!(!discovery.start_if_due(started, false));

        let first_retry = started + crate::RETRY_BACKOFF_BASE;
        assert!(discovery.start_if_due(first_retry, false));
        discovery.finish_attempt(first_retry);
        assert_eq!(
            discovery.retry_at.duration_since(first_retry),
            crate::RETRY_BACKOFF_BASE.saturating_mul(2)
        );

        for _ in 0..10 {
            let retry = discovery.retry_at;
            assert!(discovery.start_if_due(retry, false));
            discovery.finish_attempt(retry);
            assert!(
                discovery.retry_at.duration_since(retry) <= crate::RETRY_BACKOFF_CAP,
                "recovery attempts must remain live without becoming a tight loop"
            );
        }

        let collection = CollectionHandle::new([0x31; 32]);
        let first = [0x32; 32];
        let second = [0x33; 32];
        let mut participants = HashMap::new();
        observe_participant(&mut participants, collection.raw, first, started);
        assert!(
            live_participants(
                &mut participants,
                collection.raw,
                started + COLLECTION_PARTICIPANT_LEASE + std::time::Duration::from_nanos(1)
            )
            .is_empty(),
            "an exhausted lease leaves no repair candidate"
        );
        let mut exhausted = DiscoveryState::new(started);
        exhausted.observe_success(started);
        assert!(exhausted.start_if_due(
            started + COLLECTION_PARTICIPANT_LEASE + std::time::Duration::from_nanos(1),
            false
        ));

        let peers = vec![first, second];
        let mut failures = HashMap::from([(
            RepairTarget {
                collection,
                peer: first,
            },
            (1, started),
        )]);
        assert!(has_repair_candidate(
            collection, &peers, &failures, [0x34; 32]
        ));
        failures.insert(
            RepairTarget {
                collection,
                peer: second,
            },
            (1, started),
        );
        assert!(!has_repair_candidate(
            collection, &peers, &failures, [0x34; 32]
        ));
        let mut failed = DiscoveryState::new(started);
        failed.observe_success(started);
        assert!(failed.start_if_due(started, false));
    }

    #[test]
    fn local_provider_is_never_a_collection_repair_candidate() {
        let collection = CollectionHandle::new([0x35; 32]);
        let local = [0x36; 32];
        assert!(!has_repair_candidate(
            collection,
            &[local],
            &HashMap::new(),
            local
        ));
    }

    #[test]
    fn an_untracked_failure_cannot_retain_a_healthy_participant_lease() {
        let collection = CollectionHandle::new([0x3b; 32]);
        let peer = [0x3c; 32];
        let now = crate::clock::mono_now();
        let mut participants = HashMap::new();
        observe_participant(&mut participants, collection.raw, peer, now);

        let failures = (0..MAX_PENDING_REPAIRS)
            .map(|index| {
                let mut failed_peer = [0u8; 32];
                failed_peer[..8].copy_from_slice(&(index as u64).to_be_bytes());
                (
                    RepairTarget {
                        collection: CollectionHandle::new([0x3d; 32]),
                        peer: failed_peer,
                    },
                    (1, now),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(failures.len(), MAX_PENDING_REPAIRS);

        forget_participant(&mut participants, collection.raw, peer);

        let live = live_participants(&mut participants, collection.raw, now);
        assert!(live.is_empty());
        assert!(!has_repair_candidate(
            collection, &live, &failures, [0x3e; 32]
        ));
    }

    #[test]
    fn repair_success_does_not_forge_discovery_task_completion() {
        let started = crate::clock::mono_now();
        let mut discovery = DiscoveryState::new(started);
        assert!(discovery.start_if_due(started, false));

        discovery.observe_success(started + std::time::Duration::from_secs(1));

        assert!(discovery.in_flight);
        assert!(!discovery.start_if_due(started + std::time::Duration::from_secs(2), false));
        discovery.finish_attempt(started + std::time::Duration::from_secs(3));
        assert!(!discovery.in_flight);
    }

    #[test]
    fn removed_collections_release_their_repair_state() {
        let retained = RepairTarget {
            collection: CollectionHandle::new([0x37; 32]),
            peer: [0x38; 32],
        };
        let removed = RepairTarget {
            collection: CollectionHandle::new([0x39; 32]),
            peer: [0x3a; 32],
        };
        let mut state = HashMap::from([(retained, 1u8), (removed, 2u8)]);
        let active = std::collections::HashSet::from([retained.collection.raw]);

        retain_active_repair_state(&mut state, |raw| active.contains(raw));

        assert_eq!(state, HashMap::from([(retained, 1u8)]));
    }

    #[test]
    fn successful_repair_refreshes_the_participant_lease() {
        let collection = [0x42; 32];
        let peer = [0x43; 32];
        let started = crate::clock::mono_now();
        let refreshed = started + std::time::Duration::from_secs(4 * 60);
        let after_original_expiry =
            started + COLLECTION_PARTICIPANT_LEASE + std::time::Duration::from_secs(1);
        let mut participants = HashMap::new();
        let mut discovery = DiscoveryState::new(started);

        observe_participant(&mut participants, collection, peer, started);
        observe_participant(&mut participants, collection, peer, refreshed);
        discovery.observe_success(refreshed);

        assert_eq!(
            live_participants(&mut participants, collection, after_original_expiry),
            vec![peer],
            "a healthy identical repair keeps the origin live past its first observation"
        );
        assert!(!discovery.start_if_due(after_original_expiry, true));
        assert!(
            live_participants(
                &mut participants,
                collection,
                refreshed + COLLECTION_PARTICIPANT_LEASE + std::time::Duration::from_nanos(1)
            )
            .is_empty()
        );
    }

    #[test]
    fn learned_wake_peers_survive_resubscription_with_a_bounded_recent_set() {
        let configured = endpoint(0x51);
        let mut bootstrap = WakeBootstrapPeers::new(vec![configured]);
        assert!(
            bootstrap.has_recovery_route(),
            "a configured topology seed can reopen the collection topic without becoming a repair participant"
        );
        let learned = (0..=MAX_COLLECTION_PARTICIPANTS)
            .map(|index| endpoint((index as u8).wrapping_add(0x60)))
            .collect::<Vec<_>>();
        bootstrap.remember(learned.iter().copied());
        assert!(bootstrap.has_recovery_route());

        let resubscribe = bootstrap.current();
        assert_eq!(resubscribe.first(), Some(&configured));
        assert_eq!(resubscribe.len(), 1 + MAX_COLLECTION_PARTICIPANTS);
        assert!(!resubscribe.contains(&learned[0]));
        assert!(resubscribe.contains(learned.last().unwrap()));

        bootstrap.remember([learned[1]]);
        assert_eq!(bootstrap.current().last(), Some(&learned[1]));
    }

    #[test]
    fn gossip_recovery_waits_until_every_participant_failed() {
        let collection = [0x71; 32];
        let first = [0x72; 32];
        let second = [0x73; 32];
        let now = crate::clock::mono_now();
        let mut participants = HashMap::new();
        observe_participant(&mut participants, collection, first, now);
        observe_participant(&mut participants, collection, second, now);

        assert!(!forget_participant(&mut participants, collection, first));
        assert_eq!(
            live_participants(&mut participants, collection, now),
            vec![second]
        );
        assert!(forget_participant(&mut participants, collection, second));
        assert!(live_participants(&mut participants, collection, now).is_empty());
    }

    #[test]
    fn pending_repairs_are_coalesced_and_bounded_under_wake_flood() {
        let mut queue = std::collections::VecDeque::new();
        let mut pending = std::collections::HashSet::new();
        for index in 0..(MAX_PENDING_REPAIRS * 2) {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let target = RepairTarget {
                collection: triblespace_core::collection::CollectionHandle::new([0x51; 32]),
                peer,
            };
            enqueue_repair(&mut queue, &mut pending, target);
            enqueue_repair(&mut queue, &mut pending, target);
        }
        assert_eq!(queue.len(), MAX_PENDING_REPAIRS);
        assert_eq!(pending.len(), MAX_PENDING_REPAIRS);
    }
}

/// Production relay defaults with trailing-dot hostnames normalized for HTTP
/// intermediaries that reject absolute-FQDN Host headers.
pub(crate) fn dot_stripped_default_relay_map() -> iroh::RelayMap {
    let original = iroh::defaults::prod::default_relay_map();
    let urls: Vec<String> = original
        .urls::<Vec<_>>()
        .into_iter()
        .map(|relay| {
            let mut url: url::Url = relay.into();
            if let Some(host) = url.host_str().and_then(|host| host.strip_suffix('.')) {
                let host = host.to_owned();
                let _ = url.set_host(Some(&host));
            }
            url.to_string()
        })
        .collect();
    iroh::RelayMap::try_from_iter(urls.iter().map(String::as_str))
        .expect("default relay URLs remain valid after hostname normalization")
}

#[cfg(test)]
mod wake_relay_tests;

#[cfg(test)]
mod blob_inventory_tests;
