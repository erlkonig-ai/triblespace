//! Local runtime evidence, not a replicated inventory or a claim about a swarm.
//!
//! Reading health neither starts networking nor refreshes any timestamp. All
//! instants belong to this process's monotonic clock; a reporter must preserve
//! their age and its process identity instead of serializing them as wall time.
//! Missing observations, offline peers, and missing cached blobs are not
//! corruption. A pair's sync concerns READ-authorized repair evidence
//! (`Record × AuthorizationEvidence`), including inert records, not admitted
//! application values or payload availability: what the peer confirmed of
//! this side's trees, and what landed of the peer's.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh_base::EndpointId;
use triblespace_core::collection::CollectionHandle;

use crate::clock::Mono;
use crate::collection_wire::CollectionRepairManifest;
use crate::patch_repair::PatchSummary;
use crate::transport::PeerId;
use crate::walk::WalkKind;

/// Hard per-active-collection bound on retained pairwise runtime evidence.
pub const MAX_HEALTH_PEERS_PER_COLLECTION: usize = 128;

/// Semantic evidence from an immutable manifest received after READ(C)
/// admission, plus its composite root for diagnostics. Held blobs are in
/// neither: cache equality is deliberately not required for record/AUTH
/// health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairFrontier {
    pub wake_root: [u8; 32],
    pub records: PatchSummary,
    pub authorization_evidence: PatchSummary,
}

impl RepairFrontier {
    /// Equality of the collection's repair evidence, independent of caching.
    /// Demand and shallow peers may intentionally retain different bodies.
    pub fn same_evidence(&self, other: &Self) -> bool {
        self.records == other.records && self.authorization_evidence == other.authorization_evidence
    }
}

impl From<CollectionRepairManifest> for RepairFrontier {
    fn from(manifest: CollectionRepairManifest) -> Self {
        Self {
            wake_root: manifest.wake_root,
            records: manifest.records,
            authorization_evidence: manifest.authorization_evidence,
        }
    }
}

/// One direction of a pair's sync, as its ends were observed here: the
/// pushes of this side's trees to the peer, or the pushes of the peer's trees
/// received here.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ends {
    /// When the last one ended, and whether it ended well: a push the peer
    /// confirmed, or a receive that landed whole.
    pub last_at: Option<Mono>,
    pub last_ok: bool,
    /// When the last one that ended well did.
    pub last_ok_at: Option<Mono>,
    pub ok: u64,
    pub failed: u64,
}

impl Ends {
    fn ended(&mut self, at: Mono, ok: bool) {
        self.last_at = Some(at);
        self.last_ok = ok;
        if ok {
            self.last_ok_at = Some(at);
            self.ok += 1;
        } else {
            self.failed += 1;
        }
    }
}

/// The roots of a collection's records and authorization trees as pushes
/// carry them, each from the last push of that tree that ended well. The
/// references tree is in neither: held blobs are no part of record/AUTH
/// health.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Roots {
    pub records: Option<PatchSummary>,
    pub authorization_evidence: Option<PatchSummary>,
}

impl Roots {
    fn set(&mut self, kind: WalkKind, root: PatchSummary) {
        match kind {
            WalkKind::Records => self.records = Some(root),
            WalkKind::Authorization => self.authorization_evidence = Some(root),
            WalkKind::References => {}
        }
    }

    /// Whether both roots are those of `frontier`.
    pub fn hold(&self, frontier: &RepairFrontier) -> bool {
        self.records == Some(frontier.records)
            && self.authorization_evidence == Some(frontier.authorization_evidence)
    }
}

/// One collection's sync with one peer, as this side observed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerHealth {
    pub peer: PeerId,
    /// The first push or receive that ended while this observation is
    /// retained. The progress grace counts from it; later ends cannot extend
    /// it.
    pub first_at: Option<Mono>,
    /// Pushes of this side's trees to the peer: one ends well when the peer
    /// confirms it landed.
    pub pushes: Ends,
    /// What the peer confirmed: a root is held once a push of its tree was
    /// confirmed, and the peer holds that tree.
    pub confirmed: Roots,
    /// Pushes of the peer's trees received here: one ends well when
    /// everything it pushed landed.
    pub receives: Ends,
    /// What the peer pushed that landed whole here.
    pub received: Roots,
}

impl PeerHealth {
    fn new(peer: PeerId) -> Self {
        Self {
            peer,
            first_at: None,
            pushes: Ends::default(),
            confirmed: Roots::default(),
            receives: Ends::default(),
            received: Roots::default(),
        }
    }

    fn last_event_at(&self) -> Option<Mono> {
        self.pushes.last_at.max(self.receives.last_at)
    }

    /// A push of the `kind` tree, whose root is `root`, ended.
    pub(crate) fn pushed(&mut self, at: Mono, kind: WalkKind, root: PatchSummary, confirmed: bool) {
        self.first_at.get_or_insert(at);
        self.pushes.ended(at, confirmed);
        if confirmed {
            self.confirmed.set(kind, root);
        }
    }

    /// A push of the peer's `kind` tree ended here; `root` is its root, if
    /// the push got that far.
    pub(crate) fn received(
        &mut self,
        at: Mono,
        kind: WalkKind,
        root: Option<PatchSummary>,
        landed: bool,
    ) {
        self.first_at.get_or_insert(at);
        self.receives.ended(at, landed);
        if let Some(root) = root.filter(|_| landed) {
            self.received.set(kind, root);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionHealth {
    pub collection: CollectionHandle,
    /// None means active locally but absent from the current serving view.
    pub local_frontier: Option<RepairFrontier>,
    pub last_local_change_at: Option<Mono>,
    /// Recent observations only, not a roster or a list of all holders.
    pub peers: Vec<PeerHealth>,
}

/// One collection's peering with one key, on one connection, as this side
/// sees it. A key on two connections at once, while a tie-break settles,
/// can appear twice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeeringHealth {
    pub collection: CollectionHandle,
    pub peer: PeerId,
    /// This side asked for the peering: the peer is one of its asked-for
    /// neighbours for the collection, or about to be.
    pub asked: bool,
    /// Both sides accepted.
    pub peered: bool,
    /// The collection flows from this side to the peer.
    pub sends: bool,
    /// The collection flows from the peer to this side.
    pub receives: bool,
    /// This side refused the peer's request, and invites it once admitted.
    pub refused_by_me: bool,
    /// The peer refused this side's request.
    pub refused_by_them: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFailure {
    Snapshot,
    Refresh,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreHealth {
    pub last_refresh_started_at: Option<Mono>,
    pub last_refresh_completed_at: Option<Mono>,
    /// Advances after a successful coherent store observation, even if its
    /// immutable frontier did not change. It is not a rebuild counter.
    pub last_snapshot_observed_at: Option<Mono>,
    pub last_snapshot_published_at: Option<Mono>,
    pub last_failure_at: Option<Mono>,
    pub last_failure: Option<StoreFailure>,
    pub serving_snapshot: bool,
    /// Exact number of blobs in the most recently published immutable store
    /// observation. This is local residency, not network availability.
    pub resident_blobs: u64,
    pub withdrawn_at: Option<Mono>,
}

/// Publication work, separate from exact-blob fetch availability. Acknowledged
/// attempts are not unique lease coverage; zero attempts may be intentional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicationHealth {
    pub resident: u64,
    pub startup_pending: u64,
    pub incremental_pending: u64,
    pub renewal_remaining: u64,
    pub in_flight: usize,
    pub topology_paused: bool,
    pub budget_exhausted: bool,
    pub attempts: u64,
    pub acknowledged: u64,
    pub rejected: u64,
    pub unavailable: u64,
    pub last_started_at: Option<Mono>,
    pub last_completed_at: Option<Mono>,
    pub last_acknowledged_at: Option<Mono>,
    pub last_rejected_at: Option<Mono>,
    pub last_unavailable_at: Option<Mono>,
    /// First unsuccessful completed publication since the last acknowledged
    /// attempt. Idle time without publication attempts never starts this clock.
    pub unacknowledged_since: Option<Mono>,
}

/// Process-lifetime observations of inbound exact-blob GETs. These are
/// operations, not unique blob coverage. Bytes count only a payload whose
/// existing write and stream shutdown both succeeded; this is not a remote
/// landing or durability acknowledgement.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobServeHealth {
    pub in_flight: u64,
    pub completed: u64,
    pub unavailable: u64,
    /// Protocol/I/O errors and interrupted exchanges, including deadlines.
    pub failed: u64,
    pub sent_bytes: u64,
    /// Sum of finished/interrupted GET wall durations, not process CPU time.
    pub work_ns: u128,
}

impl PublicationHealth {
    pub(crate) fn completed(&mut self, at: Mono, result: crate::provider::PublicationResult) {
        use crate::provider::PublicationResult;
        self.last_completed_at = Some(at);
        match result {
            PublicationResult::Published => {
                self.last_acknowledged_at = Some(at);
                self.unacknowledged_since = None;
            }
            PublicationResult::RemoteRejected => {
                self.last_rejected_at = Some(at);
                self.unacknowledged_since.get_or_insert(at);
            }
            PublicationResult::NoAuthenticatedRemoteReplica => {
                self.last_unavailable_at = Some(at);
                self.unacknowledged_since.get_or_insert(at);
            }
        }
    }
}

/// What this side knows of one pair's sync.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairState {
    Unknown,
    /// Every direction the peering has is settled.
    Current,
    /// A direction is not: `pushes` says the peer has not confirmed the
    /// records and evidence this side serves now, `receives` that the last
    /// push from the peer did not land whole, or none has arrived.
    Behind {
        pushes: bool,
        receives: bool,
    },
}

/// An immutable copy of bounded evidence recorded at actual runtime events.
/// Sampling this value cannot keep a dead host fresh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub node: EndpointId,
    pub started_at: Option<Mono>,
    /// Written only by the host loop, never by a status reader or store refresh.
    pub observed_at: Option<Mono>,
    pub store: StoreHealth,
    /// Exactly the locally active interest set, including unavailable views.
    pub collections: Vec<CollectionHealth>,
    pub publication: PublicationHealth,
    pub blob_serving: BlobServeHealth,
    /// Every collection peering on an open connection, by collection and
    /// peer. Written only by the peering task.
    pub peerings: Vec<PeeringHealth>,
    /// Collections named by proofs naming this node that wait in memory for
    /// their descriptor. Written only by the peering task.
    pub available: Vec<CollectionHandle>,
}

fn fresh(at: Option<Mono>, now: Mono, max_age: Duration) -> bool {
    at.is_some_and(|at| at <= now && now.duration_since(at) <= max_age)
}

impl HealthSnapshot {
    pub fn is_fresh(&self, now: Mono, max_age: Duration) -> bool {
        fresh(self.observed_at, now, max_age)
    }

    /// Pairwise, time-bounded evidence only: `Current` once the peer
    /// confirmed the records and evidence this side serves now, where this
    /// side sends, and the last push from the peer landed whole, where it
    /// receives. A local record/AUTH advance, an unavailable or stale store
    /// observation, an ended peering or no push or receive within `max_age`
    /// leaves the pair `Unknown`. Catching-up/stalled policy belongs to the
    /// observer: use the ends and their times, not successful RPC counts.
    pub fn pair(
        &self,
        collection: CollectionHandle,
        peer: PeerId,
        now: Mono,
        max_age: Duration,
    ) -> PairState {
        if !self.is_fresh(now, max_age)
            || !self.store.serving_snapshot
            || !fresh(self.store.last_snapshot_observed_at, now, max_age)
            || self.store.last_failure_at > self.store.last_snapshot_observed_at
        {
            return PairState::Unknown;
        }
        let Some(entry) = self
            .collections
            .iter()
            .find(|entry| entry.collection == collection)
        else {
            return PairState::Unknown;
        };
        let Some(pair) = entry.peers.iter().find(|pair| pair.peer == peer) else {
            return PairState::Unknown;
        };
        let Some(peering) = self.peerings.iter().find(|peering| {
            peering.collection == collection && peering.peer == peer && peering.peered
        }) else {
            return PairState::Unknown;
        };
        if !fresh(pair.last_event_at(), now, max_age) {
            return PairState::Unknown;
        }
        let pushes = peering.sends
            && !(pair.pushes.last_ok
                && entry
                    .local_frontier
                    .is_some_and(|local| pair.confirmed.hold(&local)));
        let receives = peering.receives && !pair.receives.last_ok;
        if pushes || receives {
            PairState::Behind { pushes, receives }
        } else {
            PairState::Current
        }
    }
}

#[derive(Clone)]
pub(crate) struct Health(Arc<Mutex<HealthSnapshot>>);

impl Health {
    pub(crate) fn new(node: EndpointId) -> Self {
        Self(Arc::new(Mutex::new(HealthSnapshot {
            node,
            started_at: None,
            observed_at: None,
            store: StoreHealth::default(),
            collections: Vec::new(),
            publication: PublicationHealth::default(),
            blob_serving: BlobServeHealth::default(),
            peerings: Vec::new(),
            available: Vec::new(),
        })))
    }

    pub(crate) fn snapshot(&self) -> Arc<HealthSnapshot> {
        Arc::new(self.0.lock().unwrap().clone())
    }

    pub(crate) fn update(&self, update: impl FnOnce(&mut HealthSnapshot)) {
        update(&mut self.0.lock().unwrap());
    }

    pub(crate) fn begin_blob_serve(&self) -> BlobServeGuard {
        self.update(|health| health.blob_serving.in_flight += 1);
        BlobServeGuard {
            health: self.clone(),
            started: crate::clock::mono_now(),
            finished: false,
        }
    }

    pub(crate) fn with_peer(
        &self,
        collection: CollectionHandle,
        peer: PeerId,
        update: impl FnOnce(&mut PeerHealth),
    ) {
        self.update(|health| {
            let Some(collection) = health
                .collections
                .iter_mut()
                .find(|entry| entry.collection == collection)
            else {
                // A cancelled/retired collection must not recreate observations.
                return;
            };
            let index = match collection.peers.iter().position(|entry| entry.peer == peer) {
                Some(index) => index,
                None => {
                    if collection.peers.len() == MAX_HEALTH_PEERS_PER_COLLECTION {
                        let Some((oldest, _)) = collection
                            .peers
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, entry)| (entry.last_event_at(), entry.peer))
                        else {
                            return;
                        };
                        collection.peers.swap_remove(oldest);
                    }
                    collection.peers.push(PeerHealth::new(peer));
                    collection.peers.len() - 1
                }
            };
            update(&mut collection.peers[index]);
        });
    }
}

/// Owns one accepted GET exchange until success, error or cancellation.
/// It deliberately retains no handle, locator, peer key or backend error.
pub(crate) struct BlobServeGuard {
    health: Health,
    started: Mono,
    finished: bool,
}

impl BlobServeGuard {
    pub(crate) fn complete(mut self, payload_bytes: Option<u64>) {
        self.health.update(|health| match payload_bytes {
            Some(bytes) => {
                health.blob_serving.completed += 1;
                health.blob_serving.sent_bytes =
                    health.blob_serving.sent_bytes.saturating_add(bytes);
            }
            None => health.blob_serving.unavailable += 1,
        });
        self.finished = true;
    }
}

impl Drop for BlobServeGuard {
    fn drop(&mut self) {
        let elapsed = crate::clock::mono_now()
            .duration_since(self.started)
            .as_nanos();
        self.health.update(|health| {
            health.blob_serving.in_flight -= 1;
            health.blob_serving.work_ns = health.blob_serving.work_ns.saturating_add(elapsed);
            if !self.finished {
                health.blob_serving.failed += 1;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serving_counts_success_unavailability_and_cancellation_separately() {
        let (health, _, _, _) = fixture();
        let successful = health.begin_blob_serve();
        let cancelled = health.begin_blob_serve();
        assert_eq!(health.snapshot().blob_serving.in_flight, 2);
        successful.complete(Some(223));
        let unavailable = health.begin_blob_serve();
        unavailable.complete(None);
        health.begin_blob_serve().complete(Some(0));
        let pinned = health.snapshot();
        assert_eq!(pinned.blob_serving.in_flight, 1);
        assert_eq!(pinned.blob_serving.completed, 2);
        assert_eq!(pinned.blob_serving.sent_bytes, 223);
        assert_eq!(pinned.blob_serving.unavailable, 1);
        assert_eq!(pinned.blob_serving.failed, 0);
        drop(cancelled);
        assert_eq!(health.snapshot().blob_serving.in_flight, 0);
        assert_eq!(health.snapshot().blob_serving.failed, 1);
        assert_eq!(
            pinned.blob_serving.in_flight, 1,
            "snapshots remain immutable"
        );
    }

    fn frontier(byte: u8, count: u64) -> RepairFrontier {
        RepairFrontier {
            wake_root: [byte; 32],
            records: PatchSummary::new(Some([byte; 32]), count).unwrap(),
            authorization_evidence: PatchSummary::new(None, 0).unwrap(),
        }
    }

    fn fixture() -> (Health, CollectionHandle, PeerId, Mono) {
        let node = EndpointId::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        let health = Health::new(node);
        let collection = CollectionHandle::new([3; 32]);
        let peer = [4; 32];
        let now = crate::clock::mono_now();
        health.update(|health| {
            health.started_at = Some(now);
            health.observed_at = Some(now);
            health.store.serving_snapshot = true;
            health.store.last_snapshot_observed_at = Some(now);
            health.collections.push(CollectionHealth {
                collection,
                local_frontier: Some(frontier(5, 1)),
                last_local_change_at: Some(now),
                peers: Vec::new(),
            });
            health.peerings.push(PeeringHealth {
                collection,
                peer,
                asked: true,
                peered: true,
                sends: true,
                receives: true,
                refused_by_me: false,
                refused_by_them: false,
            });
        });
        (health, collection, peer, now)
    }

    /// Both trees of `frontier` pushed and confirmed, and a receive landed.
    fn settle(health: &Health, collection: CollectionHandle, peer: PeerId, now: Mono) {
        health.with_peer(collection, peer, |pair| {
            let frontier = frontier(5, 1);
            pair.pushed(now, WalkKind::Records, frontier.records, true);
            pair.pushed(
                now,
                WalkKind::Authorization,
                frontier.authorization_evidence,
                true,
            );
            pair.received(now, WalkKind::Records, Some(frontier.records), true);
        });
    }

    const AGE: Duration = Duration::from_secs(180);

    #[test]
    fn unknown_until_an_end_then_a_fresh_settled_pair_expires() {
        let (health, collection, peer, now) = fixture();
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Unknown
        );
        settle(&health, collection, peer, now);
        let pinned = health.snapshot();
        assert_eq!(pinned.pair(collection, peer, now, AGE), PairState::Current);
        let later = now + AGE + Duration::from_secs(1);
        // A live store/status reader cannot replace the host's last loop tick.
        health.update(|health| health.store.last_snapshot_observed_at = Some(later));
        for _ in 0..3 {
            let sampled = health.snapshot();
            assert_eq!(sampled.observed_at, Some(now));
            assert!(!sampled.is_fresh(later, AGE));
            assert_eq!(
                sampled.pair(collection, peer, later, AGE),
                PairState::Unknown
            );
        }
        // Refreshing the host alone does not refresh the old ends.
        health.update(|health| health.observed_at = Some(later));
        assert_eq!(
            health.snapshot().pair(collection, peer, later, AGE),
            PairState::Unknown
        );
        assert_eq!(pinned.store.last_snapshot_observed_at, Some(now));
    }

    /// A local advance leaves the confirmed roots behind the frontier; a
    /// push the peer did not confirm, or a receive that did not land, each
    /// name their direction.
    #[test]
    fn a_direction_is_behind_until_its_last_end_settles_the_frontier() {
        let (health, collection, peer, now) = fixture();
        settle(&health, collection, peer, now);
        health.update(|health| health.collections[0].local_frontier = Some(frontier(6, 2)));
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Behind {
                pushes: true,
                receives: false
            }
        );
        health.with_peer(collection, peer, |pair| {
            pair.pushed(now, WalkKind::Records, frontier(6, 2).records, true);
        });
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Current
        );
        health.with_peer(collection, peer, |pair| {
            pair.pushed(now, WalkKind::Records, frontier(6, 2).records, false);
            pair.received(now, WalkKind::Authorization, None, false);
        });
        let pinned = health.snapshot();
        assert_eq!(
            pinned.pair(collection, peer, now, AGE),
            PairState::Behind {
                pushes: true,
                receives: true
            }
        );
        let pair = &pinned.collections[0].peers[0];
        assert_eq!((pair.pushes.ok, pair.pushes.failed), (3, 1));
        assert_eq!((pair.receives.ok, pair.receives.failed), (1, 1));
        assert_eq!(pair.confirmed.records, Some(frontier(6, 2).records));
        assert_eq!(pair.received.records, Some(frontier(5, 1).records));
        assert_eq!(pair.first_at, Some(now));

        // A direction the peering does not have is never behind.
        health.update(|health| {
            health.peerings[0].sends = false;
            health.peerings[0].receives = false;
        });
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Current
        );
        health.update(|health| health.peerings.clear());
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Unknown
        );
    }

    #[test]
    fn local_frontier_withdrawal_and_failed_store_observation_leave_the_pair_unknown() {
        let (health, collection, peer, now) = fixture();
        settle(&health, collection, peer, now);
        health.update(|health| {
            health.collections[0].local_frontier = None;
            health.store.serving_snapshot = false;
        });
        let snapshot = health.snapshot();
        assert_eq!(
            snapshot.collections.len(),
            1,
            "active interest is not withdrawn with its view"
        );
        assert_eq!(
            snapshot.pair(collection, peer, now, AGE),
            PairState::Unknown
        );

        let (health, collection, peer, now) = fixture();
        settle(&health, collection, peer, now);
        let later = now + Duration::from_secs(1);
        health.update(|health| {
            health.store.last_failure_at = Some(later);
            health.store.last_failure = Some(StoreFailure::Snapshot);
        });
        assert_eq!(
            health.snapshot().pair(collection, peer, later, AGE),
            PairState::Unknown
        );
        health.update(|health| health.store.last_snapshot_observed_at = Some(later));
        assert_eq!(
            health.snapshot().pair(collection, peer, later, AGE),
            PairState::Current
        );
    }

    #[test]
    fn recent_peer_evidence_is_bounded_and_removed_interest_cannot_reappear() {
        let (health, collection, _, now) = fixture();
        for index in 0..MAX_HEALTH_PEERS_PER_COLLECTION + 10 {
            let mut peer = [0; 32];
            peer[..8].copy_from_slice(&(index as u64).to_be_bytes());
            health.with_peer(collection, peer, |health| {
                health.pushed(now, WalkKind::Records, frontier(1, 1).records, false)
            });
        }
        assert_eq!(
            health.snapshot().collections[0].peers.len(),
            MAX_HEALTH_PEERS_PER_COLLECTION
        );
        health.update(|health| health.collections.clear());
        health.with_peer(collection, [8; 32], |_| {
            panic!("retired observation recreated")
        });
        assert!(health.snapshot().collections.is_empty());
    }

    #[test]
    fn publication_failure_clock_ignores_idle_time_and_repeated_failures() {
        use crate::provider::PublicationResult;
        let now = crate::clock::mono_now();
        let mut health = PublicationHealth::default();
        assert_eq!(health.unacknowledged_since, None);
        health.completed(now, PublicationResult::NoAuthenticatedRemoteReplica);
        health.completed(
            now + Duration::from_secs(60),
            PublicationResult::RemoteRejected,
        );
        assert_eq!(health.unacknowledged_since, Some(now));
        health.completed(now + Duration::from_secs(90), PublicationResult::Published);
        assert_eq!(health.unacknowledged_since, None);
        let later = now + Duration::from_secs(8 * 60 * 60);
        health.completed(later, PublicationResult::NoAuthenticatedRemoteReplica);
        assert_eq!(health.unacknowledged_since, Some(later));
    }
}
