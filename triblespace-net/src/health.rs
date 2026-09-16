//! Local runtime evidence, not a replicated inventory or a claim about a swarm.
//!
//! Reading health neither starts networking nor refreshes any timestamp. All
//! instants belong to this process's monotonic clock; a reporter must preserve
//! their age and its process identity instead of serializing them as wall time.
//! Missing observations, offline peers, and missing cached blobs are not
//! corruption. Collection comparisons concern READ-authorized repair evidence
//! (`Record × AuthorizationEvidence`), including inert records, not admitted
//! application values or payload availability.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh_base::EndpointId;
use triblespace_core::collection::CollectionHandle;

use crate::clock::Mono;
use crate::collection_wire::CollectionRepairManifest;
use crate::inventory::ReconcileDirection;
use crate::patch_repair::PatchSummary;
use crate::transport::PeerId;

/// Hard per-active-collection bound on retained pairwise runtime evidence.
pub const MAX_HEALTH_PEERS_PER_COLLECTION: usize = 128;

/// The existing immutable manifest received after READ(C) admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairFrontier {
    pub wake_root: [u8; 32],
    pub records: PatchSummary,
    pub authorization_evidence: PatchSummary,
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

/// A completed, validated pull's pinned observations, before store admission.
/// `more == false` or receiving no leaves does not establish equality: the
/// local set may strictly contain the remote set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairComparison {
    pub observed_at: Mono,
    pub local: RepairFrontier,
    pub remote: RepairFrontier,
    pub records_received: u64,
    pub proofs_received: u64,
    pub more: bool,
}

/// Sanitized failure classes. No error strings or bearer handles are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairFailure {
    Failed,
    Deadline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairHealth {
    pub peer: PeerId,
    pub in_flight: bool,
    /// First scheduled attempt while this peer observation is retained. Retries
    /// cannot extend the grace period of a peer that has never answered.
    pub first_started_at: Option<Mono>,
    pub last_started_at: Option<Mono>,
    pub last_completed_at: Option<Mono>,
    /// Last validated nonempty repair delta; not a durability receipt. Repeated
    /// downloads can advance this while store admission remains blocked.
    pub last_progress_at: Option<Mono>,
    /// First authorized comparison, or a change in its remote frontier. Local
    /// writes and repeated identical remote replies never advance this clock.
    /// This is evidence of a changing remote frontier, not proof of gap closure.
    pub last_remote_change_at: Option<Mono>,
    pub last_failure_at: Option<Mono>,
    pub last_failure: Option<RepairFailure>,
    pub comparison: Option<RepairComparison>,
}

impl RepairHealth {
    fn new(peer: PeerId) -> Self {
        Self {
            peer,
            in_flight: false,
            first_started_at: None,
            last_started_at: None,
            last_completed_at: None,
            last_progress_at: None,
            last_remote_change_at: None,
            last_failure_at: None,
            last_failure: None,
            comparison: None,
        }
    }

    fn last_event_at(&self) -> Option<Mono> {
        self.last_started_at.max(self.last_completed_at)
    }

    pub(crate) fn started(&mut self, at: Mono) {
        self.in_flight = true;
        self.first_started_at.get_or_insert(at);
        self.last_started_at = Some(at);
    }

    pub(crate) fn compared(&mut self, comparison: RepairComparison, completed_at: Mono) {
        if self
            .comparison
            .is_none_or(|previous| previous.remote != comparison.remote)
        {
            self.last_remote_change_at = Some(comparison.observed_at);
        }
        if comparison.records_received != 0 || comparison.proofs_received != 0 {
            self.last_progress_at = Some(completed_at);
        }
        self.comparison = Some(comparison);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionHealth {
    pub collection: CollectionHandle,
    /// None means active locally but absent from the current serving view.
    pub local_frontier: Option<RepairFrontier>,
    pub last_local_change_at: Option<Mono>,
    /// Recent observations only, not a roster or a list of all holders.
    pub peers: Vec<RepairHealth>,
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
    pub retry_pending: u64,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonState {
    Unknown,
    Matching,
    Different,
    /// The local scheduler is configured not to pull collections.
    NotApplicable,
}

/// An immutable copy of bounded evidence recorded at actual runtime events.
/// Sampling this value cannot keep a dead host fresh.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub node: EndpointId,
    pub direction: Option<ReconcileDirection>,
    pub started_at: Option<Mono>,
    /// Written only by the host loop, never by a status reader or store refresh.
    pub observed_at: Option<Mono>,
    pub store: StoreHealth,
    /// Exactly the locally active interest set, including unavailable views.
    pub collections: Vec<CollectionHealth>,
    pub publication: PublicationHealth,
    pub blob_serving: BlobServeHealth,
}

fn fresh(at: Option<Mono>, now: Mono, max_age: Duration) -> bool {
    at.is_some_and(|at| at <= now && now.duration_since(at) <= max_age)
}

impl HealthSnapshot {
    pub fn is_fresh(&self, now: Mono, max_age: Duration) -> bool {
        fresh(self.observed_at, now, max_age)
    }

    /// Pairwise, time-bounded evidence only. A local frontier advance or
    /// unavailable/stale store observation invalidates a former match.
    /// Catching-up/stalled policy belongs to the observer: use actual local
    /// changes, in-flight work, failures and progress, not successful RPC counts.
    pub fn comparison(
        &self,
        collection: CollectionHandle,
        peer: PeerId,
        now: Mono,
        max_age: Duration,
    ) -> ComparisonState {
        if self.direction.is_some_and(|direction| !direction.pulls()) {
            return ComparisonState::NotApplicable;
        }
        if !self.is_fresh(now, max_age)
            || !self.store.serving_snapshot
            || !fresh(self.store.last_snapshot_observed_at, now, max_age)
            || self.store.last_failure_at > self.store.last_snapshot_observed_at
        {
            return ComparisonState::Unknown;
        }
        let Some(collection) = self
            .collections
            .iter()
            .find(|entry| entry.collection == collection)
        else {
            return ComparisonState::Unknown;
        };
        let Some(comparison) = collection
            .peers
            .iter()
            .find(|entry| entry.peer == peer)
            .and_then(|entry| entry.comparison)
        else {
            return ComparisonState::Unknown;
        };
        if !fresh(Some(comparison.observed_at), now, max_age)
            || collection.local_frontier != Some(comparison.local)
        {
            return ComparisonState::Unknown;
        }
        if comparison.local == comparison.remote {
            ComparisonState::Matching
        } else {
            ComparisonState::Different
        }
    }
}

#[derive(Clone)]
pub(crate) struct Health(Arc<Mutex<HealthSnapshot>>);

impl Health {
    pub(crate) fn new(node: EndpointId) -> Self {
        Self(Arc::new(Mutex::new(HealthSnapshot {
            node,
            direction: None,
            started_at: None,
            observed_at: None,
            store: StoreHealth::default(),
            collections: Vec::new(),
            publication: PublicationHealth::default(),
            blob_serving: BlobServeHealth::default(),
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
        update: impl FnOnce(&mut RepairHealth),
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
                            .filter(|(_, entry)| !entry.in_flight)
                            .min_by_key(|(_, entry)| (entry.last_event_at(), entry.peer))
                        else {
                            return;
                        };
                        collection.peers.swap_remove(oldest);
                    }
                    collection.peers.push(RepairHealth::new(peer));
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
            health.direction = Some(ReconcileDirection::Bidirectional);
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
        });
        (health, collection, peer, now)
    }

    fn compare(health: &Health, collection: CollectionHandle, peer: PeerId, now: Mono) {
        health.with_peer(collection, peer, |health| {
            health.last_started_at = Some(now);
            health.last_completed_at = Some(now);
            health.comparison = Some(RepairComparison {
                observed_at: now,
                local: frontier(5, 1),
                remote: frontier(5, 1),
                records_received: 0,
                proofs_received: 0,
                more: false,
            });
        });
    }

    #[test]
    fn unknown_until_an_actual_comparison_then_fresh_match_expires() {
        let (health, collection, peer, now) = fixture();
        let age = Duration::from_secs(180);
        assert_eq!(
            health.snapshot().comparison(collection, peer, now, age),
            ComparisonState::Unknown
        );
        compare(&health, collection, peer, now);
        let pinned = health.snapshot();
        assert_eq!(
            pinned.comparison(collection, peer, now, age),
            ComparisonState::Matching
        );
        let later = now + age + Duration::from_secs(1);
        // A live store/status reader cannot replace the host's last loop tick.
        health.update(|health| health.store.last_snapshot_observed_at = Some(later));
        for _ in 0..3 {
            let sampled = health.snapshot();
            assert_eq!(sampled.observed_at, Some(now));
            assert!(!sampled.is_fresh(later, age));
            assert_eq!(
                sampled.comparison(collection, peer, later, age),
                ComparisonState::Unknown
            );
        }
        // Refreshing the host alone does not refresh the old remote comparison.
        health.update(|health| health.observed_at = Some(later));
        assert_eq!(
            health.snapshot().comparison(collection, peer, later, age),
            ComparisonState::Unknown
        );
        assert_eq!(pinned.store.last_snapshot_observed_at, Some(now));
    }

    #[test]
    fn one_way_pull_success_and_empty_delta_do_not_mean_equal() {
        let (health, collection, peer, now) = fixture();
        compare(&health, collection, peer, now);
        health.update(|health| {
            let collection = &mut health.collections[0];
            collection.local_frontier = Some(frontier(6, 2));
            collection.peers[0].comparison.as_mut().unwrap().local = frontier(6, 2);
        });
        assert_eq!(
            health
                .snapshot()
                .comparison(collection, peer, now, Duration::from_secs(180)),
            ComparisonState::Different,
        );
    }

    #[test]
    fn local_advances_and_identical_remote_replies_do_not_extend_remote_progress_grace() {
        let now = crate::clock::mono_now();
        let mut health = RepairHealth::new([4; 32]);
        health.started(now);
        let first_comparison = now + Duration::from_secs(1);
        let comparison = RepairComparison {
            observed_at: first_comparison,
            local: frontier(5, 2),
            remote: frontier(6, 1),
            records_received: 0,
            proofs_received: 0,
            more: false,
        };
        health.compared(comparison, first_comparison);
        assert_eq!(health.last_remote_change_at, Some(first_comparison));

        let later = now + Duration::from_secs(601);
        health.started(later);
        health.compared(
            RepairComparison {
                observed_at: later,
                local: frontier(7, 3),
                ..comparison
            },
            later,
        );
        assert_eq!(health.first_started_at, Some(now));
        assert_eq!(health.last_started_at, Some(later));
        assert_eq!(health.last_remote_change_at, Some(first_comparison));
        assert_eq!(health.comparison.unwrap().local, frontier(7, 3));
        assert_eq!(health.last_progress_at, None);

        let changed = later + Duration::from_secs(1);
        health.compared(
            RepairComparison {
                observed_at: changed,
                remote: frontier(8, 2),
                ..health.comparison.unwrap()
            },
            changed,
        );
        assert_eq!(health.last_remote_change_at, Some(changed));
    }

    #[test]
    fn unanswered_attempts_keep_the_first_attempt_for_grace() {
        let now = crate::clock::mono_now();
        let mut health = RepairHealth::new([4; 32]);
        health.started(now);
        health.started(now + Duration::from_secs(601));
        assert_eq!(health.first_started_at, Some(now));
        assert_eq!(health.last_remote_change_at, None);
        assert_eq!(health.comparison, None);
    }

    #[test]
    fn local_frontier_advance_and_withdrawal_invalidate_former_match() {
        let (health, collection, peer, now) = fixture();
        compare(&health, collection, peer, now);
        let age = Duration::from_secs(180);
        health.update(|health| health.collections[0].local_frontier = Some(frontier(6, 2)));
        assert_eq!(
            health.snapshot().comparison(collection, peer, now, age),
            ComparisonState::Unknown
        );
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
            snapshot.comparison(collection, peer, now, age),
            ComparisonState::Unknown
        );
    }

    #[test]
    fn failed_store_observation_is_not_a_fresh_match() {
        let (health, collection, peer, now) = fixture();
        compare(&health, collection, peer, now);
        let later = now + Duration::from_secs(1);
        let age = Duration::from_secs(180);
        health.update(|health| {
            health.store.last_failure_at = Some(later);
            health.store.last_failure = Some(StoreFailure::Snapshot);
        });
        assert_eq!(
            health.snapshot().comparison(collection, peer, later, age),
            ComparisonState::Unknown
        );
        health.update(|health| health.store.last_snapshot_observed_at = Some(later));
        assert_eq!(
            health.snapshot().comparison(collection, peer, later, age),
            ComparisonState::Matching
        );
    }

    #[test]
    fn write_only_is_explicitly_not_applicable() {
        let (health, collection, peer, now) = fixture();
        health.update(|health| health.direction = Some(ReconcileDirection::WriteOnly));
        assert_eq!(
            health
                .snapshot()
                .comparison(collection, peer, now, Duration::from_secs(180)),
            ComparisonState::NotApplicable,
        );
    }

    #[test]
    fn recent_peer_evidence_is_bounded_and_removed_interest_cannot_reappear() {
        let (health, collection, _, now) = fixture();
        for index in 0..MAX_HEALTH_PEERS_PER_COLLECTION + 10 {
            let mut peer = [0; 32];
            peer[..8].copy_from_slice(&(index as u64).to_be_bytes());
            health.with_peer(collection, peer, |health| {
                health.last_started_at = Some(now)
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
