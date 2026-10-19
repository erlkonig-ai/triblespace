//! Local runtime evidence, not a replicated inventory or a claim about a swarm.
//!
//! Reading health neither starts networking nor refreshes any timestamp. All
//! instants belong to this process's monotonic clock; a reporter must preserve
//! their age and its process identity instead of serializing them as wall time.
//! Missing observations, offline peers, and missing cached blobs are not
//! corruption. A pair's sync concerns READ-authorized records, including
//! inert ones, and grant agreement, not admitted application values or
//! payload availability: what the peer confirmed of this side's record
//! trees, what landed of the peer's, and whether the peer's standing listing
//! of C's grants is this side's grant index root for C ([`GrantHealth`]).

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

/// The record summaries of an immutable collection observation, plus their
/// composite root for diagnostics. Held blobs are not in it: cache equality
/// is deliberately not required for record health. Grants are reported per
/// resource ([`GrantHealth`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairFrontier {
    pub wake_root: [u8; 32],
    pub commits: PatchSummary,
    pub derives: PatchSummary,
}

impl RepairFrontier {
    /// Equality of the collection's records, independent of caching.
    /// Demand and shallow peers may intentionally retain different bodies.
    pub fn same_evidence(&self, other: &Self) -> bool {
        self.commits == other.commits && self.derives == other.derives
    }
}

impl From<CollectionRepairManifest> for RepairFrontier {
    fn from(manifest: CollectionRepairManifest) -> Self {
        Self {
            wake_root: manifest.wake_root,
            commits: manifest.commits,
            derives: manifest.derives,
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
    pub(crate) fn ended(&mut self, at: Mono, ok: bool) {
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

/// The roots of a collection's records trees as pushes carry them, each
/// from the last push of that tree that ended well. Held blobs and grants
/// are no part of record health.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Roots {
    pub commits: Option<PatchSummary>,
    pub derives: Option<PatchSummary>,
}

impl Roots {
    fn set(&mut self, kind: WalkKind, root: PatchSummary) {
        match kind {
            WalkKind::Commit => self.commits = Some(root),
            WalkKind::Derive => self.derives = Some(root),
            WalkKind::Authorization | WalkKind::References => {}
        }
    }

    /// Whether both record roots are those of `frontier`.
    pub fn hold(&self, frontier: &RepairFrontier) -> bool {
        self.commits == Some(frontier.commits) && self.derives == Some(frontier.derives)
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
    /// Latest successful completion of each record receive component
    /// (COMMIT, DERIVE), cleared on its failure or disconnection. Roots above
    /// remain last-landed diagnostics, not fresh-completion evidence.
    received_complete_at: [Option<Mono>; 2],
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
            received_complete_at: [None; 2],
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
        let component = match kind {
            WalkKind::Commit => 0,
            WalkKind::Derive => 1,
            // Neither held-blob availability nor grants are record health.
            WalkKind::Authorization | WalkKind::References => return,
        };
        self.received_complete_at[component] = (landed && root.is_some()).then_some(at);
    }

    pub(crate) fn disconnected(&mut self) {
        // Keep last-confirmed/landed roots as diagnostics, as before. Only
        // receive completion needs fresh evidence on the next connection.
        self.received_complete_at = [None; 2];
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
    /// Grant agreement per resource R: what this side holds of R's grants
    /// and what each connected peer listed for R. Written only by the
    /// peering task.
    pub grants: Vec<GrantHealth>,
    /// Collections an indexed grant names this node on that it has not
    /// selected: what it was granted and does not sync yet. Written only by
    /// the peering task.
    pub named_unselected: Vec<CollectionHandle>,
}

/// What this side holds of the grants over one resource R, and what each
/// connected peer listed for R.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantHealth {
    pub resource: CollectionHandle,
    /// Root and count of R's grants in the grant index here.
    pub local: PatchSummary,
    pub peers: Vec<GrantPeerHealth>,
}

/// One connected peer's statement about R's grants: its standing listing,
/// cleared when the connection closes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrantPeerHealth {
    pub peer: PeerId,
    /// The peer's last GRANT_ROOTS entry for R on the current connection.
    pub listed: Option<PatchSummary>,
    /// What this side held of R's grants when the last grant walk with the
    /// peer over R confirmed.
    pub agreed: Option<PatchSummary>,
    /// Grant walks with the peer over R that ran to an end: confirmed ones
    /// end well; failed and refused ones do not.
    pub ends: Ends,
    /// Proofs those walks received here and skipped.
    pub skipped: u64,
    /// Proofs the peer delivered over R that waited for R's descriptor.
    pub pending: u64,
    /// Grant walks over R opened again after a failure or a give-up.
    pub retries: u64,
}

fn fresh(at: Option<Mono>, now: Mono, max_age: Duration) -> bool {
    at.is_some_and(|at| at <= now && now.duration_since(at) <= max_age)
}

impl HealthSnapshot {
    pub fn is_fresh(&self, now: Mono, max_age: Duration) -> bool {
        fresh(self.observed_at, now, max_age)
    }

    /// Pairwise evidence only: `Current` once, where this side sends, the
    /// peer confirmed the records this side serves now and listed its root
    /// of C's grants, and, where it receives, each COMMIT/DERIVE receive
    /// component completed successfully within `max_age` and the peer's
    /// listed root of C's grants is this side's. Empty components must
    /// complete too; a different kind's success cannot mask failure.
    /// References never establish or invalidate receive-component
    /// completion. Grant agreement carries no age: a listing is the peer's
    /// standing statement for the life of its connection.
    /// A local record advance, an unavailable or stale store observation, an
    /// ended peering or no push or receive within `max_age` leaves the pair
    /// `Unknown`. Catching-up/stalled policy belongs to the observer: use the
    /// ends and their times, not successful RPC counts.
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
        let grants = self.grants.iter().find(|grants| grants.resource == collection);
        let local = grants.map(|grants| grants.local);
        let listed = grants
            .and_then(|grants| grants.peers.iter().find(|listing| listing.peer == peer))
            .and_then(|listing| listing.listed);
        let pushes = peering.sends
            && (listed.is_none()
                || !(pair.pushes.last_ok
                    && entry
                        .local_frontier
                        .is_some_and(|local| pair.confirmed.hold(&local))));
        let receives = peering.receives
            && (listed.is_none_or(|listed| Some(listed) != local)
                || !pair.received_complete_at.iter().all(|at| fresh(*at, now, max_age)));
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
            grants: Vec::new(),
            named_unselected: Vec::new(),
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
            derives: PatchSummary::new(None, 0).unwrap(),
            commits: PatchSummary::new(Some([byte; 32]), count).unwrap(),
        }
    }

    /// The root of C's grants both sides of the fixture's pair hold.
    fn agreed() -> PatchSummary {
        PatchSummary::new(Some([7; 32]), 2).unwrap()
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
            health.grants.push(GrantHealth {
                resource: collection,
                local: agreed(),
                peers: vec![GrantPeerHealth {
                    peer,
                    listed: Some(agreed()),
                    ..Default::default()
                }],
            });
        });
        (health, collection, peer, now)
    }

    /// Both record trees of `frontier` pushed and confirmed, and receives
    /// landed.
    fn settle(health: &Health, collection: CollectionHandle, peer: PeerId, now: Mono) {
        health.with_peer(collection, peer, |pair| {
            let frontier = frontier(5, 1);
            pair.pushed(now, WalkKind::Commit, frontier.commits, true);
            pair.pushed(now, WalkKind::Derive, frontier.derives, true);
            pair.received(now, WalkKind::Commit, Some(frontier.commits), true);
            pair.received(now, WalkKind::Derive, Some(frontier.derives), true);
        });
    }

    const AGE: Duration = Duration::from_secs(180);

    /// This side holds `local` of C's grants and the peer listed `listed`.
    fn listing(
        health: &Health,
        collection: CollectionHandle,
        peer: PeerId,
        local: PatchSummary,
        listed: Option<PatchSummary>,
    ) {
        health.update(|sample| {
            sample.grants = vec![GrantHealth {
                resource: collection,
                local,
                peers: vec![GrantPeerHealth {
                    peer,
                    listed,
                    ..Default::default()
                }],
            }];
        });
    }

    /// The record trees of the fixture's frontier pushed, confirmed and
    /// received at `at`, as the record timer keeps doing.
    fn records(health: &Health, collection: CollectionHandle, peer: PeerId, at: Mono) {
        health.update(|sample| {
            sample.observed_at = Some(at);
            sample.store.last_snapshot_observed_at = Some(at);
        });
        health.with_peer(collection, peer, |pair| {
            let local = frontier(5, 1);
            pair.pushed(at, WalkKind::Commit, local.commits, true);
            pair.pushed(at, WalkKind::Derive, local.derives, true);
            pair.received(at, WalkKind::Commit, Some(local.commits), true);
            pair.received(at, WalkKind::Derive, Some(local.derives), true);
        });
    }

    /// Grant agreement is the peer's standing listing, not a timed receive:
    /// a pair whose peer listed this side's root for C stays current long
    /// past the default age with no grant walk at all, while the record
    /// trees keep being exchanged.
    #[test]
    fn a_pair_agreeing_on_grants_stays_current_without_grant_walks() {
        let (health, collection, peer, now) = fixture();
        let agreed = PatchSummary::new(Some([9; 32]), 3).unwrap();
        listing(&health, collection, peer, agreed, Some(agreed));
        records(&health, collection, peer, now);
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Current
        );
        let later = now + Duration::from_secs(600);
        records(&health, collection, peer, later);
        assert_eq!(
            health.snapshot().pair(collection, peer, later, AGE),
            PairState::Current
        );
    }

    /// Control for the test above: a peer listing another root for C leaves
    /// this side receiving, and no listing yet leaves it pushing as well;
    /// a direction the peering lacks is never behind on grants either.
    #[test]
    fn a_pair_whose_peer_lists_other_grants_is_behind() {
        let (health, collection, peer, now) = fixture();
        let local = PatchSummary::new(Some([9; 32]), 3).unwrap();
        let other = PatchSummary::new(Some([8; 32]), 2).unwrap();
        records(&health, collection, peer, now);
        listing(&health, collection, peer, local, Some(other));
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Behind {
                pushes: false,
                receives: true
            }
        );
        listing(&health, collection, peer, local, None);
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Behind {
                pushes: true,
                receives: true
            }
        );
        health.update(|sample| sample.peerings[0].receives = false);
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Behind {
                pushes: true,
                receives: false
            }
        );
        health.update(|sample| sample.peerings[0].receives = true);
        listing(&health, collection, peer, local, Some(local));
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Current
        );
    }

    #[test]
    fn receive_only_completion_isolated_by_foundation_kind() {
        let (health, collection, peer, now) = fixture();
        health.update(|sample| sample.peerings[0].sends = false);
        let f = frontier(5, 1);
        health.with_peer(collection, peer, |pair| {
            pair.received(now, WalkKind::Derive, None, false);
            pair.received(now, WalkKind::Commit, Some(f.commits), true);
        });
        assert_eq!(health.snapshot().pair(collection, peer, now, AGE),
            PairState::Behind { pushes: false, receives: true });
        health.with_peer(collection, peer, |pair| {
            pair.received(now, WalkKind::Derive, Some(f.derives), true);
        });
        assert_eq!(health.snapshot().pair(collection, peer, now, AGE), PairState::Current);
        health.with_peer(collection, peer, |pair| {
            pair.received(now, WalkKind::Derive, Some(f.derives), false);
            pair.received(now, WalkKind::Commit, Some(frontier(6, 2).commits), true);
            pair.received(now, WalkKind::References, Some(f.derives), true);
        });
        assert_eq!(health.snapshot().pair(collection, peer, now, AGE),
            PairState::Behind { pushes: false, receives: true });
    }

    #[test]
    fn receive_completion_freshness_and_disconnect_do_not_reuse_old_roots() {
        let (health, collection, peer, now) = fixture();
        health.update(|sample| sample.peerings[0].sends = false);
        settle(&health, collection, peer, now);
        let later = now + AGE + Duration::from_secs(1);
        health.update(|sample| {
            sample.observed_at = Some(later);
            sample.store.last_snapshot_observed_at = Some(later);
        });
        health.with_peer(collection, peer, |pair| {
            pair.received(later, WalkKind::Commit, Some(frontier(6, 2).commits), true);
        });
        assert_eq!(health.snapshot().pair(collection, peer, later, AGE),
            PairState::Behind { pushes: false, receives: true });
        health.with_peer(collection, peer, |pair| {
            pair.received(later, WalkKind::Derive, Some(frontier(6, 2).derives), true);
        });
        assert_eq!(health.snapshot().pair(collection, peer, later, AGE), PairState::Current);
        let confirmed = health.snapshot().collections[0].peers[0].confirmed;
        health.with_peer(collection, peer, |pair| pair.disconnected());
        assert_eq!(health.snapshot().collections[0].peers[0].confirmed, confirmed);
        assert!(health.snapshot().collections[0].peers[0].received.derives.is_some(), "last-landed diagnostic root survives");
        health.update(|sample| sample.peerings[0].peered = false);
        assert_eq!(health.snapshot().pair(collection, peer, later, AGE), PairState::Unknown);
        health.update(|sample| sample.peerings[0].peered = true);
        assert_eq!(health.snapshot().pair(collection, peer, later, AGE),
            PairState::Behind { pushes: false, receives: true });
    }

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
            pair.pushed(now, WalkKind::Commit, frontier(6, 2).commits, true);
        });
        assert_eq!(
            health.snapshot().pair(collection, peer, now, AGE),
            PairState::Current
        );
        health.with_peer(collection, peer, |pair| {
            pair.pushed(now, WalkKind::Commit, frontier(6, 2).commits, false);
            pair.received(now, WalkKind::Derive, None, false);
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
        assert_eq!((pair.receives.ok, pair.receives.failed), (2, 1));
        assert_eq!(pair.confirmed.commits, Some(frontier(6, 2).commits));
        assert_eq!(pair.received.commits, Some(frontier(5, 1).commits));
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
                health.pushed(now, WalkKind::Commit, frontier(1, 1).commits, false)
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
