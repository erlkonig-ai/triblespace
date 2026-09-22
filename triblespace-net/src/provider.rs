//! Exact soft-state provider leases for resident bearer blobs.
//!
//! Resident blob handles map to opaque full-width rendezvous keys. Providers
//! renew them at their K closest DHT nodes; directory nodes receive neither raw
//! blob handles nor collection membership.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use triblespace_core::patch::{
    Entry as PatchEntry, IdentitySchema, PATCH, PATCHIntoOrderedIterator,
};

use crate::bearer::BearerLocatorIndex;
pub use crate::bearer::blob_locator;
use crate::clock::Mono;
use crate::transport::PeerId;

#[cfg(test)]
#[path = "provider/directory_model.rs"]
mod directory_model;

#[cfg(test)]
#[path = "provider/patch_directory.rs"]
mod patch_directory;

/// Opaque rendezvous key for one exact bearer identity.
pub(crate) type ProviderKey = [u8; 32];
pub(crate) type ProviderToken = [u8; 32];
type ProviderIdentity = [u8; 32];
const PROVIDER_TOKEN_CONTEXT: &[u8] = b"triblespace.net/provider-token/v1\0";

/// Receiver-chosen lifetime of one exact provider lease.
pub(crate) const PROVIDER_LEASE_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// Complete one deterministic renewal traversal within one third of a lease.
/// The first sweep therefore finishes with at least eight hours of latency
/// margin before even its last initial lease can expire.
pub(crate) const PROVIDER_RENEWAL_PERIOD: Duration = Duration::from_secs(8 * 60 * 60);
/// Maximum fan-out retained and returned for one exact rendezvous key.
pub(crate) const MAX_PROVIDERS_PER_KEY: usize = 64;
const _: () = assert!(MAX_PROVIDERS_PER_KEY <= u8::MAX as usize);
/// Receiver-local aggregate soft bound. Exact-key responsibility decides
/// which membership survives when a full shard receives a closer key.
const MAX_PROVIDER_MEMBERSHIPS: usize = 1 << 24;

/// Bound opportunistic expiry reclamation performed by one RPC.
const MAX_EXPIRED_PROVIDER_MEMBERSHIPS_PER_CALL: usize = 64;

/// Endpoint-bound directory proof for one opaque rendezvous key.
///
/// `identity` is H for an exact blob lease. Keying by H makes the token a proof
/// of bearer-handle knowledge, bound to the domain-separated rendezvous key and
/// the provider endpoint without storing a second per-H token trie.
pub(crate) fn provider_lease_token(
    identity: [u8; 32],
    key: ProviderKey,
    provider: PeerId,
) -> ProviderToken {
    let mut hasher = blake3::Hasher::new_keyed(&identity);
    hasher.update(PROVIDER_TOKEN_CONTEXT);
    hasher.update(&key);
    hasher.update(&provider);
    *hasher.finalize().as_bytes()
}

/// Derive the expected endpoint-bound directory token for one exact blob.
///
/// A reader who knows the bearer handle can compare this value with a
/// `protocol::op_provider_get` reply without fetching the blob or sending the
/// handle. A matching token proves knowledge of the handle, not current
/// provider reachability or residency. Never log the input handle.
pub fn blob_provider_token(identity: [u8; 32], provider: PeerId) -> [u8; 32] {
    provider_lease_token(identity, blob_locator(identity), provider)
}

/// Canonical exact publication set for one serving snapshot. Values retain the
/// hidden identity H; endpoint-bound tokens are derived only when the
/// publisher schedules a key.
type ProviderLeasePatch = PATCH<32, IdentitySchema, ProviderIdentity>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProviderSet {
    leases: ProviderLeasePatch,
}

/// One snapshot-bound set of exact rendezvous keys and their hidden identity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProviderObservation {
    set: ProviderSet,
}

impl ProviderObservation {
    #[cfg(test)]
    pub(crate) fn from_blob_handles(handles: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let mut locators = BearerLocatorIndex::new();
        for handle in handles {
            locators.replace(&PatchEntry::with_value(&blob_locator(handle), handle));
        }
        Self::from_locators(&locators)
    }

    pub(crate) fn into_set(self) -> ProviderSet {
        self.set
    }

    /// Share the snapshot's L→H PATCH unchanged. Exact H transport is independent
    /// of collection repair, so every resident bearer locator is publishable.
    /// Publication tokens are computed only when a key is scheduled, so this
    /// adds no second per-H trie.
    pub(crate) fn from_locators(locators: &BearerLocatorIndex) -> Self {
        Self {
            set: ProviderSet {
                leases: locators.clone(),
            },
        }
    }
}

impl ProviderSet {
    #[cfg(test)]
    pub(crate) fn contains(&self, key: &ProviderKey) -> bool {
        self.leases.get(key).is_some()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> u64 {
        self.leases.len()
    }

    #[cfg(test)]
    pub(crate) fn identity(&self, key: &ProviderKey) -> Option<ProviderIdentity> {
        self.leases.get(key).copied()
    }
}

struct PublicationCycle {
    keys: PATCHIntoOrderedIterator<32, IdentitySchema, ProviderIdentity>,
    started: Mono,
    total: u64,
    remaining: u64,
    next_due: Mono,
}

struct PublicationTopologyOutage {
    attempts: u32,
    retry_at: Mono,
    probe: Option<ProviderKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationResult {
    Published,
    NoAuthenticatedRemoteReplica,
    RemoteRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderPutResult {
    /// The target returned `PROVIDER_PUT_OK`.
    Accepted,
    /// The target returned `PROVIDER_PUT_FULL`.
    ExplicitlyRejected,
    /// No complete provider-PUT protocol response arrived.
    Unavailable,
}

impl PublicationResult {
    pub(crate) fn observe_put(
        self,
        local: PeerId,
        peer: PeerId,
        result: ProviderPutResult,
    ) -> Self {
        if peer == local {
            return self;
        }
        match (self, result) {
            (Self::Published, _) | (_, ProviderPutResult::Accepted) => Self::Published,
            (Self::RemoteRejected, _) | (_, ProviderPutResult::ExplicitlyRejected) => {
                Self::RemoteRejected
            }
            (Self::NoAuthenticatedRemoteReplica, ProviderPutResult::Unavailable) => {
                Self::NoAuthenticatedRemoteReplica
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn from_put_results(
        local: PeerId,
        results: impl IntoIterator<Item = (PeerId, ProviderPutResult)>,
    ) -> Self {
        results.into_iter().fold(
            Self::NoAuthenticatedRemoteReplica,
            |publication, (peer, result)| publication.observe_put(local, peer, result),
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PublicationEffect {
    pub(crate) topology_outage_started: bool,
    pub(crate) topology_recovered: bool,
    pub(crate) retry_budget_full: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationLane {
    Startup,
    Incremental,
}

/// One bounded in-flight attempt, retaining its pending lane through a topology
/// outage. Retries and renewals return to historical work, not fresh arrivals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderPublication {
    pub(crate) key: ProviderKey,
    pub(crate) identity: ProviderIdentity,
    lane: PublicationLane,
}

/// Constant-time operational counts, not unique remote lease coverage.
pub(crate) struct PublicationProgress {
    pub(crate) resident: u64,
    pub(crate) startup_pending: u64,
    pub(crate) incremental_pending: u64,
    pub(crate) retry_pending: u64,
    pub(crate) renewal_remaining: u64,
    pub(crate) topology_paused: bool,
}

/// Bounded-work publication scheduler for an arbitrarily large resident set.
///
/// Snapshot changes use PATCH difference to queue newly resident keys separately
/// from startup inventory. These two queues alternate within the pending lane:
/// neither waits for the other to drain, irrespective of their locator ordering.
/// Retry and due-renewal turns retain their existing outer alternation. One
/// persistent ordered cursor renews the complete set over one third of a lease;
/// no timer tick scans the inventory or allocates a flat resident queue.
pub(crate) struct ProviderPublisher {
    resident: ProviderSet,
    initialized: bool,
    startup: ProviderSet,
    additions: ProviderSet,
    retries: ProviderSet,
    retry_at: Mono,
    cycle: Option<PublicationCycle>,
    next_renewal: Mono,
    prefer_cycle: bool,
    prefer_retry: bool,
    prefer_startup: bool,
    topology_outage: Option<PublicationTopologyOutage>,
}

const MAX_PROVIDER_PUBLICATION_RETRIES: u64 = 1 << 10;

impl ProviderPublisher {
    pub(crate) fn new(now: Mono) -> Self {
        Self {
            resident: ProviderSet::default(),
            initialized: false,
            startup: ProviderSet::default(),
            additions: ProviderSet::default(),
            retries: ProviderSet::default(),
            retry_at: now,
            cycle: None,
            next_renewal: now + PROVIDER_RENEWAL_PERIOD,
            prefer_cycle: false,
            prefer_retry: false,
            prefer_startup: true,
            topology_outage: None,
        }
    }

    pub(crate) fn install(&mut self, resident: ProviderSet, now: Mono) {
        // Record/AUTH refreshes may publish a new serving snapshot with the
        // same resident PATCH. Its pending work and renewal clocks already
        // describe this set; do not rebuild those sets for an unchanged input.
        if self.initialized && self.resident == resident {
            return;
        }
        if self.initialized {
            let added = resident.leases.difference(&self.resident.leases);
            self.startup.leases = self.startup.leases.intersect(&resident.leases);
            self.additions.leases = self.additions.leases.intersect(&resident.leases);
            self.additions.leases.union(added);
            self.retries.leases = self.retries.leases.intersect(&resident.leases);
        } else {
            self.initialized = true;
            self.startup = resident.clone();
            self.next_renewal = now + PROVIDER_RENEWAL_PERIOD;
        }
        self.resident = resident;
    }

    pub(crate) fn progress(&self) -> PublicationProgress {
        PublicationProgress {
            resident: self.resident.leases.len(),
            startup_pending: self.startup.leases.len(),
            incremental_pending: self.additions.leases.len(),
            retry_pending: self.retries.leases.len(),
            renewal_remaining: self.cycle.as_ref().map_or(0, |cycle| cycle.remaining),
            topology_paused: self.topology_outage.is_some(),
        }
    }

    /// Queue one failed publication without allowing an outage to duplicate
    /// the whole resident set in retry state. False makes degraded coverage
    /// explicit to the host log rather than silently growing memory.
    pub(crate) fn retry(&mut self, key: ProviderKey, now: Mono) -> bool {
        if self.retries.leases.len() >= MAX_PROVIDER_PUBLICATION_RETRIES
            && self.retries.leases.get(&key).is_none()
        {
            return false;
        }
        let Some(identity) = self.resident.leases.get(&key).copied() else {
            return true;
        };
        let was_empty = self.retries.leases.is_empty();
        self.retries
            .leases
            .replace(&PatchEntry::with_value(&key, identity));
        if was_empty {
            self.retry_at = now + crate::RETRY_BACKOFF_BASE;
        }
        true
    }

    fn preserve_for_topology_retry(&mut self, work: ProviderPublication) {
        let Some(identity) = self.resident.leases.get(&work.key).copied() else {
            return;
        };
        let pending = match work.lane {
            PublicationLane::Startup => &mut self.startup,
            PublicationLane::Incremental => &mut self.additions,
        };
        pending
            .leases
            .replace(&PatchEntry::with_value(&work.key, identity));
    }

    fn topology_backoff(attempts: u32) -> Duration {
        let shift = attempts.saturating_sub(1).min(6);
        crate::RETRY_BACKOFF_BASE
            .saturating_mul(1u32 << shift)
            .min(crate::RETRY_BACKOFF_CAP)
    }

    pub(crate) fn complete(
        &mut self,
        work: ProviderPublication,
        result: PublicationResult,
        now: Mono,
    ) -> PublicationEffect {
        let key = work.key;
        match result {
            PublicationResult::Published => PublicationEffect {
                topology_recovered: self.topology_outage.take().is_some(),
                ..PublicationEffect::default()
            },
            PublicationResult::RemoteRejected => PublicationEffect {
                topology_recovered: self.topology_outage.take().is_some(),
                retry_budget_full: !self.retry(key, now),
                ..PublicationEffect::default()
            },
            PublicationResult::NoAuthenticatedRemoteReplica => {
                self.preserve_for_topology_retry(work);
                let topology_outage_started = self.topology_outage.is_none();
                match &mut self.topology_outage {
                    Some(outage) if outage.probe == Some(key) => {
                        outage.probe = None;
                        outage.attempts = outage.attempts.saturating_add(1);
                        outage.retry_at = now + Self::topology_backoff(outage.attempts);
                    }
                    Some(_) => {
                        // Other attempts from the bounded pre-outage flight may
                        // finish after the first one trips the breaker. Preserve
                        // them, but let only the eventual probe advance backoff.
                    }
                    None => {
                        self.topology_outage = Some(PublicationTopologyOutage {
                            attempts: 1,
                            retry_at: now + Self::topology_backoff(1),
                            probe: None,
                        });
                    }
                }
                PublicationEffect {
                    topology_outage_started,
                    ..PublicationEffect::default()
                }
            }
        }
    }

    fn start_cycle_if_due(&mut self, now: Mono) {
        if self.cycle.is_some() || !self.initialized || now < self.next_renewal {
            return;
        }
        let total = self.resident.leases.len();
        if total == 0 {
            self.next_renewal = now + PROVIDER_RENEWAL_PERIOD;
            return;
        }
        self.cycle = Some(PublicationCycle {
            keys: self.resident.leases.clone().into_iter_ordered(),
            started: now,
            total,
            remaining: total,
            next_due: now,
        });
    }

    fn pop_pending(
        pending: &mut ProviderSet,
        resident: &ProviderSet,
        lane: PublicationLane,
    ) -> Option<ProviderPublication> {
        loop {
            let key = pending
                .leases
                .first_infix_range(&[], &[0; 32], &[u8::MAX; 32])?;
            pending.leases.remove(&key);
            if let Some(identity) = resident.leases.get(&key).copied() {
                return Some(ProviderPublication {
                    key,
                    identity,
                    lane,
                });
            }
        }
    }

    fn pop_arrival(&mut self) -> Option<ProviderPublication> {
        let next = if self.prefer_startup {
            Self::pop_pending(&mut self.startup, &self.resident, PublicationLane::Startup).or_else(
                || {
                    Self::pop_pending(
                        &mut self.additions,
                        &self.resident,
                        PublicationLane::Incremental,
                    )
                },
            )
        } else {
            Self::pop_pending(
                &mut self.additions,
                &self.resident,
                PublicationLane::Incremental,
            )
            .or_else(|| {
                Self::pop_pending(&mut self.startup, &self.resident, PublicationLane::Startup)
            })
        };
        if let Some(work) = next {
            self.prefer_startup = work.lane == PublicationLane::Incremental;
        }
        next
    }

    fn pop_cycle(&mut self, now: Mono) -> Option<ProviderPublication> {
        loop {
            let (key, completed, started, total) = {
                let cycle = self.cycle.as_mut()?;
                if now < cycle.next_due {
                    return None;
                }
                let key = cycle
                    .keys
                    .next()
                    .expect("a fixed PATCH traversal yields its recorded leaf count");
                cycle.remaining -= 1;
                let interval_nanos = (PROVIDER_RENEWAL_PERIOD.as_nanos() / u128::from(cycle.total))
                    .max(1)
                    .min(u128::from(u64::MAX));
                cycle.next_due = cycle.next_due + Duration::from_nanos(interval_nanos as u64);
                (key, cycle.remaining == 0, cycle.started, cycle.total)
            };
            if completed {
                self.cycle = None;
                self.next_renewal = started + PROVIDER_RENEWAL_PERIOD;
                let elapsed = now.duration_since(started);
                if elapsed > PROVIDER_RENEWAL_PERIOD {
                    tracing::warn!(
                        keys = total,
                        ?elapsed,
                        "provider renewal traversal exceeded its eight-hour budget; discovery coverage may decay"
                    );
                }
            }
            if let Some(identity) = self.resident.leases.get(&key).copied() {
                return Some(ProviderPublication {
                    key,
                    identity,
                    lane: PublicationLane::Startup,
                });
            }
            if completed {
                return None;
            }
        }
    }

    fn next_ready(&mut self, now: Mono) -> Option<ProviderPublication> {
        self.start_cycle_if_due(now);
        if self.prefer_cycle
            && let Some(next) = self.pop_cycle(now)
        {
            self.prefer_cycle = false;
            return Some(next);
        }

        let retry_due = now >= self.retry_at;
        let mut from_retry = false;
        let pending = if self.prefer_retry && retry_due {
            let retry =
                Self::pop_pending(&mut self.retries, &self.resident, PublicationLane::Startup);
            from_retry = retry.is_some();
            retry.or_else(|| self.pop_arrival())
        } else {
            let addition = self.pop_arrival();
            if addition.is_some() {
                addition
            } else if retry_due {
                let retry =
                    Self::pop_pending(&mut self.retries, &self.resident, PublicationLane::Startup);
                from_retry = retry.is_some();
                retry
            } else {
                None
            }
        };
        if let Some(next) = pending {
            self.prefer_retry = !self.prefer_retry;
            self.prefer_cycle = true;
            if from_retry {
                self.retry_at = now + crate::RETRY_BACKOFF_BASE;
            }
            return Some(next);
        }
        let next = self.pop_cycle(now);
        if next.is_some() {
            self.prefer_cycle = false;
        }
        next
    }

    pub(crate) fn next(&mut self, now: Mono) -> Option<ProviderPublication> {
        if self
            .topology_outage
            .as_ref()
            .is_some_and(|outage| outage.probe.is_some() || now < outage.retry_at)
        {
            return None;
        }
        let probing = self.topology_outage.is_some();
        let next = self.next_ready(now);
        if probing && let Some(work) = next {
            self.topology_outage
                .as_mut()
                .expect("an active topology outage remains until an outcome")
                .probe = Some(work.key);
        }
        next
    }
}

/// Receiver-local exact soft directory. The primary map owns lease deadlines;
/// the secondary map locates the at-most-64 providers for one exact key.
pub(crate) struct ProviderDirectory {
    local_id: PeerId,
    memberships: BTreeMap<(ProviderKey, PeerId), (Mono, ProviderToken)>,
    providers_by_key: BTreeMap<ProviderKey, BTreeSet<PeerId>>,
    deadlines: BTreeSet<(Mono, ProviderKey, PeerId)>,
    responsibility: BTreeSet<([u8; 32], ProviderKey, PeerId)>,
    limits: DirectoryLimits,
}

#[derive(Clone, Copy)]
struct DirectoryLimits {
    lease: Duration,
    memberships: usize,
}

impl Default for ProviderDirectory {
    fn default() -> Self {
        Self::new([0; 32])
    }
}

impl ProviderDirectory {
    pub(crate) fn new(local_id: PeerId) -> Self {
        Self {
            local_id,
            memberships: BTreeMap::new(),
            providers_by_key: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            responsibility: BTreeSet::new(),
            limits: DirectoryLimits {
                lease: PROVIDER_LEASE_LIFETIME,
                memberships: MAX_PROVIDER_MEMBERSHIPS,
            },
        }
    }

    /// O(1) retained soft-state counts; expired entries may await bounded prune.
    pub(crate) fn retained_counts(&self) -> (usize, usize) {
        (self.memberships.len(), self.providers_by_key.len())
    }

    /// Install or renew one exact membership. Capacity pressure never prevents
    /// an already-admitted live membership from renewing.
    pub(crate) fn put(
        &mut self,
        key: ProviderKey,
        provider: PeerId,
        token: ProviderToken,
        now: Mono,
    ) -> bool {
        self.prune_expired(now);
        let membership = (key, provider);
        if let Some((previous, _)) = self.memberships.get(&membership).copied() {
            self.deadlines.remove(&(previous, key, provider));
        } else {
            self.prune_expired_key(key, now);
            if self
                .providers_by_key
                .get(&key)
                .is_some_and(|providers| providers.len() >= MAX_PROVIDERS_PER_KEY)
            {
                return false;
            }
            if self.memberships.len() >= self.limits.memberships {
                let candidate = (self.distance(key), key, provider);
                let Some(farthest) = self.responsibility.last().copied() else {
                    return false;
                };
                if candidate >= farthest {
                    return false;
                }
                self.remove_membership(farthest.1, farthest.2);
            }
            self.providers_by_key
                .entry(key)
                .or_default()
                .insert(provider);
            self.responsibility
                .insert((self.distance(key), key, provider));
        }

        let expires_at = now + self.limits.lease;
        self.memberships.insert(membership, (expires_at, token));
        self.deadlines.insert((expires_at, key, provider));
        true
    }

    /// Reclaim the at-most-64 stale memberships that can block this exact key.
    /// Global expiry cleanup remains bounded too, but unrelated older entries
    /// must never make a live insertion spuriously observe a saturated key.
    fn prune_expired_key(&mut self, key: ProviderKey, now: Mono) {
        let expired = self
            .providers_by_key
            .get(&key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|provider| {
                self.memberships
                    .get(&(key, *provider))
                    .is_some_and(|(expires_at, _)| *expires_at <= now)
            })
            .collect::<Vec<_>>();
        for provider in expired {
            self.remove_membership(key, provider);
        }
    }

    /// Return every live provider retained for one exact rendezvous key.
    pub(crate) fn get(&mut self, key: ProviderKey, now: Mono) -> Vec<(PeerId, ProviderToken)> {
        self.prune_expired(now);
        let Some(providers) = self.providers_by_key.get(&key) else {
            return Vec::new();
        };
        let mut result = Vec::with_capacity(MAX_PROVIDERS_PER_KEY.min(providers.len()));
        for provider in providers.iter().copied() {
            if self
                .memberships
                .get(&(key, provider))
                .is_some_and(|(expires_at, _)| *expires_at > now)
            {
                result.push((provider, self.memberships[&(key, provider)].1));
            }
        }
        result
    }

    fn prune_expired(&mut self, now: Mono) {
        for _ in 0..MAX_EXPIRED_PROVIDER_MEMBERSHIPS_PER_CALL {
            let Some((expires_at, key, provider)) = self.deadlines.first().copied() else {
                break;
            };
            if expires_at > now {
                break;
            }
            self.deadlines.remove(&(expires_at, key, provider));
            let membership = (key, provider);
            if self
                .memberships
                .get(&membership)
                .is_none_or(|(deadline, _)| *deadline != expires_at)
            {
                continue;
            }
            self.remove_membership(key, provider);
        }
    }

    fn distance(&self, key: ProviderKey) -> [u8; 32] {
        std::array::from_fn(|index| key[index] ^ self.local_id[index])
    }

    fn remove_membership(&mut self, key: ProviderKey, provider: PeerId) {
        let Some((deadline, _)) = self.memberships.remove(&(key, provider)) else {
            return;
        };
        self.deadlines.remove(&(deadline, key, provider));
        self.responsibility
            .remove(&(self.distance(key), key, provider));
        let remove_key = {
            let providers = self
                .providers_by_key
                .get_mut(&key)
                .expect("stored membership contributes to its exact-key index");
            providers.remove(&provider);
            providers.is_empty()
        };
        if remove_key {
            self.providers_by_key.remove(&key);
        }
    }

    #[cfg(test)]
    fn with_limits(lease: Duration, memberships: usize) -> Self {
        Self {
            limits: DirectoryLimits { lease, memberships },
            ..Self::new([0; 32])
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::time::Instant;

    use anybytes::Bytes;
    use triblespace_core::blob::encodings::UnknownBlob;
    use triblespace_core::inline::Inline;
    use triblespace_core::inline::encodings::hash::Handle;
    use triblespace_core::repo::memoryrepo::MemoryRepo;
    use triblespace_core::repo::{BlobStorePut, SnapshotSource};

    use super::*;

    type BlobHandle = Inline<Handle<UnknownBlob>>;

    const PROVIDER_SCALE_BATCH_LIMIT: usize = 256;

    #[derive(Debug)]
    struct PlacementBatchStats {
        entries: usize,
        frames: usize,
        max_entries_per_frame: usize,
    }

    fn deterministic_bytes(domain: &'static str, index: usize) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        hasher.update(&(index as u64).to_be_bytes());
        *hasher.finalize().as_bytes()
    }

    fn scale_parameter(name: &str, default: usize) -> usize {
        std::env::var(name).map_or(default, |value| {
            value
                .parse::<usize>()
                .unwrap_or_else(|error| panic!("{name} must be a positive integer: {error}"))
        })
    }

    #[cfg(target_os = "linux")]
    fn linux_rss_bytes() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kilobytes = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))?
            .split_ascii_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?;
        Some(kilobytes * 1024)
    }

    #[cfg(not(target_os = "linux"))]
    fn linux_rss_bytes() -> Option<u64> {
        None
    }

    fn placement_batch_stats(
        keys: impl IntoIterator<Item = ProviderKey>,
        peers: &[PeerId],
    ) -> PlacementBatchStats {
        assert!(peers.len() >= crate::routing::K);
        let mut entries_by_peer = BTreeMap::<PeerId, usize>::new();
        let mut ordered_peers = peers.to_vec();
        let mut entries = 0;
        for key in keys {
            ordered_peers.copy_from_slice(peers);
            ordered_peers
                .sort_unstable_by(|left, right| crate::routing::distance_cmp(key, *left, *right));
            for peer in ordered_peers.iter().take(crate::routing::K).copied() {
                *entries_by_peer.entry(peer).or_default() += 1;
                entries += 1;
            }
        }
        PlacementBatchStats {
            entries,
            frames: entries_by_peer.len(),
            max_entries_per_frame: entries_by_peer.values().copied().max().unwrap_or(0),
        }
    }

    fn put_blob(store: &mut MemoryRepo, byte: u8) -> BlobHandle {
        store
            .put::<UnknownBlob, _>(Bytes::from_source(vec![byte; 257]))
            .unwrap()
    }

    #[test]
    fn observation_contains_every_resident_blob_without_collection_participation() {
        let mut store = MemoryRepo::default();
        let handles = [
            put_blob(&mut store, 21).raw,
            put_blob(&mut store, 22).raw,
            put_blob(&mut store, 23).raw,
        ];
        let snapshot = store.snapshot().unwrap();
        let locators = crate::bearer::locator_index(&snapshot).unwrap();
        let observation = ProviderObservation::from_locators(&locators);
        assert_eq!(observation, ProviderObservation::from_blob_handles(handles));
        let set = observation.into_set();
        assert_eq!(set.len(), 3);
        assert_eq!(set.leases, locators);
        for handle in handles {
            assert_eq!(set.identity(&blob_locator(handle)), Some(handle));
            assert!(
                !set.contains(&handle),
                "raw bearer handles are not directory keys"
            );
        }
        assert_eq!(
            ProviderObservation::from_locators(&BearerLocatorIndex::new()),
            ProviderObservation::default()
        );
    }

    #[test]
    fn observation_remains_bound_to_its_resident_snapshot() {
        let mut store = MemoryRepo::default();
        let resident = put_blob(&mut store, 44);
        let snapshot = store.snapshot().unwrap();
        let mut locators = crate::bearer::locator_index(&snapshot).unwrap();
        let mut observed = ProviderObservation::from_locators(&locators).into_set();
        assert_eq!(observed.leases, locators);

        let later = [45; 32];
        locators.replace(&PatchEntry::with_value(&blob_locator(later), later));
        assert!(!observed.contains(&blob_locator(later)));
        observed.leases.remove(&blob_locator(resident.raw));
        assert_eq!(
            locators.get(&blob_locator(resident.raw)),
            Some(&resident.raw)
        );
        assert!(observed.leases.is_empty());
    }

    #[test]
    fn blob_handle_fixture_uses_exact_locators_and_deduplicates() {
        let handle = [44; 32];
        let set = ProviderObservation::from_blob_handles([handle, handle]).into_set();
        assert_eq!(set.len(), 1);
        assert_eq!(set.identity(&blob_locator(handle)), Some(handle));
        assert!(!set.contains(&handle));
    }

    #[test]
    fn blob_lease_tokens_are_handle_key_and_endpoint_bound() {
        let handle = [44; 32];
        let key = blob_locator(handle);
        let provider = [45; 32];
        assert_eq!(
            provider_lease_token(handle, key, provider),
            blob_provider_token(handle, provider)
        );
        assert_ne!(
            provider_lease_token(handle, key, provider),
            provider_lease_token(handle, key, [46; 32])
        );
        assert_ne!(
            provider_lease_token(handle, key, provider),
            provider_lease_token([47; 32], key, provider)
        );
        assert_ne!(
            provider_lease_token(handle, key, provider),
            provider_lease_token(handle, [48; 32], provider)
        );
    }

    #[test]
    fn directory_is_addressed_by_exact_blob_locator_not_raw_handle() {
        let artifact = [6; 32];
        let key = blob_locator(artifact);
        let provider = [7; 32];
        let now = crate::clock::mono_now();
        let mut directory = ProviderDirectory::default();
        assert!(directory.put(key, provider, [8; 32], now));

        assert!(directory.get(artifact, now).is_empty());
        assert_eq!(directory.get(key, now), vec![(provider, [8; 32])]);
    }

    #[test]
    fn keys_sharing_the_first_byte_remain_separate_dht_records() {
        let mut left = [0; 32];
        left[0] = 9;
        left[31] = 1;
        let mut right = left;
        right[31] = 2;
        let now = crate::clock::mono_now();
        let mut directory = ProviderDirectory::default();
        assert!(directory.put(left, [1; 32], [11; 32], now));
        assert!(directory.put(right, [2; 32], [12; 32], now));

        assert_eq!(directory.get(left, now), vec![([1; 32], [11; 32])]);
        assert_eq!(directory.get(right, now), vec![([2; 32], [12; 32])]);
    }

    #[test]
    fn renewal_at_capacity_preserves_membership_and_extends_lease() {
        let now = crate::clock::mono_now();
        let key = [1; 32];
        let provider = [2; 32];
        let mut directory = ProviderDirectory::with_limits(Duration::from_secs(10), 1);
        assert!(directory.put(key, provider, [8; 32], now));
        assert!(!directory.put([3; 32], [4; 32], [9; 32], now));
        assert!(directory.put(key, provider, [8; 32], now + Duration::from_secs(5)));
        assert_eq!(
            directory.get(key, now + Duration::from_secs(14)),
            vec![(provider, [8; 32])]
        );
        assert!(directory.get(key, now + Duration::from_secs(15)).is_empty());
    }

    #[test]
    fn exact_key_rejects_the_sixty_fifth_provider_but_renews_existing() {
        let now = crate::clock::mono_now();
        let key = [3; 32];
        let mut directory = ProviderDirectory::default();
        for byte in 1..=MAX_PROVIDERS_PER_KEY as u8 {
            assert!(directory.put(key, [byte; 32], [byte + 1; 32], now));
        }
        assert!(!directory.put(key, [65; 32], [66; 32], now));
        assert!(directory.put(key, [1; 32], [2; 32], now));
        assert_eq!(directory.get(key, now).len(), MAX_PROVIDERS_PER_KEY);
    }

    #[test]
    fn expired_exact_key_capacity_is_reclaimed_despite_global_backlog() {
        let now = crate::clock::mono_now();
        let expired_at = now + Duration::from_secs(1);
        let mut directory = ProviderDirectory::with_limits(Duration::from_secs(1), 1024);
        for index in 0_u16..128 {
            let mut key = [0; 32];
            key[..2].copy_from_slice(&index.to_be_bytes());
            assert!(directory.put(key, [1; 32], [2; 32], now));
        }
        let key = [0xFF; 32];
        for byte in 1..=MAX_PROVIDERS_PER_KEY as u8 {
            assert!(directory.put(key, [byte; 32], [byte; 32], now));
        }

        assert!(directory.put(key, [65; 32], [65; 32], expired_at));
        assert_eq!(directory.get(key, expired_at), vec![([65; 32], [65; 32])]);
    }

    #[test]
    fn one_provider_can_publish_more_than_1024_exact_keys() {
        let now = crate::clock::mono_now();
        let provider = [7; 32];
        let mut directory = ProviderDirectory::default();
        for index in 0_u32..2048 {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&index.to_be_bytes());
            assert!(directory.put(key, provider, [8; 32], now));
        }
        assert_eq!(directory.memberships.len(), 2048);
    }

    #[test]
    fn fresh_arrival_gets_a_turn_before_the_startup_backlog_drains() {
        let now = crate::clock::mono_now();
        let mut resident = ProviderSet::default();
        for index in 0_u32..4096 {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&index.to_be_bytes());
            resident.leases.replace(&PatchEntry::with_value(&key, key));
        }
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident.clone(), now);

        // The only incremental arrival sorts after every startup key. This
        // regression also compiles against the old single-queue scheduler,
        // where both turns consume startup entries and the assertion fails.
        let fresh = [0xFF; 32];
        resident
            .leases
            .replace(&PatchEntry::with_value(&fresh, fresh));
        publisher.install(resident, now);
        for _ in 0..2 {
            assert!(publisher.next(now).is_some());
        }
        assert!(
            !publisher.additions.contains(&fresh),
            "the incremental queue gets a turn within two non-retry pending turns"
        );
    }

    #[test]
    fn sustained_incremental_arrivals_do_not_starve_startup_work() {
        let now = crate::clock::mono_now();
        let mut resident = ProviderSet::default();
        for byte in 0..32 {
            resident
                .leases
                .replace(&PatchEntry::with_value(&[byte; 32], [byte; 32]));
        }
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident.clone(), now);

        for byte in 128..160 {
            let fresh = [byte; 32];
            resident
                .leases
                .replace(&PatchEntry::with_value(&fresh, fresh));
            publisher.install(resident.clone(), now);
            let first = publisher.next(now).unwrap();
            let second = publisher.next(now).unwrap();
            assert_eq!(first.lane, PublicationLane::Startup);
            assert_eq!(second.lane, PublicationLane::Incremental);
            assert_eq!(second.key, fresh);
        }
        let progress = publisher.progress();
        assert_eq!(progress.resident, 64);
        assert_eq!(progress.startup_pending, 0);
        assert_eq!(progress.incremental_pending, 0);
        assert_eq!(progress.retry_pending, 0);
        assert_eq!(progress.renewal_remaining, 0);
        assert!(!progress.topology_paused);
    }

    #[test]
    fn topology_failure_preserves_startup_and_incremental_pending_lanes() {
        let now = crate::clock::mono_now();
        let old = [0; 32];
        let fresh = [0xFF; 32];
        let mut resident = ProviderSet::default();
        resident.leases.replace(&PatchEntry::with_value(&old, old));
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident.clone(), now);
        let startup = publisher.next(now).unwrap();
        resident
            .leases
            .replace(&PatchEntry::with_value(&fresh, fresh));
        publisher.install(resident, now);
        let incremental = publisher.next(now).unwrap();
        assert_eq!(startup.lane, PublicationLane::Startup);
        assert_eq!(incremental.lane, PublicationLane::Incremental);

        for work in [startup, incremental] {
            publisher.complete(work, PublicationResult::NoAuthenticatedRemoteReplica, now);
        }
        let progress = publisher.progress();
        assert_eq!(progress.startup_pending, 1);
        assert_eq!(progress.incremental_pending, 1);
        assert!(progress.topology_paused);
        assert!(publisher.startup.contains(&old));
        assert!(!publisher.startup.contains(&fresh));
        assert!(publisher.additions.contains(&fresh));
        assert!(!publisher.additions.contains(&old));

        // Failed bounded probes retain their lane too, and still alternate
        // when the topology gate next grants a pending turn.
        for expected in [PublicationLane::Startup, PublicationLane::Incremental] {
            let retry_at = publisher.topology_outage.as_ref().unwrap().retry_at;
            let probe = publisher.next(retry_at).unwrap();
            assert_eq!(probe.lane, expected);
            publisher.complete(
                probe,
                PublicationResult::NoAuthenticatedRemoteReplica,
                retry_at,
            );
        }
        assert_eq!(publisher.progress().startup_pending, 1);
        assert_eq!(publisher.progress().incremental_pending, 1);
    }

    #[test]
    fn topology_failed_retry_and_renewal_return_as_historical_work() {
        let now = crate::clock::mono_now();
        let fresh = [0xFF; 32];
        for renewal in [false, true] {
            let mut publisher = ProviderPublisher::new(now);
            publisher.install(ProviderSet::default(), now);
            let mut resident = ProviderSet::default();
            resident
                .leases
                .replace(&PatchEntry::with_value(&fresh, fresh));
            publisher.install(resident, now);
            let first = publisher.next(now).unwrap();
            assert_eq!(first.lane, PublicationLane::Incremental);
            let due = if renewal {
                publisher.complete(first, PublicationResult::Published, now);
                now + PROVIDER_RENEWAL_PERIOD
            } else {
                publisher.complete(first, PublicationResult::RemoteRejected, now);
                now + crate::RETRY_BACKOFF_BASE
            };
            let work = publisher.next(due).unwrap();
            assert_eq!(work.lane, PublicationLane::Startup);
            publisher.complete(work, PublicationResult::NoAuthenticatedRemoteReplica, due);
            assert_eq!(publisher.progress().startup_pending, 1);
            assert_eq!(publisher.progress().incremental_pending, 0);
            assert_eq!(publisher.progress().retry_pending, 0);
        }
    }

    #[test]
    fn snapshot_removal_prunes_both_pending_lanes() {
        let now = crate::clock::mono_now();
        let old = [0; 32];
        let fresh = [0xFF; 32];
        let mut resident = ProviderSet::default();
        resident.leases.replace(&PatchEntry::with_value(&old, old));
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident.clone(), now);
        resident
            .leases
            .replace(&PatchEntry::with_value(&fresh, fresh));
        publisher.install(resident, now);
        assert_eq!(publisher.progress().startup_pending, 1);
        assert_eq!(publisher.progress().incremental_pending, 1);
        publisher.install(ProviderSet::default(), now);
        assert_eq!(publisher.progress().resident, 0);
        assert_eq!(publisher.progress().startup_pending, 0);
        assert_eq!(publisher.progress().incremental_pending, 0);
        assert!(publisher.next(now).is_none());
    }

    #[test]
    fn due_renewal_is_not_starved_by_sustained_additions() {
        let now = crate::clock::mono_now();
        let old_key = [0; 32];
        let old_token = [1; 32];
        let mut resident = ProviderSet::default();
        resident
            .leases
            .replace(&PatchEntry::with_value(&old_key, old_token));
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident.clone(), now);
        assert_eq!(
            publisher.next(now).map(|work| (work.key, work.identity)),
            Some((old_key, old_token))
        );

        // Make the next due call service a new arrival first. The following
        // call must nevertheless advance the already-due renewal traversal.
        publisher.prefer_cycle = false;
        let due = now + PROVIDER_RENEWAL_PERIOD;
        let first_new = [2; 32];
        resident
            .leases
            .replace(&PatchEntry::with_value(&first_new, [3; 32]));
        publisher.install(resident.clone(), due);
        assert_eq!(
            publisher.next(due).map(|work| (work.key, work.identity)),
            Some((first_new, [3; 32]))
        );

        let second_new = [4; 32];
        resident
            .leases
            .replace(&PatchEntry::with_value(&second_new, [5; 32]));
        publisher.install(resident, due);
        assert_eq!(
            publisher.next(due).map(|work| (work.key, work.identity)),
            Some((old_key, old_token))
        );
    }

    #[test]
    fn failed_publication_waits_for_retry_backoff() {
        let now = crate::clock::mono_now();
        let key = [9; 32];
        let token = [10; 32];
        let mut resident = ProviderSet::default();
        resident
            .leases
            .replace(&PatchEntry::with_value(&key, token));
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident, now);
        assert_eq!(
            publisher.next(now).map(|work| (work.key, work.identity)),
            Some((key, token))
        );
        assert!(publisher.retry(key, now));

        assert_eq!(publisher.next(now), None);
        assert_eq!(
            publisher
                .next(now + crate::RETRY_BACKOFF_BASE)
                .map(|work| (work.key, work.identity)),
            Some((key, token))
        );
    }

    #[test]
    fn latest_inventory_preserves_pending_and_retry_work_without_intermediate_installs() {
        let now = crate::clock::mono_now();
        let inventory = |keys: &[u8]| {
            let mut set = ProviderSet::default();
            for key in keys {
                set.leases
                    .replace(&PatchEntry::with_value(&[*key; 32], [*key; 32]));
            }
            set
        };
        let mut replayed = ProviderPublisher::new(now);
        let mut latest = ProviderPublisher::new(now);
        for publisher in [&mut replayed, &mut latest] {
            publisher.install(inventory(&[1, 2, 3, 4]), now);
            assert_eq!(publisher.next(now).unwrap().key, [1; 32]);
            assert!(publisher.retry([1; 32], now));
        }
        replayed.install(inventory(&[1, 2, 3, 4, 5]), now);
        replayed.install(inventory(&[1, 2, 3, 4, 5, 6]), now);
        latest.install(inventory(&[1, 2, 3, 4, 5, 6]), now);
        assert_eq!(replayed.resident, latest.resident);
        assert_eq!(replayed.startup, latest.startup);
        assert_eq!(replayed.additions, latest.additions);
        assert_eq!(replayed.retries, latest.retries);
        assert_eq!(latest.startup, inventory(&[2, 3, 4]));
        assert_eq!(latest.additions, inventory(&[5, 6]));
        assert_eq!(latest.retries, inventory(&[1]));

        let renewal = latest.next_renewal;
        let retry = latest.retry_at;
        latest.install(inventory(&[1, 2, 3, 4, 5, 6]), now + Duration::from_secs(1));
        assert_eq!(latest.next_renewal, renewal);
        assert_eq!(latest.retry_at, retry);
        assert_eq!(latest.startup, replayed.startup);
        assert_eq!(latest.additions, replayed.additions);
        assert_eq!(latest.retries, replayed.retries);

        latest.install(inventory(&[3, 4, 5, 6]), now);
        assert_eq!(latest.startup, inventory(&[3, 4]));
        assert_eq!(latest.additions, inventory(&[5, 6]));
        assert!(latest.retries.leases.is_empty());
        // A late failure from the old generation cannot resurrect a withdrawn key.
        assert!(latest.retry([1; 32], now));
        assert!(latest.retries.leases.is_empty());
        let mut scheduled = BTreeSet::new();
        while let Some(work) = latest.next(now) {
            scheduled.insert(work.key);
        }
        assert_eq!(
            scheduled,
            BTreeSet::from([[3; 32], [4; 32], [5; 32], [6; 32]])
        );
        latest.install(ProviderSet::default(), now);
        assert!(latest.next(now + PROVIDER_RENEWAL_PERIOD).is_none());
        latest.install(inventory(&[7]), now + PROVIDER_RENEWAL_PERIOD);
        assert_eq!(
            latest.next(now + PROVIDER_RENEWAL_PERIOD).unwrap().key,
            [7; 32]
        );
    }

    #[test]
    fn find_node_responder_then_put_unavailable_preserves_the_large_pending_sweep() {
        let now = crate::clock::mono_now();
        let local = [0x11; 32];
        let remote = [0x22; 32];
        let unavailable = PublicationResult::from_put_results(
            local,
            [
                (local, ProviderPutResult::Accepted),
                (remote, ProviderPutResult::Unavailable),
            ],
        );
        assert_eq!(unavailable, PublicationResult::NoAuthenticatedRemoteReplica);
        let key_count = MAX_PROVIDER_PUBLICATION_RETRIES as usize + 1025;
        let resident = ProviderObservation::from_blob_handles((0..key_count).map(|index| {
            deterministic_bytes("triblespace.net/isolated-provider-handle/v1", index)
        }))
        .into_set();
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident, now);

        // These are the only attempts that can have left before the first
        // no-route outcome closes the global breaker.
        let initial = (0..crate::routing::ALPHA)
            .map(|_| publisher.next(now).expect("initial publication attempt"))
            .collect::<Vec<_>>();
        for (index, work) in initial.into_iter().enumerate() {
            let effect = publisher.complete(work, unavailable, now);
            assert_eq!(effect.topology_outage_started, index == 0);
        }

        assert_eq!(publisher.startup.leases.len(), key_count as u64);
        assert!(publisher.additions.leases.is_empty());
        assert!(publisher.retries.leases.is_empty());
        assert!(publisher.next(now).is_none());

        let retry_at = publisher.topology_outage.as_ref().unwrap().retry_at;
        let probe = publisher.next(retry_at).expect("one bounded retry probe");
        assert!(publisher.next(retry_at).is_none());
        let effect = publisher.complete(probe, unavailable, retry_at);
        assert!(!effect.topology_outage_started);
        assert_eq!(publisher.startup.leases.len(), key_count as u64);
        assert!(publisher.additions.leases.is_empty());
        assert!(publisher.retries.leases.is_empty());
        assert!(publisher.next(retry_at).is_none());
    }

    #[test]
    fn authenticated_peer_appearance_releases_the_complete_pending_sweep() {
        let now = crate::clock::mono_now();
        let local = [0x11; 32];
        let remote = [0x22; 32];
        let unavailable =
            PublicationResult::from_put_results(local, [(remote, ProviderPutResult::Unavailable)]);
        let published =
            PublicationResult::from_put_results(local, [(remote, ProviderPutResult::Accepted)]);
        let key_count = MAX_PROVIDER_PUBLICATION_RETRIES as usize + 1025;
        let resident =
            ProviderObservation::from_blob_handles((0..key_count).map(|index| {
                deterministic_bytes("triblespace.net/resumed-provider-handle/v1", index)
            }))
            .into_set();
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident, now);

        let first = publisher.next(now).unwrap();
        assert!(
            publisher
                .complete(first, unavailable, now)
                .topology_outage_started
        );
        let retry_at = publisher.topology_outage.as_ref().unwrap().retry_at;
        let probe = publisher.next(retry_at).expect("topology retry probe");
        let effect = publisher.complete(probe, published, retry_at);

        assert!(effect.topology_recovered);
        assert!(publisher.topology_outage.is_none());
        assert!(publisher.retries.leases.is_empty());
        let mut published_count = 1;
        while let Some(work) = publisher.next(retry_at) {
            let effect = publisher.complete(work, published, retry_at);
            assert!(!effect.topology_outage_started);
            published_count += 1;
        }
        assert_eq!(published_count, key_count);
        assert!(publisher.startup.leases.is_empty());
        assert!(publisher.additions.leases.is_empty());
        assert!(publisher.retries.leases.is_empty());
    }

    #[test]
    fn authenticated_remote_rejection_uses_the_per_key_retry_set() {
        let now = crate::clock::mono_now();
        let local = [0x11; 32];
        let remote = [0x22; 32];
        let rejected = PublicationResult::from_put_results(
            local,
            [(remote, ProviderPutResult::ExplicitlyRejected)],
        );
        assert_eq!(rejected, PublicationResult::RemoteRejected);
        let key = [0xA5; 32];
        let identity = [0x5A; 32];
        let mut resident = ProviderSet::default();
        resident
            .leases
            .replace(&PatchEntry::with_value(&key, identity));
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident, now);

        let work = publisher.next(now).unwrap();
        assert_eq!((work.key, work.identity), (key, identity));
        let effect = publisher.complete(work, rejected, now);
        assert!(!effect.topology_outage_started);
        assert!(!effect.retry_budget_full);
        assert!(publisher.topology_outage.is_none());
        assert_eq!(publisher.retries.leases.len(), 1);
        assert_eq!(publisher.next(now), None);
        assert_eq!(
            publisher
                .next(now + crate::RETRY_BACKOFF_BASE)
                .map(|work| (work.key, work.identity)),
            Some((key, identity))
        );
    }

    #[test]
    fn renewal_cycle_uses_an_eight_hour_anchor() {
        let now = crate::clock::mono_now();
        let mut resident = ProviderSet::default();
        for byte in 1..=4 {
            resident
                .leases
                .replace(&PatchEntry::with_value(&[byte; 32], [byte + 10; 32]));
        }
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident, now);
        while publisher.next(now).is_some() {}

        let started = now + PROVIDER_RENEWAL_PERIOD;
        let interval =
            Duration::from_nanos((PROVIDER_RENEWAL_PERIOD.as_nanos() / 4).try_into().unwrap());
        for offset in 0..4 {
            assert!(publisher.next(started + interval * offset).is_some());
        }
        assert!(publisher.cycle.is_none());
        assert_eq!(publisher.next_renewal, started + PROVIDER_RENEWAL_PERIOD);
        assert!(
            publisher.next(started + PROVIDER_RENEWAL_PERIOD).is_some(),
            "the next traversal begins at the prior cycle's anchored deadline"
        );
    }

    #[test]
    fn first_sweep_renews_its_last_key_with_a_full_cycle_of_margin() {
        let now = crate::clock::mono_now();
        let resident = ProviderObservation::from_blob_handles((0_u16..257).map(|index| {
            let mut handle = [0; 32];
            handle[..2].copy_from_slice(&index.to_be_bytes());
            handle
        }))
        .into_set();
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident, now);
        while publisher.next(now).is_some() {}

        let mut emitted_at = now + PROVIDER_RENEWAL_PERIOD;
        assert!(publisher.next(emitted_at).is_some());
        while let Some(next_due) = publisher.cycle.as_ref().map(|cycle| cycle.next_due) {
            emitted_at = next_due;
            assert!(publisher.next(emitted_at).is_some());
        }

        assert!(
            emitted_at <= now + (PROVIDER_LEASE_LIFETIME - PROVIDER_RENEWAL_PERIOD),
            "the final initial lease needs one complete renewal-cycle budget before expiry"
        );
    }

    #[test]
    fn expiry_reclamation_is_bounded_and_stale_entries_are_never_returned() {
        let now = crate::clock::mono_now();
        let key = [3; 32];
        let mut directory = ProviderDirectory::with_limits(Duration::from_secs(1), 100);
        for byte in 1..=64 {
            assert!(directory.put(key, [byte; 32], [byte + 1; 32], now));
        }
        let other = [4; 32];
        assert!(directory.put(other, [65; 32], [66; 32], now));

        assert!(directory.get(key, now + Duration::from_secs(1)).is_empty());
        assert_eq!(directory.memberships.len(), 1);
        assert!(
            directory
                .get(other, now + Duration::from_secs(1))
                .is_empty()
        );
        assert!(directory.memberships.is_empty());
    }

    #[test]
    fn prospective_provider_put_batching_preserves_every_placement() {
        let keys = (0..16)
            .map(|index| deterministic_bytes("triblespace.net/provider-scale-key/v1", index));
        let peers = (0..64)
            .map(|index| deterministic_bytes("triblespace.net/provider-scale-peer/v1", index))
            .collect::<Vec<_>>();
        let stats = placement_batch_stats(keys, &peers);

        assert_eq!(stats.entries, 16 * crate::routing::K);
        assert!(stats.frames <= stats.entries);
        assert!(stats.max_entries_per_frame <= 16);
    }

    #[test]
    fn pending_publication_descent_matches_ordered_selection_with_stale_entries() {
        let mut pending = ProviderSet::default();
        let mut resident = ProviderSet::default();
        for index in 0..1024 {
            let key = deterministic_bytes("provider-descent-test-key", index);
            pending
                .leases
                .replace(&PatchEntry::with_value(&key, [0; 32]));
            if index % 3 == 0 {
                resident
                    .leases
                    .replace(&PatchEntry::with_value(&key, [1; 32]));
            }
        }
        let expected: Vec<_> = resident.leases.iter_ordered().copied().collect();
        let actual: Vec<_> = std::iter::from_fn(|| {
            ProviderPublisher::pop_pending(&mut pending, &resident, PublicationLane::Incremental)
        })
        .map(|work| {
            assert_eq!(work.identity, [1; 32]);
            assert_eq!(work.lane, PublicationLane::Incremental);
            work.key
        })
        .collect();
        assert_eq!(actual, expected);
        assert!(pending.leases.is_empty());
    }

    #[test]
    #[ignore = "manual pending-publication selection comparison"]
    fn pending_publication_selection_probe() {
        let count = scale_parameter("TRIBLESPACE_PROVIDER_SCALE_KEYS", 10_000);
        let mut original = ProviderSet::default();
        for index in 0..count {
            let key = deterministic_bytes("provider-descent-test-key", index);
            original.leases.replace(&PatchEntry::with_value(&key, key));
        }
        let expected = original.leases.iter_ordered().copied().collect::<Vec<_>>();
        for direct in [false, true, true, false] {
            let mut pending = original.clone();
            let start = Instant::now();
            for expected_key in &expected {
                let key = if direct {
                    pending
                        .leases
                        .first_infix_range(&[], &[0; 32], &[255; 32])
                        .unwrap()
                } else {
                    *pending.leases.iter_ordered().next().unwrap()
                };
                assert_eq!(&key, expected_key);
                pending.leases.remove(&key);
                black_box(key);
            }
            assert!(pending.leases.is_empty());
            println!(
                "pending_selection direct={direct} keys={count} seconds={:.6}",
                start.elapsed().as_secs_f64()
            );
        }
    }

    /// Deterministic, opt-in scale probe for the provider directory, publisher,
    /// and a prospective bounded PUT-frame grouping. This intentionally stays
    /// beside the private implementation seam instead of becoming public API.
    ///
    /// Run with `cargo test -p triblespace-net --release provider_scale_probe
    /// -- --ignored --nocapture`. `TRIBLESPACE_PROVIDER_SCALE_KEYS` controls
    /// directory/publisher cardinality (default 100,000), while
    /// `TRIBLESPACE_PROVIDER_SCALE_PEERS` controls the synthetic XOR mesh
    /// (default 1,024). At most 256 keys participate in the placement sample.
    #[test]
    #[ignore = "manual deterministic provider scale measurement"]
    fn provider_scale_probe() {
        let key_count = scale_parameter("TRIBLESPACE_PROVIDER_SCALE_KEYS", 100_000);
        let peer_count = scale_parameter("TRIBLESPACE_PROVIDER_SCALE_PEERS", 1_024);
        assert!(key_count > 0);
        assert!(peer_count >= crate::routing::K);

        let entries = (0..key_count)
            .map(|index| {
                (
                    deterministic_bytes("triblespace.net/provider-scale-key/v1", index),
                    deterministic_bytes("triblespace.net/provider-scale-token/v1", index),
                )
            })
            .collect::<Vec<_>>();
        let provider = deterministic_bytes("triblespace.net/provider-scale-provider/v1", 0);
        let now = crate::clock::mono_now();
        let rss_before = linux_rss_bytes();
        let mut directory = ProviderDirectory::new(deterministic_bytes(
            "triblespace.net/provider-scale-directory/v1",
            0,
        ));

        let insert_started = Instant::now();
        for (key, token) in entries.iter().copied() {
            assert!(directory.put(key, provider, token, now));
        }
        let insert_elapsed = insert_started.elapsed();
        let rss_after = linux_rss_bytes();

        let get_started = Instant::now();
        let returned = entries
            .iter()
            .map(|(key, _)| directory.get(*key, now).len())
            .sum::<usize>();
        black_box(returned);
        let get_elapsed = get_started.elapsed();
        assert_eq!(returned, key_count);

        let rss_delta = rss_before
            .zip(rss_after)
            .map(|(before, after)| after.saturating_sub(before));
        println!(
            "provider_directory keys={key_count} insert_seconds={:.6} insert_per_second={:.2} get_seconds={:.6} get_per_second={:.2} linux_rss_delta_bytes={} linux_rss_delta_bytes_per_key={}",
            insert_elapsed.as_secs_f64(),
            key_count as f64 / insert_elapsed.as_secs_f64(),
            get_elapsed.as_secs_f64(),
            key_count as f64 / get_elapsed.as_secs_f64(),
            rss_delta.map_or_else(|| "n/a".to_owned(), |bytes| bytes.to_string()),
            rss_delta.map_or_else(
                || "n/a".to_owned(),
                |bytes| format!("{:.2}", bytes as f64 / key_count as f64),
            ),
        );
        drop(directory);

        let mut resident = ProviderSet::default();
        for (key, identity) in entries.iter().copied() {
            resident
                .leases
                .replace(&PatchEntry::with_value(&key, identity));
        }
        let mut publisher = ProviderPublisher::new(now);
        publisher.install(resident, now);
        while publisher.next(now).is_some() {}

        let renewal_started = Instant::now();
        let mut renewal_now = now + PROVIDER_RENEWAL_PERIOD;
        let mut renewed = 0;
        while renewed < key_count {
            assert!(publisher.next(renewal_now).is_some());
            renewed += 1;
            if renewed < key_count {
                renewal_now = publisher
                    .cycle
                    .as_ref()
                    .expect("the renewal traversal remains active")
                    .next_due;
            }
        }
        let renewal_elapsed = renewal_started.elapsed();
        let required_keys_per_second = key_count as f64 / PROVIDER_RENEWAL_PERIOD.as_secs_f64();
        let required_put_entries_per_second = required_keys_per_second * crate::routing::K as f64;
        println!(
            "provider_scheduler keys={key_count} selection_seconds={:.6} selections_per_second={:.2} required_key_lookups_per_second_8h={required_keys_per_second:.6} required_put_entries_per_second_8h={required_put_entries_per_second:.6}",
            renewal_elapsed.as_secs_f64(),
            key_count as f64 / renewal_elapsed.as_secs_f64(),
        );

        let batch_size = key_count.min(PROVIDER_SCALE_BATCH_LIMIT);
        let peers = (0..peer_count)
            .map(|index| deterministic_bytes("triblespace.net/provider-scale-peer/v1", index))
            .collect::<Vec<_>>();
        let placement_started = Instant::now();
        let stats =
            placement_batch_stats(entries.iter().take(batch_size).map(|(key, _)| *key), &peers);
        let placement_elapsed = placement_started.elapsed();
        let frame_compression = stats.entries as f64 / stats.frames as f64;
        let overlap = 1.0 - stats.frames as f64 / stats.entries as f64;
        println!(
            "provider_put_projection keys={batch_size} peers={peer_count} replicas_per_key={} placement_seconds={:.6} unbatched_frames={} grouped_frames={} frame_compression={frame_compression:.3} target_overlap={overlap:.6} max_entries_per_frame={}",
            crate::routing::K,
            placement_elapsed.as_secs_f64(),
            stats.entries,
            stats.frames,
            stats.max_entries_per_frame,
        );
    }
}
